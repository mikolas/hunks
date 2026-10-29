// Package callgraph constructs a static subroutine call graph over the project's active
// segments, resolving both direct `BSR`/`JSR` edges and indirect `jsr d16(An)` jump-vector
// table calls, and provides bottom-up (`--leaves`, `--ready`), hardware/string anchor
// (`--anchors`), and suspect-boundary (`--suspect`) queries.
package callgraph

import (
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/google/btree"
	"github.com/mikolas/hunks/internal/amiga"
	"github.com/mikolas/hunks/internal/db"
	"github.com/mikolas/hunks/internal/m68k"
	"github.com/mikolas/hunks/internal/project"
)

type CallSite struct {
	CallerFunc uint32 `json:"caller_func"`
	CallInsn   uint32 `json:"call_insn"`
	TargetFunc uint32 `json:"target_func"`
	Kind       string `json:"kind"`
}

type AddrStringPair struct {
	Addr uint32
	Text string
}

func (p AddrStringPair) MarshalJSON() ([]byte, error) {
	return json.Marshal([2]any{p.Addr, p.Text})
}

type FunctionNode struct {
	EntryAddr      uint32           `json:"entry_addr"`
	Name           string           `json:"name"`
	RawName        string           `json:"raw_name"`
	IsRenamed      bool             `json:"is_renamed"`
	IsExported     bool             `json:"is_exported"`
	Segment        string           `json:"segment"`
	OffsetInSeg    uint32           `json:"offset_in_seg"`
	InsnAddrs      []uint32         `json:"insn_addrs"`
	ByteSize       uint32           `json:"byte_size"`
	SelfMinCycles  uint32           `json:"self_min_cycles"`
	SelfMaxCycles  uint32           `json:"self_max_cycles"`
	InclMinCycles  uint32           `json:"incl_min_cycles"`
	InclMaxCycles  uint32           `json:"incl_max_cycles"`
	HasLoop        bool             `json:"has_loop"`
	HasIndirect    bool             `json:"has_indirect"`
	HasSMC         bool             `json:"has_smc,omitempty"`
	ABI            string           `json:"abi,omitempty"`
	InRegs         []string         `json:"in_regs,omitempty"`
	ModRegs        []string         `json:"mod_regs,omitempty"`
	SavedRegs      []string         `json:"saved_regs,omitempty"`
	BlockComment   *string          `json:"block_comment"`
	Callers        []CallSite       `json:"callers"`
	Callees        []CallSite       `json:"callees"`
	Strings        []AddrStringPair `json:"strings"`
	HWRegs         []string         `json:"hw_regs"`
	GlobalsRead    []AddrStringPair `json:"globals_read,omitempty"`
	GlobalsWritten []AddrStringPair `json:"globals_written,omitempty"`
	DataAddrs      []AddrStringPair `json:"data_addrs,omitempty"`
	IndirectCalls  []AddrStringPair `json:"indirect_calls"`
	SuspectCutoff  *AddrStringPair  `json:"suspect_cutoff"`
}

func regMaskNames(mask m68k.RegMask) []string {
	var out []string
	for r := uint8(0); r < 8; r++ {
		if (mask & m68k.RegD(r)) != 0 {
			out = append(out, m68k.RegDName(r))
		}
	}
	for r := uint8(0); r < 7; r++ {
		if (mask & m68k.RegA(r)) != 0 {
			out = append(out, m68k.RegAName(r))
		}
	}
	return out
}

func (f *FunctionNode) StaticABISummary() string {
	var parts []string
	if len(f.InRegs) > 0 {
		parts = append(parts, "in: "+strings.Join(f.InRegs, ","))
	} else {
		parts = append(parts, "in: none")
	}
	if len(f.ModRegs) > 0 {
		parts = append(parts, "mod: "+strings.Join(f.ModRegs, ","))
	} else {
		parts = append(parts, "mod: none")
	}
	if len(f.SavedRegs) > 0 {
		parts = append(parts, "saved: "+strings.Join(f.SavedRegs, ","))
	}
	return strings.Join(parts, " | ")
}

// VerifyABI checks a free-form ABI string against statically inferred InRegs and ModRegs
// and returns human-readable contradiction warnings (or nil if consistent).
func VerifyABI(abiStr string, inRegs, modRegs, savedRegs []string) []string {
	lower := strings.ToLower(abiStr)
	inSection := lower
	var modSection string
	for _, sep := range []string{"clobbers:", "clobber:", "mod:", "modifies:"} {
		if before, after, ok := strings.Cut(inSection, sep); ok {
			inSection = before
			modSection = after
			break
		}
	}
	if before, _, ok := strings.Cut(inSection, "->"); ok {
		inSection = before
	}

	isValidReg := func(tok string) bool {
		if len(tok) != 2 {
			return false
		}
		if tok[0] == 'd' {
			return tok[1] >= '0' && tok[1] <= '7'
		}
		if tok[0] == 'a' {
			return tok[1] >= '0' && tok[1] <= '6'
		}
		return false
	}

	extractRegs := func(s string) []string {
		tokens := strings.FieldsFunc(s, func(r rune) bool {
			return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-'
		})
		var regs []string
		addReg := func(r string) {
			if isValidReg(r) && !slices.Contains(regs, r) {
				regs = append(regs, r)
			}
		}
		for _, tok := range tokens {
			if startR, endR, hasDash := strings.Cut(tok, "-"); hasDash {
				if isValidReg(startR) {
					if len(endR) == 1 && endR[0] >= '0' && endR[0] <= '7' {
						endR = string(startR[0]) + endR
					}
					if isValidReg(endR) && startR[0] == endR[0] && startR[1] <= endR[1] {
						for ch := startR[1]; ch <= endR[1]; ch++ {
							addReg(string([]byte{startR[0], ch}))
						}
						continue
					}
				}
				for _, sub := range strings.Split(tok, "-") {
					addReg(sub)
				}
				continue
			}
			addReg(tok)
		}
		return regs
	}

	var warnings []string
	for _, r := range extractRegs(inSection) {
		if !slices.Contains(inRegs, r) && !slices.Contains(savedRegs, r) {
			if slices.Contains(modRegs, r) {
				warnings = append(warnings, fmt.Sprintf("claimed input register %s is overwritten before being read in function body", r))
			} else {
				warnings = append(warnings, fmt.Sprintf("claimed input register %s is never read in function body", r))
			}
		}
	}
	for _, r := range extractRegs(modSection) {
		if !slices.Contains(modRegs, r) {
			warnings = append(warnings, fmt.Sprintf("claimed clobbered register %s is never written (or is callee-saved)", r))
		}
	}
	return warnings
}

type IndirectSiteInfo struct {
	Addr        uint32   `json:"addr"`
	Segment     string   `json:"segment"`
	OffsetInSeg uint32   `json:"offset_in_seg"`
	FuncName    string   `json:"func_name"`
	FnOffset    string   `json:"fn_offset"`
	InsnText    string   `json:"insn"`
	Status      string   `json:"status"`
	Targets     []string `json:"targets"`
}

func formatFnOffset(addr, entryAddr uint32) string {
	if addr >= entryAddr {
		return fmt.Sprintf("+%X", addr-entryAddr)
	}
	return fmt.Sprintf("-%X", entryAddr-addr)
}

func formatCycleSpan(lo, hi uint32) string {
	if lo == hi {
		return strconv.FormatUint(uint64(lo), 10)
	}
	return strconv.FormatUint(uint64(lo), 10) + "-" + strconv.FormatUint(uint64(hi), 10)
}

func (f *FunctionNode) FormatCycles() string {
	if f.SelfMaxCycles == 0 {
		return "-- cyc"
	}
	var sb strings.Builder
	sb.WriteString(formatCycleSpan(f.SelfMinCycles, f.SelfMaxCycles))
	sb.WriteString(" cyc")
	if f.InclMaxCycles > f.SelfMaxCycles || f.InclMinCycles > f.SelfMinCycles {
		sb.WriteString(" [incl: ")
		sb.WriteString(formatCycleSpan(f.InclMinCycles, f.InclMaxCycles))
		sb.WriteString(" cyc]")
	}
	if f.HasLoop {
		sb.WriteString(" +loop")
	}
	if f.HasIndirect {
		sb.WriteString(" +ind")
	}
	return sb.String()
}

func (f *FunctionNode) IsLeaf() bool {
	return len(f.Callees) == 0 && len(f.IndirectCalls) == 0
}

func (f *FunctionNode) QualifiedName() string {
	if f.Segment != "" && f.Segment != "unknown" {
		return fmt.Sprintf("%s:%s", f.Segment, f.Name)
	}
	return f.Name
}

func (f *FunctionNode) FormatLoc() string {
	return fmt.Sprintf("%s +%05X", f.Segment, f.OffsetInSeg)
}

type CallGraph struct {
	Functions     map[uint32]*FunctionNode
	FuncAddrs     []uint32
	InsnToFunc    map[uint32]uint32
	Cells         map[uint32]db.Cell
	Comments      map[uint32]db.AddressComment
	CellsTree     *btree.BTreeG[db.Cell]
	Labels        map[uint32]string
	RawLabels     map[uint32]string
	IndirectSites []IndirectSiteInfo
}

type Options struct {
	Target    string
	Segment   string
	Depth     int
	UpDepth   int
	Code      bool
	Leaves    bool
	Anchors   bool
	Ready     bool
	Suspect   bool
	Indirect  bool
	Unrenamed bool
	Limit     int
	Format    string
}

type edgeTarget struct {
	target uint32
	kind   db.EdgeKind
}

type xrefTarget struct {
	addr uint32
	kind db.XrefKind
}

// Build constructs the complete CallGraph for `proj`'s active address space.
//
// It infers subroutine entry points from explicit project entries, segment bases, direct
// `CALL` targets, exported `XDEF` code labels, and non-branch code pointers, then traces
// each subroutine's reachable basic-block closure (`traceFunction`), collects string and
// hardware-register references, resolves `jsr/jmp d16(An)` jump-vector calls, and wires
// deduplicated caller/callee edges across functions.
func Build(proj *project.Project) (*CallGraph, error) {
	cells := make(map[uint32]db.Cell)
	cellsTree := btree.NewG(32, func(a, b db.Cell) bool {
		return a.Addr < b.Addr
	})
	rawLabels := make(map[uint32]string)
	labels := make(map[uint32]string)
	comments := make(map[uint32]db.AddressComment)
	segDataCache := make(map[uint32][]byte)
	exportedSet := make(map[uint32]bool)
	edgesBySrc := make(map[uint32][]edgeTarget)
	callTargets := make(map[uint32]bool)
	branchTargets := make(map[uint32]bool)
	xrefsBySrc := make(map[uint32][]xrefTarget)
	pointerTargets := make(map[uint32]bool)
	jmpTableBases := make(map[string]uint32)

	seenDBs := make(map[string]bool)
	for _, seg := range proj.ActiveSegments() {
		if seenDBs[seg.DB] {
			continue
		}
		seenDBs[seg.DB] = true
		if err := func(dbPath string) error {
			ctrl, err := db.New(dbPath)
			if err != nil {
				return err
			}
			defer ctrl.Close()
			proj.SyncDBScope(ctrl)

			allCells, err := ctrl.GetAllCells()
			if err != nil {
				return err
			}
			for _, c := range allCells {
				cells[c.Addr] = c
				cellsTree.ReplaceOrInsert(c)
			}

			for _, lb := range ctrl.AllLabelsWithExport() {
				rawLabels[lb.Addr] = lb.Name
				if lb.IsExported {
					exportedSet[lb.Addr] = true
				}
			}

			if resolvedMap, err := ctrl.GetAllLabelsResolved(); err == nil {
				maps.Copy(labels, resolvedMap)
			}
			if cmts, err := ctrl.GetAllTargetComments(); err == nil {
				maps.Copy(comments, cmts)
			}

			for _, e := range ctrl.AllEdgesNoFallthrough() {
				if e.Kind == db.EdgeCall {
					callTargets[e.Target] = true
				} else {
					branchTargets[e.Target] = true
				}
				edgesBySrc[e.Source] = append(edgesBySrc[e.Source], edgeTarget{target: e.Target, kind: e.Kind})
			}

			for _, x := range ctrl.AllXrefs() {
				if srcCell, ok := cells[x.Source]; ok && srcCell.Type == db.CellPointer {
					pointerTargets[x.Target] = true
				}
				xrefsBySrc[x.Source] = append(xrefsBySrc[x.Source], xrefTarget{
					addr: x.Target,
					kind: x.Kind,
				})
			}
			maps.Copy(jmpTableBases, ctrl.DetectJumpVectorBases())
			return nil
		}(seg.DB); err != nil {
			return nil, err
		}
	}

	activeSegs := proj.ActiveSegments()
	funcStartsSet := make(map[uint32]bool)
	isCodeAt := func(addr uint32) bool {
		c, ok := cells[addr]
		return ok && c.Type == db.CellCode
	}

	for _, ep := range proj.Data.EntryPoints {
		inActive := ep.Segment == ""
		if !inActive {
			for _, s := range activeSegs {
				if strings.EqualFold(s.Name, ep.Segment) {
					inActive = true
					break
				}
			}
		}
		if inActive && isCodeAt(ep.Addr) {
			funcStartsSet[ep.Addr] = true
		}
	}
	for _, seg := range activeSegs {
		if isCodeAt(seg.Base) {
			funcStartsSet[seg.Base] = true
		}
	}
	for tgt := range callTargets {
		if isCodeAt(tgt) {
			funcStartsSet[tgt] = true
		}
	}
	for expAddr := range exportedSet {
		if isCodeAt(expAddr) {
			funcStartsSet[expAddr] = true
		}
	}
	for pt := range pointerTargets {
		if !branchTargets[pt] && isCodeAt(pt) {
			funcStartsSet[pt] = true
		}
	}
	for lAddr, lName := range labels {
		rawName := rawLabels[lAddr]
		if (lName != rawName || !project.IsAutoLabel(lName)) && !branchTargets[lAddr] && isCodeAt(lAddr) {
			funcStartsSet[lAddr] = true
		}
	}

	hwEquates := make(map[string]bool)
	for k := range amiga.GetAllEquates() {
		if k != "_custom" && k != "_ciaa" && k != "_ciab" {
			hwEquates[k] = true
		}
	}

	resolveVectoredCall := func(opStr string) (string, int32, uint32, bool) {
		regStr, disp, ok := db.ParseVectoredOperand(opStr)
		if !ok {
			return "", 0, 0, false
		}
		baseAddr, ok := jmpTableBases[regStr]
		if !ok {
			return "", 0, 0, false
		}
		trampAddr := uint32(int64(baseAddr) + int64(disp))
		for _, edge := range edgesBySrc[trampAddr] {
			if edge.kind == db.EdgeUncond || edge.kind == db.EdgeCall {
				return regStr, disp, edge.target, true
			}
		}
		if trampXrefs := xrefsBySrc[trampAddr+2]; len(trampXrefs) > 0 {
			return regStr, disp, trampXrefs[0].addr, true
		}
		if isCodeAt(trampAddr) {
			return regStr, disp, trampAddr, true
		}
		return "", 0, 0, false
	}

	functions := make(map[uint32]*FunctionNode)
	insnToFunc := make(map[uint32]uint32)

	traceFunction := func(entryAddr uint32, knownStarts map[uint32]bool) *FunctionNode {
		segOpt := proj.SegmentAtAddr(entryAddr)
		segName := "?"
		segBase := uint32(0)
		segEnd := uint32(0xFFFFFFFF)
		if segOpt != nil {
			segName = segOpt.Name
			segBase = segOpt.Base
			segEnd = segOpt.EndAddr()
		}

		visitedSet := make(map[uint32]bool)
		queue := []uint32{entryAddr}
		visitedSet[entryAddr] = true
		var suspectCutoff *AddrStringPair

		for len(queue) > 0 {
			addr := queue[0]
			queue = queue[1:]

			cell, ok := cells[addr]
			if !ok || cell.Type != db.CellCode {
				continue
			}
			if _, owned := insnToFunc[addr]; !owned {
				insnToFunc[addr] = entryAddr
			}

			mnem := cell.MnemonicStr()
			isTerm := isTerminator(mnem)

			for _, outEdge := range edgesBySrc[addr] {
				tgt := outEdge.target
				kind := outEdge.kind
				if (kind == db.EdgeCondTrue || kind == db.EdgeUncond) &&
					tgt >= segBase && tgt < segEnd &&
					(tgt == entryAddr || !knownStarts[tgt]) {
					if tgtCell, ok := cells[tgt]; ok {
						if tgtCell.Type == db.CellCode {
							if !visitedSet[tgt] {
								visitedSet[tgt] = true
								queue = append(queue, tgt)
							}
						} else if suspectCutoff == nil {
							suspectCutoff = &AddrStringPair{Addr: tgt, Text: tgtCell.Type.AsStr()}
						}
					}
				}
			}

			if !isTerm {
				nextAddr := addr + cell.Size
				if nextAddr >= segBase && nextAddr < segEnd && !knownStarts[nextAddr] {
					if nextCell, ok := cells[nextAddr]; ok {
						if nextCell.Type == db.CellCode {
							if !visitedSet[nextAddr] {
								visitedSet[nextAddr] = true
								queue = append(queue, nextAddr)
							}
						} else if suspectCutoff == nil {
							suspectCutoff = &AddrStringPair{Addr: nextAddr, Text: nextCell.Type.AsStr()}
						}
					}
				}
			}
		}

		insnAddrs := slices.Sorted(maps.Keys(visitedSet))

		var byteSize uint32
		for _, a := range insnAddrs {
			if c, ok := cells[a]; ok {
				byteSize += c.Size
			}
		}

		rawName, ok := rawLabels[entryAddr]
		if !ok || rawName == "" {
			rawName = proj.AutoLabel(entryAddr)
		}
		name, ok := labels[entryAddr]
		if !ok || name == "" {
			name = rawName
		}
		isRenamed := name != rawName || !project.IsAutoLabel(name)
		isExported := exportedSet[entryAddr]

		var blockComment *string
		if ac, ok := comments[entryAddr]; ok {
			if ac.BlockComment != "" {
				s := ac.BlockComment
				blockComment = &s
			} else if eff := ac.EffectiveComment(); eff != "" {
				blockComment = &eff
			}
		}

		stringMap := make(map[uint32]string)
		hwSet := make(map[string]bool)
		globalsReadMap := make(map[uint32]string)
		globalsWriteMap := make(map[uint32]string)
		dataAddrMap := make(map[uint32]string)
		var indirectCalls []AddrStringPair
		var selfMinCyc, selfMaxCyc uint32
		var inMask, modMask, savedMask m68k.RegMask
		hasLoop := false
		hasSMC := false

		// Order instructions starting from entryAddr first, followed by any backward-branched
		// tail/helper blocks at addresses < entryAddr, so prologue register saves (isEntrySave)
		// and read-before-write liveness (inMask vs modMask) evaluate from the true entry point.
		flowAddrs := make([]uint32, 0, len(insnAddrs))
		for _, ia := range insnAddrs {
			if ia >= entryAddr {
				flowAddrs = append(flowAddrs, ia)
			}
		}
		for _, ia := range insnAddrs {
			if ia < entryAddr {
				flowAddrs = append(flowAddrs, ia)
			}
		}

		for insnIdx, ia := range flowAddrs {
			cell, ok := cells[ia]
			if !ok {
				continue
			}
			mnem := cell.MnemonicStr()
			opStr := cell.OpStrVal()

			raw := cell.RawBytes
			if len(raw) < 2 && segOpt != nil {
				data, ok := segDataCache[segOpt.Base]
				if !ok {
					data = segOpt.LoadBinaryData()
					segDataCache[segOpt.Base] = data
				}
				off := int(ia - segOpt.Base)
				end := min(off+int(cell.Size), len(data))
				if off >= 0 && off < end {
					raw = data[off:end]
				}
			}
			if insn, ok := m68k.Decode(raw, ia); ok {
				isEntrySave := insnIdx <= 2 && insn.Op == m68k.OpMOVEM && insn.NumOps == 2 && insn.Ops[1].Mode == m68k.EAPreDec && insn.Ops[1].Reg == 7
				isExitRestore := insn.Op == m68k.OpMOVEM && insn.NumOps == 2 && insn.Ops[0].Mode == m68k.EAPostInc && insn.Ops[0].Reg == 7
				if isEntrySave {
					savedMask |= insn.ReadRegs &^ m68k.RegA(7)
				} else if !isExitRestore {
					rMask := insn.ReadRegs &^ m68k.RegA(7)
					if (insn.Op == m68k.OpSUB || insn.Op == m68k.OpEOR) && insn.NumOps == 2 &&
						insn.Ops[0].Mode == insn.Ops[1].Mode && insn.Ops[0].Reg == insn.Ops[1].Reg {
						rMask = 0
					}
					inMask |= rMask &^ modMask
					modMask |= insn.WriteRegs &^ m68k.RegA(7)
				}

				t := insn.Timing()
				switch t.Kind {
				case m68k.TimingBranch, m68k.TimingRange:
					selfMinCyc += uint32(min(t.Primary.Cycles, t.Secondary.Cycles))
					selfMaxCyc += uint32(max(t.Primary.Cycles, t.Secondary.Cycles))
				default:
					selfMinCyc += uint32(t.Primary.Cycles)
					selfMaxCyc += uint32(t.Primary.Cycles)
				}
				if insn.IsBranch() && !insn.IsCall() {
					for _, op := range insn.Operands() {
						if (op.Mode == m68k.EABranch || op.Mode == m68k.EAPCDisp16) && op.UVal >= entryAddr && op.UVal <= ia {
							hasLoop = true
						}
					}
				}
			}
			for _, e := range edgesBySrc[ia] {
				if (e.kind == db.EdgeCondTrue || e.kind == db.EdgeUncond) && e.target >= entryAddr && e.target <= ia {
					hasLoop = true
				}
			}

			if mnem == "jsr" || mnem == "jmp" {
				hasDirectEdge := false
				for _, e := range edgesBySrc[ia] {
					if e.kind == db.EdgeCall || e.kind == db.EdgeUncond {
						hasDirectEdge = true
						break
					}
				}
				if !hasDirectEdge {
					if _, _, _, ok := resolveVectoredCall(opStr); !ok {
						indirectCalls = append(indirectCalls, AddrStringPair{
							Addr: ia,
							Text: fmt.Sprintf("%s %s", mnem, opStr),
						})
					}
				}
			}

			tokens := strings.FieldsFunc(opStr, func(r rune) bool {
				return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_'
			})
			for _, tok := range tokens {
				if tok != "" && (hwEquates[tok] ||
					strings.HasPrefix(tok, "CUSTOM_") ||
					strings.HasPrefix(tok, "CIAA_") ||
					strings.HasPrefix(tok, "CIAB_")) {
					hwSet[tok] = true
				}
			}
			if ac, ok := comments[ia]; ok && strings.Contains(ac.EffectiveComment(), "[SMC]") {
				hasSMC = true
			}

			for subAddr := ia; subAddr < ia+cell.Size; subAddr++ {
				for _, xr := range xrefsBySrc[subAddr] {
					if _, isHW := amiga.GetAmigaHWLabel(xr.addr); isHW {
						continue
					}
					if xr.addr >= 0xDFF000 && xr.addr <= 0xDFF1FF {
						continue
					}
					if tgtCell, ok := cells[xr.addr]; ok && tgtCell.Type == db.CellStr {
						sVal := extractStringPreview(proj, xr.addr, &tgtCell, segDataCache)
						if sVal != "" {
							stringMap[xr.addr] = sVal
							continue
						}
					}
					lbl := labels[xr.addr]
					switch xr.kind {
					case db.XrefDataRead:
						globalsReadMap[xr.addr] = lbl
					case db.XrefDataWrite:
						globalsWriteMap[xr.addr] = lbl
						if tgtCell, ok := cells[xr.addr]; ok && tgtCell.Type == db.CellCode {
							hasSMC = true
						}
					case db.XrefDataAddr:
						dataAddrMap[xr.addr] = lbl
					}
				}
			}
		}
		modMask &^= savedMask

		strAddrs := slices.Sorted(maps.Keys(stringMap))
		stringsList := make([]AddrStringPair, len(strAddrs))
		for i, a := range strAddrs {
			stringsList[i] = AddrStringPair{Addr: a, Text: stringMap[a]}
		}

		toSortedPairs := func(m map[uint32]string) []AddrStringPair {
			if len(m) == 0 {
				return nil
			}
			keys := slices.Sorted(maps.Keys(m))
			res := make([]AddrStringPair, len(keys))
			for i, a := range keys {
				res[i] = AddrStringPair{Addr: a, Text: m[a]}
			}
			return res
		}

		hwRegs := slices.Sorted(maps.Keys(hwSet))

		if indirectCalls == nil {
			indirectCalls = []AddrStringPair{}
		}

		var offsetInSeg uint32
		if entryAddr > segBase {
			offsetInSeg = entryAddr - segBase
		}

		return &FunctionNode{
			EntryAddr:      entryAddr,
			Name:           name,
			RawName:        rawName,
			IsRenamed:      isRenamed,
			IsExported:     isExported,
			Segment:        segName,
			OffsetInSeg:    offsetInSeg,
			InsnAddrs:      insnAddrs,
			ByteSize:       byteSize,
			SelfMinCycles:  selfMinCyc,
			SelfMaxCycles:  selfMaxCyc,
			InclMinCycles:  selfMinCyc,
			InclMaxCycles:  selfMaxCyc,
			HasLoop:        hasLoop,
			HasIndirect:    len(indirectCalls) > 0,
			HasSMC:         hasSMC,
			ABI:            proj.GetFunctionABI(name, rawName, proj.AutoLabel(entryAddr)),
			InRegs:         regMaskNames(inMask),
			ModRegs:        regMaskNames(modMask),
			SavedRegs:      regMaskNames(savedMask),
			BlockComment:   blockComment,
			Callers:        []CallSite{},
			Callees:        []CallSite{},
			Strings:        stringsList,
			HWRegs:         hwRegs,
			GlobalsRead:    toSortedPairs(globalsReadMap),
			GlobalsWritten: toSortedPairs(globalsWriteMap),
			DataAddrs:      toSortedPairs(dataAddrMap),
			IndirectCalls:  indirectCalls,
			SuspectCutoff:  suspectCutoff,
		}
	}

	// Pass 1: Trace from explicit function starts in ascending order
	for _, entryAddr := range slices.Sorted(maps.Keys(funcStartsSet)) {
		if _, visited := insnToFunc[entryAddr]; !visited {
			functions[entryAddr] = traceFunction(entryAddr, funcStartsSet)
		}
	}

	// Pass 2: Pick up remaining unvisited CODE islands
	cellsTree.Ascend(func(c db.Cell) bool {
		if c.Type == db.CellCode {
			if _, visited := insnToFunc[c.Addr]; !visited {
				funcStartsSet[c.Addr] = true
				functions[c.Addr] = traceFunction(c.Addr, funcStartsSet)
			}
		}
		return true
	})

	funcAddrs := slices.Sorted(maps.Keys(functions))

	// Pass 3: Wire up caller <-> callee edges
	var allCallSites []CallSite
	for _, funcAddr := range funcAddrs {
		insns := functions[funcAddr].InsnAddrs
		for _, ia := range insns {
			var cellMnem string
			if c, ok := cells[ia]; ok {
				cellMnem = c.MnemonicStr()
			}
			if outEdges, hasEdges := edgesBySrc[ia]; hasEdges {
				for _, outEdge := range outEdges {
					tgt := outEdge.target
					kind := outEdge.kind
					var tf uint32
					var hasTF bool
					if _, isFunc := functions[tgt]; isFunc {
						tf = tgt
						hasTF = true
					} else if owner, ok := insnToFunc[tgt]; ok {
						tf = owner
						hasTF = true
					}
					if hasTF {
						if kind == db.EdgeCall {
							via := "via jsr"
							if cellMnem != "" {
								via = fmt.Sprintf("via %s", cellMnem)
							}
							allCallSites = append(allCallSites, CallSite{
								CallerFunc: funcAddr,
								CallInsn:   ia,
								TargetFunc: tf,
								Kind:       via,
							})
						} else if kind == db.EdgeUncond && tf != funcAddr {
							if _, isEntry := functions[tgt]; isEntry {
								via := "via jmp"
								if cellMnem != "" {
									via = fmt.Sprintf("via %s", cellMnem)
								}
								allCallSites = append(allCallSites, CallSite{
									CallerFunc: funcAddr,
									CallInsn:   ia,
									TargetFunc: tf,
									Kind:       via,
								})
							}
						}
					}
				}
			} else if cell, ok := cells[ia]; ok {
				mnem := cell.MnemonicStr()
				opStr := cell.OpStrVal()
				if mnem == "jsr" || mnem == "jmp" {
					if reg, disp, realTgt, ok := resolveVectoredCall(opStr); ok {
						var tf uint32
						var hasTF bool
						if _, isFunc := functions[realTgt]; isFunc {
							tf = realTgt
							hasTF = true
						} else if owner, ok := insnToFunc[realTgt]; ok {
							tf = owner
							hasTF = true
						}
						if hasTF {
							allCallSites = append(allCallSites, CallSite{
								CallerFunc: funcAddr,
								CallInsn:   ia,
								TargetFunc: tf,
								Kind:       fmt.Sprintf("via %s %d(%s)", mnem, disp, reg),
							})
						}
					}
				}
			}
		}
	}

	for _, site := range allCallSites {
		if caller, ok := functions[site.CallerFunc]; ok {
			dup := false
			for _, c := range caller.Callees {
				if c.TargetFunc == site.TargetFunc && c.CallInsn == site.CallInsn {
					dup = true
					break
				}
			}
			if !dup {
				caller.Callees = append(caller.Callees, site)
			}
		}
		if callee, ok := functions[site.TargetFunc]; ok {
			dup := false
			for _, c := range callee.Callers {
				if c.CallerFunc == site.CallerFunc && c.CallInsn == site.CallInsn {
					dup = true
					break
				}
			}
			if !dup {
				callee.Callers = append(callee.Callers, site)
			}
		}
	}

	type inclResult struct {
		minCyc      uint32
		maxCyc      uint32
		hasLoop     bool
		hasIndirect bool
	}
	memo := make(map[uint32]inclResult, len(funcAddrs))
	visiting := make(map[uint32]bool)
	var computeIncl func(addr uint32) inclResult
	computeIncl = func(addr uint32) inclResult {
		if res, ok := memo[addr]; ok {
			return res
		}
		f, ok := functions[addr]
		if !ok {
			return inclResult{}
		}
		if visiting[addr] {
			return inclResult{hasLoop: true}
		}
		visiting[addr] = true
		res := inclResult{
			minCyc:      f.SelfMinCycles,
			maxCyc:      f.SelfMaxCycles,
			hasLoop:     f.HasLoop,
			hasIndirect: f.HasIndirect,
		}
		for _, site := range f.Callees {
			if site.TargetFunc == addr || visiting[site.TargetFunc] {
				res.hasLoop = true
				continue
			}
			sub := computeIncl(site.TargetFunc)
			res.minCyc += sub.minCyc
			res.maxCyc += sub.maxCyc
			if sub.hasLoop {
				res.hasLoop = true
			}
			if sub.hasIndirect {
				res.hasIndirect = true
			}
		}
		delete(visiting, addr)
		memo[addr] = res
		return res
	}
	for _, addr := range funcAddrs {
		res := computeIncl(addr)
		f := functions[addr]
		f.InclMinCycles = res.minCyc
		f.InclMaxCycles = res.maxCyc
		f.HasLoop = res.hasLoop
		f.HasIndirect = res.hasIndirect
	}

	// Collect all indirect/trampoline dispatch sites across active functions.
	indirectSiteSet := make(map[uint32]bool)
	for _, s := range proj.Data.Analysis.IndirectAddressing {
		if a, err := project.ParseHex(s); err == nil {
			indirectSiteSet[a] = true
		}
	}
	for _, fAddr := range funcAddrs {
		f := functions[fAddr]
		for _, ic := range f.IndirectCalls {
			indirectSiteSet[ic.Addr] = true
		}
		for _, ia := range f.InsnAddrs {
			if c, ok := cells[ia]; ok {
				mnem := c.MnemonicStr()
				opStr := c.OpStrVal()
				if mnem == "jsr" || mnem == "jmp" {
					if strings.Contains(opStr, "(") {
						indirectSiteSet[ia] = true
					}
				}
			}
		}
	}
	var indirectSites []IndirectSiteInfo
	for _, ia := range slices.Sorted(maps.Keys(indirectSiteSet)) {
		c, ok := cells[ia]
		if !ok || c.Type != db.CellCode {
			continue
		}
		seg := proj.SegmentAtAddr(ia)
		segName := "?"
		var offInSeg uint32
		if seg != nil {
			segName = seg.Name
			if ia >= seg.Base {
				offInSeg = ia - seg.Base
			}
		}
		var fnName, fnOff string
		if fAddr, ok := insnToFunc[ia]; ok {
			if f, ok := functions[fAddr]; ok {
				fnName = f.QualifiedName()
				fnOff = formatFnOffset(ia, f.EntryAddr)
			}
		}
		mnem := c.MnemonicStr()
		opStr := c.OpStrVal()
		var targets []string
		for _, e := range edgesBySrc[ia] {
			if e.kind == db.EdgeCall || e.kind == db.EdgeUncond {
				lbl := labels[e.target]
				if lbl == "" {
					lbl = proj.AutoLabel(e.target)
				}
				if !slices.Contains(targets, lbl) {
					targets = append(targets, lbl)
				}
			}
		}
		if len(targets) == 0 {
			if _, _, realTgt, ok := resolveVectoredCall(opStr); ok {
				lbl := labels[realTgt]
				if lbl == "" {
					lbl = proj.AutoLabel(realTgt)
				}
				targets = append(targets, lbl)
			}
		}
		status := "unresolved"
		if len(targets) > 0 {
			status = "resolved"
		}
		indirectSites = append(indirectSites, IndirectSiteInfo{
			Addr:        ia,
			Segment:     segName,
			OffsetInSeg: offInSeg,
			FuncName:    fnName,
			FnOffset:    fnOff,
			InsnText:    strings.TrimSpace(mnem + " " + opStr),
			Status:      status,
			Targets:     targets,
		})
	}

	return &CallGraph{
		Functions:     functions,
		FuncAddrs:     funcAddrs,
		InsnToFunc:    insnToFunc,
		Cells:         cells,
		Comments:      comments,
		CellsTree:     cellsTree,
		Labels:        labels,
		RawLabels:     rawLabels,
		IndirectSites: indirectSites,
	}, nil
}

func isTerminator(mnem string) bool {
	switch mnem {
	case "rts", "rte", "rtr", "jmp", "bra", "bra.s", "bra.w", "bra.l", "illegal", "stop":
		return true
	}
	return false
}

func extractStringPreview(
	proj *project.Project,
	addr uint32,
	cell *db.Cell,
	segCache map[uint32][]byte,
) string {
	if op := cell.OpStrVal(); op != "" {
		return op
	}
	seg := proj.SegmentAtAddr(addr)
	if seg == nil {
		return ""
	}
	data, ok := segCache[seg.Base]
	if !ok {
		data = seg.LoadBinaryData()
		segCache[seg.Base] = data
	}
	off := int(addr - seg.Base)
	end := min(off+int(cell.Size), len(data))
	if off >= end {
		return ""
	}
	var sb strings.Builder
	for _, b := range data[off:end] {
		if b == 0 {
			break
		} else if b >= 0x20 && b <= 0x7E {
			sb.WriteByte(b)
		} else if b == '\t' {
			sb.WriteString("\\t")
		} else if b == '\n' {
			sb.WriteString("\\n")
		}
		if sb.Len() >= 48 {
			sb.WriteString("...")
			break
		}
	}
	return sb.String()
}

func NormalizeSegmentFilter(seg string) string {
	trimmed := strings.TrimSpace(seg)
	if trimmed == "" {
		return ""
	}
	allDigits := true
	for i := 0; i < len(trimmed); i++ {
		if trimmed[i] < '0' || trimmed[i] > '9' {
			allDigits = false
			break
		}
	}
	if allDigits {
		return fmt.Sprintf("hunk%s", trimmed)
	}
	return trimmed
}

func (cg *CallGraph) ResolveTarget(proj *project.Project, target string, segFilter string) (uint32, bool) {
	target = strings.TrimSpace(target)
	normSeg := NormalizeSegmentFilter(segFilter)
	if segPart, rest, hasColon := strings.Cut(target, ":"); hasColon {
		normPart := NormalizeSegmentFilter(segPart)
		return cg.ResolveTarget(proj, strings.TrimSpace(rest), normPart)
	}

	// 1. Exact match on resolved label name, raw label name, or qualified name
	for _, addr := range cg.FuncAddrs {
		f := cg.Functions[addr]
		if normSeg != "" && !strings.EqualFold(f.Segment, normSeg) {
			continue
		}
		if strings.EqualFold(f.Name, target) ||
			strings.EqualFold(f.RawName, target) ||
			strings.EqualFold(f.QualifiedName(), target) {
			return addr, true
		}
	}

	segMatches := func(fAddr uint32) bool {
		if normSeg == "" {
			return true
		}
		if f, ok := cg.Functions[fAddr]; ok {
			return strings.EqualFold(f.Segment, normSeg)
		}
		return true
	}

	for addr, name := range cg.Labels {
		if strings.EqualFold(name, target) {
			if fAddr, ok := cg.InsnToFunc[addr]; ok && segMatches(fAddr) {
				return fAddr, true
			}
		}
	}
	for addr, raw := range cg.RawLabels {
		if strings.EqualFold(raw, target) {
			if fAddr, ok := cg.InsnToFunc[addr]; ok && segMatches(fAddr) {
				return fAddr, true
			}
		}
	}

	// 2. Pattern LAB_<hunk>_<offset>
	rest, hasLab := strings.CutPrefix(target, "LAB_")
	if !hasLab {
		rest, hasLab = strings.CutPrefix(target, "lab_")
	}
	if hasLab {
		if hunkStr, offStr, hasU := strings.Cut(rest, "_"); hasU {
			hunkIdx, err1 := strconv.Atoi(hunkStr)
			off, err2 := strconv.ParseUint(offStr, 16, 32)
			if err1 == nil && err2 == nil {
				for i := range proj.Data.Segments {
					s := &proj.Data.Segments[i]
					if s.HunkIndex == hunkIdx && s.IsRelocatable() {
						abs := s.Base + uint32(off)
						if _, ok := cg.Functions[abs]; ok {
							return abs, true
						}
						if fAddr, ok := cg.InsnToFunc[abs]; ok {
							return fAddr, true
						}
					}
				}
			}
		}
	}

	// 3. Segment offset (+0011C)
	if offStr, ok := strings.CutPrefix(target, "+"); ok {
		if off, err := project.ParseHex(offStr); err == nil {
			var seg *project.Segment
			if normSeg != "" {
				seg = proj.SegmentByName(normSeg)
			} else {
				seg = proj.CurrentSegment()
			}
			if seg != nil {
				abs := seg.Base + off
				if _, ok := cg.Functions[abs]; ok {
					return abs, true
				}
				if fAddr, ok := cg.InsnToFunc[abs]; ok {
					return fAddr, true
				}
				return 0, false
			}
		}
	}

	// 4. Hex address or offset within segFilter
	if addr, err := project.ParseHex(target); err == nil {
		if normSeg != "" {
			if s := proj.SegmentByName(normSeg); s != nil {
				abs := addr
				if addr < s.FileSize() || addr < s.AllocSize {
					abs = s.Base + addr
				}
				if _, ok := cg.Functions[abs]; ok {
					return abs, true
				}
				if fAddr, ok := cg.InsnToFunc[abs]; ok {
					return fAddr, true
				}
				if abs != addr && addr >= s.Base && addr < s.EndAddr() {
					if _, ok := cg.Functions[addr]; ok {
						return addr, true
					}
					if fAddr, ok := cg.InsnToFunc[addr]; ok {
						return fAddr, true
					}
				}
				return 0, false
			}
		}
		if _, ok := cg.Functions[addr]; ok {
			return addr, true
		}
		if fAddr, ok := cg.InsnToFunc[addr]; ok {
			return fAddr, true
		}
	}

	return 0, false
}

func (cg *CallGraph) Render(proj *project.Project, opts *Options) (string, error) {
	normSeg := NormalizeSegmentFilter(opts.Segment)
	if opts.Indirect {
		return cg.renderIndirect(opts, normSeg)
	}
	if opts.Target != "" {
		funcAddr, ok := cg.ResolveTarget(proj, opts.Target, normSeg)
		if !ok {
			return "", fmt.Errorf("Function or address '%s' not found in call graph", opts.Target)
		}
		return cg.renderTarget(proj, funcAddr, opts)
	}
	return cg.renderWorklist(opts, normSeg)
}

func (cg *CallGraph) renderIndirect(opts *Options, normSeg string) (string, error) {
	var sites []IndirectSiteInfo
	var resolvedCnt, unresolvedCnt int
	for _, s := range cg.IndirectSites {
		if normSeg != "" && !strings.EqualFold(s.Segment, normSeg) {
			continue
		}
		if s.Status == "resolved" {
			resolvedCnt++
		} else {
			unresolvedCnt++
		}
		sites = append(sites, s)
	}
	if opts.Format == "json" {
		payload := map[string]any{
			"total":      len(sites),
			"resolved":   resolvedCnt,
			"unresolved": unresolvedCnt,
			"sites":      sites,
		}
		b, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	var out strings.Builder
	fmt.Fprintf(&out, "=== Indirect Dispatch Sites (%d total: %d resolved, %d unresolved) ===\n", len(sites), resolvedCnt, unresolvedCnt)
	for _, s := range sites {
		fnCtx := ""
		if s.FuncName != "" {
			fnCtx = fmt.Sprintf("[%s%s]", s.FuncName, s.FnOffset)
		}
		if s.Status == "resolved" {
			fmt.Fprintf(&out, "  +%05X  %-24s %-22s -> %s (resolved)\n", s.OffsetInSeg, fnCtx, s.InsnText, strings.Join(s.Targets, ", "))
		} else {
			fmt.Fprintf(&out, "  +%05X  %-24s %-22s -> [UNRESOLVED]\n", s.OffsetInSeg, fnCtx, s.InsnText)
		}
	}
	return out.String(), nil
}

func (cg *CallGraph) renderTarget(proj *project.Project, funcAddr uint32, opts *Options) (string, error) {
	f := cg.Functions[funcAddr]
	segBase := f.EntryAddr - f.OffsetInSeg

	if opts.Format == "json" {
		type codeLine struct {
			Offset   string `json:"offset"`
			FnOffset string `json:"fn_offset"`
			Label    string `json:"label"`
			Mnemonic string `json:"mnemonic"`
			Operands string `json:"operands"`
			Comment  string `json:"comment"`
		}
		codeLines := []codeLine{}
		if opts.Code {
			for _, ia := range f.InsnAddrs {
				if c, ok := cg.Cells[ia]; ok {
					var off uint32
					if ia > segBase {
						off = ia - segBase
					}
					fnOffStr := fmt.Sprintf("+%03X", ia-f.EntryAddr)
					if ia < f.EntryAddr {
						fnOffStr = fmt.Sprintf("-%03X", f.EntryAddr-ia)
					}
					ops := proj.ApplyStructAliasesToOpStr(c.OpStrVal(), f.Name, f.RawName)
					cmt := cg.Comments[ia].EffectiveComment()
					for _, site := range f.Callees {
						if site.CallInsn == ia {
							if tf, ok := cg.Functions[site.TargetFunc]; ok {
								if cmt == "" && (tf.Segment != f.Segment || strings.Contains(ops, "(")) {
									cmt = fmt.Sprintf("-> %s", tf.QualifiedName())
								}
								if tf.ABI != "" && !strings.Contains(cmt, "ABI:") {
									if cmt == "" {
										cmt = fmt.Sprintf("[ABI: %s]", tf.ABI)
									} else {
										cmt += fmt.Sprintf(" [ABI: %s]", tf.ABI)
									}
								}
							}
							break
						}
					}
					codeLines = append(codeLines, codeLine{
						Offset:   fmt.Sprintf("+%05X", off),
						FnOffset: fnOffStr,
						Label:    cg.Labels[ia],
						Mnemonic: c.MnemonicStr(),
						Operands: ops,
						Comment:  cmt,
					})
				}
			}
		}
		payload := map[string]any{
			"function":    f,
			"disassembly": codeLines,
		}
		b, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return "", err
		}
		return string(b), nil
	}

	if opts.Format == "dot" || opts.Format == "mermaid" {
		subNodes := make(map[uint32]bool)
		cg.collectNeighborhood(funcAddr, opts.UpDepth, opts.Depth, subNodes)
		sortedNodes := slices.Sorted(maps.Keys(subNodes))
		return cg.renderGraphDiagram(sortedNodes, opts.Format), nil
	}

	var out strings.Builder

	// 1. Incoming Callers
	fmt.Fprintf(&out, "=== Incoming Callers (up to depth %d) ===\n", opts.UpDepth)
	if len(f.Callers) == 0 {
		out.WriteString("  (none — root/entry or called indirectly via pointer table)\n")
	} else {
		visited := map[uint32]bool{funcAddr: true}
		cg.fmtCallersTree(&out, funcAddr, 1, opts.UpDepth, visited)
	}
	out.WriteByte('\n')

	// 2. Target Function Summary
	renameTag := " [UNRENAMED]"
	if f.IsRenamed {
		renameTag = fmt.Sprintf(" (was %s)", f.RawName)
	}
	expTag := ""
	if f.IsExported {
		expTag = " [XDEF]"
	}
	out.WriteString("=== Target Function ===\n")
	fmt.Fprintf(
		&out,
		"  %s%s [+%05X] — %d insts, %d bytes, %s%s\n",
		f.QualifiedName(),
		renameTag,
		f.OffsetInSeg,
		len(f.InsnAddrs),
		f.ByteSize,
		f.FormatCycles(),
		expTag,
	)
	if f.BlockComment != nil {
		for _, line := range strings.Split(*f.BlockComment, "\n") {
			line = strings.TrimSuffix(line, "\r")
			fmt.Fprintf(&out, "  ; %s\n", line)
		}
	}
	if f.ABI != "" {
		fmt.Fprintf(&out, "  ABI:            %s\n", f.ABI)
	}
	if staticABI := f.StaticABISummary(); staticABI != "" {
		fmt.Fprintf(&out, "  Regs (static):  %s\n", staticABI)
	}
	if len(f.Strings) > 0 {
		strs := make([]string, len(f.Strings))
		for i, sp := range f.Strings {
			lbl := cg.Labels[sp.Addr]
			if lbl == "" {
				lbl = proj.AutoLabel(sp.Addr)
			}
			qual := proj.QualifiedLabel(sp.Addr, lbl)
			strs[i] = fmt.Sprintf("%s:%q", qual, sp.Text)
		}
		fmt.Fprintf(&out, "  Strings:        %s\n", strings.Join(strs, ", "))
	}
	if len(f.HWRegs) > 0 {
		fmt.Fprintf(&out, "  HW Registers:   %s\n", strings.Join(f.HWRegs, ", "))
	}
	if len(f.IndirectCalls) > 0 {
		ind := make([]string, len(f.IndirectCalls))
		for i, ic := range f.IndirectCalls {
			var off uint32
			if ic.Addr > segBase {
				off = ic.Addr - segBase
			}
			ind[i] = fmt.Sprintf("+%05X: %s", off, ic.Text)
		}
		fmt.Fprintf(&out, "  Indirect Calls: %s\n", strings.Join(ind, ", "))
	}
	if f.SuspectCutoff != nil {
		var off uint32
		if f.SuspectCutoff.Addr > segBase {
			off = f.SuspectCutoff.Addr - segBase
		}
		fmt.Fprintf(
			&out,
			"  [!] SUSPECT FALLTHROUGH: falls into %s at +%05X without rts/jmp/bra\n",
			f.SuspectCutoff.Text,
			off,
		)
	}
	out.WriteByte('\n')

	// 3. Outgoing Callees
	fmt.Fprintf(&out, "=== Outgoing Callees (up to depth %d) ===\n", opts.Depth)
	if len(f.Callees) == 0 {
		out.WriteString("  (none — leaf function)\n")
	} else {
		visited := map[uint32]bool{funcAddr: true}
		cg.fmtCalleesTree(&out, funcAddr, 1, opts.Depth, visited)
	}

	if len(f.GlobalsRead) > 0 || len(f.GlobalsWritten) > 0 || len(f.DataAddrs) > 0 {
		out.WriteString("\n=== Globals & Memory Flow ===\n")
		fmtGlobals := func(items []AddrStringPair) string {
			limit := min(12, len(items))
			parts := make([]string, limit)
			for i, p := range items[:limit] {
				if p.Text != "" {
					parts[i] = fmt.Sprintf("$%X (%s)", p.Addr, p.Text)
				} else {
					parts[i] = fmt.Sprintf("$%X", p.Addr)
				}
			}
			s := strings.Join(parts, ", ")
			if len(items) > limit {
				s += fmt.Sprintf(" (+%d more)", len(items)-limit)
			}
			return s
		}
		if len(f.GlobalsRead) > 0 {
			fmt.Fprintf(&out, "  Reads:     %s\n", fmtGlobals(f.GlobalsRead))
		}
		if len(f.GlobalsWritten) > 0 {
			fmt.Fprintf(&out, "  Writes:    %s\n", fmtGlobals(f.GlobalsWritten))
		}
		if len(f.DataAddrs) > 0 {
			fmt.Fprintf(&out, "  Addresses: %s\n", fmtGlobals(f.DataAddrs))
		}
	}

	// 4. Optional Disassembly & Caller Context (--code)
	if opts.Code {
		out.WriteString("\n=== Disassembly ===\n")
		for _, ia := range f.InsnAddrs {
			if cell, ok := cg.Cells[ia]; ok {
				if lbl, hasLbl := cg.Labels[ia]; hasLbl && lbl != "" {
					fmt.Fprintf(&out, "%s:\n", lbl)
				}
				mnem := cell.MnemonicStr()
				if mnem == "" {
					mnem = "?"
				}
				ops := proj.ApplyStructAliasesToOpStr(cell.OpStrVal(), f.Name, f.RawName)
				var cmt string
				if eff := cg.Comments[ia].EffectiveComment(); eff != "" {
					cmt = fmt.Sprintf(" ; %s", eff)
				}
				for _, site := range f.Callees {
					if site.CallInsn == ia {
						if tf, ok := cg.Functions[site.TargetFunc]; ok {
							if cmt == "" && (tf.Segment != f.Segment || strings.Contains(ops, "(")) {
								cmt = fmt.Sprintf(" ; -> %s", tf.QualifiedName())
							}
							if tf.ABI != "" && !strings.Contains(cmt, "ABI:") {
								if cmt == "" {
									cmt = fmt.Sprintf(" ; [ABI: %s]", tf.ABI)
								} else {
									cmt += fmt.Sprintf(" [ABI: %s]", tf.ABI)
								}
							}
						}
						break
					}
				}
				var off uint32
				if ia > segBase {
					off = ia - segBase
				}
				fnOffStr := fmt.Sprintf("+%03X", ia-f.EntryAddr)
				if ia < f.EntryAddr {
					fnOffStr = fmt.Sprintf("-%03X", f.EntryAddr-ia)
				}
				fmt.Fprintf(&out, "  +%05X (%s)  %-8s %s%s\n", off, fnOffStr, mnem, ops, cmt)
			}
		}
		if f.SuspectCutoff != nil {
			out.WriteString("  --- Suspect non-CODE cells immediately following ---\n")
			count := 0
			cg.CellsTree.AscendGreaterOrEqual(db.Cell{Addr: f.SuspectCutoff.Addr}, func(cell db.Cell) bool {
				if count >= 6 {
					return false
				}
				mnem := cell.MnemonicStr()
				if mnem == "" {
					mnem = cell.Type.AsStr()
				}
				ops := proj.ApplyStructAliasesToOpStr(cell.OpStrVal(), f.Name, f.RawName)
				var off uint32
				if cell.Addr > segBase {
					off = cell.Addr - segBase
				}
				fmt.Fprintf(&out, "  +%05X  %-8s %s [%s]\n", off, mnem, ops, cell.Type.AsStr())
				count++
				return true
			})
		}

		if len(f.Callers) > 0 {
			out.WriteString("\n=== Caller Site Snippets ===\n")
			limit := min(8, len(f.Callers))
			for _, site := range f.Callers[:limit] {
				if cf, ok := cg.Functions[site.CallerFunc]; ok {
					cfSegBase := cf.EntryAddr - cf.OffsetInSeg
					var siteOff uint32
					if site.CallInsn > cfSegBase {
						siteOff = site.CallInsn - cfSegBase
					}
					fmt.Fprintf(&out, "  From %s (+%05X, %s):\n", cf.QualifiedName(), siteOff, site.Kind)
					var startRange uint32
					if site.CallInsn > 16 {
						startRange = site.CallInsn - 16
					}
					endRange := site.CallInsn + 8
					cg.CellsTree.AscendRange(db.Cell{Addr: startRange}, db.Cell{Addr: endRange + 1}, func(cell db.Cell) bool {
						ca := cell.Addr
						if cell.Type == db.CellCode && ca >= cfSegBase {
							if lbl, hasLbl := cg.Labels[ca]; hasLbl && lbl != "" {
								fmt.Fprintf(&out, "    %s:\n", lbl)
							}
							marker := "  "
							if ca == site.CallInsn {
								marker = ">>"
							}
							var cmt string
							if eff := cg.Comments[ca].EffectiveComment(); eff != "" {
								cmt = fmt.Sprintf(" ; %s", eff)
							}
							fmt.Fprintf(
								&out,
								"  %s +%05X: %-8s %s%s\n",
								marker,
								ca-cfSegBase,
								cell.MnemonicStr(),
								cell.OpStrVal(),
								cmt,
							)
						}
						return true
					})
				}
			}
		}
	}

	return out.String(), nil
}

func (cg *CallGraph) fmtCallersTree(
	out *strings.Builder,
	funcAddr uint32,
	level int,
	maxDepth int,
	visited map[uint32]bool,
) {
	if level > maxDepth {
		return
	}
	f, ok := cg.Functions[funcAddr]
	if !ok {
		return
	}
	indent := strings.Repeat("  ", level)
	seenCallers := make(map[uint32]bool)
	for _, site := range f.Callers {
		if seenCallers[site.CallerFunc] {
			continue
		}
		seenCallers[site.CallerFunc] = true
		if cf, ok := cg.Functions[site.CallerFunc]; ok {
			cfSegBase := cf.EntryAddr - cf.OffsetInSeg
			cyc := ""
			if visited[cf.EntryAddr] {
				cyc = " [cycle]"
			}
			var off uint32
			if site.CallInsn > cfSegBase {
				off = site.CallInsn - cfSegBase
			}
			fmt.Fprintf(out, "%s◄── %s (+%05X, %s)%s\n", indent, cf.QualifiedName(), off, site.Kind, cyc)
			if !visited[cf.EntryAddr] {
				visited[cf.EntryAddr] = true
				cg.fmtCallersTree(out, cf.EntryAddr, level+1, maxDepth, visited)
				delete(visited, cf.EntryAddr)
			}
		}
	}
}

func (cg *CallGraph) fmtCalleesTree(
	out *strings.Builder,
	funcAddr uint32,
	level int,
	maxDepth int,
	visited map[uint32]bool,
) {
	if level > maxDepth {
		return
	}
	f, ok := cg.Functions[funcAddr]
	if !ok {
		return
	}
	indent := strings.Repeat("  ", level)
	seenCallees := make(map[uint32]bool)
	for _, site := range f.Callees {
		if seenCallees[site.TargetFunc] {
			continue
		}
		seenCallees[site.TargetFunc] = true
		if tf, ok := cg.Functions[site.TargetFunc]; ok {
			leafTag := ""
			if tf.IsLeaf() {
				leafTag = ", leaf"
			}
			hwTag := ""
			if len(tf.HWRegs) > 0 {
				n := min(4, len(tf.HWRegs))
				hwTag = fmt.Sprintf(" | HW: %s", strings.Join(tf.HWRegs[:n], ","))
			}
			abiTag := ""
			if tf.ABI != "" {
				abiTag = fmt.Sprintf(" | ABI: %s", tf.ABI)
			} else if len(tf.InRegs) > 0 {
				abiTag = fmt.Sprintf(" | in:%s", strings.Join(tf.InRegs, ","))
			}
			cmtTag := ""
			if tf.BlockComment != nil && *tf.BlockComment != "" {
				firstLine, _, _ := strings.Cut(*tf.BlockComment, "\n")
				firstLine = strings.TrimSuffix(firstLine, "\r")
				cmtTag = fmt.Sprintf(" — %q", firstLine)
			}
			cyc := ""
			if visited[tf.EntryAddr] {
				cyc = " [cycle]"
			}
			fmt.Fprintf(
				out,
				"%s├──► %s (%s | %d insts%s%s%s%s)%s\n",
				indent,
				tf.QualifiedName(),
				site.Kind,
				len(tf.InsnAddrs),
				leafTag,
				hwTag,
				abiTag,
				cyc,
				cmtTag,
			)
			if !visited[tf.EntryAddr] {
				visited[tf.EntryAddr] = true
				cg.fmtCalleesTree(out, tf.EntryAddr, level+1, maxDepth, visited)
				delete(visited, tf.EntryAddr)
			}
		}
	}
}

func (cg *CallGraph) collectNeighborhood(
	center uint32,
	upDepth int,
	downDepth int,
	nodes map[uint32]bool,
) {
	nodes[center] = true
	type qItem struct {
		curr    uint32
		depth   int
		goingUp bool
	}
	q := []qItem{
		{curr: center, depth: 0, goingUp: true},
		{curr: center, depth: 0, goingUp: false},
	}
	for len(q) > 0 {
		item := q[0]
		q = q[1:]
		f, ok := cg.Functions[item.curr]
		if !ok {
			continue
		}
		if item.goingUp && item.depth < upDepth {
			for _, s := range f.Callers {
				if !nodes[s.CallerFunc] {
					nodes[s.CallerFunc] = true
					q = append(q, qItem{curr: s.CallerFunc, depth: item.depth + 1, goingUp: true})
				}
			}
		} else if !item.goingUp && item.depth < downDepth {
			for _, s := range f.Callees {
				if !nodes[s.TargetFunc] {
					nodes[s.TargetFunc] = true
					q = append(q, qItem{curr: s.TargetFunc, depth: item.depth + 1, goingUp: false})
				}
			}
		}
	}
}

func (cg *CallGraph) renderGraphDiagram(nodeAddrs []uint32, format string) string {
	nodeSet := make(map[uint32]bool, len(nodeAddrs))
	for _, a := range nodeAddrs {
		nodeSet[a] = true
	}
	var out strings.Builder
	if format == "mermaid" {
		out.WriteString("flowchart TD\n")
		for _, addr := range nodeAddrs {
			if f, ok := cg.Functions[addr]; ok {
				fmt.Fprintf(&out, "    F_%05X[\"%s\"]\n", addr, f.QualifiedName())
				seen := make(map[uint32]bool)
				for _, c := range f.Callees {
					if nodeSet[c.TargetFunc] && !seen[c.TargetFunc] {
						seen[c.TargetFunc] = true
						fmt.Fprintf(&out, "    F_%05X --> F_%05X\n", addr, c.TargetFunc)
					}
				}
			}
		}
	} else {
		out.WriteString("digraph CallGraph {\n  rankdir=LR;\n  node [shape=box, fontname=\"monospace\"];\n")
		for _, addr := range nodeAddrs {
			if f, ok := cg.Functions[addr]; ok {
				fmt.Fprintf(
					&out,
					"  \"%s\" [label=\"%s\\n+%05X\"];\n",
					f.QualifiedName(),
					f.QualifiedName(),
					f.OffsetInSeg,
				)
				seen := make(map[uint32]bool)
				for _, c := range f.Callees {
					if nodeSet[c.TargetFunc] && !seen[c.TargetFunc] {
						seen[c.TargetFunc] = true
						if tf, ok := cg.Functions[c.TargetFunc]; ok {
							fmt.Fprintf(&out, "  \"%s\" -> \"%s\";\n", f.QualifiedName(), tf.QualifiedName())
						}
					}
				}
			}
		}
		out.WriteString("}\n")
	}
	return out.String()
}

func (cg *CallGraph) IsReadyBottomUp(f *FunctionNode) bool {
	if f.IsRenamed || len(f.Callees) == 0 {
		return false
	}
	for _, c := range f.Callees {
		if c.TargetFunc == f.EntryAddr {
			continue
		}
		tf, ok := cg.Functions[c.TargetFunc]
		if !ok || !tf.IsRenamed {
			return false
		}
	}
	return true
}

func (cg *CallGraph) renderWorklist(opts *Options, normSeg string) (string, error) {
	isHunkOverview := normSeg != "" && !opts.Leaves && !opts.Anchors && !opts.Ready && !opts.Suspect

	var allFuncs []*FunctionNode
	for _, addr := range cg.FuncAddrs {
		f := cg.Functions[addr]
		if normSeg != "" && !strings.EqualFold(f.Segment, normSeg) {
			continue
		}
		allFuncs = append(allFuncs, f)
	}

	total := len(allFuncs)
	renamedCnt := 0
	leavesCnt := 0
	anchorCnt := 0
	readyCnt := 0
	suspectCnt := 0
	for _, f := range allFuncs {
		if f.IsRenamed {
			renamedCnt++
		}
		if f.IsLeaf() {
			leavesCnt++
		}
		if len(f.Strings) > 0 || len(f.HWRegs) > 0 {
			anchorCnt++
		}
		if cg.IsReadyBottomUp(f) {
			readyCnt++
		}
		if f.SuspectCutoff != nil {
			suspectCnt++
		}
	}

	var filtered []*FunctionNode
	for _, f := range allFuncs {
		if opts.Unrenamed && f.IsRenamed {
			continue
		}
		if opts.Leaves && !f.IsLeaf() {
			continue
		} else if opts.Anchors && len(f.Strings) == 0 && len(f.HWRegs) == 0 {
			continue
		} else if opts.Ready && !cg.IsReadyBottomUp(f) {
			continue
		} else if opts.Suspect && f.SuspectCutoff == nil {
			continue
		}
		filtered = append(filtered, f)
	}

	if opts.Anchors {
		slices.SortFunc(filtered, func(a, b *FunctionNode) int {
			scoreA := len(a.Strings)*3 + len(a.HWRegs) + len(a.Callers)
			scoreB := len(b.Strings)*3 + len(b.HWRegs) + len(b.Callers)
			if c := cmp.Compare(scoreB, scoreA); c != 0 {
				return c
			}
			return cmp.Compare(a.EntryAddr, b.EntryAddr)
		})
	} else if opts.Suspect || isHunkOverview {
		slices.SortFunc(filtered, func(a, b *FunctionNode) int {
			return cmp.Compare(a.EntryAddr, b.EntryAddr)
		})
	} else {
		slices.SortFunc(filtered, func(a, b *FunctionNode) int {
			if c := cmp.Compare(len(b.Callers), len(a.Callers)); c != 0 {
				return c
			}
			return cmp.Compare(a.EntryAddr, b.EntryAddr)
		})
	}

	limit := opts.Limit
	if limit == 0 || isHunkOverview || limit > len(filtered) {
		limit = len(filtered)
	}
	shown := filtered[:limit]

	if opts.Format == "json" {
		payload := map[string]any{
			"summary": map[string]any{
				"total_functions": total,
				"renamed":         renamedCnt,
				"leaves":          leavesCnt,
				"anchored":        anchorCnt,
				"ready_bottom_up": readyCnt,
				"suspect_cutoffs": suspectCnt,
			},
			"functions": shown,
		}
		b, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return "", err
		}
		return string(b), nil
	}

	if opts.Format == "dot" || opts.Format == "mermaid" {
		nodeAddrs := make([]uint32, len(shown))
		for i, f := range shown {
			nodeAddrs[i] = f.EntryAddr
		}
		slices.Sort(nodeAddrs)
		return cg.renderGraphDiagram(nodeAddrs, opts.Format), nil
	}

	var out strings.Builder
	scope := "all segments"
	if normSeg != "" {
		scope = normSeg
	}
	var pct float64
	if total > 0 {
		pct = (float64(renamedCnt) / float64(total)) * 100.0
	}
	fmt.Fprintf(
		&out,
		"=== Call Graph Summary (%s) ===\n  Functions: %d total | %d renamed (%.1f%%) | %d leaves | %d string/HW-anchored | %d bottom-up ready | %d suspect cutoffs\n\n",
		scope, total, renamedCnt, pct, leavesCnt, anchorCnt, readyCnt, suspectCnt,
	)

	var modeTitle string
	switch {
	case opts.Leaves:
		modeTitle = "Leaf Functions (0 outgoing calls, by caller count)"
	case opts.Anchors:
		modeTitle = "String & Hardware-Anchored Functions"
	case opts.Ready:
		modeTitle = "Bottom-Up Ready Functions (all callees renamed)"
	case opts.Suspect:
		modeTitle = "Suspect Cutoff Functions (fallthrough into DATA/STRING)"
	case normSeg != "":
		modeTitle = fmt.Sprintf("Module Functions in %s (offset order)", normSeg)
	default:
		modeTitle = "Top Functions by Caller Count"
	}

	fmt.Fprintf(&out, "=== %s (showing %d) ===\n", modeTitle, len(shown))
	for _, f := range shown {
		segBase := f.EntryAddr - f.OffsetInSeg
		var tags []string
		if f.IsExported {
			tags = append(tags, "XDEF")
		}
		if f.IsLeaf() {
			tags = append(tags, "leaf")
		}
		if len(f.HWRegs) > 0 {
			n := min(4, len(f.HWRegs))
			tags = append(tags, fmt.Sprintf("HW:%s", strings.Join(f.HWRegs[:n], ",")))
		}
		if len(f.Strings) > 0 {
			n := min(2, len(f.Strings))
			strPrev := make([]string, n)
			for i := range n {
				strPrev[i] = fmt.Sprintf("%q", f.Strings[i].Text)
			}
			tags = append(tags, fmt.Sprintf("str:%s", strings.Join(strPrev, ",")))
		}
		if f.SuspectCutoff != nil {
			var off uint32
			if f.SuspectCutoff.Addr > segBase {
				off = f.SuspectCutoff.Addr - segBase
			}
			tags = append(tags, fmt.Sprintf("SUSPECT:%s@+%05X", f.SuspectCutoff.Text, off))
		}
		if f.BlockComment != nil && *f.BlockComment != "" {
			firstLine, _, _ := strings.Cut(*f.BlockComment, "\n")
			firstLine = strings.TrimSuffix(firstLine, "\r")
			tags = append(tags, fmt.Sprintf("%q", firstLine))
		}
		tagStr := ""
		if len(tags) > 0 {
			tagStr = fmt.Sprintf(" | %s", strings.Join(tags, " | "))
		}

		fmt.Fprintf(
			&out,
			"  %-28s [+%05X] in:%-3d out:%-3d %4d insts (%5d B) | %s%s\n",
			f.QualifiedName(),
			f.OffsetInSeg,
			len(f.Callers),
			len(f.Callees),
			len(f.InsnAddrs),
			f.ByteSize,
			f.FormatCycles(),
			tagStr,
		)

		if isHunkOverview {
			if len(f.Callers) > 0 {
				seenCallers := make(map[uint32]bool)
				var callerNames []string
				for _, site := range f.Callers {
					if !seenCallers[site.CallerFunc] {
						seenCallers[site.CallerFunc] = true
						if cf, ok := cg.Functions[site.CallerFunc]; ok {
							callerNames = append(callerNames, cf.QualifiedName())
						}
					}
				}
				if len(callerNames) > 0 {
					fmt.Fprintf(&out, "    ◄── callers: %s\n", strings.Join(callerNames, ", "))
				}
			}
			if len(f.Callees) > 0 {
				seenCallees := make(map[uint32]bool)
				var calleeNames []string
				for _, site := range f.Callees {
					if !seenCallees[site.TargetFunc] {
						seenCallees[site.TargetFunc] = true
						if tf, ok := cg.Functions[site.TargetFunc]; ok {
							calleeNames = append(calleeNames, tf.QualifiedName())
						}
					}
				}
				if len(calleeNames) > 0 {
					fmt.Fprintf(&out, "    ──► callees: %s\n", strings.Join(calleeNames, ", "))
				}
			}
		}
	}

	return out.String(), nil
}
