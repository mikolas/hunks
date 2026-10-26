// Package emitter generates single-file flat (`out.s`) and modular multi-hunk
// (`disasm/<target>.asm` + `src/<target>/hunk*.asm` + `src/equates.i`) assembly
// formatted for `vasmm68k_mot`.
package emitter

import (
	"cmp"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/mikolas/hunks/internal/amiga"
	"github.com/mikolas/hunks/internal/db"
	"github.com/mikolas/hunks/internal/hunk"
	"github.com/mikolas/hunks/internal/m68k"
	"github.com/mikolas/hunks/internal/project"
)

type EmitItem struct {
	Addr     uint32
	HasAddr  bool
	Label    string
	Mnem     string
	Op       string
	Comment  string
	SubAddrs []uint32
	Size     uint32
}

type emitSpaceCache struct {
	allLabels        map[uint32]string
	sortedLabelAddrs []uint32
	allRelocs        map[uint32]uint32
	jmpBases         map[string]uint32
	vectoredXrefs    map[uint32][]db.AddrText
	sortedVecTargets []uint32
	cellSpans        []db.CellSpan
}

func (sc *emitSpaceCache) findContainingSpan(addr uint32) (db.CellSpan, bool) {
	spans := sc.cellSpans
	lo, hi := 0, len(spans)
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if spans[mid].Addr <= addr {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo > 0 && addr < spans[lo-1].Addr+spans[lo-1].Size {
		return spans[lo-1], true
	}
	return db.CellSpan{}, false
}

func (sc *emitSpaceCache) isCellAligned(addr uint32) bool {
	span, ok := sc.findContainingSpan(addr)
	return !ok || span.Addr == addr
}

func buildSpaceCache(ctrl *db.Controller) (*emitSpaceCache, error) {
	allLabels, err := ctrl.GetAllLabelsResolved()
	if err != nil {
		return nil, err
	}
	sortedLabelAddrs := slices.Sorted(maps.Keys(allLabels))
	allRelocs, err := ctrl.GetAllRelocs()
	if err != nil || allRelocs == nil {
		allRelocs = make(map[uint32]uint32)
	}
	jmpBases := ctrl.DetectJumpVectorBases()
	vecXrefs := ctrl.GetVectoredCallXrefs(0, ^uint32(0), jmpBases, allRelocs)
	sortedVecTargets := slices.Sorted(maps.Keys(vecXrefs))
	cellSpans, err := ctrl.GetSpaceCellSpans()
	if err != nil {
		return nil, err
	}
	return &emitSpaceCache{
		allLabels:        allLabels,
		sortedLabelAddrs: sortedLabelAddrs,
		allRelocs:        allRelocs,
		jmpBases:         jmpBases,
		vectoredXrefs:    vecXrefs,
		sortedVecTargets: sortedVecTargets,
		cellSpans:        cellSpans,
	}, nil
}

type Emitter struct {
	Proj        *project.Project
	DB          *db.Controller
	BinaryData  []byte
	BaseAddr    uint32
	OutItems    []EmitItem
	OutLines    []string
	Relocatable bool
	cache       *emitSpaceCache
}

func (e *Emitter) ensureSpaceCache() (*emitSpaceCache, error) {
	if e.cache != nil {
		return e.cache, nil
	}
	sc, err := buildSpaceCache(e.DB)
	if err != nil {
		return nil, err
	}
	e.cache = sc
	return sc, nil
}

func New(proj *project.Project, database *db.Controller) (*Emitter, error) {
	proj.SyncDBScope(database)
	seg := proj.CurrentSegment()
	if seg == nil {
		return nil, fmt.Errorf("no active segment; run `hunks init` first")
	}
	binaryData := seg.LoadBinaryData()
	baseAddr := seg.Base
	return &Emitter{
		Proj:       proj,
		DB:         database,
		BinaryData: binaryData,
		BaseAddr:   baseAddr,
	}, nil
}

func (e *Emitter) addItem(label, mnem, op, comment string) {
	e.OutItems = append(e.OutItems, EmitItem{
		Label:   label,
		Mnem:    mnem,
		Op:      op,
		Comment: comment,
	})
}

func (e *Emitter) addItemAt(addr uint32, label, mnem, op, comment string) {
	e.OutItems = append(e.OutItems, EmitItem{
		Addr:    addr,
		HasAddr: true,
		Label:   label,
		Mnem:    mnem,
		Op:      op,
		Comment: comment,
	})
}

func (e *Emitter) addItemSizedAt(addr uint32, label, mnem, op, comment string, size uint32) {
	e.OutItems = append(e.OutItems, EmitItem{
		Addr:    addr,
		HasAddr: true,
		Label:   label,
		Mnem:    mnem,
		Op:      op,
		Comment: comment,
		Size:    size,
	})
}

func (e *Emitter) emitXrefComments(addr uint32, xrefsMap map[uint32][]string) {
	if callerStrs, ok := xrefsMap[addr]; ok {
		for i := 0; i < len(callerStrs); i += 4 {
			end := min(i+4, len(callerStrs))
			e.addItem("", "", "", "; XREF: "+strings.Join(callerStrs[i:end], ", "))
		}
	}
}

type rawXrefSource struct {
	srcAddr      uint32
	overrideDesc *string
}

func findContainingCell(cells []db.Cell, addr uint32) *db.Cell {
	lo, hi := 0, len(cells)
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if cells[mid].Addr <= addr {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo > 0 && addr < cells[lo-1].Addr+cells[lo-1].Size {
		return &cells[lo-1]
	}
	return nil
}

// buildXrefsMap collects all incoming direct and indirect (`d16(An)` jump-vector)
// cross-references targeting `[startAddr, endAddr)` and formats each caller as
// `[<seg>:]<enclosing_label> (<mnemonic>)` for `; XREF:` header comments.
func (e *Emitter) buildXrefsMap(
	startAddr, endAddr uint32,
	sc *emitSpaceCache,
	localCells []db.Cell,
	includeVectored bool,
) (map[uint32][]string, error) {
	rawRefs := make(map[uint32][]rawXrefSource)
	for _, rf := range e.DB.RefsTargetingRange(startAddr, endAddr) {
		rawRefs[rf.Target] = append(rawRefs[rf.Target], rawXrefSource{srcAddr: rf.Source})
	}

	if includeVectored && len(sc.sortedVecTargets) > 0 {
		idxStart, _ := slices.BinarySearch(sc.sortedVecTargets, startAddr)
		idxEnd, _ := slices.BinarySearch(sc.sortedVecTargets, endAddr)
		for _, targetAddr := range sc.sortedVecTargets[idxStart:idxEnd] {
			for _, vc := range sc.vectoredXrefs[targetAddr] {
				desc := vc.Text
				rawRefs[targetAddr] = append(rawRefs[targetAddr], rawXrefSource{
					srcAddr:      vc.Addr,
					overrideDesc: &desc,
				})
			}
		}
	}

	result := make(map[uint32][]string, len(rawRefs))

	for targetAddr, sources := range rawRefs {
		slices.SortStableFunc(sources, func(a, b rawXrefSource) int {
			return cmp.Compare(a.srcAddr, b.srcAddr)
		})
		formatted := make([]string, 0, len(sources))
		for _, src := range sources {
			rawSrc := src.srcAddr
			var snappedAddr uint32
			var mnem string

			if src.overrideDesc != nil {
				snappedAddr = rawSrc
				mnem = *src.overrideDesc
			} else if rawSrc >= startAddr && rawSrc < endAddr && len(localCells) > 0 {
				if c := findContainingCell(localCells, rawSrc); c != nil {
					if c.Mnemonic != nil {
						mnem = *c.Mnemonic
					} else if c.Type == db.CellPointer || c.Type == db.CellDataL {
						mnem = "dc.l"
					}
					snappedAddr = c.Addr
				} else {
					snappedAddr = rawSrc
				}
			} else if span, ok := sc.findContainingSpan(rawSrc); ok {
				snappedAddr = span.Addr
				mnem = span.Mnemonic
			} else {
				snappedAddr = rawSrc
			}

			callerSeg := e.Proj.SegmentAtAddr(snappedAddr)
			var callerSegBase uint32
			if callerSeg != nil {
				callerSegBase = callerSeg.Base
			}
			// Find last label in [callerSegBase, snappedAddr]
			idx, found := slices.BinarySearch(sc.sortedLabelAddrs, snappedAddr)
			if found {
				idx++
			}
			var enclosingLabel string
			if idx > 0 && sc.sortedLabelAddrs[idx-1] >= callerSegBase {
				enclosingLabel = sc.allLabels[sc.sortedLabelAddrs[idx-1]]
			} else {
				enclosingLabel = e.Proj.AutoLabel(snappedAddr)
			}

			callerRef := enclosingLabel
			if callerSeg != nil && callerSeg.Base != startAddr {
				callerRef = fmt.Sprintf("%s:%s", callerSeg.Name, enclosingLabel)
			}

			entry := callerRef
			if mnem != "" {
				entry = fmt.Sprintf("%s (%s)", callerRef, mnem)
			}
			if !slices.Contains(formatted, entry) {
				formatted = append(formatted, entry)
			}
		}
		if len(formatted) > 0 {
			result[targetAddr] = formatted
		}
	}
	return result, nil
}

type equateKV struct {
	name string
	addr uint32
}

func sortedEquates(equates map[string]uint32) []equateKV {
	vec := make([]equateKV, 0, len(equates))
	for name, addr := range equates {
		vec = append(vec, equateKV{name: name, addr: addr})
	}
	slices.SortFunc(vec, func(a, b equateKV) int {
		if c := cmp.Compare(a.addr, b.addr); c != 0 {
			return c
		}
		return cmp.Compare(a.name, b.name)
	})
	return vec
}

func (e *Emitter) GenerateItems(relocatable bool) error {
	e.Relocatable = relocatable
	e.OutItems = nil

	e.addItem("", "", "", "; Generated by hunks")
	e.addItem("", "", "", "")

	e.addItem("", "", "", "; --- Hardware Equates ---")
	equates := amiga.GetAllEquates()
	amiga.CollectUsedHWEquates(e.DB, equates)
	for _, eq := range sortedEquates(equates) {
		e.addItem(eq.name, "equ", fmt.Sprintf("$%X", eq.addr), "")
	}

	e.addItem("", "", "", "")
	e.addItem("", "", "", "; --- External/BSS Equates ---")

	endAddr := e.BaseAddr + uint32(len(e.BinaryData))
	memoryRegionLabels := make(map[uint32]bool)

	for _, region := range e.Proj.Data.MemoryRegions {
		r := db.AddrRange{Start: region.Start, End: region.End}
		for _, addr := range e.DB.LabelAddrs(&r) {
			memoryRegionLabels[addr] = true
		}
	}

	sc, err := e.ensureSpaceCache()
	if err != nil {
		return err
	}
	allLabelsResolved := sc.allLabels
	sortedAllLabelAddrs := sc.sortedLabelAddrs
	for _, addr := range sortedAllLabelAddrs {
		finalLabel := allLabelsResolved[addr]
		if addr < e.BaseAddr || addr >= endAddr {
			if _, isHW := amiga.GetAmigaHWLabel(addr); !isHW {
				if memoryRegionLabels[addr] {
					continue
				}
				e.addItem(finalLabel, "equ", fmt.Sprintf("$%X", addr), "")
			}
		}
	}

	e.addItem("", "", "", "")

	for _, region := range e.Proj.Data.MemoryRegions {
		var regionLabels []struct {
			addr  uint32
			label string
		}
		for _, a := range sortedAllLabelAddrs {
			if a >= region.Start && a < region.End {
				regionLabels = append(regionLabels, struct {
					addr  uint32
					label string
				}{addr: a, label: allLabelsResolved[a]})
			}
		}
		if len(regionLabels) == 0 {
			continue
		}

		e.addItem("", "", "", fmt.Sprintf("; --- Region: %s ---", region.Name))
		if relocatable {
			secType := "bss"
			if region.Start < 0x80000 {
				secType = "bss_c"
			}
			e.addItem("", "section", fmt.Sprintf("%s,%s", region.Name, secType), "")
		} else {
			e.addItem("", "OFFSET", fmt.Sprintf("$%X", region.Start), "")
		}

		curAddr := region.Start
		for _, rl := range regionLabels {
			if rl.addr > curAddr {
				e.addItemAt(curAddr, "", "ds.b", fmt.Sprintf("$%X", rl.addr-curAddr), "")
			}
			e.addItemAt(rl.addr, rl.label, "", "", "")
			curAddr = rl.addr
		}
		e.addItem("", "", "", "")
	}

	if !relocatable && len(e.Proj.Data.MemoryRegions) > 0 {
		e.addItem("", "section", "text,code", "")
		e.addItem("", "", "", "")
	}

	e.addItem("", "", "", "")

	if e.Relocatable {
		e.addItem("", "section", ".text,code", "")
	} else {
		e.addItem("", "org", fmt.Sprintf("$%X", e.BaseAddr), "")
	}

	return e.PopulateCellsItems()
}

func isAllHexDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// resolveFlatCrossSegOperands rewrites `.l` and `#imm.l` hex operands in non-relocatable
// flat segments into symbolic labels (plus a cross-segment `-> seg:label` comment hint)
// when the target address falls outside the current segment `[e.BaseAddr, endAddr)` and
// resolves to a cell-aligned label in another active segment.
//
// Keeping `OpStr` pure in the database during per-segment analysis and resolving cross-segment
// labels here at view/emit time prevents overlapping overlay segments from polluting each
// other's stored instruction text.
func (e *Emitter) resolveFlatCrossSegOperands(
	mnem string,
	opStr string,
	endAddr uint32,
	sc *emitSpaceCache,
	arrow string,
	curSeg string,
) (string, string) {
	if opStr == "" || !strings.Contains(opStr, "$") {
		return opStr, ""
	}

	var tokBuf [4]string
	tokens := tokBuf[:0]
	depth := 0
	last := 0
	for i := 0; i < len(opStr); i++ {
		switch opStr[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				tokens = append(tokens, opStr[last:i])
				last = i + 1
			}
		}
	}
	tokens = append(tokens, opStr[last:])

	op, sz := m68k.ParseMnemonic(mnem)
	isLong := op.HasLongEA(sz)

	var outBuf [4]string
	outTokens := outBuf[:0]
	var hint string
	rewritten := false

	for _, rawTok := range tokens {
		tok := strings.TrimSpace(rawTok)
		var matchedTarget uint32
		var isAbsLong bool
		var matched bool

		if afterDollar, ok := strings.CutPrefix(tok, "$"); ok {
			if inner, ok := strings.CutSuffix(afterDollar, ".l"); ok && isAllHexDigits(inner) {
				if val, err := strconv.ParseUint(inner, 16, 32); err == nil {
					matchedTarget = uint32(val)
					isAbsLong = true
					matched = true
				}
			}
		} else if isLong {
			if inner, ok := strings.CutPrefix(tok, "#$"); ok && isAllHexDigits(inner) {
				if val, err := strconv.ParseUint(inner, 16, 32); err == nil && val >= 0x100 {
					matchedTarget = uint32(val)
					isAbsLong = false
					matched = true
				}
			}
		}

		if matched && (matchedTarget < e.BaseAddr || matchedTarget >= endAddr) {
			if _, isHW := amiga.GetAmigaHWLabel(matchedTarget); !isHW {
				if lbl, ok := sc.allLabels[matchedTarget]; ok && lbl != "" &&
					!strings.HasPrefix(lbl, "CUSTOM_") &&
					!strings.HasPrefix(lbl, "CIAA_") &&
					!strings.HasPrefix(lbl, "CIAB_") {
					if sc.isCellAligned(matchedTarget) {
						rewritten = true
						if isAbsLong {
							outTokens = append(outTokens, lbl+".l")
						} else {
							outTokens = append(outTokens, "#"+lbl)
						}
						if hint == "" {
							if tseg := e.Proj.SegmentAtAddr(matchedTarget); tseg != nil && !strings.EqualFold(tseg.Name, curSeg) {
								hint = arrow + " " + tseg.Name + ":" + lbl
							}
						}
						continue
					}
				}
			}
		}

		outTokens = append(outTokens, rawTok)
	}

	if !rewritten {
		return opStr, ""
	}
	return strings.Join(outTokens, ","), hint
}

// PopulateCellsItems walks `[e.BaseAddr, endAddr)` sequentially, emitting both analyzed
// database cells (`CODE`, `POINTER`, `STRING`, `INCBIN`, `DATA_*`) and any unmapped gap
// bytes (`dc.l`/`dc.w`/`dc.b` split at interior labels) so that the emitted output covers
// 100% of `e.BinaryData` with zero byte drift.
func (e *Emitter) PopulateCellsItems() error {
	endAddr := e.BaseAddr + uint32(len(e.BinaryData))
	addr := e.BaseAddr

	sc, err := e.ensureSpaceCache()
	if err != nil {
		return err
	}
	allLabels := sc.allLabels
	sortedAllLabelAddrs := sc.sortedLabelAddrs
	allRelocs := sc.allRelocs
	jmpBases := sc.jmpBases

	allCells, err := e.DB.CellsInRange(e.BaseAddr, endAddr)
	if err != nil {
		return err
	}

	commentsMap, err := e.DB.GetCommentsInRange(e.BaseAddr, endAddr)
	if err != nil {
		return err
	}

	xrefsMap, err := e.buildXrefsMap(e.BaseAddr, endAddr, sc, allCells, true)
	if err != nil {
		return err
	}
	const arrow = "->"

	var allLabelAddrs []uint32
	for _, k := range sortedAllLabelAddrs {
		if k >= e.BaseAddr && k < endAddr {
			allLabelAddrs = append(allLabelAddrs, k)
		}
	}
	cellIdx := 0

	curSeg := e.DB.ActiveSeg()
	segIsRelocatable := e.Relocatable
	if s := e.Proj.CurrentSegment(); s != nil {
		segIsRelocatable = s.IsRelocatable()
	}

	entryAddrs := make(map[uint32]bool, len(e.Proj.Data.EntryPoints))
	for _, ep := range e.Proj.Data.EntryPoints {
		if ep.Segment == "" || strings.EqualFold(ep.Segment, curSeg) {
			entryAddrs[ep.Addr] = true
		}
	}
	isEntry := func(a uint32) bool {
		return entryAddrs[a]
	}

	getLabelStr := func(a uint32) string {
		if l, ok := allLabels[a]; ok {
			if strings.HasPrefix(l, "CUSTOM_") || strings.HasPrefix(l, "CIAA_") || strings.HasPrefix(l, "CIAB_") {
				return ""
			}
			return l
		}
		if hw, ok := amiga.GetAmigaHWLabel(a); ok {
			return hw
		}
		return ""
	}

	for addr < endAddr {
		nextCellAddr := endAddr
		if cellIdx < len(allCells) {
			nextCellAddr = allCells[cellIdx].Addr
		}

		if nextCellAddr < addr {
			cellIdx++
			continue
		}

		if addr < nextCellAddr {
			gapSize := nextCellAddr - addr
			offset := int(addr - e.BaseAddr)
			remBin := 0
			if offset < len(e.BinaryData) {
				remBin = len(e.BinaryData) - offset
			}
			gapBytesLen := min(int(gapSize), remBin)

			idxStart, _ := slices.BinarySearch(allLabelAddrs, addr)
			idxEnd, _ := slices.BinarySearch(allLabelAddrs, nextCellAddr)
			gapLabels := allLabelAddrs[idxStart:idxEnd]

			if len(gapLabels) > 0 {
				nextGapBreak := gapLabels[0]
				if nextGapBreak == addr {
					label := getLabelStr(addr)
					if label != "" {
						e.emitXrefComments(addr, xrefsMap)
						if e.Relocatable && isEntry(addr) {
							e.addItem("", "xdef", label, "")
						}
						e.addItemAt(addr, label, "", "", "")
					}

					var subsequent []uint32
					for _, l := range gapLabels {
						if l > addr {
							subsequent = append(subsequent, l)
						}
					}
					if len(subsequent) > 0 {
						nextGapBreak = subsequent[0]
						gapSize = nextGapBreak - addr
					} else {
						gapSize = nextCellAddr - addr
					}
				} else {
					gapSize = nextGapBreak - addr
				}
				gapBytesLen = min(int(gapSize), remBin)
			}

			curGapAddr := addr
			bufIdx := 0
			for bufIdx < gapBytesLen {
				if curGapAddr%2 != 0 {
					e.addItemSizedAt(curGapAddr, "", "dc.b", fmt.Sprintf("$%02X", e.BinaryData[offset+bufIdx]), "", 1)
					bufIdx++
					curGapAddr++
					continue
				}

				rem := gapBytesLen - bufIdx
				if rem >= 4 {
					longsToDo := min(4, rem/4)
					longStrs := make([]string, 0, longsToDo)
					startAddr := curGapAddr
					for range longsToDo {
						val := uint32(e.BinaryData[offset+bufIdx])<<24 |
							uint32(e.BinaryData[offset+bufIdx+1])<<16 |
							uint32(e.BinaryData[offset+bufIdx+2])<<8 |
							uint32(e.BinaryData[offset+bufIdx+3])
						longStrs = append(longStrs, fmt.Sprintf("$%08X", val))
						bufIdx += 4
						curGapAddr += 4
					}
					e.addItemSizedAt(startAddr, "", "dc.l", strings.Join(longStrs, ","), "", uint32(longsToDo)*4)
					if longsToDo > 1 {
						subs := make([]uint32, longsToDo)
						for i := range longsToDo {
							subs[i] = startAddr + uint32(i)*4
						}
						e.OutItems[len(e.OutItems)-1].SubAddrs = subs
					}
				} else if rem >= 2 {
					val := uint32(e.BinaryData[offset+bufIdx])<<8 | uint32(e.BinaryData[offset+bufIdx+1])
					e.addItemSizedAt(curGapAddr, "", "dc.w", fmt.Sprintf("$%04X", val), "", 2)
					bufIdx += 2
					curGapAddr += 2
				} else {
					e.addItemSizedAt(curGapAddr, "", "dc.b", fmt.Sprintf("$%02X", e.BinaryData[offset+bufIdx]), "", 1)
					bufIdx++
					curGapAddr++
				}
			}

			addr += gapSize
			continue
		}

		cell := &allCells[cellIdx]
		cellIdx++

		label := getLabelStr(addr)
		if label != "" {
			e.emitXrefComments(addr, xrefsMap)
			if e.Relocatable && isEntry(addr) {
				e.addItem("", "xdef", label, "")
			}
		}

		ac := commentsMap[addr]
		if ac.BlockComment != "" {
			for _, line := range strings.Split(ac.BlockComment, "\n") {
				line = strings.TrimSuffix(line, "\r")
				e.addItem("", "", "", "; "+line)
			}
		}
		if cell.Type == db.CellStr {
			if eff := ac.EffectiveComment(); eff != "" && eff != ac.BlockComment {
				for _, line := range strings.Split(eff, "\n") {
					line = strings.TrimSuffix(line, "\r")
					e.addItem("", "", "", "; "+line)
				}
			}
		}

		var mnem, opStr string
		if cell.Mnemonic != nil {
			mnem = *cell.Mnemonic
		}
		if cell.OpStr != nil {
			opStr = *cell.OpStr
		}

		if mnem == "" && (cell.Type.IsData() || cell.Type == db.CellPointer) {
			var raw []byte
			if cell.RawBytes != nil {
				raw = cell.RawBytes
			} else {
				offset := int(addr - e.BaseAddr)
				if offset < len(e.BinaryData) {
					end := min(offset+int(cell.Size), len(e.BinaryData))
					raw = e.BinaryData[offset:end]
				}
			}

			switch cell.Type {
			case db.CellIncbin:
				file := opStr
				if file == "" {
					if lbl := getLabelStr(addr); lbl != "" {
						file = fmt.Sprintf("assets/%s.bin", lbl)
					} else {
						file = fmt.Sprintf("assets/incbin_%08X.bin", addr)
					}
				}
				outPath := file
				if !filepath.IsAbs(outPath) {
					outPath = filepath.Join(e.Proj.WorkspaceRoot, outPath)
				}
				if dir := filepath.Dir(outPath); dir != "" {
					if err := os.MkdirAll(dir, 0o755); err != nil {
						return err
					}
				}
				if err := os.WriteFile(outPath, raw, 0o644); err != nil {
					return err
				}
				mnem = "incbin"
				opStr = fmt.Sprintf("\"%s\"", file)

			case db.CellDataZero:
				if cell.Size%4 == 0 {
					cnt := int(cell.Size / 4)
					mnem = "dc.l"
					zeros := make([]string, cnt)
					for i := range zeros {
						zeros[i] = "0"
					}
					opStr = strings.Join(zeros, ",")
				} else if cell.Size%2 == 0 {
					cnt := int(cell.Size / 2)
					mnem = "dc.w"
					zeros := make([]string, cnt)
					for i := range zeros {
						zeros[i] = "0"
					}
					opStr = strings.Join(zeros, ",")
				} else {
					cnt := int(cell.Size)
					mnem = "dc.b"
					zeros := make([]string, cnt)
					for i := range zeros {
						zeros[i] = "0"
					}
					opStr = strings.Join(zeros, ",")
				}

			case db.CellDataB:
				var val byte
				if len(raw) > 0 {
					val = raw[0]
				}
				mnem = "dc.b"
				opStr = fmt.Sprintf("$%02X", val)

			case db.CellDataW:
				var val uint32
				if len(raw) >= 2 {
					val = uint32(raw[0])<<8 | uint32(raw[1])
				}
				mnem = "dc.w"
				opStr = fmt.Sprintf("$%04X", val)

			case db.CellDataL, db.CellPointer:
				var val uint32
				if len(raw) >= 4 {
					val = uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])
				}
				mnem = "dc.l"
				if cell.Type == db.CellPointer {
					lbl := getLabelStr(val)
					var defined bool
					if lbl != "" {
						if val >= e.BaseAddr && val < endAddr {
							c := findContainingCell(allCells, val)
							defined = c == nil || c.Addr == val
						} else {
							defined = sc.isCellAligned(val)
						}
					}
					if defined {
						opStr = lbl
					} else {
						opStr = fmt.Sprintf("$%08X", val)
					}
				} else {
					opStr = fmt.Sprintf("$%08X", val)
				}

			case db.CellStr:
				mnem = "dc.b"
				var sb strings.Builder
				inStr := false
				for i, b := range raw {
					isASCII := b >= 32 && b <= 126 && b != '\''
					if isASCII {
						if !inStr {
							if i > 0 {
								sb.WriteByte(',')
							}
							sb.WriteByte('\'')
							inStr = true
						}
						sb.WriteByte(b)
					} else {
						if inStr {
							sb.WriteByte('\'')
							inStr = false
						}
						if i > 0 {
							sb.WriteByte(',')
						}
						sb.WriteString(fmt.Sprintf("$%02X", b))
					}
				}
				if inStr {
					sb.WriteByte('\'')
				}
				opStr = sb.String()
			}
		}

		var targetHint string
		if cell.Type == db.CellCode {
			if !segIsRelocatable && !e.Relocatable {
				opStr, targetHint = e.resolveFlatCrossSegOperands(
					mnem,
					opStr,
					endAddr,
					sc,
					arrow,
					curSeg,
				)
			}
			op, _ := m68k.ParseMnemonic(mnem)
			if (op == m68k.OpJSR || op == m68k.OpJMP || op == m68k.OpBSR) && strings.Contains(opStr, "(") && !strings.Contains(opStr, "pc") {
				if _, realTgt, ok := e.DB.ResolveVectoredTarget(opStr, jmpBases, allRelocs); ok {
					tgtLbl := getLabelStr(realTgt)
					if tgtLbl == "" {
						tgtLbl = e.Proj.AutoLabel(realTgt)
					}
					qual := e.Proj.QualifiedLabel(realTgt, tgtLbl)
					targetHint = fmt.Sprintf("%s %s", arrow, qual)
				}
			}
			if targetHint == "" {
				for off := addr; off < addr+cell.Size; off++ {
					if relocTgt, ok := allRelocs[off]; ok {
						if tseg := e.Proj.SegmentAtAddr(relocTgt); tseg != nil && tseg.Base != e.BaseAddr {
							targetHint = fmt.Sprintf("%s %s", arrow, tseg.Name)
							break
						}
					}
				}
			}
		} else if cell.Type == db.CellPointer {
			if relocTgt, ok := allRelocs[addr]; ok {
				if tseg := e.Proj.SegmentAtAddr(relocTgt); tseg != nil && tseg.Base != e.BaseAddr {
					targetHint = fmt.Sprintf("%s %s", arrow, tseg.Name)
				}
			}
		}

		var userComment string
		if cell.Type != db.CellStr {
			userComment = ac.EffectiveComment()
		}
		var effectiveComment string
		switch {
		case userComment == "" && targetHint == "":
			effectiveComment = ""
		case userComment == "" && targetHint != "":
			effectiveComment = targetHint
		case userComment != "" && targetHint == "":
			effectiveComment = userComment
		default:
			if strings.Contains(userComment, "->") || strings.Contains(userComment, "→") {
				effectiveComment = userComment
			} else {
				effectiveComment = fmt.Sprintf("%s (%s)", userComment, targetHint)
			}
		}

		combined := false
		if len(e.OutItems) > 0 {
			last := &e.OutItems[len(e.OutItems)-1]
			if last.Label == label && last.Mnem == "" && label != "" {
				last.Mnem = mnem
				last.Op = opStr
				if effectiveComment != "" {
					if last.Comment == "" {
						last.Comment = fmt.Sprintf("; %s", effectiveComment)
					} else {
						last.Comment = fmt.Sprintf("%s ; %s", last.Comment, effectiveComment)
					}
				}
				combined = true
			}
		}

		if !combined {
			var commentStr string
			if effectiveComment != "" {
				commentStr = "; " + effectiveComment
			}
			e.addItemSizedAt(addr, label, mnem, opStr, commentStr, cell.Size)
		}

		addr += cell.Size
	}

	if len(e.BinaryData) == 0 {
		label := getLabelStr(e.BaseAddr)
		if label != "" {
			emptyXrefs, err := e.buildXrefsMap(e.BaseAddr, e.BaseAddr+1, sc, allCells, true)
			if err != nil {
				return err
			}
			e.emitXrefComments(e.BaseAddr, emptyXrefs)
			if e.Relocatable && isEntry(e.BaseAddr) {
				e.addItem("", "xdef", label, "")
			}
			e.addItemAt(e.BaseAddr, label, "", "", "")
		}
	}

	return nil
}

func (e *Emitter) FormatLines() []string {
	lines := make([]string, 0, len(e.OutItems))
	for _, item := range e.OutItems {
		var line string
		if item.Label != "" {
			switch item.Mnem {
			case "equ", "OFFSET", "section", "SECTION", "xdef", "XDEF":
				line = item.Label + "\t" + item.Mnem + "\t" + item.Op
			default:
				if item.Mnem != "" {
					lines = append(lines, item.Label+":")
					line = "\t" + item.Mnem + "\t" + item.Op
				} else {
					line = item.Label + ":"
				}
			}
		} else if item.Mnem != "" {
			line = "\t" + item.Mnem + "\t" + item.Op
		}

		if item.Comment != "" {
			if line != "" {
				line = line + "\t" + item.Comment
			} else {
				line = item.Comment
			}
		}

		if line != "" || (item.Label == "" && item.Mnem == "" && item.Comment == "") {
			lines = append(lines, line)
		}
	}
	return lines
}

func (e *Emitter) TargetOutputPath() string {
	if e.Proj.Data.Output != "" && e.Proj.Data.Output != "out.s" {
		if filepath.IsAbs(e.Proj.Data.Output) {
			return e.Proj.Data.Output
		}
		return filepath.Join(e.Proj.WorkspaceRoot, e.Proj.Data.Output)
	}
	if e.Proj.Data.TargetName != "" {
		if len(e.Proj.Data.Segments) > 1 {
			segName := "main"
			if s := e.Proj.CurrentSegment(); s != nil {
				segName = s.Name
			}
			return filepath.Join(e.Proj.WorkspaceRoot, "disasm", fmt.Sprintf("%s_%s.asm", e.Proj.Data.TargetName, segName))
		}
		return filepath.Join(e.Proj.WorkspaceRoot, "disasm", fmt.Sprintf("%s.asm", e.Proj.Data.TargetName))
	}
	if s := e.Proj.CurrentSegment(); s != nil {
		return fmt.Sprintf("%s.s", s.Name)
	}
	return e.Proj.Data.Output
}

func (e *Emitter) Emit(relocatable, force bool) error {
	outputPath := e.TargetOutputPath()
	if !force && outputPath != "" && fileExists(outputPath) {
		return fmt.Errorf("Refusing to overwrite existing '%s'. Pass --force to overwrite.", outputPath)
	}
	if err := e.GenerateItems(relocatable); err != nil {
		return err
	}
	e.OutLines = e.FormatLines()

	if outputPath != "" {
		if dir := filepath.Dir(outputPath); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return err
			}
		}
		if err := os.WriteFile(outputPath, []byte(strings.Join(e.OutLines, "\n")+"\n"), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func (e *Emitter) emitReserveSpan(addr, diff uint32, useDx bool) {
	if useDx {
		if addr%4 == 0 && diff%4 == 0 {
			e.addItemSizedAt(addr, "", "dx.l", strconv.FormatUint(uint64(diff/4), 10), "", diff)
		} else if addr%2 == 0 && diff%2 == 0 {
			e.addItemSizedAt(addr, "", "dx.w", strconv.FormatUint(uint64(diff/2), 10), "", diff)
		} else {
			e.addItemSizedAt(addr, "", "dx.b", strconv.FormatUint(uint64(diff), 10), "", diff)
		}
		return
	}
	if diff%4 == 0 {
		e.addItemSizedAt(addr, "", "ds.l", strconv.FormatUint(uint64(diff/4), 10), "", diff)
	} else {
		e.addItemSizedAt(addr, "", "ds.b", strconv.FormatUint(uint64(diff), 10), "", diff)
	}
}

func (e *Emitter) emitUninitRange(startAddr, totalEnd, queryEnd uint32, useDx bool) error {
	sc, err := e.ensureSpaceCache()
	if err != nil {
		return err
	}
	xrefsMap, err := e.buildXrefsMap(startAddr, queryEnd, sc, nil, false)
	if err != nil {
		return err
	}
	labels := e.DB.LabelsNamedInRange(startAddr, queryEnd)
	curAddr := startAddr
	for _, lbl := range labels {
		if lbl.Addr > curAddr {
			e.emitReserveSpan(curAddr, lbl.Addr-curAddr, useDx)
			curAddr = lbl.Addr
		}
		e.emitXrefComments(lbl.Addr, xrefsMap)
		e.addItemAt(lbl.Addr, lbl.Text, "", "", "")
	}
	if curAddr < totalEnd {
		e.emitReserveSpan(curAddr, totalEnd-curAddr, useDx)
	}
	return nil
}

// GenerateModularHunkItems emits a single relocatable AmigaOS hunk (`SECTION S_<idx>,<type>[,chip|fast]`),
// including its `XDEF` cross-hunk symbol exports, initialized cell payload (`PopulateCellsItems`),
// and any uninitialized zero-extended allocation tail (`dx.l`/`dx.w`/`dx.b` when `AllocSize > FileDataLen`,
// or `ds.l`/`ds.b` for pure `HUNK_BSS` segments).
func (e *Emitter) GenerateModularHunkItems() error {
	e.OutItems = nil
	segPtr := e.Proj.CurrentSegment()
	if segPtr == nil {
		return fmt.Errorf("no active segment")
	}
	seg := *segPtr

	secName := fmt.Sprintf("S_%d", seg.HunkIndex)
	secType := "code"
	switch seg.HunkType {
	case hunk.HunkTypeCode:
		secType = "code"
	case hunk.HunkTypeData:
		secType = "data"
	case hunk.HunkTypeBss:
		secType = "bss"
	}
	secMem := ""
	switch seg.MemoryType {
	case hunk.MemoryChip:
		secMem = ",chip"
	case hunk.MemoryFast:
		secMem = ",fast"
	case hunk.MemoryPublic:
		secMem = ""
	}
	secDirective := fmt.Sprintf("%s,%s%s", secName, secType, secMem)
	e.addItem("", "SECTION", secDirective, "")
	e.addItem("", "", "", "")

	segEnd := max(seg.EndAddr(), seg.Base+1)
	exported, err := e.DB.GetExportedLabelsInRange(seg.Base, segEnd)
	if err != nil {
		return err
	}
	if len(exported) > 0 {
		e.addItem("", "", "", "; --- Exported Symbols (Cross-Hunk Interface) ---")
		for _, name := range exported {
			e.addItem("", "XDEF", name, "")
		}
		e.addItem("", "", "", "")
	}

	if seg.HunkType == hunk.HunkTypeBss {
		totalEnd := seg.Base + seg.AllocSize
		return e.emitUninitRange(seg.Base, totalEnd, max(totalEnd, seg.Base+1), false)
	}

	if err := e.PopulateCellsItems(); err != nil {
		return err
	}

	onDiskLen := uint32(len(e.BinaryData))
	if seg.FileDataLen != nil {
		onDiskLen = *seg.FileDataLen
	}
	if seg.AllocSize > onDiskLen {
		tailStart := seg.Base + onDiskLen
		tailEnd := seg.Base + seg.AllocSize
		if err := e.emitUninitRange(tailStart, tailEnd, tailEnd, true); err != nil {
			return err
		}
	}

	return nil
}

func (e *Emitter) EmitModularHunk(outputPath string, force bool) error {
	if !force && fileExists(outputPath) {
		return fmt.Errorf("Refusing to overwrite existing '%s'. Pass --force to overwrite.", outputPath)
	}
	if err := e.GenerateModularHunkItems(); err != nil {
		return err
	}
	e.OutLines = e.FormatLines()
	return os.WriteFile(outputPath, []byte(strings.Join(e.OutLines, "\n")+"\n"), 0o644)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// EmitAllAmiga writes the complete modular multi-hunk assembly tree to `outDir`:
//   - `src/equates.i`: shared Amiga hardware register equates used across all hunks
//   - `src/<target>/<seg>.asm`: per-hunk assembly modules (`EmitModularHunk`)
//   - `disasm/<target>.asm`: master assembly file with `opt o-,a-` and `include` directives
//
// Unless `force` is true, EmitAllAmiga refuses to overwrite any existing `.asm` file on disk.
func EmitAllAmiga(proj *project.Project, outDir string, force bool) error {
	targetName := proj.Data.TargetName
	if targetName == "" {
		targetName = "main"
	}

	srcDir := filepath.Join(outDir, "src")
	targetSrcDir := filepath.Join(srcDir, targetName)
	disasmDir := filepath.Join(outDir, "disasm")
	masterPath := filepath.Join(disasmDir, fmt.Sprintf("%s.asm", targetName))

	if !force {
		if fileExists(masterPath) {
			return fmt.Errorf("Refusing to overwrite existing '%s'. Pass --force to overwrite.", masterPath)
		}
		for _, seg := range proj.Data.Segments {
			hunkPath := filepath.Join(targetSrcDir, fmt.Sprintf("%s.asm", seg.Name))
			if fileExists(hunkPath) {
				return fmt.Errorf("Refusing to overwrite existing '%s'. Pass --force to overwrite.", hunkPath)
			}
		}
	}

	if err := os.MkdirAll(targetSrcDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(disasmDir, 0o755); err != nil {
		return err
	}

	// 1. Write shared src/equates.i
	equatesLines := []string{
		"; Commodore Amiga Hardware Equates",
		"",
	}
	equates := amiga.GetAllEquates()
	segments := slices.Clone(proj.Data.Segments)
	sharedDBPath := proj.SharedDB()
	sharedCtrl, err := db.New(sharedDBPath)
	if err != nil {
		return err
	}
	defer sharedCtrl.Close()

	withSegCtrl := func(segDB string, fn func(ctrl *db.Controller) error) error {
		if segDB == "" || segDB == sharedDBPath {
			return fn(sharedCtrl)
		}
		ctrl, err := db.New(segDB)
		if err != nil {
			return err
		}
		defer ctrl.Close()
		return fn(ctrl)
	}

	seenDBs := make(map[string]bool)
	for _, seg := range segments {
		dbName := seg.DB
		if dbName == "" {
			dbName = sharedDBPath
		}
		if seenDBs[dbName] {
			continue
		}
		seenDBs[dbName] = true
		if err := withSegCtrl(dbName, func(ctrl *db.Controller) error {
			proj.SyncDBScope(ctrl)
			amiga.CollectUsedHWEquates(ctrl, equates)
			return nil
		}); err != nil {
			return err
		}
	}
	for _, eq := range sortedEquates(equates) {
		equatesLines = append(equatesLines, fmt.Sprintf("%s\tequ\t$%X", eq.name, eq.addr))
	}
	if err := os.WriteFile(filepath.Join(srcDir, "equates.i"), []byte(strings.Join(equatesLines, "\n")+"\n"), 0o644); err != nil {
		return err
	}

	// 2. Emit each modular hunk to src/<targetName>/{seg.Name}.asm
	proj.SyncDBScope(sharedCtrl)
	sharedCache, err := buildSpaceCache(sharedCtrl)
	if err != nil {
		return err
	}
	hunkFiles := make([]string, 0, len(segments))
	for _, seg := range segments {
		proj.ActiveSegmentName = seg.Name
		if err := withSegCtrl(seg.DB, func(ctrl *db.Controller) error {
			em, err := New(proj, ctrl)
			if err != nil {
				return err
			}
			if seg.DB == "" || seg.DB == sharedDBPath {
				em.cache = sharedCache
			}
			diskHunkPath := filepath.Join(targetSrcDir, fmt.Sprintf("%s.asm", seg.Name))
			return em.EmitModularHunk(diskHunkPath, force)
		}); err != nil {
			return err
		}
		relHunkFilename := fmt.Sprintf("src/%s/%s.asm", targetName, seg.Name)
		hunkFiles = append(hunkFiles, relHunkFilename)
	}
	proj.ActiveSegmentName = ""

	// 3. Write master disasm/<targetName>.asm
	mainLines := []string{
		"; Generated by hunks",
		fmt.Sprintf("; Master Multi-Hunk Assembly (%s)", targetName),
		"",
		"\topt\to-,a-\t; Lock optimizations for 100% bit-for-bit parity",
		"",
		"; --- Hardware Equates ---",
		"\tinclude\t\"src/equates.i\"",
		"",
		"; --- Modular Hunk Subsystems ---",
	}
	for _, file := range hunkFiles {
		mainLines = append(mainLines, fmt.Sprintf("\tinclude\t\"%s\"", file))
	}
	if err := os.WriteFile(masterPath, []byte(strings.Join(mainLines, "\n")+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Printf("Emitted %d modular hunks to src/%s/ and master file to disasm/%s.asm\n", len(segments), targetName, targetName)
	return nil
}
