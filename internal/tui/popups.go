package tui

import (
	"bytes"
	"cmp"
	"encoding/hex"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/mikolas/hunks/internal/amiga"
	"github.com/mikolas/hunks/internal/db"
	"github.com/mikolas/hunks/internal/emitter"
	"github.com/mikolas/hunks/internal/hunk"
	"github.com/mikolas/hunks/internal/project"
)

type clusterSig struct {
	offs  [][2]uint16
	mnems []string
}

func inRange(addr uint32, rng *db.AddrRange) bool {
	if rng == nil {
		return true
	}
	return addr >= rng.Start && addr < rng.End
}

func isIdentByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

func resolveCustomName(s string) (uint16, bool) {
	customRegs := amiga.GetCustomRegs()
	tokens := strings.FieldsFunc(s, func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_')
	})
	for off, name := range customRegs {
		if slices.Contains(tokens, name) {
			return uint16(off), true
		}
	}
	return 0, false
}

func cellCustomOffset(op string, comment *string) (uint16, bool) {
	p := strings.Index(op, "$DFF")
	if p < 0 {
		p = strings.Index(op, "$00DFF")
	}
	if p >= 0 {
		dffIdx := strings.Index(op[p:], "DFF")
		hexStart := p + dffIdx + 3
		end := hexStart
		for end < len(op) {
			c := op[end]
			if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
				end++
			} else {
				break
			}
		}
		if end > hexStart {
			if v, err := strconv.ParseUint(op[hexStart:end], 16, 16); err == nil {
				return uint16(v) & 0x1FE, true
			}
		}
	}

	if off, ok := resolveCustomName(op); ok {
		return off, true
	}

	if strings.Contains(op, "(a") && comment != nil {
		for _, frag := range strings.Split(*comment, "; ") {
			_, rhs, hasEq := strings.Cut(frag, " = ")
			if !hasEq {
				continue
			}
			rhs = strings.TrimLeft(rhs, " \t")
			end := 0
			for end < len(rhs) && isIdentByte(rhs[end]) {
				end++
			}
			tok := rhs[:end]
			if off, ok := resolveCustomName(tok); ok {
				return off, true
			}
			if hexStr, ok := strings.CutPrefix(tok, "CUSTOM_"); ok {
				if v, err := strconv.ParseUint(hexStr, 16, 16); err == nil {
					return uint16(v) & 0x1FE, true
				}
			}
		}
	}
	return 0, false
}

// OpenXrefs opens the cross-reference modal for the cursor address.
func (a *App) OpenXrefs() {
	addr, ok := a.CursorAddr()
	if !ok {
		return
	}
	allLabels, _ := a.DB.GetAllLabelsResolved()
	sortedLabelAddrs := slices.Sorted(maps.Keys(allLabels))
	rawRefs := a.DB.RefsTo(addr)

	jmpBases := a.DB.DetectJumpVectorBases()
	if len(jmpBases) > 0 {
		allRelocs, _ := a.DB.GetAllRelocs()
		vecMap := a.DB.GetVectoredCallXrefs(addr, addr+1, jmpBases, allRelocs)
		if vecCallers, hasVec := vecMap[addr]; hasVec {
			for _, vc := range vecCallers {
				rawRefs = append(rawRefs, db.AddrText{Addr: vc.Addr, Text: "VEC_CALL"})
			}
		}
	}
	slices.SortFunc(rawRefs, func(x, y db.AddrText) int {
		return cmp.Compare(x.Addr, y.Addr)
	})

	var xrefs []XrefItem
	seenSnapped := make(map[uint32]struct{})
	for _, r := range rawRefs {
		snappedSrc := r.Addr
		var mnem, ops string
		if cell, err := a.DB.GetCellContaining(r.Addr); err == nil && cell != nil {
			snappedSrc = cell.Addr
			if cell.Mnemonic != nil {
				mnem = *cell.Mnemonic
			} else if cell.Type == db.CellPointer || cell.Type == db.CellDataL {
				mnem = "dc.l"
			} else {
				mnem = cell.Type.AsStr()
			}
			if cell.OpStr != nil {
				ops = *cell.OpStr
			}
		}
		if _, dup := seenSnapped[snappedSrc]; dup {
			continue
		}
		seenSnapped[snappedSrc] = struct{}{}

		var callerSegBase uint32
		if seg := a.Proj.SegmentAtAddr(snappedSrc); seg != nil {
			callerSegBase = seg.Base
		}
		enclosingLbl := a.Proj.AutoLabel(snappedSrc)
		idx, found := slices.BinarySearch(sortedLabelAddrs, snappedSrc)
		if found {
			idx++
		}
		if idx > 0 && sortedLabelAddrs[idx-1] >= callerSegBase {
			enclosingLbl = allLabels[sortedLabelAddrs[idx-1]]
		}
		qualLbl := a.Proj.QualifiedLabel(snappedSrc, enclosingLbl)
		var insnStr string
		if mnem == "" {
			insnStr = fmt.Sprintf("(in %s)", qualLbl)
		} else {
			insnStr = fmt.Sprintf("(in %s)  %s %s", qualLbl, mnem, ops)
		}
		xrefs = append(xrefs, XrefItem{
			Addr: snappedSrc,
			Type: r.Text,
			Insn: insnStr,
		})
	}

	if len(xrefs) == 0 {
		a.StatusMsg = "No XREFs to this address"
	} else {
		a.Modal = Modal{
			Kind:       ModalXrefs,
			Xrefs:      xrefs,
			ListSelect: 0,
		}
	}
}

// OpenFunctions opens the function list modal.
func (a *App) OpenFunctions() {
	allLabels, _ := a.DB.GetAllLabelsResolved()
	activeSegs := a.Proj.ActiveSegments()
	funcSet := make(map[uint32]struct{})
	for _, ep := range a.Proj.Data.EntryPoints {
		if ep.Segment == "" {
			funcSet[ep.Addr] = struct{}{}
			continue
		}
		for _, s := range activeSegs {
			if strings.EqualFold(s.Name, ep.Segment) {
				funcSet[ep.Addr] = struct{}{}
				break
			}
		}
	}
	for _, fa := range a.DB.FunctionLabelAddrs() {
		funcSet[fa] = struct{}{}
	}
	addrs := make([]uint32, 0, len(funcSet))
	for addr := range funcSet {
		addrs = append(addrs, addr)
	}
	slices.Sort(addrs)

	funcs := make([]FuncItem, len(addrs))
	for i, addr := range addrs {
		name, ok := allLabels[addr]
		if !ok || name == "" {
			name = a.Proj.AutoLabel(addr)
		}
		var cycStr string
		if sc, ok := a.SubCycles[addr]; ok {
			cycStr = sc.FormatSummary()
		}
		funcs[i] = FuncItem{
			Addr:   addr,
			Name:   name,
			Cycles: cycStr,
			ABI:    a.Proj.GetFunctionABI(name, a.Proj.AutoLabel(addr)),
		}
	}
	a.Modal = Modal{
		Kind:       ModalFunctions,
		AllFuncs:   funcs,
		ListSelect: 0,
	}
}

// OpenSearch opens the interactive search modal.
func (a *App) OpenSearch() {
	a.Modal = Modal{
		Kind:  ModalSearch,
		Input: EmptyTextInput(),
	}
}

// DoSearch runs a prefix-scoped search or navigation resolution.
func (a *App) DoSearch(query string) []SearchHit {
	trimmed := strings.TrimSpace(query)
	if trimmed == "" {
		return nil
	}

	known := []string{"m", "o", "s", "c", "b", "l", "cluster"}
	prefix, rest, hasColon := strings.Cut(trimmed, ":")
	if !hasColon || !slices.Contains(known, prefix) {
		return a.searchNavigate(trimmed)
	}

	var segOpt string
	content := rest
	if s, c, hasSlash := strings.Cut(rest, "/"); hasSlash {
		segOpt = strings.TrimSpace(s)
		content = c
	}
	content = strings.TrimSpace(content)

	var targetSeg *project.Segment
	var rng *db.AddrRange
	switch {
	case segOpt == "all" || segOpt == "*":
		targetSeg = nil
		rng = nil
	case segOpt != "":
		if s := a.Proj.SegmentByName(segOpt); s != nil {
			targetSeg = s
			sz := max(s.AllocSize, 1)
			rng = &db.AddrRange{Start: s.Base, End: s.Base + sz}
		}
	default:
		if s := a.Proj.CurrentSegment(); s != nil {
			targetSeg = s
			sz := max(s.AllocSize, 1)
			rng = &db.AddrRange{Start: s.Base, End: s.Base + sz}
		}
	}

	toHits := func(pairs []db.AddrText) []SearchHit {
		out := make([]SearchHit, len(pairs))
		for i, p := range pairs {
			out[i] = SearchHit{Addr: p.Addr, Text: p.Text}
		}
		return out
	}

	run := func() []SearchHit {
		switch prefix {
		case "m":
			return toHits(a.DB.SearchCode("m", content, rng, 100))
		case "o":
			return toHits(a.DB.SearchCode("o", content, rng, 100))
		case "s":
			return toHits(a.DB.SearchStrings(content, rng, 100))
		case "c":
			raw := a.DB.SearchComments(content, rng, 100)
			out := make([]SearchHit, len(raw))
			for i, r := range raw {
				firstLine, _, _ := strings.Cut(r.Text, "\n")
				out[i] = SearchHit{Addr: r.Addr, Text: "; " + firstLine}
			}
			return out
		case "l":
			return toHits(a.DB.SearchLabels(content, rng, 100))
		case "b":
			return a.searchBytes(content, targetSeg, rng)
		case "cluster":
			return a.searchCluster(content, rng)
		default:
			return nil
		}
	}

	if targetSeg != nil {
		var hits []SearchHit
		a.DB.WithActiveSeg(targetSeg.Name, func() {
			hits = run()
		})
		return hits
	}
	return run()
}

func (a *App) searchNavigate(q string) []SearchHit {
	var segOpt *project.Segment
	if sPart, _, hasColon := strings.Cut(q, ":"); hasColon {
		segOpt = a.Proj.SegmentByName(strings.TrimSpace(sPart))
	}
	addr, ok := a.Proj.ResolveTarget(a.DB, q)
	if !ok {
		return nil
	}
	resolveLbl := func() string {
		if n, hasLbl, _ := a.DB.GetLabel(addr); hasLbl && n != "" {
			if ren, hasRen, _ := a.DB.GetRename(n); hasRen && ren != "" {
				return ren
			}
			return n
		}
		if segOpt != nil {
			return segOpt.AutoLabel(addr)
		}
		return a.Proj.AutoLabel(addr)
	}
	var lbl string
	if segOpt != nil {
		a.DB.WithActiveSeg(segOpt.Name, func() {
			lbl = resolveLbl()
		})
	} else {
		lbl = resolveLbl()
	}
	return []SearchHit{{Addr: addr, Text: lbl}}
}

func (a *App) searchBytes(content string, targetSeg *project.Segment, rng *db.AddrRange) []SearchHit {
	var hexChars strings.Builder
	for i := 0; i < len(content); i++ {
		c := content[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			hexChars.WriteByte(c)
		}
	}
	hexStr := hexChars.String()
	if len(hexStr) < 2 || len(hexStr)%2 != 0 {
		return nil
	}
	pat, err := hex.DecodeString(hexStr)
	if err != nil || len(pat) == 0 {
		return nil
	}

	var out []SearchHit
	scanSlice := func(data []byte, base uint32, checkRange bool) {
		for i := 0; i+len(pat) <= len(data); i++ {
			if bytes.Equal(data[i:i+len(pat)], pat) {
				addr := base + uint32(i)
				if !checkRange || inRange(addr, rng) {
					out = append(out, SearchHit{
						Addr: addr,
						Text: fmt.Sprintf("bytes @ %s", a.FormatAddr(addr)),
					})
					if len(out) >= 100 {
						return
					}
				}
			}
		}
	}

	if targetSeg != nil {
		cur := a.Proj.CurrentSegment()
		if cur != nil && cur.Name == targetSeg.Name {
			scanSlice(a.BinaryData, a.BaseAddr, true)
		} else {
			scanSlice(targetSeg.LoadBinaryData(), targetSeg.Base, true)
		}
	} else {
		for _, seg := range a.Proj.ActiveSegments() {
			scanSlice(seg.LoadBinaryData(), seg.Base, false)
			if len(out) >= 100 {
				break
			}
		}
	}
	return out
}

func (a *App) searchCluster(preset string, rng *db.AddrRange) []SearchHit {
	var sig clusterSig
	switch strings.ToLower(strings.TrimSpace(preset)) {
	case "3dmath", "math", "trig", "sin", "cos":
		sig = clusterSig{mnems: []string{"mul", "div"}}
	case "mul":
		sig = clusterSig{mnems: []string{"mul"}}
	case "div":
		sig = clusterSig{mnems: []string{"div"}}
	case "blitter":
		sig = clusterSig{offs: [][2]uint16{{0x040, 0x074}}}
	case "copper":
		sig = clusterSig{offs: [][2]uint16{{0x080, 0x08A}}}
	case "bitplane", "display", "video":
		sig = clusterSig{offs: [][2]uint16{{0x08E, 0x094}, {0x0E0, 0x0FE}, {0x100, 0x10A}, {0x180, 0x1BE}}}
	case "audio", "paula":
		sig = clusterSig{offs: [][2]uint16{{0x0A0, 0x0DF}, {0x09E, 0x09E}}}
	case "sprite", "sprites":
		sig = clusterSig{offs: [][2]uint16{{0x120, 0x17E}}}
	case "dma":
		sig = clusterSig{offs: [][2]uint16{{0x002, 0x002}, {0x096, 0x096}}}
	case "irq", "interrupt":
		sig = clusterSig{offs: [][2]uint16{{0x01C, 0x01E}, {0x09A, 0x09C}}}
	default:
		return nil
	}

	lo := uint32(0)
	hi := uint32(0xFFFFFFFF)
	if rng != nil {
		lo, hi = rng.Start, rng.End
	}
	cells, _ := a.DB.CellsInRange(lo, hi)
	comments, _ := a.DB.GetCommentsInRange(lo, hi)

	type markEntry struct {
		addr uint32
		hit  bool
	}
	var marks []markEntry
	for _, c := range cells {
		if c.Type != db.CellCode {
			continue
		}
		var mnem string
		if c.Mnemonic != nil {
			mnem = *c.Mnemonic
		}
		base, _, _ := strings.Cut(mnem, ".")
		mHit := false
		for _, p := range sig.mnems {
			if strings.HasPrefix(base, p) {
				mHit = true
				break
			}
		}
		oHit := false
		if len(sig.offs) > 0 {
			var opStr string
			if c.OpStr != nil {
				opStr = *c.OpStr
			}
			var cmtPtr *string
			if eff := comments[c.Addr].EffectiveComment(); eff != "" {
				cmtPtr = &eff
			}
			if off, ok := cellCustomOffset(opStr, cmtPtr); ok {
				for _, pair := range sig.offs {
					if off >= pair[0] && off <= pair[1] {
						oHit = true
						break
					}
				}
			}
		}
		marks = append(marks, markEntry{addr: c.Addr, hit: mHit || oHit})
	}
	if len(marks) == 0 {
		return nil
	}

	const win = 24
	const minHits = 3
	funcs := a.DB.FunctionLabelAddrs()
	type regionHit struct {
		addr uint32
		hits int
	}
	var regions []regionHit
	countHits := func(slice []markEntry) int {
		n := 0
		for _, m := range slice {
			if m.hit {
				n++
			}
		}
		return n
	}

	i := 0
	for i < len(marks) {
		end := min(i+win, len(marks))
		hits := countHits(marks[i:end])
		if hits >= minHits {
			start := marks[i].addr
			j := end
			for j < len(marks) {
				wEnd := min(j+win, len(marks))
				if countHits(marks[j:wEnd]) >= minHits {
					j++
				} else {
					break
				}
			}
			total := countHits(marks[i:min(j, len(marks))])
			regions = append(regions, regionHit{addr: start, hits: total})
			i = j
		} else {
			i++
		}
	}
	slices.SortFunc(regions, func(x, y regionHit) int {
		return cmp.Compare(y.hits, x.hits)
	})
	if len(regions) > 50 {
		regions = regions[:50]
	}

	pTrim := strings.TrimSpace(preset)
	out := make([]SearchHit, len(regions))
	for idx, reg := range regions {
		var funcAddr uint32
		hasFunc := false
		for _, f := range funcs {
			if f <= reg.addr && (!hasFunc || f > funcAddr) {
				funcAddr = f
				hasFunc = true
			}
		}
		var fname string
		if hasFunc {
			if n, ok, _ := a.DB.GetLabel(funcAddr); ok && n != "" {
				if ren, hasRen, _ := a.DB.GetRename(n); hasRen && ren != "" {
					fname = ren
				} else {
					fname = n
				}
			}
		}
		var label string
		if fname == "" {
			label = fmt.Sprintf("%s: %d hits", pTrim, reg.hits)
		} else {
			label = fmt.Sprintf("%s: %d hits in %s", pTrim, reg.hits, fname)
		}
		out[idx] = SearchHit{Addr: reg.addr, Text: label}
	}
	return out
}

// OpenMemoryMap opens the memory regions modal.
func (a *App) OpenMemoryMap() {
	a.Modal = Modal{Kind: ModalMemoryMap, ListSelect: 0}
}

// OpenContextMenu opens the right-click context menu modal.
func (a *App) OpenContextMenu() {
	a.Modal = Modal{Kind: ModalContextMenu, ListSelect: 0}
}

// OpenStructEditor opens the struct editor modal.
func (a *App) OpenStructEditor() {
	structs := make([]string, 0, len(a.Proj.Data.Structs))
	for k := range a.Proj.Data.Structs {
		structs = append(structs, k)
	}
	slices.Sort(structs)
	a.Modal = Modal{
		Kind: ModalStructEditor,
		StructState: StructEditorState{
			Structs:        structs,
			SelectedStruct: -1,
			Selected:       0,
			InputMode:      StructInputNone,
		},
	}
}

// OpenAliasEditor opens the register alias editor modal.
func (a *App) OpenAliasEditor() {
	a.Modal = Modal{Kind: ModalAliasEditor, ListSelect: 0}
}

// MarkPointerTable marks count consecutive 32-bit pointers starting at the cursor.
func (a *App) MarkPointerTable(count uint32) {
	if a.incbinCellAtCursor() != nil {
		a.StatusMsg = "Folded incbin — press 'b' or 'K' to unfold first"
		return
	}
	addr, ok := a.CursorAddr()
	if !ok {
		return
	}
	if a.rangeOverlapsIncbin(addr, count*4) {
		a.StatusMsg = "Folded incbin — press 'b' or 'K' to unfold first"
		return
	}
	a.pushUndoForRegion(addr, count*4)
	_ = a.DB.WithTransaction(func() error {
		for i := range count {
			if err := a.DB.MarkData(addr+i*4, 4, db.CellPointer); err != nil {
				return err
			}
		}
		return nil
	})
	a.ReloadAtCursor()
	a.StatusMsg = fmt.Sprintf("Marked %d pointers at %s", count, a.FormatAddr(addr))
}

// ExportASM exports the active segment (or flat assembly) to disk.
func (a *App) ExportASM() {
	em, err := emitter.New(a.Proj, a.DB)
	if err != nil {
		a.StatusMsg = fmt.Sprintf("Export failed: %v", err)
		return
	}
	if a.IsRelocatable {
		segName := "hunk0"
		if s := a.Proj.CurrentSegment(); s != nil {
			segName = s.Name
		}
		targetName := a.Proj.Data.TargetName
		if targetName == "" {
			targetName = "main"
		}
		targetSrcDir := filepath.Join(a.Proj.WorkspaceRoot, "src", targetName)
		outputFile := filepath.Join(targetSrcDir, fmt.Sprintf("%s.asm", segName))
		if _, err := os.Stat(outputFile); err == nil {
			a.StatusMsg = fmt.Sprintf("Export refused: src/%s/%s.asm already exists (use CLI --force to overwrite)", targetName, segName)
			return
		}
		_ = os.MkdirAll(targetSrcDir, 0o755)
		if err := em.EmitModularHunk(outputFile, false); err != nil {
			a.StatusMsg = fmt.Sprintf("Export failed: %v", err)
		} else {
			a.StatusMsg = fmt.Sprintf("Exported to src/%s/%s.asm", targetName, segName)
		}
	} else {
		outputPath := em.TargetOutputPath()
		if outputPath != "" {
			if _, err := os.Stat(outputPath); err == nil {
				a.StatusMsg = fmt.Sprintf("Export refused: %s already exists (use CLI --force to overwrite)", outputPath)
				return
			}
		}
		if err := em.Emit(false, false); err != nil {
			a.StatusMsg = fmt.Sprintf("Export failed: %v", err)
		} else {
			a.StatusMsg = fmt.Sprintf("Exported to %s", outputPath)
		}
	}
}

// OpenSpaceSwitcher opens the address-space switcher modal.
func (a *App) OpenSpaceSwitcher() {
	a.Modal = Modal{Kind: ModalSpaceSwitcher, ListSelect: 0}
}

// OpenSegmentManager opens the segment manager modal.
func (a *App) OpenSegmentManager() {
	a.Modal = Modal{Kind: ModalSegmentManager, ListSelect: 0}
}

// OpenFileBrowser opens the file browser modal starting at the current directory.
func (a *App) OpenFileBrowser() {
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}
	entries := ReadDirEntries(cwd)
	a.Modal = Modal{
		Kind: ModalFileBrowser,
		FileBrowser: FileBrowserState{
			Path:     cwd,
			Entries:  entries,
			Selected: 0,
		},
	}
}

// ReadDirEntries reads non-hidden directory entries sorted with directories first.
func ReadDirEntries(path string) []DirEntryItem {
	entries := []DirEntryItem{{Name: "..", IsDir: true, Size: 0}}
	rd, err := os.ReadDir(path)
	if err != nil {
		return entries
	}
	var dirs, files []DirEntryItem
	for _, e := range rd {
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		info, err := e.Info()
		isDir := e.IsDir()
		var size uint64
		if err == nil {
			isDir = info.IsDir()
			size = uint64(info.Size())
		}
		if isDir {
			dirs = append(dirs, DirEntryItem{Name: name, IsDir: true})
		} else {
			files = append(files, DirEntryItem{Name: name, IsDir: false, Size: size})
		}
	}
	slices.SortFunc(dirs, func(x, y DirEntryItem) int { return cmp.Compare(x.Name, y.Name) })
	slices.SortFunc(files, func(x, y DirEntryItem) int { return cmp.Compare(x.Name, y.Name) })
	entries = append(entries, dirs...)
	entries = append(entries, files...)
	return entries
}

// OpenSegmentForm opens the new-segment creation form for file.
func (a *App) OpenSegmentForm(file string, fileSize uint64) {
	base := filepath.Base(file)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)
	a.Modal = Modal{
		Kind: ModalSegmentForm,
		SegmentForm: SegmentFormState{
			File:     file,
			FileSize: fileSize,
			Name:     name,
			Space:    a.Proj.Data.ActiveSpace,
		},
	}
}

// CreateSegment adds a new flat segment to the project and optional space.
func (a *App) CreateSegment(name, file string, base uint32, space string) bool {
	for _, s := range a.Proj.Data.Segments {
		if strings.EqualFold(s.Name, name) {
			a.StatusMsg = fmt.Sprintf("Segment '%s' already exists", name)
			return false
		}
	}
	dbName := a.Proj.SharedDB()
	var flatSize uint32
	if info, err := os.Stat(file); err == nil {
		flatSize = uint32(info.Size())
	}
	fileCopy := file
	a.Proj.Data.Segments = append(a.Proj.Data.Segments, project.Segment{
		Name:        name,
		HunkIndex:   len(a.Proj.Data.Segments),
		HunkType:    hunk.HunkTypeCode,
		MemoryType:  hunk.MemoryPublic,
		AllocSize:   flatSize,
		File:        &fileCopy,
		Base:        base,
		DB:          dbName,
		Relocatable: false,
	})
	if space != "" {
		for i := range a.Proj.Data.Spaces {
			if a.Proj.Data.Spaces[i].Name == space {
				a.Proj.Data.Spaces[i].Segments = append(a.Proj.Data.Spaces[i].Segments, name)
				break
			}
		}
	}
	_ = a.Proj.Save()
	a.Proj.SyncDBScope(a.DB)
	a.StatusMsg = fmt.Sprintf("Created segment '%s' at $%X", name, base)
	return true
}
