// Package analyzer implements the unified M68000 static and trace-seeded analysis pipeline.
//
// The pipeline operates over a shared 32-bit virtual address space populated by the
// project's active segments (either relocatable AmigaOS hunks at synthetic bases or
// fixed-address flat binaries/overlays) and runs in coordinated stages:
//   - Stage 1 / 1.5: Ground-truth seeding from HUNK_RELOC32, entry points, and DATA
//     jump-vector tables (`seedJumpTableTargets`).
//   - Stage 2 (`stage2_code.go`): Worklist recursive-descent code tracer, PC-relative and
//     register-indirect switch/offset table resolver, trampoline/vector table scanner, and
//     sandbox-validated gap sweep.
//   - Base-register pass (`baseregs.go`): Global and block-local `a0`..`a6` base propagation,
//     vectored/register-indirect call resolution, and custom hardware register displacement
//     annotation.
//   - Stage 3 (`stage3_data.go` & `format.go`): Label- and relocation-bounded data
//     classification followed by `vasmm68k_mot`-compatible operand formatting.
//   - Stage 4 (`stage4_funcmeta.go`): Post-traversal function-bounds, no-return, and
//     stack-frame inference over the committed cells and control-flow edges.
//   - Trace-seeded analysis (`trace.go` & `chipset.go`): Optional bounded execution in
//     `m68kemu` with a 6-level Amiga OCS/ECS chipset state machine to discover runtime
//     indirect dispatches, interrupt vectors, and base-register hardware accesses.
package analyzer

import (
	"encoding/binary"
	"fmt"
	"slices"
	"strings"

	"github.com/mikolas/hunks/internal/amiga"
	"github.com/mikolas/hunks/internal/db"
	"github.com/mikolas/hunks/internal/hunk"
	"github.com/mikolas/hunks/internal/m68k"
	"github.com/mikolas/hunks/internal/project"
)

// LoadedSegment holds a segment's binary data and synthetic address bounds during analysis.
type LoadedSegment struct {
	Name        string
	HunkIndex   int
	HunkType    hunk.HunkType
	Base        uint32
	End         uint32
	Data        []byte
	Relocatable bool
}

// CustomEAKey identifies a specific instruction operand `(Addr, OpIdx)` for symbolic custom-register EA substitution.
type CustomEAKey struct {
	Addr  uint32
	OpIdx int
}

// Analyzer coordinates the multi-stage M68000 static analysis pipeline.
type Analyzer struct {
	Proj                *project.Project
	DB                  *db.Controller
	Segments            []LoadedSegment
	Relocs              map[uint32]uint32
	RelocTargets        map[uint32]struct{}
	IndirectSites       []uint32
	LabelsCache         map[uint32]string
	ExportedCache       map[uint32]struct{}
	OperandFormatsCache map[uint32]string
	CustomEA            map[CustomEAKey]string
	funcEntries         []uint32
	cellRanges          []db.AddrRange
	cellRangesLoaded    bool
	insnCache           map[uint32]m68k.Insn
}

func loadedSegmentFrom(seg *project.Segment) LoadedSegment {
	data := seg.LoadBinaryData()
	size := seg.AllocSize
	if size == 0 {
		size = uint32(len(data))
	}
	return LoadedSegment{
		Name:        seg.Name,
		HunkIndex:   seg.HunkIndex,
		HunkType:    seg.HunkType,
		Base:        seg.Base,
		End:         seg.Base + size,
		Data:        data,
		Relocatable: seg.IsRelocatable(),
	}
}

func newAnalyzerWithSegments(proj *project.Project, database *db.Controller, segments []LoadedSegment) *Analyzer {
	relocs, err := database.GetAllRelocs()
	if err != nil {
		relocs = make(map[uint32]uint32)
	}
	relocTargets := make(map[uint32]struct{}, len(relocs))
	for _, t := range relocs {
		relocTargets[t] = struct{}{}
	}
	labelsCache, err := database.GetAllLabelsResolved()
	if err != nil {
		labelsCache = make(map[uint32]string)
	}
	opFormatsCache, err := database.GetAllOperandFormats()
	if err != nil {
		opFormatsCache = make(map[uint32]string)
	}

	return &Analyzer{
		Proj:                proj,
		DB:                  database,
		Segments:            segments,
		Relocs:              relocs,
		RelocTargets:        relocTargets,
		LabelsCache:         labelsCache,
		ExportedCache:       make(map[uint32]struct{}),
		OperandFormatsCache: opFormatsCache,
		CustomEA:            make(map[CustomEAKey]string),
	}
}

// New constructs an Analyzer over the project's active space.
func New(proj *project.Project, database *db.Controller) (*Analyzer, error) {
	proj.SyncDBScope(database)
	activeSegs := proj.ActiveSegments()
	segments := make([]LoadedSegment, 0, len(activeSegs))
	for _, seg := range activeSegs {
		segments = append(segments, loadedSegmentFrom(seg))
	}
	return newAnalyzerWithSegments(proj, database, segments), nil
}

// NewForSegment constructs an Analyzer scoped strictly to a single segment segName.
func NewForSegment(proj *project.Project, database *db.Controller, segName string) (*Analyzer, error) {
	segPtr := proj.SegmentByName(segName)
	if segPtr == nil {
		return nil, fmt.Errorf("segment %q not found", segName)
	}
	seg := *segPtr
	database.SetSpaceSegs([]db.SpaceSeg{{
		Name: seg.Name,
		Base: seg.Base,
		End:  seg.EndAddr(),
	}})
	database.SetActiveSeg(seg.Name)

	segments := []LoadedSegment{loadedSegmentFrom(&seg)}
	return newAnalyzerWithSegments(proj, database, segments), nil
}

// ApplyCodeHint marks the word-aligned address as a code entry point and runs incremental analysis.
func ApplyCodeHint(proj *project.Project, ctrl *db.Controller, rawAddr uint32) (uint32, error) {
	addr := rawAddr &^ 1
	autoLbl := proj.AutoLabel(addr)
	_ = ctrl.ClearOverlaps(addr, 2)

	var segName string
	isReloc := false
	if targetSeg := proj.SegmentAtAddr(addr); targetSeg != nil {
		segName = targetSeg.Name
		isReloc = targetSeg.IsRelocatable()
	}

	hasEP := false
	for _, ep := range proj.Data.EntryPoints {
		if (ep.Segment == "" || strings.EqualFold(ep.Segment, segName)) && ep.Addr == addr {
			hasEP = true
			break
		}
	}
	if !hasEP {
		proj.Data.EntryPoints = append(proj.Data.EntryPoints, project.EntryPoint{
			Addr:    addr,
			Name:    autoLbl,
			Segment: segName,
		})
	}
	_ = proj.Save()

	if lbl, err := ctrl.GetLabelFull(addr); err != nil || lbl == nil || lbl.IsAuto {
		_ = ctrl.SetLabel(addr, autoLbl, db.LabelLab, true)
	}

	var an *Analyzer
	var err error
	if isReloc || segName == "" {
		an, err = New(proj, ctrl)
	} else {
		an, err = NewForSegment(proj, ctrl, segName)
	}
	if err != nil {
		proj.SyncDBScope(ctrl)
		return addr, err
	}
	an.AnalyzeIncremental([]uint32{addr})
	if !isReloc && segName != "" {
		proj.RefreshCoverageStats(ctrl)
		_ = proj.Save()
	} else {
		proj.SyncDBScope(ctrl)
	}
	return addr, nil
}

func (a *Analyzer) RefreshCaches() {
	if m, err := a.DB.GetAllLabelsResolved(); err == nil {
		a.LabelsCache = m
	} else {
		a.LabelsCache = make(map[uint32]string)
	}
	if m, err := a.DB.GetAllOperandFormats(); err == nil {
		a.OperandFormatsCache = m
	} else {
		a.OperandFormatsCache = make(map[uint32]string)
	}
	a.funcEntries = a.DB.FunctionEntries()
	a.cellRanges = nil
	a.cellRangesLoaded = false
}

// SegmentAt resolves the active LoadedSegment covering addr.
// Segments are walked in reverse order so that later-listed overlay segments
// take precedence over earlier base segments when address ranges overlap.
func (a *Analyzer) SegmentAt(addr uint32) *LoadedSegment {
	for i := len(a.Segments) - 1; i >= 0; i-- {
		s := &a.Segments[i]
		if s.Base == s.End {
			if addr == s.Base {
				return s
			}
		} else if addr >= s.Base && addr < s.End {
			return s
		}
	}
	return nil
}

func (a *Analyzer) IsInCodeSegment(addr uint32) bool {
	s := a.SegmentAt(addr)
	return s != nil && s.HunkType == hunk.HunkTypeCode && addr < s.End
}

// IsRelocatableAt returns true if the segment at addr is a relocatable hunk
// (or if relocation entries are present).
func (a *Analyzer) IsRelocatableAt(addr uint32) bool {
	if len(a.Relocs) > 0 {
		return true
	}
	if s := a.SegmentAt(addr); s != nil {
		return s.Relocatable
	}
	return false
}

func (a *Analyzer) IsInAnySegment(addr uint32) bool {
	return a.SegmentAt(addr) != nil
}

func (a *Analyzer) IsInAnyProjectSegment(addr uint32) bool {
	if a.IsInAnySegment(addr) {
		return true
	}
	for i := range a.Proj.Data.Segments {
		if a.Proj.Data.Segments[i].Contains(addr) {
			return true
		}
	}
	return false
}

func (a *Analyzer) IsSameSegment(addr1, addr2 uint32) bool {
	s1 := a.SegmentAt(addr1)
	s2 := a.SegmentAt(addr2)
	if s1 == nil || s2 == nil {
		return false
	}
	return s1.HunkIndex == s2.HunkIndex && s1.Name == s2.Name
}

func (a *Analyzer) ReadBytes(addr uint32, length int) []byte {
	seg := a.SegmentAt(addr)
	if seg == nil {
		return nil
	}
	off := int(addr - seg.Base)
	if off < 0 || off >= len(seg.Data) {
		return nil
	}
	end := min(off+length, len(seg.Data))
	return seg.Data[off:end]
}

func (a *Analyzer) ReadU16(addr uint32) (uint16, bool) {
	b := a.ReadBytes(addr, 2)
	if len(b) < 2 {
		return 0, false
	}
	return binary.BigEndian.Uint16(b), true
}

func (a *Analyzer) ReadI16(addr uint32) (int16, bool) {
	v, ok := a.ReadU16(addr)
	return int16(v), ok
}

func (a *Analyzer) ReadU32(addr uint32) (uint32, bool) {
	b := a.ReadBytes(addr, 4)
	if len(b) < 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(b), true
}

func (a *Analyzer) GetOrDefaultLabel(addr uint32) string {
	if l, ok := a.LabelsCache[addr]; ok {
		return l
	}
	segName := a.DB.SegOf(addr)
	for _, ep := range a.Proj.Data.EntryPoints {
		if (ep.Segment == "" || strings.EqualFold(ep.Segment, segName)) && ep.Addr == addr {
			return ep.Name
		}
	}
	return a.Proj.AutoLabel(addr)
}

func (a *Analyzer) IsInMemoryRegion(addr uint32) bool {
	for _, r := range a.Proj.Data.MemoryRegions {
		if addr >= r.Start && addr < r.End {
			return true
		}
	}
	return false
}

// AddLabel ensures a symbolic label exists at targetAddr if it falls within an active
// segment or declared memory region (and is not a dedicated Amiga hardware register).
// When srcAddr belongs to a different segment than targetAddr, the label is marked
// exported (`is_exported = 1`) so modular hunk emission outputs an `XDEF` directive.
func (a *Analyzer) AddLabel(srcAddr *uint32, targetAddr uint32) {
	if _, ok := amiga.GetAmigaHWLabel(targetAddr); ok {
		return
	}
	inMemRegion := a.IsInMemoryRegion(targetAddr)
	isFlatOut := srcAddr != nil && !a.IsRelocatableAt(*srcAddr) && !a.IsInAnyProjectSegment(targetAddr) && targetAddr > 0 && (targetAddr&0xFF000000) == 0
	if !a.IsInAnySegment(targetAddr) && !inMemRegion && !isFlatOut {
		return
	}

	isCrossSeg := false
	if srcAddr != nil {
		isCrossSeg = !a.IsSameSegment(*srcAddr, targetAddr) && a.IsInAnySegment(targetAddr)
	}

	if existing, exists := a.LabelsCache[targetAddr]; exists {
		if isFlatOut && strings.HasPrefix(existing, "LAB_") {
			if lbl, err := a.DB.GetLabelFull(targetAddr); err == nil && lbl != nil && lbl.IsAuto && lbl.Name == existing {
				auto := a.Proj.AutoLabel(targetAddr)
				_ = a.DB.SetLabel(targetAddr, auto, db.LabelLab, true)
				if resolved, err := a.DB.GetAllLabelsResolved(); err == nil {
					if r, ok := resolved[targetAddr]; ok {
						a.LabelsCache[targetAddr] = r
					}
				}
			}
		}
		if isCrossSeg {
			if _, exp := a.ExportedCache[targetAddr]; !exp {
				a.ExportedCache[targetAddr] = struct{}{}
				_ = a.DB.MarkExported(targetAddr)
			}
		}
		return
	}

	segName := a.DB.SegOf(targetAddr)
	var name string
	for _, ep := range a.Proj.Data.EntryPoints {
		if (ep.Segment == "" || strings.EqualFold(ep.Segment, segName)) && ep.Addr == targetAddr {
			name = ep.Name
			break
		}
	}
	if name == "" {
		name = a.Proj.AutoLabel(targetAddr)
	}

	a.LabelsCache[targetAddr] = name
	if isCrossSeg {
		a.ExportedCache[targetAddr] = struct{}{}
		_ = a.DB.SetLabelExported(targetAddr, name, db.LabelLab, true, true)
	} else {
		_ = a.DB.SetLabel(targetAddr, name, db.LabelLab, true)
	}
}

// GetUnmappedGapsInRange returns all contiguous [Start, End) intervals within
// [startAddr, endAddr) that are not covered by any existing cell in the database.
func (a *Analyzer) GetUnmappedGapsInRange(startAddr, endAddr uint32) []db.AddrRange {
	ranges := a.DB.CellRangesIn(startAddr, endAddr)
	var merged []db.AddrRange
	if len(ranges) > 0 {
		current := ranges[0]
		for _, r := range ranges[1:] {
			if r.Start <= current.End {
				current.End = max(current.End, r.End)
			} else {
				merged = append(merged, current)
				current = r
			}
		}
		merged = append(merged, current)
	}

	var gaps []db.AddrRange
	cur := startAddr
	for _, r := range merged {
		if r.Start > cur {
			gaps = append(gaps, db.AddrRange{Start: cur, End: r.Start})
		}
		cur = max(cur, r.End)
	}
	if cur < endAddr {
		gaps = append(gaps, db.AddrRange{Start: cur, End: endAddr})
	}
	return gaps
}

// AnalyzeIncremental runs the unified pipeline starting from incremental code seeds.
func (a *Analyzer) AnalyzeIncremental(addrs []uint32) {
	if len(a.Segments) == 0 {
		return
	}
	a.runPipeline(addrs)
}

// Analyze runs the full multi-stage unified analysis pipeline (see runPipeline) across
// all loaded segments, then refreshes coverage statistics.
func (a *Analyzer) Analyze(startAddrs []uint32) {
	if len(a.Segments) == 0 {
		return
	}
	var entries []uint32
	if startAddrs != nil {
		entries = slices.Clone(startAddrs)
	} else {
		for _, ep := range a.Proj.Data.EntryPoints {
			include := false
			if ep.Segment == "" {
				include = a.IsInAnySegment(ep.Addr)
			} else {
				for _, s := range a.Segments {
					if strings.EqualFold(s.Name, ep.Segment) {
						include = true
						break
					}
				}
			}
			if include {
				entries = append(entries, ep.Addr)
			}
		}
	}

	for _, seg := range a.Segments {
		if seg.HunkType == hunk.HunkTypeCode && seg.HunkIndex == 0 && !slices.Contains(entries, seg.Base) {
			entries = append(entries, seg.Base)
		}
	}
	if startAddrs == nil {
		for _, fnAddr := range a.DB.FunctionEntries() {
			if a.IsInCodeSegment(fnAddr) && !slices.Contains(entries, fnAddr) {
				entries = append(entries, fnAddr)
			}
		}
	}
	_ = a.DB.DeleteCodeCells()

	a.runPipeline(entries)
	a.updateCoverageStats()
}

// runPipeline executes the core multi-stage analysis pass from the given code entry seeds.
// A per-pipeline decode cache (`insnCache`) is reset here and shared across the stages so
// each committed CODE cell is decoded roughly once (populated by the base-register walk,
// consumed by operand formatting and function-metadata inference):
//  1. Seed targets from relocated `JMP target.L` jump tables in DATA segments.
//  2. Discover and validate all reachable and gap-swept CODE cells, resolving PC-relative
//     and register-indirect dispatch inside the fixed-point loop (Stage 2).
//  3. Propagate `a0`..`a6` base registers to resolve vectored/register-indirect calls,
//     global data XREFs, and custom hardware register displacements.
//  4. Classify remaining unmapped gaps into structured DATA/STRING/POINTER/ZERO cells (Stage 3a).
//  5. Format all CODE instruction mnemonics and operands into `vasmm68k_mot` syntax (Stage 3b).
//  6. Record function bounds, no-return status, and stack-frame size, pruning fallthrough
//     edges past no-return calls (Stage 4, `stage4_funcmeta.go`).
func (a *Analyzer) runPipeline(entries []uint32) {
	a.insnCache = make(map[uint32]m68k.Insn)
	jumpTable := a.seedJumpTableTargets()
	for _, target := range jumpTable {
		entries = append(entries, target)
	}

	a.stage2DiscoverCode(entries, jumpTable)
	a.propagateBaseRegs(jumpTable)
	a.stage3ClassifyData()
	a.Stage3FormatOperands()
	a.stage4FunctionMeta()
	// The decode cache is only consumed within the pipeline (base-register walk, operand
	// formatting, function-metadata). Release it so the per-cell m68k.Insn values (several
	// MB on large targets) are not retained on the Analyzer after analysis completes.
	a.insnCache = nil
}

// decodeCached returns the decoded instruction at addr, using the per-pipeline decode
// cache (populated by the base-register walk) and falling back to a direct decode of raw
// on a miss. Correctness never depends on a cache hit: a miss decodes the same bytes.
// The cache is address-keyed and rebuilt fresh each runPipeline; it is populated only
// after Stage 2 has committed final CODE cells, so cached entries match the bytes the
// later passes (format, function-metadata) read for the same address.
func (a *Analyzer) decodeCached(addr uint32, raw []byte) (m68k.Insn, bool) {
	if a.insnCache != nil {
		if insn, ok := a.insnCache[addr]; ok {
			return insn, true
		}
	}
	insn, ok := m68k.Decode(raw, addr)
	if !ok {
		return m68k.Insn{}, false
	}
	if a.insnCache != nil {
		a.insnCache[addr] = insn
	}
	return insn, true
}

func (a *Analyzer) updateCoverageStats() {
	bytes := a.DB.CodeCoverageBytes()
	var totalCodeSegBytes uint32
	for _, s := range a.Segments {
		if s.HunkType != hunk.HunkTypeBss {
			totalCodeSegBytes += uint32(len(s.Data))
		}
	}
	a.Proj.Data.Analysis.CodeBytes = bytes
	a.Proj.Data.Analysis.TotalBytes = totalCodeSegBytes

	indirect := slices.Clone(a.IndirectSites)
	slices.Sort(indirect)
	indirect = slices.Compact(indirect)
	hexIndirect := make([]string, len(indirect))
	for i, addr := range indirect {
		hexIndirect[i] = fmt.Sprintf("0x%X", addr)
	}
	a.Proj.Data.Analysis.IndirectAddressing = hexIndirect
	_ = a.Proj.Save()
}
