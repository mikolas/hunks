package analyzer

import (
	"cmp"
	"slices"

	"github.com/google/btree"
	"github.com/mikolas/hunks/internal/db"
	"github.com/mikolas/hunks/internal/hunk"
	"github.com/mikolas/hunks/internal/m68k"
)

type workItem struct {
	addr       uint32
	confidence uint8
}

func newCodeBTree() *btree.BTreeG[db.Cell] {
	return btree.NewG(32, func(a, b db.Cell) bool {
		return a.Addr < b.Addr
	})
}

func hasCodeCell(tree *btree.BTreeG[db.Cell], addr uint32) bool {
	_, ok := tree.Get(db.Cell{Addr: addr})
	return ok
}

func overlapsExistingCode(tree *btree.BTreeG[db.Cell], addr, size uint32) bool {
	end := addr + size
	if end == 0 {
		return false
	}
	overlaps := false
	tree.DescendLessOrEqual(db.Cell{Addr: end - 1}, func(prev db.Cell) bool {
		if prev.Addr+prev.Size > addr {
			overlaps = true
		}
		return false
	})
	return overlaps
}

// protectedOverlaps reports whether [addr, end) intersects any range in the address-sorted,
// non-overlapping `protected` slice, via binary search rather than a linear scan.
func protectedOverlaps(protected []db.AddrRange, addr, end uint32) bool {
	idx, _ := slices.BinarySearchFunc(protected, addr, func(r db.AddrRange, t uint32) int {
		return cmp.Compare(r.Start, t)
	})
	// The predecessor (largest Start <= addr) may extend past addr; the range at idx may
	// start before end.
	if idx > 0 && protected[idx-1].End > addr {
		return true
	}
	if idx < len(protected) && protected[idx].Start < end && protected[idx].End > addr {
		return true
	}
	return false
}

// stage2DiscoverCode runs a fixed-point loop to discover, validate, and persist all CODE cells.
//
// Each iteration progresses through five discovery tiers, always draining higher-confidence
// tiers before consulting lower-confidence heuristics:
//  1. Worklist recursive descent (`ConfDefinite` / `ConfHigh`): decodes basic blocks along
//     direct calls, conditional/unconditional branches, and fallthrough edges, recording
//     XREFs, control-flow edges, data read targets, and indirect dispatch sites.
//  2. Indirect jump/switch dispatch resolution: resolves `JMP`/`JSR` through `d8(PC,Xn)`
//     as well as register-indirect modes (`(An)`, `d16(An)`, `d8(An,Xn)`) using the
//     block-local register file captured at each dispatch site, into `BRA.W`/`BRA.B`
//     branch tables, 16-bit relative offset (`dc.w target-table`) tables, or a single
//     resolved target.
//  3. Contiguous trampoline & vector table scan: scans once for `JMP target.L` (`$4EF9`)
//     trampoline arrays and `BRA.W`/`RTS` vector tables in CODE segments.
//  4. Candidate code validation (`ConfHigh`): sandbox-validates addresses referenced via
//     `HUNK_RELOC32` or `LEA`/`PEA` (`RefDataAddr`) that were not directly read as data.
//  5. Monotonic gap sweep & prologue reclaim (`ConfMedium`): scans remaining unmapped CODE
//     gaps at gap heads or function prologue signatures (`LINK`, `MOVEM.L`), accepting only
//     sequences that pass `validateCandidate`.
//
// Before persisting, step 6 removes any speculative CODE cell that would swallow an interior
// label (`cell.Addr < labelAddr < cell.Addr + cell.Size`), guaranteeing that every label in
// the database aligns with a cell boundary for 100% reassembly parity.
func (a *Analyzer) stage2DiscoverCode(initialEntries []uint32, jumpTable map[uint32]uint32) {
	var worklist []workItem
	var candidateCode []uint32
	codeCells := newCodeBTree()
	visited := make(map[uint32]struct{})
	rejectedCandidates := make(map[uint32]struct{})
	reclaimedPrologues := make(map[uint32]struct{})
	dataReadTargets := make(map[uint32]struct{})
	processedIndirect := make(map[uint32]struct{})
	siteRegs := make(map[uint32]regFile)
	hintedGlobals, hintedBases := a.hintedBaseRegs()

	for _, c := range a.DB.CodeCells() {
		codeCells.ReplaceOrInsert(c)
	}

	const confProtected uint8 = 100
	protected := a.DB.ProtectedNoncodeRanges(confProtected)
	// protected is address-sorted and non-overlapping (ProtectedNoncodeRanges ORDER BY addr),
	// so containment/overlap resolve with a binary search instead of a per-call linear scan.
	isProtected := func(addr uint32) bool {
		return protectedOverlaps(protected, addr, addr+1)
	}
	overlapsProtected := func(addr, size uint32) bool {
		return protectedOverlaps(protected, addr, addr+size)
	}

	for _, addr := range initialEntries {
		if a.IsInCodeSegment(addr) && addr%2 == 0 {
			a.AddLabel(nil, addr)
			labelName := a.GetOrDefaultLabel(addr)
			_ = a.DB.InsertFunction(addr, labelName, ConfDefinite)
			worklist = append(worklist, workItem{addr: addr, confidence: ConfDefinite})
		}
	}

	var relocCodeTargets []uint32
	for t := range a.RelocTargets {
		if a.IsInCodeSegment(t) && t%2 == 0 {
			relocCodeTargets = append(relocCodeTargets, t)
		}
	}
	slices.Sort(relocCodeTargets)
	candidateCode = append(candidateCode, relocCodeTargets...)

	a.DB.Begin()

	tablesScanned := false
	scanCursors := make([]uint32, len(a.Segments))
	for i, s := range a.Segments {
		scanCursors[i] = s.Base
	}

	for {
		// 1. Drain definite worklist
		for len(worklist) > 0 {
			item := worklist[0]
			worklist = worklist[1:]
			startAddr := item.addr
			confidence := item.confidence

			if _, seen := visited[startAddr]; seen || !a.IsInCodeSegment(startAddr) || startAddr%2 != 0 {
				continue
			}
			if overlapsExistingCode(codeCells, startAddr, 2) {
				continue
			}
			if isProtected(startAddr) {
				continue
			}

			addr := startAddr
			blockRegs := hintedGlobals
			for {
				if _, seen := visited[addr]; seen || hasCodeCell(codeCells, addr) {
					break
				}
				if isProtected(addr) {
					break
				}
				insn, ok := a.DecodeValidInsn(addr, false)
				if !ok {
					break
				}
				size := uint32(insn.Size)
				if overlapsProtected(addr, size) {
					break
				}
				if overlapsExistingCode(codeCells, addr, size) {
					break
				}

				visited[addr] = struct{}{}

				for opIdx := uint8(0); opIdx < insn.NumOps; opIdx++ {
					op := insn.Ops[opIdx]
					ref, hasRef := a.ClassifyReference(addr, &insn, op, int(opIdx))
					if !hasRef {
						continue
					}
					src := addr
					switch ref.Kind {
					case RefCodeCall:
						target := ref.Target
						_ = a.DB.InsertXref(addr, target, db.XrefCodeCall)
						_ = a.DB.InsertEdge(addr, target, db.EdgeCall)
						a.AddLabel(&src, target)
						if a.IsInCodeSegment(target) {
							labelName := a.GetOrDefaultLabel(target)
							_ = a.DB.InsertFunction(target, labelName, confidence)
							if _, seen := visited[target]; !seen {
								worklist = append(worklist, workItem{addr: target, confidence: confidence})
							}
						}

					case RefCodeBranch:
						target := ref.Target
						_ = a.DB.InsertXref(addr, target, db.XrefCodeBranch)
						if ref.IsConditional {
							_ = a.DB.InsertEdge(addr, target, db.EdgeCondTrue)
							_ = a.DB.InsertEdge(addr, addr+size, db.EdgeCondFalse)
						} else {
							_ = a.DB.InsertEdge(addr, target, db.EdgeUncond)
						}
						a.AddLabel(&src, target)
						if a.IsInCodeSegment(target) {
							if _, seen := visited[target]; !seen {
								worklist = append(worklist, workItem{addr: target, confidence: confidence})
							}
						}

					case RefDataAddr:
						target := ref.Target
						_ = a.DB.InsertXref(addr, target, db.XrefDataAddr)
						a.AddLabel(&src, target)
						if a.IsInCodeSegment(target) && target%2 == 0 {
							candidateCode = append(candidateCode, target)
						}

					case RefDataRead:
						target := ref.Target
						_ = a.DB.InsertXref(addr, target, db.XrefDataRead)
						a.AddLabel(&src, target)
						dataReadTargets[target] = struct{}{}

					case RefDataWrite:
						target := ref.Target
						_ = a.DB.InsertXref(addr, target, db.XrefDataWrite)
						a.AddLabel(&src, target)
						dataReadTargets[target] = struct{}{}

					case RefIndirect:
						if _, proc := processedIndirect[addr]; !proc {
							siteRegs[addr] = blockRegs
							a.IndirectSites = append(a.IndirectSites, addr)
						}
					}
				}

				a.stepInsn(addr, &insn, &blockRegs, &hintedGlobals)

				mnemCopy := insn.FullMnemonic()
				codeCells.ReplaceOrInsert(db.Cell{
					Seg:        a.DB.SegOf(addr),
					Addr:       addr,
					Size:       size,
					Type:       db.CellCode,
					Confidence: confidence,
					Mnemonic:   &mnemCopy,
					RawBytes:   a.ReadBytes(addr, int(size)),
				})

				if !insn.IsConditionalBranch() && !insn.IsTerminator() {
					_ = a.DB.InsertEdge(addr, addr+size, db.EdgeFallthrough)
				}
				if insn.IsTerminator() {
					break
				}
				addr += size
			}
		}

		// 2. Resolve PC-relative and register-indirect jump/dispatch sites
		sites := a.IndirectSites
		a.IndirectSites = nil
		for _, siteAddr := range sites {
			if _, proc := processedIndirect[siteAddr]; proc {
				continue
			}
			processedIndirect[siteAddr] = struct{}{}
			if targets, ok := a.resolveJumpTable(siteAddr, siteRegs[siteAddr], jumpTable, codeCells, dataReadTargets); ok {
				for _, target := range targets {
					if _, seen := visited[target]; !seen {
						worklist = append(worklist, workItem{addr: target, confidence: ConfHigh})
					}
				}
			}
		}
		if len(worklist) > 0 {
			continue
		}

		// 3. Scan once for contiguous JMP target.L trampolines and BRA.W / RTS vector tables
		if !tablesScanned {
			tablesScanned = true
			trampTargets := a.resolveTrampolineTables(codeCells)
			for _, t := range trampTargets {
				if _, seen := visited[t]; !seen {
					worklist = append(worklist, workItem{addr: t, confidence: ConfHigh})
				}
			}
			vecTargets := a.resolveVectorTables(codeCells)
			for _, t := range vecTargets {
				if _, seen := visited[t]; !seen {
					worklist = append(worklist, workItem{addr: t, confidence: ConfHigh})
				}
			}
			if len(worklist) > 0 {
				continue
			}
		}

		// 4. Sandbox-validate queued candidateCode targets
		addedFromCandidates := false
		for len(candidateCode) > 0 {
			cand := candidateCode[0]
			candidateCode = candidateCode[1:]
			if _, seen := visited[cand]; seen || hasCodeCell(codeCells, cand) {
				continue
			}
			if _, isData := dataReadTargets[cand]; isData {
				continue
			}
			if _, rej := rejectedCandidates[cand]; rej || isProtected(cand) {
				continue
			}
			if ok, suspect := a.validateCandidate(cand, codeCells, dataReadTargets, protected, hintedBases); ok {
				conf := ConfHigh
				if suspect {
					conf = ConfMedium
				}
				a.AddLabel(nil, cand)
				labelName := a.GetOrDefaultLabel(cand)
				_ = a.DB.InsertFunction(cand, labelName, conf)
				worklist = append(worklist, workItem{addr: cand, confidence: conf})
				addedFromCandidates = true
				break
			}
			rejectedCandidates[cand] = struct{}{}
		}
		if addedFromCandidates {
			continue
		}

		// 5. Sandbox-validated gap sweep across all Code segments
		gapEntries := a.scanCodeGapsForCandidates(codeCells, dataReadTargets, rejectedCandidates, scanCursors, protected, hintedBases)
		if len(gapEntries) > 0 {
			for _, addr := range gapEntries {
				a.AddLabel(nil, addr)
				labelName := a.GetOrDefaultLabel(addr)
				_ = a.DB.InsertFunction(addr, labelName, ConfMedium)
				worklist = append(worklist, workItem{addr: addr, confidence: ConfMedium})
			}
			continue
		}

		// 5.5 Prologue-DATA reclaim
		if addr, ok := a.findPrologueDataToReclaim(codeCells, dataReadTargets, reclaimedPrologues, protected, hintedBases); ok {
			_ = a.DB.ClearOverlaps(addr, 2)
			a.AddLabel(nil, addr)
			labelName := a.GetOrDefaultLabel(addr)
			_ = a.DB.InsertFunction(addr, labelName, ConfMedium)
			worklist = append(worklist, workItem{addr: addr, confidence: ConfMedium})
			continue
		}

		break
	}

	// 6. Verify no CODE cell swallows an interior label in `labels`
	allLabelAddrs := a.DB.LabelAddrs(nil)
	var invalidCodeAddrs []uint32
	codeCells.Ascend(func(cell db.Cell) bool {
		cEnd := cell.Addr + cell.Size
		idx, _ := slices.BinarySearch(allLabelAddrs, cell.Addr+1)
		if idx < len(allLabelAddrs) && allLabelAddrs[idx] < cEnd {
			invalidCodeAddrs = append(invalidCodeAddrs, cell.Addr)
		}
		return true
	})
	for _, cAddr := range invalidCodeAddrs {
		codeCells.Delete(db.Cell{Addr: cAddr})
	}

	// 7. Persist all verified non-overlapping CODE cells to SQLite
	_ = a.DB.DeleteCodeCells()
	codeCells.Ascend(func(cell db.Cell) bool {
		if overlapsProtected(cell.Addr, cell.Size) {
			return true
		}
		cp := cell
		_ = a.DB.InsertCell(&cp)
		return true
	})

	a.DB.Commit()
}

// validateCandidate performs a linear sandbox dry-run from start to determine whether
// an unreferenced address is genuine M68000 code rather than data bytes that happen to
// decode as instructions.
//
// A candidate is accepted (ok == true) only if it decodes cleanly (`strictSandbox = true`)
// without overlapping protected ranges, data-read targets, interior labels, or
// mid-instruction code cells until it either merges into an already-verified CODE cell,
// reaches a valid block terminator (`RTS`/`RTE`/`RTR`/`JMP`/`BRA`), or survives 500
// consecutive valid instructions.
//
// suspect is an advisory liveness tie-breaker (ANALYZER_HEURISTICS_SPEC.md §3.7): it is set
// when an early instruction dereferences an address register as a memory base before that
// register is written within the candidate window, and the register is neither a hinted
// global base nor a7 (the stack pointer). This signals data-that-decodes-as-code and lets
// callers demote confidence; it NEVER rejects a candidate (ok is unaffected).
func (a *Analyzer) validateCandidate(
	start uint32,
	codeCells *btree.BTreeG[db.Cell],
	dataReadTargets map[uint32]struct{},
	protected []db.AddrRange,
	hintedBases [8]bool,
) (ok bool, suspect bool) {
	if !a.IsInCodeSegment(start) || start%2 != 0 {
		return false, false
	}
	if overlapsExistingCode(codeCells, start, 2) {
		return false, false
	}

	var written [8]bool // address registers written so far within the window
	addr := start
	count := 0
	for {
		if addr != start && hasCodeCell(codeCells, addr) {
			return true, suspect
		}
		if _, isData := dataReadTargets[addr]; isData {
			return false, false
		}
		insn, ok := a.DecodeValidInsn(addr, true)
		if !ok {
			return false, false
		}
		size := uint32(insn.Size)
		iEnd := addr + size
		if protectedOverlaps(protected, addr, iEnd) {
			return false, false
		}
		if addr != start {
			midOverlap := false
			codeCells.AscendRange(db.Cell{Addr: addr + 1}, db.Cell{Addr: iEnd}, func(c db.Cell) bool {
				if c.Addr < iEnd {
					midOverlap = true
				}
				return false
			})
			if midOverlap {
				return false, false
			}
		}
		for inner := addr + 1; inner < iEnd; inner++ {
			if _, isData := dataReadTargets[inner]; isData {
				return false, false
			}
			if _, hasLbl := a.LabelsCache[inner]; hasLbl {
				return false, false
			}
		}

		// Liveness tie-breaker: a dereference through an address-register base that was never
		// written in-window (and is not a hinted global or a7) looks like data.
		var postPreMask m68k.RegMask
		for _, op := range insn.Operands() {
			if op.Reg > 7 {
				continue
			}
			if op.Mode == m68k.EAPostInc || op.Mode == m68k.EAPreDec {
				postPreMask |= m68k.RegA(op.Reg)
			}
			if !suspect {
				switch op.Mode {
				case m68k.EAAddrInd, m68k.EADisp16, m68k.EAIndex, m68k.EAPostInc, m68k.EAPreDec:
					if (op.Access&(m68k.AccessRead|m68k.AccessWrite)) != 0 && !written[op.Reg] &&
						op.Reg != 7 && !hintedBases[op.Reg] {
						suspect = true
					}
				}
			}
		}
		// Record address-register writes for subsequent use-before-def checks (excluding bare
		// (An)+ / -(An) self-updates, which require An to already be live).
		initWriteMask := insn.WriteRegs &^ postPreMask
		if insn.NumOps >= 2 {
			dst := insn.Ops[insn.NumOps-1]
			if dst.Mode == m68k.EAAddrReg && dst.Reg < 8 {
				initWriteMask |= m68k.RegA(dst.Reg)
			}
		}
		for r := uint8(0); r < 8; r++ {
			if (initWriteMask & m68k.RegA(r)) != 0 {
				written[r] = true
			}
		}

		if insn.IsReturn() || insn.IsUnconditionalJump() {
			return true, suspect
		}

		addr += size
		count++
		if count > 500 {
			return true, suspect
		}
	}
}

// findPrologueDataToReclaim inspects low-confidence DATA cells for classic M68000
// subroutine prologues (`LINK A5,#imm` $4E55, `LINK A6,#imm` $4E56, `MOVEM.L regs,-(SP)` $48E7)
// that have no incoming data XREFs or relocations and pass `validateCandidate`.
// isMovemToPredecA7 reports whether insn is `MOVEM.x reglist,-(a7)` (a register-save
// subroutine prologue), identified semantically rather than by opcode literal so every
// register-list mask matches (not just the common `$48E7`).
func isMovemToPredecA7(insn *m68k.Insn) bool {
	if insn.Op != m68k.OpMOVEM || insn.NumOps < 2 {
		return false
	}
	dst := insn.Ops[insn.NumOps-1]
	return dst.Mode == m68k.EAPreDec && dst.Reg == 7
}

// isDefinitePrologueAt decodes the instruction at addr and reports whether it is a
// definite M68000 subroutine prologue: `LINK An,#disp` or `MOVEM.x reglist,-(a7)`.
func (a *Analyzer) isDefinitePrologueAt(addr uint32) bool {
	raw := a.ReadBytes(addr, 10)
	if len(raw) < 2 {
		return false
	}
	insn, ok := m68k.Decode(raw, addr)
	if !ok {
		return false
	}
	return insn.Op == m68k.OpLINK || isMovemToPredecA7(&insn)
}

func (a *Analyzer) findPrologueDataToReclaim(
	codeCells *btree.BTreeG[db.Cell],
	dataReadTargets map[uint32]struct{},
	already map[uint32]struct{},
	protected []db.AddrRange,
	hintedBases [8]bool,
) (uint32, bool) {
	candidates := a.DB.DataCellsOrdered()
	for _, c := range candidates {
		addr := c.Start
		if _, seen := already[addr]; seen {
			continue
		}
		if !a.IsInCodeSegment(addr) || addr%2 != 0 {
			continue
		}
		if _, ok := a.ReadU16(addr); !ok {
			continue
		}
		if !a.isDefinitePrologueAt(addr) {
			continue
		}
		already[addr] = struct{}{}
		if cell, err := a.DB.GetCell(addr); err == nil && cell != nil && cell.Confidence >= 100 {
			continue
		}
		if _, hasReloc := a.Relocs[addr]; hasReloc {
			continue
		}
		if _, isData := dataReadTargets[addr]; isData {
			continue
		}
		if a.DB.HasDataXref(addr) {
			continue
		}
		if ok, _ := a.validateCandidate(addr, codeCells, dataReadTargets, protected, hintedBases); ok {
			return addr, true
		}
	}
	return 0, false
}

// scanCodeGapsForCandidates advances per-segment monotonic cursors across unmapped gaps
// in CODE segments, probing addresses that either immediately follow a previous code block
// (with optional 2-byte zero alignment padding) or begin with a common subroutine prologue.
// It returns as soon as the first valid candidate per segment is found so the main worklist
// can trace its full call/branch closure before scanning further.
func (a *Analyzer) scanCodeGapsForCandidates(
	codeCells *btree.BTreeG[db.Cell],
	dataReadTargets map[uint32]struct{},
	rejectedCandidates map[uint32]struct{},
	scanCursors []uint32,
	protected []db.AddrRange,
	hintedBases [8]bool,
) []uint32 {
	var discovered []uint32

	for segIdx, seg := range a.Segments {
		if seg.HunkType != hunk.HunkTypeCode {
			continue
		}
		addr := scanCursors[segIdx]
		if addr%2 != 0 {
			addr++
		}

		for addr+2 <= seg.End {
			var coveringEnd uint32
			codeCells.DescendLessOrEqual(db.Cell{Addr: addr}, func(c db.Cell) bool {
				if c.Addr+c.Size > addr {
					coveringEnd = c.Addr + c.Size
				}
				return false
			})
			if coveringEnd > addr {
				addr = coveringEnd
				if addr%2 != 0 {
					addr++
				}
				scanCursors[segIdx] = addr
				continue
			}

			if _, rej := rejectedCandidates[addr]; rej {
				addr += 2
				scanCursors[segIdx] = addr
				continue
			}
			if _, isData := dataReadTargets[addr]; isData {
				addr += 2
				scanCursors[segIdx] = addr
				continue
			}
			w0, ok := a.ReadU16(addr)
			if !ok || w0 == 0 || w0 == 0xFFFF {
				addr += 2
				scanCursors[segIdx] = addr
				continue
			}

			prevCodeEnd := seg.Base
			if addr > 0 {
				codeCells.DescendLessOrEqual(db.Cell{Addr: addr - 1}, func(c db.Cell) bool {
					if c.Addr >= seg.Base {
						prevCodeEnd = c.Addr + c.Size
					}
					return false
				})
			}

			_, prevIsData := dataReadTargets[prevCodeEnd]
			prevWord, prevOk := a.ReadU16(prevCodeEnd)
			isGapHead := addr == prevCodeEnd || (addr == prevCodeEnd+2 && !prevIsData && prevOk && prevWord == 0)

			isPrologue := a.isDefinitePrologueAt(addr) ||
				(w0&0xFFF0) == 0x2F00 ||
				w0 == 0x6100 ||
				w0 == 0x4EB9

			if isGapHead || isPrologue {
				if ok, _ := a.validateCandidate(addr, codeCells, dataReadTargets, protected, hintedBases); ok {
					scanCursors[segIdx] = addr + 2
					discovered = append(discovered, addr)
					break
				}
				rejectedCandidates[addr] = struct{}{}
			}

			addr += 2
			scanCursors[segIdx] = addr
		}
	}

	return discovered
}

// resolveTrampolineTables scans CODE segments for contiguous runs of two or more
// `JMP target.L` (`$4EF9`) trampoline entries (common in Amiga library vector tables
// and overlay thunks) and returns their target addresses as high-confidence code seeds.
func (a *Analyzer) resolveTrampolineTables(codeCells *btree.BTreeG[db.Cell]) []uint32 {
	var discoveredTargets []uint32
	hunkMode := len(a.Relocs) > 0

	for _, seg := range a.Segments {
		if seg.HunkType != hunk.HunkTypeCode {
			continue
		}
		segBase := seg.Base
		segEnd := seg.End
		addr := segBase

		for addr+12 <= segEnd {
			if hasCodeCell(codeCells, addr) {
				addr += 2
				continue
			}
			w0, ok0 := a.ReadU16(addr)
			w6, ok6 := a.ReadU16(addr + 6)
			if ok0 && w0 == 0x4EF9 && !hasCodeCell(codeCells, addr+6) && ok6 && w6 == 0x4EF9 {
				curAddr := addr
				for curAddr+6 <= segEnd && !hasCodeCell(codeCells, curAddr) {
					wCur, okCur := a.ReadU16(curAddr)
					if !okCur || wCur != 0x4EF9 {
						break
					}
					var targetAddr uint32
					if hunkMode {
						t, ok := a.Relocs[curAddr+2]
						if !ok {
							break
						}
						targetAddr = t
					} else {
						t, ok := a.ReadU32(curAddr + 2)
						if !ok || !a.isValidTarget(t) {
							break
						}
						targetAddr = t
					}

					b := a.ReadBytes(curAddr, 6)
					if len(b) != 6 {
						break
					}
					mnem := "jmp"
					codeCells.ReplaceOrInsert(db.Cell{
						Seg:        a.DB.SegOf(curAddr),
						Addr:       curAddr,
						Size:       6,
						Type:       db.CellCode,
						Confidence: ConfHigh,
						Mnemonic:   &mnem,
						RawBytes:   b,
					})

					_ = a.DB.InsertXref(curAddr, targetAddr, db.XrefCodeBranch)
					_ = a.DB.InsertEdge(curAddr, targetAddr, db.EdgeUncond)
					src := curAddr
					a.AddLabel(&src, targetAddr)

					if a.IsInCodeSegment(targetAddr) {
						labelName := a.GetOrDefaultLabel(targetAddr)
						_ = a.DB.InsertFunction(targetAddr, labelName, ConfHigh)
						discoveredTargets = append(discoveredTargets, targetAddr)
					}

					curAddr += 6
				}
				if curAddr > addr {
					addr = curAddr
					continue
				}
			}
			addr += 2
		}
	}

	return discoveredTargets
}

// resolveVectorTables scans CODE segments for contiguous jump-vector tables composed of
// `BRA.W disp16` (`$6000`) and `RTS` (`$4E75`, optionally padded with `$0000`) entries.
func (a *Analyzer) resolveVectorTables(codeCells *btree.BTreeG[db.Cell]) []uint32 {
	var discoveredTargets []uint32

	for _, seg := range a.Segments {
		if seg.HunkType != hunk.HunkTypeCode {
			continue
		}
		segBase := seg.Base
		segEnd := seg.End
		addr := segBase

		for addr+8 <= segEnd {
			if hasCodeCell(codeCells, addr) {
				addr += 2
				continue
			}
			len1, _, ok1 := a.checkVecEntry(addr, segEnd)
			if ok1 && !hasCodeCell(codeCells, addr+len1) {
				if _, _, ok2 := a.checkVecEntry(addr+len1, segEnd); ok2 {
					curAddr := addr
					for !hasCodeCell(codeCells, curAddr) {
						entLen, maybeDisp, ok := a.checkVecEntry(curAddr, segEnd)
						if !ok {
							break
						}
						if maybeDisp != nil {
							disp := *maybeDisp
							targetAddr := uint32(int64(curAddr) + 2 + int64(disp))
							if !a.IsSameSegment(curAddr, targetAddr) || targetAddr%2 != 0 {
								break
							}
							b := a.ReadBytes(curAddr, 4)
							if len(b) != 4 {
								break
							}
							mnem := "bra.w"
							codeCells.ReplaceOrInsert(db.Cell{
								Seg:        a.DB.SegOf(curAddr),
								Addr:       curAddr,
								Size:       4,
								Type:       db.CellCode,
								Confidence: ConfHigh,
								Mnemonic:   &mnem,
								RawBytes:   b,
							})
							_ = a.DB.InsertXref(curAddr, targetAddr, db.XrefCodeBranch)
							_ = a.DB.InsertEdge(curAddr, targetAddr, db.EdgeUncond)
							src := curAddr
							a.AddLabel(&src, targetAddr)
							labelName := a.GetOrDefaultLabel(targetAddr)
							_ = a.DB.InsertFunction(targetAddr, labelName, ConfHigh)
							discoveredTargets = append(discoveredTargets, targetAddr)
						} else {
							b := a.ReadBytes(curAddr, 2)
							if len(b) != 2 {
								break
							}
							mnem := "rts"
							codeCells.ReplaceOrInsert(db.Cell{
								Seg:        a.DB.SegOf(curAddr),
								Addr:       curAddr,
								Size:       2,
								Type:       db.CellCode,
								Confidence: ConfHigh,
								Mnemonic:   &mnem,
								RawBytes:   b,
							})
						}
						curAddr += entLen
					}
					if curAddr > addr {
						addr = curAddr
						continue
					}
				}
			}
			addr += 2
		}
	}

	return discoveredTargets
}

func (a *Analyzer) checkVecEntry(addr, segEnd uint32) (uint32, *int16, bool) {
	if addr+4 <= segEnd {
		if w, ok := a.ReadU16(addr); ok && w == 0x6000 {
			if disp, ok := a.ReadI16(addr + 2); ok && disp != 0 && disp%2 == 0 {
				return 4, &disp, true
			}
		} else if ok && w == 0x4E75 {
			if w2, ok2 := a.ReadU16(addr + 2); ok2 && w2 == 0x0000 {
				return 4, nil, true
			}
		}
	}
	if addr+2 <= segEnd {
		if w, ok := a.ReadU16(addr); ok && w == 0x4E75 {
			return 2, nil, true
		}
	}
	return 0, nil, false
}

// resolveJumpTable analyzes an indirect jump/call site (`JMP`/`JSR` with `d8(PC,Xn)`,
// `d8(An,Xn)`, `(An)`, or `d16(An)`) at siteAddr using the pre-instruction register
// state `rf` and extracts its target code addresses.
func (a *Analyzer) resolveJumpTable(
	siteAddr uint32,
	rf regFile,
	jumpTable map[uint32]uint32,
	codeCells *btree.BTreeG[db.Cell],
	dataReadTargets map[uint32]struct{},
) ([]uint32, bool) {
	insn, ok := a.DecodeValidInsn(siteAddr, false)
	if !ok {
		return nil, false
	}
	if (insn.Op != m68k.OpJMP && insn.Op != m68k.OpJSR) || insn.NumOps == 0 {
		return nil, false
	}

	isCall := insn.Op == m68k.OpJSR
	op := insn.Ops[0]
	src := siteAddr

	switch op.Mode {
	case m68k.EAPCIndex:
		targets, ok := a.scanIndexedJumpTable(siteAddr, op.UVal, op.IndexReg, codeCells, dataReadTargets)
		if ok {
			for _, t := range targets {
				_ = a.DB.InsertEdge(siteAddr, t, db.EdgeUncond)
				_ = a.DB.InsertXref(siteAddr, t, db.XrefCodeBranch)
			}
		}
		return targets, ok

	case m68k.EAIndex:
		if op.Reg >= 7 || !rf.a[op.Reg].known {
			return nil, false
		}
		tableAddr := uint32(int64(rf.a[op.Reg].val) + int64(op.Disp))
		targets, ok := a.scanIndexedJumpTable(siteAddr, tableAddr, op.IndexReg, codeCells, dataReadTargets)
		if ok {
			for _, t := range targets {
				_ = a.DB.InsertEdge(siteAddr, t, db.EdgeUncond)
				_ = a.DB.InsertXref(siteAddr, t, db.XrefCodeBranch)
			}
		}
		return targets, ok

	case m68k.EAAddrInd:
		if op.Reg >= 7 || !rf.a[op.Reg].known {
			return nil, false
		}
		finalTgt, ok := a.resolveDirectOrSlotTarget(rf.a[op.Reg].val, jumpTable)
		if !ok {
			return nil, false
		}
		a.recordResolvedIndirectTarget(siteAddr, finalTgt, isCall)
		return []uint32{finalTgt}, true

	case m68k.EADisp16:
		if op.Reg >= 7 || !rf.a[op.Reg].known {
			return nil, false
		}
		slotAddr := uint32(int64(rf.a[op.Reg].val) + int64(op.Disp))
		finalTgt, ok := a.resolveSlotOrRelocTarget(slotAddr, jumpTable)
		if !ok {
			return nil, false
		}
		_ = src
		a.recordResolvedIndirectTarget(siteAddr, finalTgt, isCall)
		return []uint32{finalTgt}, true
	}

	return nil, false
}

func (a *Analyzer) recordResolvedIndirectTarget(siteAddr, finalTgt uint32, isCall bool) {
	src := siteAddr
	a.AddLabel(&src, finalTgt)
	if isCall {
		_ = a.DB.InsertEdge(siteAddr, finalTgt, db.EdgeCall)
		_ = a.DB.InsertXref(siteAddr, finalTgt, db.XrefCodeCall)
		labelName := a.GetOrDefaultLabel(finalTgt)
		_ = a.DB.InsertFunction(finalTgt, labelName, ConfHigh)
	} else {
		_ = a.DB.InsertEdge(siteAddr, finalTgt, db.EdgeUncond)
		_ = a.DB.InsertXref(siteAddr, finalTgt, db.XrefCodeBranch)
	}
}

// scanIndexedJumpTable recognizes two standard M68000 compiler switch/dispatch idioms
// at `tableAddr` (shared by both `EAPCIndex` `d8(PC,Xn)` and `EAIndex` `d8(An,Xn)`):
//  1. Inline branch tables: contiguous `BRA.W` (`$6000`, stride 4, or stride 8 when
//     interleaved with 32-bit case keys) or `BRA.B`/`NOP` (`$60xx`/`$4E71`, stride 2) instructions.
//  2. Relative word-offset tables: contiguous 16-bit signed offsets (`dc.w target - tableAddr`)
//     where `tableAddr + offset` lands at an even address inside the same segment.
func (a *Analyzer) scanIndexedJumpTable(
	siteAddr, tableAddr uint32,
	idxReg uint8,
	codeCells *btree.BTreeG[db.Cell],
	dataReadTargets map[uint32]struct{},
) ([]uint32, bool) {
	if !a.IsSameSegment(siteAddr, tableAddr) {
		return nil, false
	}
	src := siteAddr
	a.AddLabel(&src, tableAddr)

	inferredBound, hasBound := a.extractJumpTableBoundsIn(siteAddr, idxReg, codeCells)
	bounds := uint32(64)
	if hasBound {
		bounds = inferredBound
	}
	var targets []uint32
	var minTarget uint32 = 0xFFFFFFFF

	// 1. Check for compiler switch branch tables (bra.w, sparse dc.l+bra.w, or bra.b/nop)
	if w0, ok := a.ReadU16(tableAddr); ok {
		if w0 == 0x6000 {
			_, isSparse := dataReadTargets[tableAddr-4]
			isSparse = isSparse && tableAddr >= 4
			stride := uint32(4)
			if isSparse {
				stride = 8
			}
			for i := uint32(0); i < bounds; i++ {
				entryAddr := tableAddr + i*stride
				if entryAddr >= minTarget || !a.IsSameSegment(tableAddr, entryAddr+2) || hasCodeCell(codeCells, entryAddr) {
					break
				}
				if w, ok := a.ReadU16(entryAddr); !ok || w != 0x6000 {
					break
				}
				disp, ok := a.ReadI16(entryAddr + 2)
				if !ok || disp == 0 || disp%2 != 0 {
					break
				}
				caseTarget := uint32(int64(entryAddr) + 2 + int64(disp))
				if !a.IsSameSegment(tableAddr, caseTarget) || caseTarget%2 != 0 {
					break
				}
				if caseTarget > tableAddr {
					minTarget = min(minTarget, caseTarget)
				}
				if isSparse {
					constAddr := entryAddr - 4
					dataReadTargets[constAddr] = struct{}{}
					dataReadTargets[constAddr+2] = struct{}{}
				}
				targets = append(targets, entryAddr)
			}
			if len(targets) > 0 {
				return targets, true
			}
		} else if (w0&0xFF00) == 0x6000 && (w0&0x00FF) != 0 && (w0&0x00FF) != 0xFF {
			for i := uint32(0); i < bounds; i++ {
				entryAddr := tableAddr + i*2
				if entryAddr >= minTarget || !a.IsSameSegment(tableAddr, entryAddr) || hasCodeCell(codeCells, entryAddr) {
					break
				}
				w, ok := a.ReadU16(entryAddr)
				if !ok {
					break
				}
				if (w & 0xFF00) == 0x6000 {
					disp8 := int8(uint8(w & 0x00FF))
					if disp8 == 0 || disp8 == -1 || disp8%2 != 0 {
						break
					}
					caseTarget := uint32(int64(entryAddr) + 2 + int64(disp8))
					if !a.IsSameSegment(tableAddr, caseTarget) || caseTarget%2 != 0 {
						break
					}
					if caseTarget > tableAddr {
						minTarget = min(minTarget, caseTarget)
					}
					targets = append(targets, entryAddr)
				} else if w == 0x4E71 {
					caseTarget := entryAddr + 2
					if !a.IsSameSegment(tableAddr, caseTarget) {
						break
					}
					minTarget = min(minTarget, caseTarget)
					targets = append(targets, entryAddr)
				} else {
					break
				}
			}
			if len(targets) > 0 {
				return targets, true
			}
		}
	}

	// 2. Check for 16-bit relative offset data table (dc.w target - table_addr)
	dataBounds := uint32(16)
	if hasBound {
		dataBounds = inferredBound
	}
	if firstWord, ok := a.ReadI16(tableAddr); ok {
		firstTarget := uint32(int64(tableAddr) + int64(firstWord))
		if a.IsSameSegment(tableAddr, firstTarget) && firstTarget%2 == 0 && firstTarget > tableAddr {
			for i := uint32(0); i < dataBounds; i++ {
				entryAddr := tableAddr + i*2
				if entryAddr >= minTarget || !a.IsSameSegment(tableAddr, entryAddr) || hasCodeCell(codeCells, entryAddr) {
					break
				}
				offset, ok := a.ReadI16(entryAddr)
				if !ok || offset <= 0 {
					break
				}
				target := uint32(int64(tableAddr) + int64(offset))
				if !a.IsSameSegment(tableAddr, target) || target%2 != 0 {
					break
				}
				minTarget = min(minTarget, target)
				dataReadTargets[entryAddr] = struct{}{}
				a.AddLabel(&src, target)
				targets = append(targets, target)
			}
			if len(targets) > 0 {
				return targets, true
			}
		}
	}

	return nil, false
}

// extractJumpTableBounds scans backward before siteAddr for a range-check
// `CMP`/`CMPI #maxIdx,Dn` or mask `AND`/`ANDI #mask,Dn` instruction to bound the number
// of entries in a jump table.
func (a *Analyzer) extractJumpTableBounds(siteAddr uint32, idxReg uint8) (uint32, bool) {
	return a.extractJumpTableBoundsIn(siteAddr, idxReg, nil)
}

// extractJumpTableBoundsIn scans up to 10 preceding instructions before siteAddr for a
// range-check `CMP`/`CMPI #maxIdx,Dn` or mask `AND`/`ANDI #mask,Dn` instruction that
// constrains the dispatch's index register (following one-hop `MOVE.W d8(pc/An,Xn),Dm`
// offset-table provenance). When `codeCells` contains the decoded predecessor cells
// before `siteAddr`, the scan walks exact instruction boundaries in `codeCells` so
// interior extension words are never mis-decoded as instructions.
func (a *Analyzer) extractJumpTableBoundsIn(siteAddr uint32, idxReg uint8, codeCells *btree.BTreeG[db.Cell]) (uint32, bool) {
	seg := a.SegmentAt(siteAddr)
	if seg == nil || idxReg >= 8 {
		return 0, false
	}

	if codeCells != nil && siteAddr > seg.Base {
		trackReg := idxReg
		expectedEnd := siteAddr
		steps := 0
		walkedCells := false
		var bound uint32
		matched := false

		codeCells.DescendLessOrEqual(db.Cell{Addr: siteAddr - 1}, func(c db.Cell) bool {
			if c.Addr < seg.Base || c.Addr+c.Size != expectedEnd || steps >= 10 {
				return false
			}
			walkedCells = true
			expectedEnd = c.Addr
			steps++
			raw := c.RawBytes
			if len(raw) < 2 {
				raw = a.ReadBytes(c.Addr, int(c.Size))
			}
			insn, ok := m68k.Decode(raw, c.Addr)
			if !ok {
				return false
			}
			b, m, stop := stepJumpTableBoundInsn(&insn, &trackReg)
			if m {
				bound = b
				matched = true
				return false
			}
			return !stop
		})
		if walkedCells {
			return bound, matched
		}
	}

	trackReg := idxReg
	addr := siteAddr
	for step := 0; step < 10; step++ {
		if addr <= seg.Base+2 {
			break
		}
		addr -= 2
		chunk := a.ReadBytes(addr, 10)
		if len(chunk) < 2 {
			continue
		}
		insn, ok := m68k.Decode(chunk, addr)
		if !ok {
			continue
		}
		b, m, stop := stepJumpTableBoundInsn(&insn, &trackReg)
		if m {
			return b, true
		}
		if stop {
			return 0, false
		}
	}
	return 0, false
}

func stepJumpTableBoundInsn(insn *m68k.Insn, trackReg *uint8) (bound uint32, matched, stop bool) {
	switch insn.Op {
	case m68k.OpCMP, m68k.OpCMPI:
		if opConstrainsDataReg(insn, *trackReg) {
			for _, op := range insn.Operands() {
				if op.Mode == m68k.EAImm && op.UVal <= 256 {
					return op.UVal + 1, true, true
				}
			}
		}
	case m68k.OpAND, m68k.OpANDI:
		if opConstrainsDataReg(insn, *trackReg) {
			for _, op := range insn.Operands() {
				if op.Mode == m68k.EAImm && op.UVal >= 2 && op.UVal <= 512 && op.UVal%2 == 0 {
					return (op.UVal / 2) + 1, true, true
				}
			}
		}
	case m68k.OpMOVE:
		// Single-hop index-provenance follow: move.w d8(pc/An,Xn),Dm where Dm is the
		// tracked index retargets tracking to the source's index register Xn.
		if insn.Suffix != m68k.SizeW || insn.NumOps < 2 {
			return 0, false, false
		}
		srcOp := insn.Ops[0]
		dstOp := insn.Ops[1]
		if dstOp.Mode != m68k.EADataReg || dstOp.Reg != *trackReg {
			return 0, false, false
		}
		if srcOp.Mode != m68k.EAPCIndex && srcOp.Mode != m68k.EAIndex {
			return 0, false, false
		}
		if srcOp.IndexReg >= 8 {
			// Index is an address register; cannot be bounded by CMP/AND Dn.
			return 0, false, true
		}
		*trackReg = srcOp.IndexReg
	}
	return 0, false, false
}

// opConstrainsDataReg reports whether insn has data register Dn (0..7) as a direct
// (`EADataReg`) operand — i.e. the register the CMP/AND bounds.
func opConstrainsDataReg(insn *m68k.Insn, dn uint8) bool {
	for _, op := range insn.Operands() {
		if op.Mode == m68k.EADataReg && op.Reg == dn {
			return true
		}
	}
	return false
}
