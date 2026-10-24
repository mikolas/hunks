package analyzer

import (
	"fmt"

	"github.com/mikolas/hunks/internal/amiga"
	"github.com/mikolas/hunks/internal/db"
	"github.com/mikolas/hunks/internal/hunk"
	"github.com/mikolas/hunks/internal/m68k"
	"github.com/mikolas/hunks/internal/project"
)

type regKnown struct {
	known bool
	val   uint32 // meaningful iff known
}

type regFile struct {
	a [8]regKnown // a0..a7
	d [8]regKnown // d0..d7 (populated for small immediates / masks)
}

func (rf *regFile) clobberMask(mask m68k.RegMask) {
	if mask == 0 {
		return
	}
	for r := uint8(0); r < 8; r++ {
		if (mask & m68k.RegD(r)) != 0 {
			rf.d[r] = regKnown{}
		}
		if (mask & m68k.RegA(r)) != 0 {
			rf.a[r] = regKnown{}
		}
	}
}

type regDefKind uint8

const (
	defNone regDefKind = iota
	defAddr
	defData
)

// stepInsn applies the per-instruction register transfer function (define -> clobber ->
// commit -> call-clobber -> terminator-reset) after operands have been resolved against
// the pre-instruction state.
func (a *Analyzer) stepInsn(addr uint32, insn *m68k.Insn, rf *regFile, globalBase *regFile) {
	defKind, defReg, defVal := a.evalRegDef(addr, insn, rf)

	rf.clobberMask(insn.WriteRegs)

	switch defKind {
	case defAddr:
		rf.a[defReg] = regKnown{known: true, val: defVal}
	case defData:
		rf.d[defReg] = regKnown{known: true, val: defVal}
	}

	if insn.Op == m68k.OpBSR || insn.Op == m68k.OpJSR {
		rf.d[0] = regKnown{}
		rf.d[1] = regKnown{}
		rf.a[0] = globalBase.a[0]
		rf.a[1] = globalBase.a[1]
	}

	if insn.IsTerminator() {
		*rf = *globalBase
	}
}

func (a *Analyzer) evalRegDef(addr uint32, insn *m68k.Insn, rf *regFile) (regDefKind, uint8, uint32) {
	if insn.NumOps < 2 {
		return defNone, 0, 0
	}
	op0 := insn.Ops[0]
	dstOp := insn.Ops[insn.NumOps-1]

	switch insn.Op {
	case m68k.OpLEA:
		if dstOp.Mode != m68k.EAAddrReg || dstOp.Reg >= 8 {
			return defNone, 0, 0
		}
		if reg, val, ok := a.decodeConstAregLoad(addr, insn); ok {
			return defAddr, reg, val
		}
		if op0.Mode == m68k.EADisp16 && op0.Reg < 8 && rf.a[op0.Reg].known {
			return defAddr, dstOp.Reg, uint32(int64(rf.a[op0.Reg].val) + int64(op0.Disp))
		}

	case m68k.OpMOVEA:
		if dstOp.Mode != m68k.EAAddrReg || dstOp.Reg >= 8 {
			return defNone, 0, 0
		}
		if reg, val, ok := a.decodeConstAregLoad(addr, insn); ok {
			return defAddr, reg, val
		}
		if insn.Suffix == m68k.SizeL && op0.Mode == m68k.EAAddrReg && op0.Reg < 8 && rf.a[op0.Reg].known {
			return defAddr, dstOp.Reg, rf.a[op0.Reg].val
		}

	case m68k.OpMOVEQ:
		if op0.Mode == m68k.EAImm && dstOp.Mode == m68k.EADataReg && dstOp.Reg < 8 {
			return defData, dstOp.Reg, op0.UVal
		}

	case m68k.OpADDQ, m68k.OpSUBQ:
		if op0.Mode != m68k.EAImm {
			return defNone, 0, 0
		}
		if dstOp.Mode == m68k.EAAddrReg && dstOp.Reg < 8 && rf.a[dstOp.Reg].known {
			val := rf.a[dstOp.Reg].val + op0.UVal
			if insn.Op == m68k.OpSUBQ {
				val = rf.a[dstOp.Reg].val - op0.UVal
			}
			return defAddr, dstOp.Reg, val
		}
		if dstOp.Mode == m68k.EADataReg && dstOp.Reg < 8 && rf.d[dstOp.Reg].known {
			val := rf.d[dstOp.Reg].val + op0.UVal
			if insn.Op == m68k.OpSUBQ {
				val = rf.d[dstOp.Reg].val - op0.UVal
			}
			return defData, dstOp.Reg, val
		}
	}
	return defNone, 0, 0
}

// seedJumpTableTargets scans `HUNK_RELOC32` entries inside `DATA` segments for 6-byte
// `JMP target.L` (`$4EF9`) jump-vector slots (used by SAS/C, Aztec C, and overlay managers
// to dispatch cross-hunk calls via `jsr d16(a5)`). Each discovered target is registered
// as an exported code entry point and returned in a `slotAddr -> targetAddr` map.
func (a *Analyzer) seedJumpTableTargets() map[uint32]uint32 {
	slotToTarget := make(map[uint32]uint32)
	for site, target := range a.Relocs {
		slot := site - 2
		seg := a.SegmentAt(slot)
		if seg == nil || seg.HunkType != hunk.HunkTypeData {
			continue
		}
		w, ok := a.ReadU16(slot)
		if !ok || w != 0x4EF9 {
			continue
		}
		if !a.IsInCodeSegment(target) {
			continue
		}
		slotToTarget[slot] = target
	}

	if len(slotToTarget) > 0 {
		a.DB.Begin()
		for _, target := range slotToTarget {
			aligned := target & ^uint32(1)
			if aligned != target {
				continue
			}
			name := a.GetOrDefaultLabel(aligned)
			segName := ""
			if seg := a.SegmentAt(aligned); seg != nil {
				segName = seg.Name
			}
			hasEP := false
			for _, ep := range a.Proj.Data.EntryPoints {
				if ep.Addr == aligned {
					hasEP = true
					break
				}
			}
			if !hasEP {
				a.Proj.Data.EntryPoints = append(a.Proj.Data.EntryPoints, project.EntryPoint{
					Addr:    aligned,
					Name:    name,
					Segment: segName,
				})
			}
			a.LabelsCache[aligned] = name
			a.ExportedCache[aligned] = struct{}{}
			_ = a.DB.SetLabelExported(aligned, name, db.LabelLab, true, true)
		}
		a.DB.Commit()
	}
	return slotToTarget
}

// hintedBaseRegs returns the user-hinted global base-register state (from `hint base-reg`)
// as a seed regFile, plus a per-register mask of which of a0..a6 were explicitly hinted
// (hinted registers are exempt from automatic whole-program promotion).
func (a *Analyzer) hintedBaseRegs() (regFile, [8]bool) {
	var globalBase regFile
	var hinted [8]bool
	if brs, err := a.DB.GetAllBaseRegs(); err == nil {
		for _, br := range brs {
			if br.Source == "hint" && br.ScopeKind == "global" && len(br.Reg) == 2 && br.Reg[0] == 'a' {
				r := br.Reg[1] - '0'
				if r <= 6 {
					hinted[r] = true
					globalBase.a[r] = regKnown{known: true, val: br.BaseAddr}
				}
			}
		}
	}
	return globalBase, hinted
}

func (a *Analyzer) resolveDirectOrSlotTarget(addr uint32, jumpTable map[uint32]uint32) (uint32, bool) {
	if finalTgt, ok := jumpTable[addr]; ok && a.IsInCodeSegment(finalTgt) && finalTgt%2 == 0 {
		return finalTgt, true
	}
	if a.IsInCodeSegment(addr) && addr%2 == 0 {
		return addr, true
	}
	return 0, false
}

func (a *Analyzer) resolveSlotOrRelocTarget(slotAddr uint32, jumpTable map[uint32]uint32) (uint32, bool) {
	if finalTgt, ok := jumpTable[slotAddr]; ok && a.IsInCodeSegment(finalTgt) && finalTgt%2 == 0 {
		return finalTgt, true
	}
	if len(a.Relocs) > 0 {
		if relTgt, ok := a.Relocs[slotAddr]; ok && a.IsInCodeSegment(relTgt) && relTgt%2 == 0 {
			return relTgt, true
		}
	}
	return 0, false
}

// propagateBaseRegs discovers program-wide constant base-register assignments for
// `a0..a6` (unless overridden by user `hint base-reg`), records them in the database,
// and resolves all `d16(An)` accesses across CODE cells.
// A register `aN` (`a0..a6`) is auto-promoted to a global base-register invariant iff
// every constant load into `aN` across the binary agrees on the same target address and
// `aN` has zero non-constant writes (`!sawDynamicWrite[n]`) anywhere in the program.
func (a *Analyzer) propagateBaseRegs(jumpTable map[uint32]uint32) {
	_ = a.DB.ClearAutoBaseRegs()

	globalBase, hinted := a.hintedBaseRegs()

	slots := a.DB.SpaceCellSlots()
	if len(slots) == 0 {
		return
	}
	if a.insnCache != nil && len(a.insnCache) == 0 {
		a.insnCache = make(map[uint32]m68k.Insn, len(slots))
	}

	var firstLoad [8]uint32
	var hasLoad [8]bool
	var sawDynamicWrite [8]bool
	for _, slot := range slots {
		if !slot.IsCode {
			continue
		}
		raw := a.ReadBytes(slot.Addr, 10)
		if len(raw) < 2 {
			continue
		}
		insn, ok := a.decodeCached(slot.Addr, raw)
		if !ok {
			continue
		}
		constReg, val, isConst := a.decodeConstAregLoad(slot.Addr, &insn)
		if isConst {
			if !hasLoad[constReg] {
				firstLoad[constReg] = val
				hasLoad[constReg] = true
			} else if firstLoad[constReg] != val {
				sawDynamicWrite[constReg] = true
			}
		}
		if (insn.WriteRegs & 0xFF00) != 0 {
			for r := uint8(0); r < 7; r++ {
				if (insn.WriteRegs & m68k.RegA(r)) != 0 {
					if !(isConst && constReg == r) {
						sawDynamicWrite[r] = true
					}
				}
			}
		}
	}

	for r := uint8(0); r < 7; r++ {
		if hinted[r] || sawDynamicWrite[r] || !hasLoad[r] {
			continue
		}
		first := firstLoad[r]
		globalBase.a[r] = regKnown{known: true, val: first}
		_ = a.DB.SetBaseReg("global", "", m68k.RegAName(r), first, "auto")
	}

	a.resolveBaseRelativeAccesses(slots, globalBase, jumpTable)
}

func (a *Analyzer) decodeConstAregLoad(addr uint32, insn *m68k.Insn) (uint8, uint32, bool) {
	if insn.Op != m68k.OpLEA && insn.Op != m68k.OpMOVEA {
		return 0, 0, false
	}
	if insn.Op == m68k.OpMOVEA && insn.Suffix != m68k.SizeL {
		return 0, 0, false
	}
	if insn.NumOps < 2 {
		return 0, 0, false
	}
	dstOp := insn.Ops[insn.NumOps-1]
	if dstOp.Mode != m68k.EAAddrReg || dstOp.Reg >= 7 {
		return 0, 0, false
	}

	if len(a.Relocs) > 0 {
		if tgt, ok := a.Relocs[addr+2]; ok {
			return dstOp.Reg, tgt, true
		}
	}
	op0 := insn.Ops[0]
	switch op0.Mode {
	case m68k.EAImm, m68k.EAAbsShort, m68k.EAAbsLong:
		return dstOp.Reg, op0.UVal, true
	case m68k.EAPCDisp16:
		if insn.Op == m68k.OpLEA {
			return dstOp.Reg, op0.UVal, true
		}
	}
	return 0, 0, false
}

// resolveBaseRelativeAccesses walks all cells in address order, maintaining active
// `a0..a6` base values (seeded from `globalBase`, updated by local `LEA`/`MOVEA`/`ADDQ`
// definitions via `stepInsn`, and invalidated on clobbers, scratch call-clobbers, or
// basic-block terminators) to resolve register-base dispatch and displacement addressing:
//  0. Register-indirect calls (`jsr`/`jmp (aN)` where `aN` is a known constant): records a
//     direct `CALL`/`UNCOND` edge and `-> target` comment.
//  1. Indirect jump-vector calls (`jsr`/`jmp d16(aN)` where `base + disp` is a slot in
//     `jumpTable` or a relocated pointer): records a direct `CALL`/`UNCOND` edge and `-> target` comment.
//  2. Custom hardware register accesses (`$DFF000..$DFF1FF` / `$BFE001` / `$BFD000`):
//     appends a `disp(aN) = REGNAME` comment. Importantly, `a.CustomEA` operand
//     substitution (`REGNAME(aN)`) is recorded ONLY when `rv.val == 0xDFF000`, because
//     hardware equates are defined as offsets from `$DFF000`; if a program loads a
//     sub-offset base (e.g. `lea $DFF002,a4`), replacing `disp(a4)` with `REGNAME(a4)`
//     would shift the assembled displacement by `rv.val - $DFF000` and break binary parity.
//  3. Small-data globals (`base + disp` landing in a `DATA` or `BSS` segment): seeds
//     a label at the target and records a `DATA_READ` or `DATA_WRITE` XREF.
func (a *Analyzer) resolveBaseRelativeAccesses(slots []db.CellSlot, globalBase regFile, jumpTable map[uint32]uint32) {
	state := globalBase

	type addrComment struct {
		addr uint32
		frag string
	}
	type globalRef struct {
		site    uint32
		target  uint32
		isWrite bool
	}
	type jtEdge struct {
		site   uint32
		target uint32
		isCall bool
	}
	type customEAEntry struct {
		key  CustomEAKey
		name string
	}

	var comments []addrComment
	var globals []globalRef
	var jtEdges []jtEdge
	var customEAs []customEAEntry

	for _, slot := range slots {
		if !slot.IsCode {
			state = globalBase
			continue
		}
		raw := a.ReadBytes(slot.Addr, 10)
		if len(raw) < 2 {
			continue
		}
		insn, ok := a.decodeCached(slot.Addr, raw)
		if !ok {
			continue
		}

		// Step 1: Use / resolve operands against pre-instruction register state.
		for opIdx := uint8(0); opIdx < insn.NumOps; opIdx++ {
			op := insn.Ops[opIdx]
			if op.Reg >= 7 {
				continue
			}
			rv := state.a[op.Reg]
			if !rv.known {
				continue
			}

			if op.Mode == m68k.EAAddrInd && (insn.Op == m68k.OpJSR || insn.Op == m68k.OpJMP) {
				if finalTgt, ok := a.resolveDirectOrSlotTarget(rv.val, jumpTable); ok {
					isCall := insn.Op == m68k.OpJSR
					jtEdges = append(jtEdges, jtEdge{site: slot.Addr, target: finalTgt, isCall: isCall})
					tname := a.GetOrDefaultLabel(finalTgt)
					comments = append(comments, addrComment{addr: slot.Addr, frag: fmt.Sprintf("-> %s", tname)})
				}
				continue
			}

			if op.Mode != m68k.EADisp16 {
				continue
			}
			baseReg := m68k.RegAName(op.Reg)
			disp := int64(op.Disp)
			target := uint32(int64(rv.val) + disp)

			if insn.Op == m68k.OpJSR || insn.Op == m68k.OpJMP {
				if finalTgt, ok := a.resolveSlotOrRelocTarget(target, jumpTable); ok {
					isCall := insn.Op == m68k.OpJSR
					jtEdges = append(jtEdges, jtEdge{site: slot.Addr, target: finalTgt, isCall: isCall})
					tname := a.GetOrDefaultLabel(finalTgt)
					comments = append(comments, addrComment{addr: slot.Addr, frag: fmt.Sprintf("-> %s", tname)})
					continue
				}
			}

			if hw, ok := amiga.GetAmigaHWLabelSub(target); ok {
				var eaStr string
				if disp == 0 {
					eaStr = fmt.Sprintf("(%s)", baseReg)
				} else {
					eaStr = fmt.Sprintf("%d(%s)", disp, baseReg)
				}
				comments = append(comments, addrComment{addr: slot.Addr, frag: fmt.Sprintf("%s = %s", eaStr, hw)})
				if rv.val == 0xDFF000 && target >= 0xDFF000 && target <= 0xDFF1FF {
					customEAs = append(customEAs, customEAEntry{
						key:  CustomEAKey{Addr: slot.Addr, OpIdx: int(opIdx)},
						name: hw,
					})
				}
			} else if a.isInDataOrBss(target) {
				isWrite := (op.Access & m68k.AccessWrite) != 0
				globals = append(globals, globalRef{site: slot.Addr, target: target, isWrite: isWrite})
			}
		}

		// Steps 2-6: Compute definition, clobber WriteRegs, commit, call-clobber, terminator reset.
		a.stepInsn(slot.Addr, &insn, &state, &globalBase)
	}

	for _, ce := range customEAs {
		a.CustomEA[ce.key] = ce.name
	}
	if len(comments) > 0 || len(globals) > 0 || len(jtEdges) > 0 {
		a.DB.Begin()
		for _, c := range comments {
			a.appendCellComment(c.addr, c.frag)
		}
		for _, g := range globals {
			site := g.site
			a.AddLabel(&site, g.target)
			xrefKind := db.XrefDataRead
			if g.isWrite {
				xrefKind = db.XrefDataWrite
			}
			_ = a.DB.InsertXref(g.site, g.target, xrefKind)
		}
		for _, je := range jtEdges {
			site := je.site
			a.AddLabel(&site, je.target)
			edgeKind := db.EdgeUncond
			xrefKind := db.XrefCodeBranch
			if je.isCall {
				edgeKind = db.EdgeCall
				xrefKind = db.XrefCodeCall
			}
			_ = a.DB.InsertEdge(je.site, je.target, edgeKind)
			_ = a.DB.InsertXref(je.site, je.target, xrefKind)
		}
		a.DB.Commit()
	}
}

func (a *Analyzer) isInDataOrBss(addr uint32) bool {
	s := a.SegmentAt(addr)
	return s != nil && (s.HunkType == hunk.HunkTypeData || s.HunkType == hunk.HunkTypeBss)
}

func (a *Analyzer) appendCellComment(addr uint32, frag string) {
	_ = a.DB.AppendAutoComment(addr, frag)
}
