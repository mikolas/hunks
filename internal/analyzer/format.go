package analyzer

import (
	"fmt"
	"strings"

	"github.com/mikolas/hunks/internal/amiga"
	"github.com/mikolas/hunks/internal/db"
	"github.com/mikolas/hunks/internal/m68k"
	"github.com/mikolas/hunks/internal/project"
)

// Stage3FormatOperands formats all CODE cells' mnemonics and operands into vasmm68k_mot syntax.
func (a *Analyzer) Stage3FormatOperands() {
	a.RefreshCaches()
	addrs := a.DB.CodeCellAddrs()

	type hwAutoComment struct {
		addr uint32
		frag string
	}
	var hwComments []hwAutoComment

	updates := make([]db.CellTextUpdate, 0, len(addrs))
	for _, addr := range addrs {
		raw := a.ReadBytes(addr, 10)
		if len(raw) < 2 {
			if c, err := a.DB.GetCell(addr); err == nil && c != nil {
				raw = c.RawBytes
			}
		}
		if len(raw) < 2 {
			continue
		}
		insn, ok := a.decodeCached(addr, raw)
		if !ok {
			continue
		}
		mnem, opStr := a.FormatInstructionTuple(addr, &insn)
		updates = append(updates, db.CellTextUpdate{
			Addr:     addr,
			Mnemonic: mnem,
			OpStr:    opStr,
		})
		if bf := a.decodeDirectCustomWriteComment(addr, &insn); bf != "" {
			hwComments = append(hwComments, hwAutoComment{addr: addr, frag: bf})
		}
	}
	_ = a.DB.SetCellTexts(updates)
	if len(hwComments) > 0 {
		_ = a.DB.WithTransaction(func() error {
			for _, hc := range hwComments {
				if err := a.DB.AppendAutoComment(hc.addr, hc.frag); err != nil {
					return err
				}
			}
			return nil
		})
	}
}

func (a *Analyzer) decodeDirectCustomWriteComment(addr uint32, insn *m68k.Insn) string {
	if insn.Op != m68k.OpMOVE || insn.NumOps != 2 || insn.Ops[0].Mode != m68k.EAImm {
		return ""
	}
	dst := insn.Ops[1]
	if dst.Mode != m68k.EAAbsShort && dst.Mode != m68k.EAAbsLong {
		return ""
	}
	if dst.Mode == m68k.EAAbsLong && a.IsRelocatableAt(addr) {
		if _, isReloc := a.Relocs[addr+uint32(dst.ExtOffset)]; isReloc {
			return ""
		}
	}
	if dst.UVal < amiga.CustomBase || dst.UVal > 0xDFF1FF {
		return ""
	}
	hwOff := dst.UVal - amiga.CustomBase
	switch insn.Suffix {
	case m68k.SizeW:
		return amiga.DecodeCustomRegWrite(hwOff, uint16(insn.Ops[0].UVal))
	case m68k.SizeL:
		return amiga.DecodeCustomRegLongWrite(hwOff, insn.Ops[0].UVal)
	}
	return ""
}

// GetLabelName returns the hardware register equate or cached DB label for addr, or "" if none.
func (a *Analyzer) GetLabelName(addr uint32) string {
	if hwLabel, ok := amiga.GetAmigaHWLabel(addr); ok {
		return hwLabel
	}
	if cached, ok := a.LabelsCache[addr]; ok {
		return cached
	}
	return ""
}

// formatOperand formats a single instruction operand at (addr, opIdx) into `vasmm68k_mot` syntax.
//
// Parity-critical rules enforced here:
//   - Absolute Short (`.w`): negative 16-bit addresses are formatted as `(-$XXXX).w` (or `(-1).w`)
//     with an explicit `.w` suffix so `vasm` never widens them to 32-bit Absolute Long.
//   - Absolute Long (`.l`): in relocatable hunk mode (`hunkMode == true`), a `.l` operand is
//     symbolized iff its extension word (`addr + op.ExtOffset`) is in `a.Relocs`, ensuring the
//     reassembled binary produces the exact same `HUNK_RELOC32` set. In flat mode, `.l` operands
//     are symbolized only when the target label starts on a cell boundary (`!a.PointsMidCell`).
//   - Displacement / Indexed (`d16(An)`, `d8(An,Xn)`): substitutes custom-chip register names from
//     `a.CustomEA` (when `An == $DFF000`) or user-defined struct field names from `RegisterAliases`.
func (a *Analyzer) formatOperand(addr uint32, insn *m68k.Insn, op m68k.Operand, opIdx int) string {
	hunkMode := a.IsRelocatableAt(addr)

	switch op.Mode {
	case m68k.EAImm:
		return a.formatImmOperand(addr, insn, op, hunkMode)

	case m68k.EABranch:
		target := op.UVal
		label := a.GetLabelName(target)
		if label == "" {
			label = a.Proj.AutoLabel(target)
			src := addr
			a.AddLabel(&src, target)
		}
		return label

	case m68k.EAAbsShort:
		target := op.UVal
		if hw, ok := amiga.GetAmigaHWOperand(target); ok {
			return hw + ".w"
		}
		if (!hunkMode || !a.IsInAnyProjectSegment(target)) && insn.Op != m68k.OpPEA && int16(uint16(target)) > 0 {
			label := a.GetLabelName(target)
			if label != "" && !a.PointsMidCell(target) {
				return label + ".w"
			}
		}
		return op.FormatASM(insn.Op)

	case m68k.EAAbsLong:
		target := op.UVal
		if hunkMode {
			extAddr := addr + uint32(op.ExtOffset)
			if relocTarget, ok := a.Relocs[extAddr]; ok {
				label := a.GetLabelName(relocTarget)
				if label == "" {
					label = a.Proj.AutoLabel(relocTarget)
					src := addr
					a.AddLabel(&src, relocTarget)
				}
				return label + ".l"
			}
			if hw, ok := amiga.GetAmigaHWOperand(target); ok {
				return hw + ".l"
			}
			return op.FormatASM(insn.Op)
		}
		if hw, ok := amiga.GetAmigaHWOperand(target); ok {
			return hw + ".l"
		}
		label := a.GetLabelName(target)
		if label != "" && !a.PointsMidCell(target) {
			return label + ".l"
		}
		return op.FormatASM(insn.Op)

	case m68k.EAPCDisp16, m68k.EAPCIndex:
		target := op.UVal
		label := a.GetLabelName(target)
		if label == "" {
			label = a.Proj.AutoLabel(target)
			src := addr
			a.AddLabel(&src, target)
		}
		if op.Mode == m68k.EAPCIndex {
			return label + "(pc," + op.IndexRegName() + op.IndexSize.DotSuffix() + ")"
		}
		return label + "(pc)"

	case m68k.EADisp16, m68k.EAIndex:
		if len(a.CustomEA) > 0 {
			if name, ok := a.CustomEA[CustomEAKey{Addr: addr, OpIdx: opIdx}]; ok {
				baseStr := m68k.RegAName(op.Reg)
				if op.Mode == m68k.EAIndex {
					return name + "(" + baseStr + "," + op.IndexRegName() + op.IndexSize.DotSuffix() + ")"
				}
				return name + "(" + baseStr + ")"
			}
		}
		if len(a.Proj.Data.RegisterAliases) > 0 {
			baseStr := m68k.RegAName(op.Reg)
			if structName, ok := a.resolveRegisterAlias(addr, baseStr); ok {
				if structDef, ok := a.Proj.Data.Structs[structName]; ok {
					if rawField, ok := structDef[fmt.Sprintf("%d", op.Disp)]; ok && rawField != "" {
						field, _ := project.StripFieldType(rawField)
						if op.Mode == m68k.EAIndex {
							return field + "(" + baseStr + "," + op.IndexRegName() + op.IndexSize.DotSuffix() + ")"
						}
						return field + "(" + baseStr + ")"
					}
				}
			}
		}
		return op.FormatASM(insn.Op)
	}

	return op.FormatASM(insn.Op)
}

func (a *Analyzer) resolveRegisterAlias(addr uint32, baseStr string) (string, bool) {
	aliases := a.Proj.Data.RegisterAliases
	if len(aliases) == 0 {
		return "", false
	}
	if len(a.funcEntries) == 0 {
		a.funcEntries = a.DB.FunctionEntries()
	}
	lo, hi := 0, len(a.funcEntries)
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if a.funcEntries[mid] <= addr {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo > 0 && a.IsSameSegment(a.funcEntries[lo-1], addr) {
		fnEntry := a.funcEntries[lo-1]
		var candKeys [4]string
		candKeys[0] = a.GetOrDefaultLabel(fnEntry) + ":" + baseStr
		candKeys[1] = a.Proj.AutoLabel(fnEntry) + ":" + baseStr
		candKeys[2] = fmt.Sprintf("LAB_%05X:%s", fnEntry, baseStr)
		candKeys[3] = fmt.Sprintf("0x%X:%s", fnEntry, baseStr)
		for _, k := range candKeys {
			if s, ok := aliases[k]; ok && s != "" {
				return s, true
			}
			for ak, av := range aliases {
				if strings.EqualFold(ak, k) && av != "" {
					return av, true
				}
			}
		}
	}
	if s, ok := aliases[baseStr]; ok && s != "" {
		return s, true
	}
	return "", false
}

func (a *Analyzer) formatImmOperand(addr uint32, insn *m68k.Insn, op m68k.Operand, hunkMode bool) string {
	val := op.UVal
	if fmtKind, ok := a.OperandFormatsCache[addr]; ok {
		if fmtKind == "DEC" {
			return fmt.Sprintf("#%d", val)
		}
		if fmtKind == "BIN" {
			return fmt.Sprintf("#%%%b", val)
		}
	}
	if insn.Op == m68k.OpMOVEQ {
		return op.FormatASM(insn.Op)
	}
	isLong := op.ImmSize == m68k.SizeL && op.ExtSize == 4

	if hunkMode {
		if isLong && insn.Size >= 6 {
			extAddr := addr + uint32(op.ExtOffset)
			if target, ok := a.Relocs[extAddr]; ok {
				label := a.GetLabelName(target)
				if label == "" {
					label = a.Proj.AutoLabel(target)
					src := addr
					a.AddLabel(&src, target)
				}
				return "#" + label
			}
		}
	} else if isLong && val >= 0x100 {
		if hw, ok := amiga.GetAmigaHWOperand(val); ok {
			return "#" + hw
		}
		label := a.GetLabelName(val)
		if label != "" && !a.PointsMidCell(val) {
			return "#" + label
		}
	}

	return op.FormatASM(insn.Op)
}

// FormatInstructionTuple formats a decoded instruction's mnemonic and operands into vasmm68k_mot syntax.
func (a *Analyzer) FormatInstructionTuple(addr uint32, insn *m68k.Insn) (string, string) {
	mnem := insn.FullMnemonic()
	if insn.NumOps == 0 {
		return mnem, ""
	}
	if insn.NumOps == 1 {
		return mnem, a.formatOperand(addr, insn, insn.Ops[0], 0)
	}
	op0 := a.formatOperand(addr, insn, insn.Ops[0], 0)
	op1 := a.formatOperand(addr, insn, insn.Ops[1], 1)
	return mnem, op0 + "," + op1
}

// ReanalyzeInstruction re-formats the instruction or pointer cell at addr.
func (a *Analyzer) ReanalyzeInstruction(addr uint32) {
	a.RefreshCaches()
	a.reanalyzeCellInternal(addr)
}

func (a *Analyzer) reanalyzeCellInternal(addr uint32) {
	cell, err := a.DB.GetCell(addr)
	if err != nil || cell == nil {
		return
	}
	if cell.Type == db.CellCode {
		if len(cell.RawBytes) >= 2 {
			if insn, ok := m68k.Decode(cell.RawBytes, addr); ok {
				_, opStr := a.FormatInstructionTuple(addr, &insn)
				_ = a.DB.SetCellOp(addr, opStr)
			}
		}
	} else if cell.Type == db.CellPointer {
		var tgt uint32
		hasTgt := false
		if rTgt, ok := a.Relocs[addr]; ok {
			tgt = rTgt
			hasTgt = true
		} else if u32Tgt, ok := a.ReadU32(addr); ok {
			tgt = u32Tgt
			hasTgt = true
		}
		if hasTgt {
			lbl := a.GetLabelName(tgt)
			if lbl != "" {
				_ = a.DB.SetCellOp(addr, lbl)
			}
		}
	}
}

// ReanalyzeXrefs re-formats all cells referencing targetAddr.
func (a *Analyzer) ReanalyzeXrefs(targetAddr uint32) {
	a.ReanalyzeXrefsBatch([]uint32{targetAddr})
}

// ReanalyzeXrefsBatch re-formats all cells referencing any of targetAddrs.
func (a *Analyzer) ReanalyzeXrefsBatch(targetAddrs []uint32) {
	if len(targetAddrs) == 0 {
		return
	}
	a.RefreshCaches()
	sourceAddrs := a.DB.SourceAddrsReferencing(targetAddrs)
	for _, addr := range sourceAddrs {
		a.reanalyzeCellInternal(addr)
	}
}
