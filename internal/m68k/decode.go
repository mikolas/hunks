package m68k

import (
	"encoding/binary"
	"math/bits"
)

// 12-bit Effective Address (<ea>) category bitmasks (bits 0..11).
//
// Each bit corresponds to one of the 12 canonical M68000 addressing modes:
//
//	Bit  0: Mode 000          Dn            Data Register Direct
//	Bit  1: Mode 001          An            Address Register Direct
//	Bit  2: Mode 010          (An)          Address Register Indirect
//	Bit  3: Mode 011          (An)+         Address Register Indirect with Postincrement
//	Bit  4: Mode 100          -(An)         Address Register Indirect with Predecrement
//	Bit  5: Mode 101          d16(An)       Address Register Indirect with 16-bit Displacement
//	Bit  6: Mode 110          d8(An,Xn.s)   Address Register Indirect with 8-bit Index
//	Bit  7: Mode 111 Reg 000  (xxx).w       Absolute Short Address
//	Bit  8: Mode 111 Reg 001  (xxx).l       Absolute Long Address
//	Bit  9: Mode 111 Reg 010  d16(pc)       Program Counter with 16-bit Displacement
//	Bit 10: Mode 111 Reg 011  d8(pc,Xn.s)   Program Counter with 8-bit Index
//	Bit 11: Mode 111 Reg 100  #<data>       Immediate Data
const (
	eaBitDn       uint16 = 1 << 0
	eaBitAn       uint16 = 1 << 1
	eaBitInd      uint16 = 1 << 2
	eaBitPostInc  uint16 = 1 << 3
	eaBitPreDec   uint16 = 1 << 4
	eaBitDisp16   uint16 = 1 << 5
	eaBitIndex    uint16 = 1 << 6
	eaBitAbsW     uint16 = 1 << 7
	eaBitAbsL     uint16 = 1 << 8
	eaBitPCDisp16 uint16 = 1 << 9
	eaBitPCIndex  uint16 = 1 << 10
	eaBitImm      uint16 = 1 << 11

	eaAll          uint16 = 0x0FFF
	eaData         uint16 = eaAll &^ eaBitAn
	eaMemory       uint16 = eaAll &^ (eaBitDn | eaBitAn)
	eaControl      uint16 = eaBitInd | eaBitDisp16 | eaBitIndex | eaBitAbsW | eaBitAbsL | eaBitPCDisp16 | eaBitPCIndex
	eaAlterable    uint16 = eaBitDn | eaBitAn | eaBitInd | eaBitPostInc | eaBitPreDec | eaBitDisp16 | eaBitIndex | eaBitAbsW | eaBitAbsL
	eaDataAlt      uint16 = eaData & eaAlterable
	eaMemAlt       uint16 = eaMemory & eaAlterable
	eaCtrlAlt      uint16 = eaControl & eaAlterable
	eaMovemToMem   uint16 = eaCtrlAlt | eaBitPreDec
	eaMovemFromMem uint16 = eaControl | eaBitPostInc
)

// Condition code tables for Bcc (bits 11..8) and Scc/DBcc (bits 11..8).
// Bcc uses "bra"/"bsr" for conditions 0/1 and "bhs"/"blo" for carry-clear/carry-set (4/5),
// whereas Scc and DBcc use "t"/"f" for 0/1 and "cc"/"cs" for 4/5.
var (
	bccNames = [16]string{
		"bra", "bsr", "bhi", "bls", "bhs", "blo", "bne", "beq",
		"bvc", "bvs", "bpl", "bmi", "bge", "blt", "bgt", "ble",
	}
	bccShortNames = [16]string{
		"bra.s", "bsr.s", "bhi.s", "bls.s", "bhs.s", "blo.s", "bne.s", "beq.s",
		"bvc.s", "bvs.s", "bpl.s", "bmi.s", "bge.s", "blt.s", "bgt.s", "ble.s",
	}
	bccWordNames = [16]string{
		"bra.w", "bsr.w", "bhi.w", "bls.w", "bhs.w", "blo.w", "bne.w", "beq.w",
		"bvc.w", "bvs.w", "bpl.w", "bmi.w", "bge.w", "blt.w", "bgt.w", "ble.w",
	}
	sccNames = [16]string{
		"st", "sf", "shi", "sls", "scc", "scs", "sne", "seq",
		"svc", "svs", "spl", "smi", "sge", "slt", "sgt", "sle",
	}
	dbccNames = [16]string{
		"dbt", "dbf", "dbhi", "dbls", "dbcc", "dbcs", "dbne", "dbeq",
		"dbvc", "dbvs", "dbpl", "dbmi", "dbge", "dblt", "dbgt", "dble",
	}
	shiftOps = [8]Op{
		OpASR, OpASL, OpLSR, OpLSL, OpROXR, OpROXL, OpROR, OpROL,
	}
	bitOps = [4]Op{OpBTST, OpBCHG, OpBCLR, OpBSET}
)

// ClassifyIndirectDispatch inspects a single 16-bit M68000 operation word and
// reports whether it is an indirect JMP or JSR instruction ((An), d16(An), d8(An,Xn),
// d16(PC), or d8(PC,Xn)), returning its EAMode, whether it is a JSR call, and its
// base address register index (0..7 for An-relative modes, -1 for PC-relative modes).
func ClassifyIndirectDispatch(opcode uint16) (mode EAMode, isCall bool, baseAn int8, ok bool) {
	isJmp := (opcode & 0xFFC0) == 0x4EC0
	isJsr := (opcode & 0xFFC0) == 0x4E80
	if !isJmp && !isJsr {
		return EANone, false, -1, false
	}
	eaMode := (opcode >> 3) & 0x7
	reg := int8(opcode & 0x7)
	switch eaMode {
	case 2:
		return EAAddrInd, isJsr, reg, true
	case 5:
		return EADisp16, isJsr, reg, true
	case 6:
		return EAIndex, isJsr, reg, true
	case 7:
		switch reg {
		case 2:
			return EAPCDisp16, isJsr, -1, true
		case 3:
			return EAPCIndex, isJsr, -1, true
		}
	}
	return EANone, false, -1, false
}

// decodeSizeBits maps a standard 2-bit M68000 size field (00=.b, 01=.w, 10=.l) to Size.
func decodeSizeBits(bits2 uint16) (Size, bool) {
	switch bits2 & 0x3 {
	case 0:
		return SizeB, true
	case 1:
		return SizeW, true
	case 2:
		return SizeL, true
	default:
		return SizeNone, false
	}
}

// decodeEA decodes a 6-bit M68000 Effective Address field (mode = 0..7, reg = 0..7)
// whose optional extension word(s) start at byte offset pos within raw.
//
// It validates:
//   - Membership in allowedMask (12-bit EA category bitmask).
//   - Address register direct (An) is never permitted when opSize == SizeB.
//   - Brief index extension words (EAIndex, EAPCIndex) must have bits 10..8 == 000
//     (extWord & 0x0700 == 0), rejecting 68020+ scale factors and full-format words.
//   - Byte-sized immediate extension words (mode 7 reg 4 with opSize == SizeB) must
//     have bits 15..8 == 0x00.
func decodeEA(
	raw []byte,
	addr uint32,
	pos uint8,
	mode, reg uint8,
	opSize Size,
	allowedMask uint16,
	access AccessFlags,
) (op Operand, nextPos uint8, readRegs, writeRegs RegMask, ok bool) {
	mode &= 0x7
	reg &= 0x7

	var eaBit uint16
	if mode < 7 {
		if mode == 1 && opSize == SizeB {
			return Operand{}, pos, 0, 0, false
		}
		eaBit = uint16(1) << mode
	} else {
		if reg > 4 {
			return Operand{}, pos, 0, 0, false
		}
		eaBit = uint16(1) << (7 + reg)
	}
	if (allowedMask & eaBit) == 0 {
		return Operand{}, pos, 0, 0, false
	}

	switch mode {
	case 0: // 000: Dn (Data Register Direct)
		return Operand{Mode: EADataReg, Access: access, Reg: reg}, pos, RegD(reg), 0, true

	case 1: // 001: An (Address Register Direct)
		return Operand{Mode: EAAddrReg, Access: access, Reg: reg}, pos, RegA(reg), 0, true

	case 2: // 010: (An) (Address Register Indirect)
		return Operand{Mode: EAAddrInd, Access: access, Reg: reg}, pos, RegA(reg), 0, true

	case 3: // 011: (An)+ (Address Register Indirect with Postincrement)
		return Operand{Mode: EAPostInc, Access: access, Reg: reg}, pos, RegA(reg), RegA(reg), true

	case 4: // 100: -(An) (Address Register Indirect with Predecrement)
		return Operand{Mode: EAPreDec, Access: access, Reg: reg}, pos, RegA(reg), RegA(reg), true

	case 5: // 101: d16(An) (Address Register Indirect with 16-bit Displacement)
		if int(pos)+2 > len(raw) {
			return Operand{}, pos, 0, 0, false
		}
		disp16 := int16(binary.BigEndian.Uint16(raw[pos : pos+2]))
		return Operand{
			Mode:      EADisp16,
			Access:    access,
			Reg:       reg,
			ExtOffset: pos,
			ExtSize:   2,
			Disp:      int32(disp16),
		}, pos + 2, RegA(reg), 0, true

	case 6: // 110: d8(An,Xn.w/.l) (Address Register Indirect with 8-bit Index)
		// Brief Extension Word:
		//   Bit 15:     0 = Dn, 1 = An
		//   Bits 14-12: Index Register Number (0..7)
		//   Bit 11:     0 = Sign-extended Word (.w), 1 = Longword (.l)
		//   Bits 10-8:  Must be 000 on M68000 (scale/full-extension on 68020+)
		//   Bits 7-0:   Signed 8-bit displacement (d8)
		if int(pos)+2 > len(raw) {
			return Operand{}, pos, 0, 0, false
		}
		ext := binary.BigEndian.Uint16(raw[pos : pos+2])
		if (ext & 0x0700) != 0 {
			return Operand{}, pos, 0, 0, false
		}
		idxReg := uint8((ext >> 12) & 0x7)
		idxMask := RegD(idxReg)
		if (ext & 0x8000) != 0 {
			idxMask = RegA(idxReg)
			idxReg += 8
		}
		idxSize := SizeW
		if (ext & 0x0800) != 0 {
			idxSize = SizeL
		}
		disp8 := int8(uint8(ext & 0xFF))
		return Operand{
			Mode:      EAIndex,
			Access:    access,
			Reg:       reg,
			IndexReg:  idxReg,
			IndexSize: idxSize,
			ExtOffset: pos,
			ExtSize:   2,
			Disp:      int32(disp8),
		}, pos + 2, RegA(reg) | idxMask, 0, true

	case 7:
		switch reg {
		case 0: // 111/000: (xxx).w (Absolute Short, sign-extended 16-bit -> 32-bit)
			if int(pos)+2 > len(raw) {
				return Operand{}, pos, 0, 0, false
			}
			w := int16(binary.BigEndian.Uint16(raw[pos : pos+2]))
			return Operand{
				Mode:      EAAbsShort,
				Access:    access,
				ExtOffset: pos,
				ExtSize:   2,
				Disp:      int32(w),
				UVal:      uint32(int32(w)),
			}, pos + 2, 0, 0, true

		case 1: // 111/001: (xxx).l (Absolute Long, 32-bit)
			if int(pos)+4 > len(raw) {
				return Operand{}, pos, 0, 0, false
			}
			u32 := binary.BigEndian.Uint32(raw[pos : pos+4])
			return Operand{
				Mode:      EAAbsLong,
				Access:    access,
				ExtOffset: pos,
				ExtSize:   4,
				Disp:      int32(u32),
				UVal:      u32,
			}, pos + 4, 0, 0, true

		case 2: // 111/010: d16(pc) (PC-Relative with 16-bit Displacement)
			if int(pos)+2 > len(raw) {
				return Operand{}, pos, 0, 0, false
			}
			disp16 := int16(binary.BigEndian.Uint16(raw[pos : pos+2]))
			target := uint32(int32(addr) + int32(pos) + int32(disp16))
			return Operand{
				Mode:      EAPCDisp16,
				Access:    access,
				ExtOffset: pos,
				ExtSize:   2,
				Disp:      int32(disp16),
				UVal:      target,
			}, pos + 2, 0, 0, true

		case 3: // 111/011: d8(pc,Xn.w/.l) (PC-Relative with 8-bit Index)
			if int(pos)+2 > len(raw) {
				return Operand{}, pos, 0, 0, false
			}
			ext := binary.BigEndian.Uint16(raw[pos : pos+2])
			if (ext & 0x0700) != 0 {
				return Operand{}, pos, 0, 0, false
			}
			idxReg := uint8((ext >> 12) & 0x7)
			idxMask := RegD(idxReg)
			if (ext & 0x8000) != 0 {
				idxMask = RegA(idxReg)
				idxReg += 8
			}
			idxSize := SizeW
			if (ext & 0x0800) != 0 {
				idxSize = SizeL
			}
			disp8 := int8(uint8(ext & 0xFF))
			target := uint32(int32(addr) + int32(pos) + int32(disp8))
			return Operand{
				Mode:      EAPCIndex,
				Access:    access,
				IndexReg:  idxReg,
				IndexSize: idxSize,
				ExtOffset: pos,
				ExtSize:   2,
				Disp:      int32(disp8),
				UVal:      target,
			}, pos + 2, idxMask, 0, true

		case 4: // 111/100: #<data> (Immediate Data)
			if opSize == SizeL {
				if int(pos)+4 > len(raw) {
					return Operand{}, pos, 0, 0, false
				}
				u32 := binary.BigEndian.Uint32(raw[pos : pos+4])
				return Operand{
					Mode:      EAImm,
					Access:    access,
					ImmSize:   SizeL,
					ExtOffset: pos,
					ExtSize:   4,
					Disp:      int32(u32),
					UVal:      u32,
				}, pos + 4, 0, 0, true
			}
			if int(pos)+2 > len(raw) {
				return Operand{}, pos, 0, 0, false
			}
			w := binary.BigEndian.Uint16(raw[pos : pos+2])
			if opSize == SizeB {
				if (w & 0xFF00) != 0 {
					return Operand{}, pos, 0, 0, false
				}
				b := uint8(w & 0xFF)
				return Operand{
					Mode:      EAImm,
					Access:    access,
					ImmSize:   SizeB,
					ExtOffset: pos,
					ExtSize:   2,
					Disp:      int32(int8(b)),
					UVal:      uint32(b),
				}, pos + 2, 0, 0, true
			}
			return Operand{
				Mode:      EAImm,
				Access:    access,
				ImmSize:   SizeW,
				ExtOffset: pos,
				ExtSize:   2,
				Disp:      int32(int16(w)),
				UVal:      uint32(w),
			}, pos + 2, 0, 0, true
		}
	}

	return Operand{}, pos, 0, 0, false
}

// dstRegMask returns the register write bitmask when an <ea> operand is written to as a destination.
func dstRegMask(op Operand) RegMask {
	switch op.Mode {
	case EADataReg:
		return RegD(op.Reg)
	case EAAddrReg:
		return RegA(op.Reg)
	default:
		return 0
	}
}

// Decode decodes a single Motorola 68000 instruction from raw at program counter addr.
// It returns (insn, true) if raw starts with a valid M68000 instruction and contains
// all required extension words, or (Insn{}, false) otherwise.
func Decode(raw []byte, addr uint32) (Insn, bool) {
	if len(raw) < 2 {
		return Insn{}, false
	}
	opcode := binary.BigEndian.Uint16(raw[0:2])
	insn := Insn{
		Addr:   addr,
		Opcode: opcode,
	}

	var ok bool
	switch opcode >> 12 {
	case 0x0:
		ok = decodeLine0(raw, addr, opcode, &insn)
	case 0x1:
		ok = decodeMove(raw, addr, opcode, SizeB, &insn)
	case 0x2:
		ok = decodeMove(raw, addr, opcode, SizeL, &insn)
	case 0x3:
		ok = decodeMove(raw, addr, opcode, SizeW, &insn)
	case 0x4:
		ok = decodeLine4(raw, addr, opcode, &insn)
	case 0x5:
		ok = decodeLine5(raw, addr, opcode, &insn)
	case 0x6:
		ok = decodeLine6(raw, addr, opcode, &insn)
	case 0x7:
		ok = decodeLine7(opcode, &insn)
	case 0x8:
		ok = decodeLine8(raw, addr, opcode, &insn)
	case 0x9:
		ok = decodeAddSub(raw, addr, opcode, addSubKind{OpSUB, OpSUBA, OpSUBX}, &insn)
	case 0xB:
		ok = decodeLineB(raw, addr, opcode, &insn)
	case 0xC:
		ok = decodeLineC(raw, addr, opcode, &insn)
	case 0xD:
		ok = decodeAddSub(raw, addr, opcode, addSubKind{OpADD, OpADDA, OpADDX}, &insn)
	case 0xE:
		ok = decodeLineE(raw, addr, opcode, &insn)
	default:
		// Lines $A (1010) and $F (1111) are unassigned / coprocessor traps on M68000.
		return Insn{}, false
	}

	if !ok || insn.Size == 0 || int(insn.Size) > len(raw) {
		return Insn{}, false
	}
	return insn, true
}

// decodeLine0 decodes Opcode Line $0 (bits 15..12 = 0000):
//   - Immediate to CCR / SR (ORI, ANDI, EORI #imm,CCR/SR)
//   - MOVEP.W / MOVEP.L (Bit 8 = 1, EA Mode = 001)
//   - Dynamic Bit Manipulation: BTST, BCHG, BCLR, BSET Dn,<ea> (Bit 8 = 1, EA Mode != 001)
//   - Static Bit Manipulation: BTST, BCHG, BCLR, BSET #imm,<ea> (Bits 11..8 = 1000)
//   - Immediate ALU: ORI, ANDI, SUBI, ADDI, EORI, CMPI #imm,<ea> (Bit 8 = 0)
func decodeLine0(raw []byte, addr uint32, opcode uint16, insn *Insn) bool {
	// 1. Exact 16-bit matches for ORI / ANDI / EORI to CCR or SR.
	switch opcode {
	case 0x003C, 0x023C, 0x0A3C: // ori.b / andi.b / eori.b #imm,ccr
		if len(raw) < 4 {
			return false
		}
		w := binary.BigEndian.Uint16(raw[2:4])
		if (w & 0xFF00) != 0 {
			return false
		}
		switch opcode {
		case 0x003C:
			insn.Op = OpORI
		case 0x023C:
			insn.Op = OpANDI
		case 0x0A3C:
			insn.Op = OpEORI
		}
		insn.Suffix = SizeB
		insn.Size = 4
		insn.NumOps = 2
		b := uint8(w & 0xFF)
		insn.Ops[0] = Operand{Mode: EAImm, Access: AccessRead, ImmSize: SizeB, ExtOffset: 2, ExtSize: 2, Disp: int32(int8(b)), UVal: uint32(b)}
		insn.Ops[1] = Operand{Mode: EASpecialReg, Access: AccessRead | AccessWrite, Reg: uint8(SpecCCR)}
		return true

	case 0x007C, 0x027C, 0x0A7C: // ori.w / andi.w / eori.w #imm,sr
		if len(raw) < 4 {
			return false
		}
		w := binary.BigEndian.Uint16(raw[2:4])
		switch opcode {
		case 0x007C:
			insn.Op = OpORI
		case 0x027C:
			insn.Op = OpANDI
		case 0x0A7C:
			insn.Op = OpEORI
		}
		insn.Suffix = SizeW
		insn.Flow = FlowPrivileged
		insn.Size = 4
		insn.NumOps = 2
		insn.Ops[0] = Operand{Mode: EAImm, Access: AccessRead, ImmSize: SizeW, ExtOffset: 2, ExtSize: 2, Disp: int32(int16(w)), UVal: uint32(w)}
		insn.Ops[1] = Operand{Mode: EASpecialReg, Access: AccessRead | AccessWrite, Reg: uint8(SpecSR)}
		return true
	}

	mode := uint8((opcode >> 3) & 0x7)
	reg := uint8(opcode & 0x7)

	// 2. Bit 8 == 1: MOVEP (when mode == 1) or Dynamic Bit Ops (BTST/BCHG/BCLR/BSET Dn,<ea>).
	if (opcode & 0x0100) != 0 {
		rx := uint8((opcode >> 9) & 0x7)
		if mode == 1 {
			// MOVEP: 0000 DDD1 d s 001 AAA + 16-bit displacement
			if len(raw) < 4 {
				return false
			}
			disp16 := int16(binary.BigEndian.Uint16(raw[2:4]))
			insn.Op = OpMOVEP
			if (opcode & 0x0040) != 0 {
				insn.Suffix = SizeL
			} else {
				insn.Suffix = SizeW
			}
			insn.Size = 4
			insn.NumOps = 2
			if (opcode & 0x0080) == 0 {
				// Memory -> Register
				insn.Ops[0] = Operand{Mode: EADisp16, Access: AccessRead, Reg: reg, ExtOffset: 2, ExtSize: 2, Disp: int32(disp16)}
				insn.Ops[1] = Operand{Mode: EADataReg, Access: AccessWrite, Reg: rx}
				insn.ReadRegs = RegA(reg)
				insn.WriteRegs = RegD(rx)
			} else {
				// Register -> Memory
				insn.Ops[0] = Operand{Mode: EADataReg, Access: AccessRead, Reg: rx}
				insn.Ops[1] = Operand{Mode: EADisp16, Access: AccessWrite, Reg: reg, ExtOffset: 2, ExtSize: 2, Disp: int32(disp16)}
				insn.ReadRegs = RegD(rx) | RegA(reg)
			}
			return true
		}

		// Dynamic Bit Operation: 0000 rrr1 tt mmm rrr
		sub := (opcode >> 6) & 0x3
		allowed := eaDataAlt
		eaAccess := AccessRead | AccessWrite
		if sub == 0 {
			allowed = eaData
			eaAccess = AccessRead
		}
		eaOp, nextPos, rRegs, wRegs, ok := decodeEA(raw, addr, 2, mode, reg, SizeB, allowed, eaAccess)
		if !ok {
			return false
		}
		insn.Op = bitOps[sub]
		insn.Suffix = SizeNone
		insn.Size = nextPos
		insn.NumOps = 2
		insn.Ops[0] = Operand{Mode: EADataReg, Access: AccessRead, Reg: rx}
		insn.Ops[1] = eaOp
		insn.ReadRegs = RegD(rx) | rRegs
		insn.WriteRegs = wRegs
		if sub != 0 {
			insn.WriteRegs |= dstRegMask(eaOp)
		}
		return true
	}

	// 3. Static Bit Operation: 0000 1000 tt mmm rrr + 16-bit immediate bit number
	if (opcode >> 8) == 0x08 {
		if len(raw) < 4 {
			return false
		}
		bitWord := binary.BigEndian.Uint16(raw[2:4])
		if (bitWord & 0xFF00) != 0 {
			return false
		}
		sub := (opcode >> 6) & 0x3
		allowed := eaDataAlt
		eaAccess := AccessRead | AccessWrite
		if sub == 0 {
			allowed = eaData &^ eaBitImm // M68000 forbids BTST #imm,#imm
			eaAccess = AccessRead
		}
		eaOp, nextPos, rRegs, wRegs, ok := decodeEA(raw, addr, 4, mode, reg, SizeB, allowed, eaAccess)
		if !ok {
			return false
		}
		insn.Op = bitOps[sub]
		insn.Suffix = SizeNone
		insn.Size = nextPos
		insn.NumOps = 2
		b := uint8(bitWord & 0xFF)
		insn.Ops[0] = Operand{Mode: EAImm, Access: AccessRead, ImmSize: SizeB, ExtOffset: 2, ExtSize: 2, Disp: int32(b), UVal: uint32(b)}
		insn.Ops[1] = eaOp
		insn.ReadRegs = rRegs
		insn.WriteRegs = wRegs
		if sub != 0 {
			insn.WriteRegs |= dstRegMask(eaOp)
		}
		return true
	}

	// 4. Immediate ALU Operations: 0000 sss0 zz mmm rrr
	//    sss: 000=ORI, 001=ANDI, 010=SUBI, 011=ADDI, 101=EORI, 110=CMPI
	var op Op
	switch (opcode >> 9) & 0x7 {
	case 0:
		op = OpORI
	case 1:
		op = OpANDI
	case 2:
		op = OpSUBI
	case 3:
		op = OpADDI
	case 5:
		op = OpEORI
	case 6:
		op = OpCMPI
	default:
		return false
	}

	opSize, ok := decodeSizeBits(opcode >> 6)
	if !ok {
		return false
	}

	immOp, posAfterImm, _, _, ok := decodeEA(raw, addr, 2, 7, 4, opSize, eaBitImm, AccessRead)
	if !ok {
		return false
	}
	eaAccess := AccessRead | AccessWrite
	if op == OpCMPI {
		eaAccess = AccessRead
	}
	eaOp, nextPos, rRegs, wRegs, ok := decodeEA(raw, addr, posAfterImm, mode, reg, opSize, eaDataAlt, eaAccess)
	if !ok {
		return false
	}

	insn.Op = op
	insn.Suffix = opSize
	insn.Size = nextPos
	insn.NumOps = 2
	insn.Ops[0] = immOp
	insn.Ops[1] = eaOp
	insn.ReadRegs = rRegs
	insn.WriteRegs = wRegs
	if op != OpCMPI {
		insn.WriteRegs |= dstRegMask(eaOp)
	}
	return true
}

// decodeMove decodes Opcode Lines $1 (MOVE.B), $2 (MOVE.L/MOVEA.L), and $3 (MOVE.W/MOVEA.W):
//
//	Bit:  15  14  13  12 | 11  10   9 |  8   7   6 |  5   4   3 |  2   1   0
//	     [ 0   0   Size ] [  Dst Reg ] [ Dst Mode ] [ Src Mode ] [  Src Reg ]
func decodeMove(raw []byte, addr uint32, opcode uint16, opSize Size, insn *Insn) bool {
	srcMode := uint8((opcode >> 3) & 0x7)
	srcReg := uint8(opcode & 0x7)
	dstMode := uint8((opcode >> 6) & 0x7)
	dstReg := uint8((opcode >> 9) & 0x7)

	srcAllowed := eaAll
	if opSize == SizeB {
		srcAllowed = eaData
	}
	srcOp, posAfterSrc, rSrc, wSrc, ok := decodeEA(raw, addr, 2, srcMode, srcReg, opSize, srcAllowed, AccessRead)
	if !ok {
		return false
	}

	if dstMode == 1 {
		// MOVEA.W / MOVEA.L (invalid for SizeB)
		if opSize == SizeB {
			return false
		}
		insn.Op = OpMOVEA
		insn.Suffix = opSize
		insn.Size = posAfterSrc
		insn.NumOps = 2
		insn.Ops[0] = srcOp
		insn.Ops[1] = Operand{Mode: EAAddrReg, Access: AccessWrite, Reg: dstReg}
		insn.ReadRegs = rSrc
		insn.WriteRegs = wSrc | RegA(dstReg)
		return true
	}

	dstOp, nextPos, rDst, wDst, ok := decodeEA(raw, addr, posAfterSrc, dstMode, dstReg, opSize, eaDataAlt, AccessWrite)
	if !ok {
		return false
	}
	insn.Op = OpMOVE
	insn.Suffix = opSize
	insn.Size = nextPos
	insn.NumOps = 2
	insn.Ops[0] = srcOp
	insn.Ops[1] = dstOp
	insn.ReadRegs = rSrc | rDst
	insn.WriteRegs = wSrc | wDst | dstRegMask(dstOp)
	return true
}

// decodeLine4 decodes Opcode Line $4 (bits 15..12 = 0100, Miscellaneous & System Control).
func decodeLine4(raw []byte, addr uint32, opcode uint16, insn *Insn) bool {
	// 1. Fixed 16-bit opcodes.
	switch opcode {
	case 0x4E70: // RESET
		insn.Op = OpRESET
		insn.Flow = FlowPrivileged
		insn.Size = 2
		return true
	case 0x4E71: // NOP
		insn.Op = OpNOP
		insn.Size = 2
		return true
	case 0x4E72: // STOP #imm
		if len(raw) < 4 {
			return false
		}
		w := binary.BigEndian.Uint16(raw[2:4])
		insn.Op = OpSTOP
		insn.Flow = FlowStop | FlowPrivileged
		insn.Size = 4
		insn.NumOps = 1
		insn.Ops[0] = Operand{Mode: EAImm, Access: AccessRead, ImmSize: SizeW, ExtOffset: 2, ExtSize: 2, Disp: int32(int16(w)), UVal: uint32(w)}
		return true
	case 0x4E73: // RTE
		insn.Op = OpRTE
		insn.Flow = FlowReturn | FlowPrivileged
		insn.ReadRegs = RegA7
		insn.WriteRegs = RegA7
		insn.Size = 2
		return true
	case 0x4E75: // RTS
		insn.Op = OpRTS
		insn.Flow = FlowReturn
		insn.ReadRegs = RegA7
		insn.WriteRegs = RegA7
		insn.Size = 2
		return true
	case 0x4E76: // TRAPV
		insn.Op = OpTRAPV
		insn.Flow = FlowTrap
		insn.Size = 2
		return true
	case 0x4E77: // RTR
		insn.Op = OpRTR
		insn.Flow = FlowReturn
		insn.ReadRegs = RegA7
		insn.WriteRegs = RegA7
		insn.Size = 2
		return true
	case 0x4AFC: // ILLEGAL
		insn.Op = OpILLEGAL
		insn.Flow = FlowTrap | FlowStop
		insn.Size = 2
		return true
	}

	// 2. Narrow register/immediate families in $4Exx and $48xx.
	switch {
	case (opcode & 0xFFF0) == 0x4E40: // TRAP #<vector> (0..15)
		vec := uint8(opcode & 0xF)
		insn.Op = OpTRAP
		insn.Flow = FlowTrap
		insn.Size = 2
		insn.NumOps = 1
		insn.Ops[0] = Operand{Mode: EAImm, Access: AccessRead, ImmSize: SizeB, Disp: int32(vec), UVal: uint32(vec)}
		return true

	case (opcode & 0xFFF8) == 0x4E50: // LINK.W An,#<disp16>
		if len(raw) < 4 {
			return false
		}
		reg := uint8(opcode & 0x7)
		disp16 := int16(binary.BigEndian.Uint16(raw[2:4]))
		insn.Op = OpLINK
		insn.Suffix = SizeW
		insn.Size = 4
		insn.NumOps = 2
		insn.Ops[0] = Operand{Mode: EAAddrReg, Access: AccessRead | AccessWrite, Reg: reg}
		insn.Ops[1] = Operand{Mode: EAImm, Access: AccessRead, ImmSize: SizeW, ExtOffset: 2, ExtSize: 2, Disp: int32(disp16), UVal: uint32(uint16(disp16))}
		insn.ReadRegs = RegA(reg) | RegA7
		insn.WriteRegs = RegA(reg) | RegA7
		return true

	case (opcode & 0xFFF8) == 0x4E58: // UNLK An
		reg := uint8(opcode & 0x7)
		insn.Op = OpUNLK
		insn.Size = 2
		insn.NumOps = 1
		insn.Ops[0] = Operand{Mode: EAAddrReg, Access: AccessRead | AccessWrite, Reg: reg}
		insn.ReadRegs = RegA(reg)
		insn.WriteRegs = RegA(reg) | RegA7
		return true

	case (opcode & 0xFFF8) == 0x4E60: // MOVE.L An,USP
		reg := uint8(opcode & 0x7)
		insn.Op = OpMOVE
		insn.Suffix = SizeL
		insn.Flow = FlowPrivileged
		insn.Size = 2
		insn.NumOps = 2
		insn.Ops[0] = Operand{Mode: EAAddrReg, Access: AccessRead, Reg: reg}
		insn.Ops[1] = Operand{Mode: EASpecialReg, Access: AccessWrite, Reg: uint8(SpecUSP)}
		insn.ReadRegs = RegA(reg)
		return true

	case (opcode & 0xFFF8) == 0x4E68: // MOVE.L USP,An
		reg := uint8(opcode & 0x7)
		insn.Op = OpMOVE
		insn.Suffix = SizeL
		insn.Flow = FlowPrivileged
		insn.Size = 2
		insn.NumOps = 2
		insn.Ops[0] = Operand{Mode: EASpecialReg, Access: AccessRead, Reg: uint8(SpecUSP)}
		insn.Ops[1] = Operand{Mode: EAAddrReg, Access: AccessWrite, Reg: reg}
		insn.WriteRegs = RegA(reg)
		return true

	case (opcode & 0xFFF8) == 0x4840: // SWAP Dn
		reg := uint8(opcode & 0x7)
		insn.Op = OpSWAP
		insn.Size = 2
		insn.NumOps = 1
		insn.Ops[0] = Operand{Mode: EADataReg, Access: AccessRead | AccessWrite, Reg: reg}
		insn.ReadRegs = RegD(reg)
		insn.WriteRegs = RegD(reg)
		return true

	case (opcode & 0xFFF8) == 0x4880: // EXT.W Dn
		reg := uint8(opcode & 0x7)
		insn.Op = OpEXT
		insn.Suffix = SizeW
		insn.Size = 2
		insn.NumOps = 1
		insn.Ops[0] = Operand{Mode: EADataReg, Access: AccessRead | AccessWrite, Reg: reg}
		insn.ReadRegs = RegD(reg)
		insn.WriteRegs = RegD(reg)
		return true

	case (opcode & 0xFFF8) == 0x48C0: // EXT.L Dn
		reg := uint8(opcode & 0x7)
		insn.Op = OpEXT
		insn.Suffix = SizeL
		insn.Size = 2
		insn.NumOps = 1
		insn.Ops[0] = Operand{Mode: EADataReg, Access: AccessRead | AccessWrite, Reg: reg}
		insn.ReadRegs = RegD(reg)
		insn.WriteRegs = RegD(reg)
		return true
	}

	mode := uint8((opcode >> 3) & 0x7)
	reg := uint8(opcode & 0x7)

	// 3. JSR and JMP: 0100 1110 10/11 mmm rrr
	if (opcode & 0xFFC0) == 0x4E80 { // JSR <ea>
		eaOp, nextPos, rRegs, _, ok := decodeEA(raw, addr, 2, mode, reg, SizeL, eaControl, AccessAddr)
		if !ok {
			return false
		}
		insn.Op = OpJSR
		insn.Flow = FlowCall
		insn.Size = nextPos
		insn.NumOps = 1
		insn.Ops[0] = eaOp
		insn.ReadRegs = rRegs | RegA7
		insn.WriteRegs = RegA7
		return true
	}
	if (opcode & 0xFFC0) == 0x4EC0 { // JMP <ea>
		eaOp, nextPos, rRegs, _, ok := decodeEA(raw, addr, 2, mode, reg, SizeL, eaControl, AccessAddr)
		if !ok {
			return false
		}
		insn.Op = OpJMP
		insn.Flow = FlowBranch
		insn.Size = nextPos
		insn.NumOps = 1
		insn.Ops[0] = eaOp
		insn.ReadRegs = rRegs
		return true
	}

	// 4. LEA and CHK: 0100 rrr1 11 mmm rrr (LEA), 0100 rrr1 10 mmm rrr (CHK.W)
	if (opcode & 0xF1C0) == 0x41C0 { // LEA.L <ea>,An
		dstAn := uint8((opcode >> 9) & 0x7)
		eaOp, nextPos, rRegs, _, ok := decodeEA(raw, addr, 2, mode, reg, SizeL, eaControl, AccessAddr)
		if !ok {
			return false
		}
		insn.Op = OpLEA
		insn.Suffix = SizeL
		insn.Size = nextPos
		insn.NumOps = 2
		insn.Ops[0] = eaOp
		insn.Ops[1] = Operand{Mode: EAAddrReg, Access: AccessWrite, Reg: dstAn}
		insn.ReadRegs = rRegs
		insn.WriteRegs = RegA(dstAn)
		return true
	}
	if (opcode & 0xF1C0) == 0x4180 { // CHK.W <ea>,Dn
		dstDn := uint8((opcode >> 9) & 0x7)
		eaOp, nextPos, rRegs, wRegs, ok := decodeEA(raw, addr, 2, mode, reg, SizeW, eaData, AccessRead)
		if !ok {
			return false
		}
		insn.Op = OpCHK
		insn.Suffix = SizeW
		insn.Flow = FlowTrap
		insn.Size = nextPos
		insn.NumOps = 2
		insn.Ops[0] = eaOp
		insn.Ops[1] = Operand{Mode: EADataReg, Access: AccessRead, Reg: dstDn}
		insn.ReadRegs = rRegs | RegD(dstDn)
		insn.WriteRegs = wRegs
		return true
	}

	// 5. PEA.L <ea>: 0100 1000 01 mmm rrr (mode != 000, since 000 is SWAP)
	if (opcode & 0xFFC0) == 0x4840 {
		eaOp, nextPos, rRegs, _, ok := decodeEA(raw, addr, 2, mode, reg, SizeL, eaControl, AccessAddr)
		if !ok {
			return false
		}
		insn.Op = OpPEA
		insn.Suffix = SizeL
		insn.Size = nextPos
		insn.NumOps = 1
		insn.Ops[0] = eaOp
		insn.ReadRegs = rRegs | RegA7
		insn.WriteRegs = RegA7
		return true
	}

	// 6. MOVEM.W / MOVEM.L: 0100 1d00 1s mmm rrr + 16-bit register list mask
	//    Note: mode == 000 is EXT.W / EXT.L, already handled above.
	if (opcode & 0xFB80) == 0x4880 {
		if len(raw) < 4 {
			return false
		}
		rawMask := binary.BigEndian.Uint16(raw[2:4])
		if rawMask == 0 {
			return false
		}
		opSize := SizeW
		if (opcode & 0x0040) != 0 {
			opSize = SizeL
		}
		memToReg := (opcode & 0x0400) != 0
		allowed := eaMovemToMem
		eaAccess := AccessWrite
		regAccess := AccessRead
		if memToReg {
			allowed = eaMovemFromMem
			eaAccess = AccessRead
			regAccess = AccessWrite
		}
		eaOp, nextPos, rRegs, wRegs, ok := decodeEA(raw, addr, 4, mode, reg, opSize, allowed, eaAccess)
		if !ok {
			return false
		}
		// Normalize predecrement -(An) mask so bit 0..7 = D0..D7 and bit 8..15 = A0..A7.
		normMask := rawMask
		if !memToReg && mode == 4 {
			normMask = bits.Reverse16(rawMask)
		}
		regListOp := Operand{
			Mode:      EARegList,
			Access:    regAccess,
			ExtOffset: 2,
			ExtSize:   2,
			UVal:      uint32(normMask),
		}
		insn.Op = OpMOVEM
		insn.Suffix = opSize
		insn.Size = nextPos
		insn.NumOps = 2
		if memToReg {
			insn.Ops[0] = eaOp
			insn.Ops[1] = regListOp
			insn.ReadRegs = rRegs
			insn.WriteRegs = wRegs | RegMask(normMask)
		} else {
			insn.Ops[0] = regListOp
			insn.Ops[1] = eaOp
			insn.ReadRegs = rRegs | RegMask(normMask)
			insn.WriteRegs = wRegs
		}
		return true
	}

	// 7. NBCD.B <ea> (0100 1000 00 mmm rrr) and TAS.B <ea> (0100 1010 11 mmm rrr).
	if (opcode & 0xFFC0) == 0x4800 {
		eaOp, nextPos, rRegs, wRegs, ok := decodeEA(raw, addr, 2, mode, reg, SizeB, eaDataAlt, AccessRead|AccessWrite)
		if !ok {
			return false
		}
		insn.Op = OpNBCD
		insn.Suffix = SizeB
		insn.Size = nextPos
		insn.NumOps = 1
		insn.Ops[0] = eaOp
		insn.ReadRegs = rRegs
		insn.WriteRegs = wRegs | dstRegMask(eaOp)
		return true
	}
	if (opcode & 0xFFC0) == 0x4AC0 {
		eaOp, nextPos, rRegs, wRegs, ok := decodeEA(raw, addr, 2, mode, reg, SizeB, eaDataAlt, AccessRead|AccessWrite)
		if !ok {
			return false
		}
		insn.Op = OpTAS
		insn.Suffix = SizeB
		insn.Size = nextPos
		insn.NumOps = 1
		insn.Ops[0] = eaOp
		insn.ReadRegs = rRegs
		insn.WriteRegs = wRegs | dstRegMask(eaOp)
		return true
	}

	// 8. MOVE from SR (0x40C0), MOVE to CCR (0x44C0), MOVE to SR (0x46C0).
	//    Note: 0x42C0 (MOVE from CCR) is 68010+ only and is rejected on M68000.
	if (opcode & 0xFFC0) == 0x40C0 { // MOVE.W SR,<ea>
		eaOp, nextPos, rRegs, wRegs, ok := decodeEA(raw, addr, 2, mode, reg, SizeW, eaDataAlt, AccessWrite)
		if !ok {
			return false
		}
		insn.Op = OpMOVE
		insn.Suffix = SizeW
		insn.Size = nextPos
		insn.NumOps = 2
		insn.Ops[0] = Operand{Mode: EASpecialReg, Access: AccessRead, Reg: uint8(SpecSR)}
		insn.Ops[1] = eaOp
		insn.ReadRegs = rRegs
		insn.WriteRegs = wRegs | dstRegMask(eaOp)
		return true
	}
	if (opcode & 0xFFC0) == 0x44C0 { // MOVE.W <ea>,CCR
		eaOp, nextPos, rRegs, wRegs, ok := decodeEA(raw, addr, 2, mode, reg, SizeW, eaData, AccessRead)
		if !ok {
			return false
		}
		insn.Op = OpMOVE
		insn.Suffix = SizeW
		insn.Size = nextPos
		insn.NumOps = 2
		insn.Ops[0] = eaOp
		insn.Ops[1] = Operand{Mode: EASpecialReg, Access: AccessWrite, Reg: uint8(SpecCCR)}
		insn.ReadRegs = rRegs
		insn.WriteRegs = wRegs
		return true
	}
	if (opcode & 0xFFC0) == 0x46C0 { // MOVE.W <ea>,SR
		eaOp, nextPos, rRegs, wRegs, ok := decodeEA(raw, addr, 2, mode, reg, SizeW, eaData, AccessRead)
		if !ok {
			return false
		}
		insn.Op = OpMOVE
		insn.Suffix = SizeW
		insn.Flow = FlowPrivileged
		insn.Size = nextPos
		insn.NumOps = 2
		insn.Ops[0] = eaOp
		insn.Ops[1] = Operand{Mode: EASpecialReg, Access: AccessWrite, Reg: uint8(SpecSR)}
		insn.ReadRegs = rRegs
		insn.WriteRegs = wRegs
		return true
	}

	// 9. Single-operand ALU: NEGX (0100 0000), CLR (0100 0010), NEG (0100 0100),
	//    NOT (0100 0110), TST (0100 1010) with size bits 7..6 in {00, 01, 10}.
	var op Op
	eaAccess := AccessRead | AccessWrite
	switch (opcode >> 8) & 0xFF {
	case 0x40:
		op = OpNEGX
	case 0x42:
		op = OpCLR
		eaAccess = AccessWrite
	case 0x44:
		op = OpNEG
	case 0x46:
		op = OpNOT
	case 0x4A:
		op = OpTST
		eaAccess = AccessRead
	default:
		return false
	}

	opSize, ok := decodeSizeBits(opcode >> 6)
	if !ok {
		return false
	}
	eaOp, nextPos, rRegs, wRegs, ok := decodeEA(raw, addr, 2, mode, reg, opSize, eaDataAlt, eaAccess)
	if !ok {
		return false
	}
	insn.Op = op
	insn.Suffix = opSize
	insn.Size = nextPos
	insn.NumOps = 1
	insn.Ops[0] = eaOp
	if op != OpCLR {
		insn.ReadRegs = rRegs
	} else if eaOp.Mode != EADataReg {
		insn.ReadRegs = rRegs
	}
	insn.WriteRegs = wRegs
	if op != OpTST {
		insn.WriteRegs |= dstRegMask(eaOp)
	}
	return true
}

// decodeLine5 decodes Opcode Line $5 (bits 15..12 = 0101):
//   - DBcc Dn,<label> (Bits 7..6 == 11, EA Mode == 001)
//   - Scc <ea>        (Bits 7..6 == 11, EA Mode != 001)
//   - ADDQ / SUBQ     (Bits 7..6 in {00, 01, 10})
func decodeLine5(raw []byte, addr uint32, opcode uint16, insn *Insn) bool {
	mode := uint8((opcode >> 3) & 0x7)
	reg := uint8(opcode & 0x7)

	if ((opcode >> 6) & 0x3) == 0x3 {
		cond := uint8((opcode >> 8) & 0xF)
		if mode == 1 {
			// DBcc Dn,<label>
			if len(raw) < 4 {
				return false
			}
			disp16 := int16(binary.BigEndian.Uint16(raw[2:4]))
			target := uint32(int32(addr) + 2 + int32(disp16))
			insn.Op = OpDBcc
			insn.Cond = cond
			insn.Suffix = SizeNone
			insn.Flow = FlowBranch | FlowCond
			insn.Size = 4
			insn.NumOps = 2
			insn.Ops[0] = Operand{Mode: EADataReg, Access: AccessRead | AccessWrite, Reg: reg}
			insn.Ops[1] = Operand{Mode: EABranch, Access: AccessAddr, ExtOffset: 2, ExtSize: 2, Disp: int32(disp16), UVal: target}
			insn.ReadRegs = RegD(reg)
			insn.WriteRegs = RegD(reg)
			return true
		}

		// Scc <ea>
		eaOp, nextPos, rRegs, wRegs, ok := decodeEA(raw, addr, 2, mode, reg, SizeB, eaDataAlt, AccessWrite)
		if !ok {
			return false
		}
		insn.Op = OpScc
		insn.Cond = cond
		insn.Suffix = SizeNone
		insn.Size = nextPos
		insn.NumOps = 1
		insn.Ops[0] = eaOp
		insn.ReadRegs = rRegs
		insn.WriteRegs = wRegs | dstRegMask(eaOp)
		return true
	}

	// ADDQ / SUBQ #<1..8>,<ea>
	opSize, ok := decodeSizeBits(opcode >> 6)
	if !ok {
		return false
	}
	allowed := eaAlterable
	if opSize == SizeB {
		allowed = eaDataAlt
	}
	eaOp, nextPos, rRegs, wRegs, ok := decodeEA(raw, addr, 2, mode, reg, opSize, allowed, AccessRead|AccessWrite)
	if !ok {
		return false
	}
	count := uint8((opcode >> 9) & 0x7)
	if count == 0 {
		count = 8
	}
	if (opcode & 0x0100) == 0 {
		insn.Op = OpADDQ
	} else {
		insn.Op = OpSUBQ
	}
	insn.Suffix = opSize
	insn.Size = nextPos
	insn.NumOps = 2
	insn.Ops[0] = Operand{Mode: EAImm, Access: AccessRead, ImmSize: SizeB, Disp: int32(count), UVal: uint32(count)}
	insn.Ops[1] = eaOp
	insn.ReadRegs = rRegs
	insn.WriteRegs = wRegs | dstRegMask(eaOp)
	return true
}

// decodeLine6 decodes Opcode Line $6 (bits 15..12 = 0110: BRA, BSR, Bcc):
//
//	Bit:  15  14  13  12 | 11  10   9   8 |  7   6   5   4   3   2   1   0
//	     [ 0   1   1   0 ] [  Condition  ] [     8-bit Displacement      ]
func decodeLine6(raw []byte, addr uint32, opcode uint16, insn *Insn) bool {
	cond := uint8((opcode >> 8) & 0xF)
	disp8 := int8(uint8(opcode & 0xFF))
	if disp8 == -1 {
		// 0xFF encodes a 32-bit branch displacement on 68020+, invalid on M68000.
		return false
	}

	insn.Cond = cond
	switch cond {
	case 0: // BRA
		insn.Op = OpBRA
		insn.Flow = FlowBranch
	case 1: // BSR
		insn.Op = OpBSR
		insn.Flow = FlowCall
		insn.ReadRegs = RegA7
		insn.WriteRegs = RegA7
	default: // Conditional Bcc
		insn.Op = OpBcc
		insn.Flow = FlowBranch | FlowCond
	}

	insn.NumOps = 1
	if disp8 == 0 {
		if len(raw) < 4 {
			return false
		}
		disp16 := int16(binary.BigEndian.Uint16(raw[2:4]))
		target := uint32(int32(addr) + 2 + int32(disp16))
		insn.Suffix = SizeW
		insn.Size = 4
		insn.Ops[0] = Operand{Mode: EABranch, Access: AccessAddr, ExtOffset: 2, ExtSize: 2, Disp: int32(disp16), UVal: target}
		return true
	}

	target := uint32(int32(addr) + 2 + int32(disp8))
	insn.Suffix = SizeS
	insn.Size = 2
	insn.Ops[0] = Operand{Mode: EABranch, Access: AccessAddr, Disp: int32(disp8), UVal: target}
	return true
}

// decodeLine7 decodes Opcode Line $7 (bits 15..12 = 0111: MOVEQ #<data8>,Dn):
//
//	Bit:  15  14  13  12 | 11  10   9 |  8 |  7   6   5   4   3   2   1   0
//	     [ 0   1   1   1 ] [    Dn    ] [0] [    Signed 8-bit Immediate   ]
func decodeLine7(opcode uint16, insn *Insn) bool {
	if (opcode & 0x0100) != 0 {
		return false
	}
	dstDn := uint8((opcode >> 9) & 0x7)
	imm8 := uint8(opcode & 0xFF)
	insn.Op = OpMOVEQ
	insn.Suffix = SizeL
	insn.Size = 2
	insn.NumOps = 2
	insn.Ops[0] = Operand{Mode: EAImm, Access: AccessRead, ImmSize: SizeB, Disp: int32(int8(imm8)), UVal: uint32(imm8)}
	insn.Ops[1] = Operand{Mode: EADataReg, Access: AccessWrite, Reg: dstDn}
	insn.WriteRegs = RegD(dstDn)
	return true
}

// decodeLine8 decodes Opcode Line $8 (bits 15..12 = 1000: OR, DIVU, DIVS, SBCD).
func decodeLine8(raw []byte, addr uint32, opcode uint16, insn *Insn) bool {
	rx := uint8((opcode >> 9) & 0x7)
	opmode := (opcode >> 6) & 0x7
	mode := uint8((opcode >> 3) & 0x7)
	ry := uint8(opcode & 0x7)

	switch opmode {
	case 3: // DIVU.W <ea>,Dn
		return decodeMulDiv(raw, addr, OpDIVU, rx, mode, ry, insn)
	case 7: // DIVS.W <ea>,Dn
		return decodeMulDiv(raw, addr, OpDIVS, rx, mode, ry, insn)
	case 4:
		if mode == 0 || mode == 1 {
			return decodeBCD(OpSBCD, rx, mode, ry, insn)
		}
	case 5, 6:
		// Mode 0/1 with opmode 5/6 is 68020+ PACK/UNPK; reject on M68000.
		if mode == 0 || mode == 1 {
			return false
		}
	}

	return decodeLogicalDyadic(raw, addr, opcode, OpOR, insn)
}

// decodeLineC decodes Opcode Line $C (bits 15..12 = 1100: AND, MULU, MULS, ABCD, EXG).
func decodeLineC(raw []byte, addr uint32, opcode uint16, insn *Insn) bool {
	rx := uint8((opcode >> 9) & 0x7)
	opmode := (opcode >> 6) & 0x7
	mode := uint8((opcode >> 3) & 0x7)
	ry := uint8(opcode & 0x7)

	switch opmode {
	case 3: // MULU.W <ea>,Dn
		return decodeMulDiv(raw, addr, OpMULU, rx, mode, ry, insn)
	case 7: // MULS.W <ea>,Dn
		return decodeMulDiv(raw, addr, OpMULS, rx, mode, ry, insn)
	case 4:
		if mode == 0 || mode == 1 {
			return decodeBCD(OpABCD, rx, mode, ry, insn)
		}
	case 5:
		if mode == 0 { // EXG Dx,Dy
			insn.Op = OpEXG
			insn.Size = 2
			insn.NumOps = 2
			insn.Ops[0] = Operand{Mode: EADataReg, Access: AccessRead | AccessWrite, Reg: rx}
			insn.Ops[1] = Operand{Mode: EADataReg, Access: AccessRead | AccessWrite, Reg: ry}
			insn.ReadRegs = RegD(rx) | RegD(ry)
			insn.WriteRegs = RegD(rx) | RegD(ry)
			return true
		}
		if mode == 1 { // EXG Ax,Ay
			insn.Op = OpEXG
			insn.Size = 2
			insn.NumOps = 2
			insn.Ops[0] = Operand{Mode: EAAddrReg, Access: AccessRead | AccessWrite, Reg: rx}
			insn.Ops[1] = Operand{Mode: EAAddrReg, Access: AccessRead | AccessWrite, Reg: ry}
			insn.ReadRegs = RegA(rx) | RegA(ry)
			insn.WriteRegs = RegA(rx) | RegA(ry)
			return true
		}
	case 6:
		if mode == 1 { // EXG Dx,Ay
			insn.Op = OpEXG
			insn.Size = 2
			insn.NumOps = 2
			insn.Ops[0] = Operand{Mode: EADataReg, Access: AccessRead | AccessWrite, Reg: rx}
			insn.Ops[1] = Operand{Mode: EAAddrReg, Access: AccessRead | AccessWrite, Reg: ry}
			insn.ReadRegs = RegD(rx) | RegA(ry)
			insn.WriteRegs = RegD(rx) | RegA(ry)
			return true
		}
		if mode == 0 {
			return false
		}
	}

	return decodeLogicalDyadic(raw, addr, opcode, OpAND, insn)
}

func decodeMulDiv(raw []byte, addr uint32, op Op, dstDn, mode, reg uint8, insn *Insn) bool {
	eaOp, nextPos, rRegs, wRegs, ok := decodeEA(raw, addr, 2, mode, reg, SizeW, eaData, AccessRead)
	if !ok {
		return false
	}
	insn.Op = op
	insn.Suffix = SizeW
	insn.Size = nextPos
	insn.NumOps = 2
	insn.Ops[0] = eaOp
	insn.Ops[1] = Operand{Mode: EADataReg, Access: AccessRead | AccessWrite, Reg: dstDn}
	insn.ReadRegs = rRegs | RegD(dstDn)
	insn.WriteRegs = wRegs | RegD(dstDn)
	return true
}

func decodeBCD(op Op, rx, mode, ry uint8, insn *Insn) bool {
	insn.Op = op
	insn.Suffix = SizeB
	insn.Size = 2
	insn.NumOps = 2
	if mode == 0 {
		insn.Ops[0] = Operand{Mode: EADataReg, Access: AccessRead, Reg: ry}
		insn.Ops[1] = Operand{Mode: EADataReg, Access: AccessRead | AccessWrite, Reg: rx}
		insn.ReadRegs = RegD(ry) | RegD(rx)
		insn.WriteRegs = RegD(rx)
	} else {
		insn.Ops[0] = Operand{Mode: EAPreDec, Access: AccessRead, Reg: ry}
		insn.Ops[1] = Operand{Mode: EAPreDec, Access: AccessRead | AccessWrite, Reg: rx}
		insn.ReadRegs = RegA(ry) | RegA(rx)
		insn.WriteRegs = RegA(ry) | RegA(rx)
	}
	return true
}

func decodeLogicalDyadic(raw []byte, addr uint32, opcode uint16, op Op, insn *Insn) bool {
	rx := uint8((opcode >> 9) & 0x7)
	dir := (opcode >> 8) & 0x1
	opSize, ok := decodeSizeBits(opcode >> 6)
	if !ok {
		return false
	}
	mode := uint8((opcode >> 3) & 0x7)
	reg := uint8(opcode & 0x7)

	allowed := eaData
	eaAccess := AccessRead
	dnAccess := AccessRead | AccessWrite
	if dir != 0 {
		allowed = eaMemAlt
		eaAccess = AccessRead | AccessWrite
		dnAccess = AccessRead
	}
	eaOp, nextPos, rRegs, wRegs, ok := decodeEA(raw, addr, 2, mode, reg, opSize, allowed, eaAccess)
	if !ok {
		return false
	}
	dnOp := Operand{Mode: EADataReg, Access: dnAccess, Reg: rx}
	insn.Op = op
	insn.Suffix = opSize
	insn.Size = nextPos
	insn.NumOps = 2
	insn.ReadRegs = rRegs | RegD(rx)
	insn.WriteRegs = wRegs
	if dir == 0 {
		insn.Ops[0] = eaOp
		insn.Ops[1] = dnOp
		insn.WriteRegs |= RegD(rx)
	} else {
		insn.Ops[0] = dnOp
		insn.Ops[1] = eaOp
	}
	return true
}

type addSubKind struct {
	std, adda, addx Op
}

// decodeAddSub decodes Opcode Lines $9 (SUB/SUBA/SUBX) and $D (ADD/ADDA/ADDX).
func decodeAddSub(raw []byte, addr uint32, opcode uint16, kind addSubKind, insn *Insn) bool {
	rx := uint8((opcode >> 9) & 0x7)
	opmode := (opcode >> 6) & 0x7
	mode := uint8((opcode >> 3) & 0x7)
	ry := uint8(opcode & 0x7)

	// 1. ADDA / SUBA (opmode 3 = .w, opmode 7 = .l).
	if opmode == 3 || opmode == 7 {
		opSize := SizeW
		if opmode == 7 {
			opSize = SizeL
		}
		eaOp, nextPos, rRegs, wRegs, ok := decodeEA(raw, addr, 2, mode, ry, opSize, eaAll, AccessRead)
		if !ok {
			return false
		}
		insn.Op = kind.adda
		insn.Suffix = opSize
		insn.Size = nextPos
		insn.NumOps = 2
		insn.Ops[0] = eaOp
		insn.Ops[1] = Operand{Mode: EAAddrReg, Access: AccessRead | AccessWrite, Reg: rx}
		insn.ReadRegs = rRegs | RegA(rx)
		insn.WriteRegs = wRegs | RegA(rx)
		return true
	}

	dir := (opcode >> 8) & 0x1
	opSize, ok := decodeSizeBits(opcode >> 6)
	if !ok {
		return false
	}

	// 2. ADDX / SUBX (dir == 1 and mode in {000, 001}).
	if dir != 0 && (mode == 0 || mode == 1) {
		insn.Op = kind.addx
		insn.Suffix = opSize
		insn.Size = 2
		insn.NumOps = 2
		if mode == 0 {
			insn.Ops[0] = Operand{Mode: EADataReg, Access: AccessRead, Reg: ry}
			insn.Ops[1] = Operand{Mode: EADataReg, Access: AccessRead | AccessWrite, Reg: rx}
			insn.ReadRegs = RegD(ry) | RegD(rx)
			insn.WriteRegs = RegD(rx)
		} else {
			insn.Ops[0] = Operand{Mode: EAPreDec, Access: AccessRead, Reg: ry}
			insn.Ops[1] = Operand{Mode: EAPreDec, Access: AccessRead | AccessWrite, Reg: rx}
			insn.ReadRegs = RegA(ry) | RegA(rx)
			insn.WriteRegs = RegA(ry) | RegA(rx)
		}
		return true
	}

	// 3. Standard ADD / SUB.
	allowed := eaAll
	if opSize == SizeB {
		allowed = eaData
	}
	eaAccess := AccessRead
	dnAccess := AccessRead | AccessWrite
	if dir != 0 {
		allowed = eaMemAlt
		eaAccess = AccessRead | AccessWrite
		dnAccess = AccessRead
	}
	eaOp, nextPos, rRegs, wRegs, ok := decodeEA(raw, addr, 2, mode, ry, opSize, allowed, eaAccess)
	if !ok {
		return false
	}
	dnOp := Operand{Mode: EADataReg, Access: dnAccess, Reg: rx}
	insn.Op = kind.std
	insn.Suffix = opSize
	insn.Size = nextPos
	insn.NumOps = 2
	insn.ReadRegs = rRegs | RegD(rx)
	insn.WriteRegs = wRegs
	if dir == 0 {
		insn.Ops[0] = eaOp
		insn.Ops[1] = dnOp
		insn.WriteRegs |= RegD(rx)
	} else {
		insn.Ops[0] = dnOp
		insn.Ops[1] = eaOp
	}
	return true
}

// decodeLineB decodes Opcode Line $B (bits 15..12 = 1011: CMP, CMPA, CMPM, EOR).
func decodeLineB(raw []byte, addr uint32, opcode uint16, insn *Insn) bool {
	rx := uint8((opcode >> 9) & 0x7)
	opmode := (opcode >> 6) & 0x7
	mode := uint8((opcode >> 3) & 0x7)
	ry := uint8(opcode & 0x7)

	// 1. CMPA.W (opmode 3) / CMPA.L (opmode 7).
	if opmode == 3 || opmode == 7 {
		opSize := SizeW
		if opmode == 7 {
			opSize = SizeL
		}
		eaOp, nextPos, rRegs, wRegs, ok := decodeEA(raw, addr, 2, mode, ry, opSize, eaAll, AccessRead)
		if !ok {
			return false
		}
		insn.Op = OpCMPA
		insn.Suffix = opSize
		insn.Size = nextPos
		insn.NumOps = 2
		insn.Ops[0] = eaOp
		insn.Ops[1] = Operand{Mode: EAAddrReg, Access: AccessRead, Reg: rx}
		insn.ReadRegs = rRegs | RegA(rx)
		insn.WriteRegs = wRegs
		return true
	}

	dir := (opcode >> 8) & 0x1
	opSize, ok := decodeSizeBits(opcode >> 6)
	if !ok {
		return false
	}

	// 2. CMP.B / CMP.W / CMP.L <ea>,Dn (dir == 0).
	if dir == 0 {
		allowed := eaAll
		if opSize == SizeB {
			allowed = eaData
		}
		eaOp, nextPos, rRegs, wRegs, ok := decodeEA(raw, addr, 2, mode, ry, opSize, allowed, AccessRead)
		if !ok {
			return false
		}
		insn.Op = OpCMP
		insn.Suffix = opSize
		insn.Size = nextPos
		insn.NumOps = 2
		insn.Ops[0] = eaOp
		insn.Ops[1] = Operand{Mode: EADataReg, Access: AccessRead, Reg: rx}
		insn.ReadRegs = rRegs | RegD(rx)
		insn.WriteRegs = wRegs
		return true
	}

	// 3. CMPM (Ay)+,(Ax)+ (dir == 1 and mode == 001).
	if mode == 1 {
		insn.Op = OpCMPM
		insn.Suffix = opSize
		insn.Size = 2
		insn.NumOps = 2
		insn.Ops[0] = Operand{Mode: EAPostInc, Access: AccessRead, Reg: ry}
		insn.Ops[1] = Operand{Mode: EAPostInc, Access: AccessRead, Reg: rx}
		insn.ReadRegs = RegA(ry) | RegA(rx)
		insn.WriteRegs = RegA(ry) | RegA(rx)
		return true
	}

	// 4. EOR Dn,<ea> (dir == 1 and mode != 001).
	eaOp, nextPos, rRegs, wRegs, ok := decodeEA(raw, addr, 2, mode, ry, opSize, eaDataAlt, AccessRead|AccessWrite)
	if !ok {
		return false
	}
	insn.Op = OpEOR
	insn.Suffix = opSize
	insn.Size = nextPos
	insn.NumOps = 2
	insn.Ops[0] = Operand{Mode: EADataReg, Access: AccessRead, Reg: rx}
	insn.Ops[1] = eaOp
	insn.ReadRegs = rRegs | RegD(rx)
	insn.WriteRegs = wRegs | dstRegMask(eaOp)
	return true
}

// decodeLineE decodes Opcode Line $E (bits 15..12 = 1110: Shift and Rotate):
//   - Memory Shift/Rotate (Bits 7..6 == 11, Bit 11 == 0)
//   - Register Shift/Rotate (Bits 7..6 in {00, 01, 10})
func decodeLineE(raw []byte, addr uint32, opcode uint16, insn *Insn) bool {
	if ((opcode >> 6) & 0x3) == 0x3 {
		// Bit 11 == 1 is 68020+ bitfield (BF*) instructions; reject on M68000.
		if (opcode & 0x0800) != 0 {
			return false
		}
		mode := uint8((opcode >> 3) & 0x7)
		reg := uint8(opcode & 0x7)
		eaOp, nextPos, rRegs, wRegs, ok := decodeEA(raw, addr, 2, mode, reg, SizeW, eaMemAlt, AccessRead|AccessWrite)
		if !ok {
			return false
		}
		shIdx := ((opcode >> 8) & 0x1) | (((opcode >> 9) & 0x3) << 1)
		insn.Op = shiftOps[shIdx]
		insn.Suffix = SizeW
		insn.Size = nextPos
		insn.NumOps = 1
		insn.Ops[0] = eaOp
		insn.ReadRegs = rRegs
		insn.WriteRegs = wRegs
		return true
	}

	opSize, ok := decodeSizeBits(opcode >> 6)
	if !ok {
		return false
	}
	shIdx := ((opcode >> 8) & 0x1) | (((opcode >> 3) & 0x3) << 1)
	rx := uint8((opcode >> 9) & 0x7)
	dy := uint8(opcode & 0x7)

	insn.Op = shiftOps[shIdx]
	insn.Suffix = opSize
	insn.Size = 2
	insn.NumOps = 2
	insn.Ops[1] = Operand{Mode: EADataReg, Access: AccessRead | AccessWrite, Reg: dy}
	insn.WriteRegs = RegD(dy)

	if (opcode & 0x0020) != 0 {
		// Dynamic register shift count: Dx,Dy
		insn.Ops[0] = Operand{Mode: EADataReg, Access: AccessRead, Reg: rx}
		insn.ReadRegs = RegD(rx) | RegD(dy)
	} else {
		// Immediate shift count (1..8, where 0 encodes 8): #<count>,Dy
		count := rx
		if count == 0 {
			count = 8
		}
		insn.Ops[0] = Operand{Mode: EAImm, Access: AccessRead, ImmSize: SizeB, Disp: int32(count), UVal: uint32(count)}
		insn.ReadRegs = RegD(dy)
	}
	return true
}
