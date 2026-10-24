package m68k

import (
	"math/bits"
	"strconv"
)

// TimingKind classifies whether an instruction's execution time is a single
// fixed cost, a two-way branch/trap outcome, or a data-dependent range.
type TimingKind uint8

const (
	TimingExact  TimingKind = iota // Fixed cost in Primary (e.g. "12 (3/0)")
	TimingBranch                   // Primary = Taken / True / No-Trap, Secondary = Not-Taken / False / Trap
	TimingRange                    // Primary = Min, Secondary = Max (e.g. MULU/DIVU/dynamic shift)
)

// BusCost represents MC68000 execution clock periods and 16-bit bus cycles: "Cycles (Reads/Writes)".
type BusCost struct {
	Cycles uint8
	Reads  uint8
	Writes uint8
}

func (a BusCost) add(b BusCost) BusCost {
	return BusCost{
		Cycles: a.Cycles + b.Cycles,
		Reads:  a.Reads + b.Reads,
		Writes: a.Writes + b.Writes,
	}
}

// Timing holds the resolved MC68000 timing for a decoded Insn (7 bytes, pointer-free).
type Timing struct {
	Primary   BusCost
	Secondary BusCost
	Kind      TimingKind
}

func exactTiming(c, r, w uint8) Timing {
	return Timing{Primary: BusCost{c, r, w}, Kind: TimingExact}
}

func exactBus(b BusCost) Timing {
	return Timing{Primary: b, Kind: TimingExact}
}

func branchTiming(taken, notTaken BusCost) Timing {
	return Timing{Primary: taken, Secondary: notTaken, Kind: TimingBranch}
}

func rangeTiming(minCost, maxCost BusCost) Timing {
	return Timing{Primary: minCost, Secondary: maxCost, Kind: TimingRange}
}

// String formats the timing for status-bar display:
//   - TimingExact:  "12 (3/0) cyc"
//   - TimingBranch: "10/12 (2/0) cyc" (or "10/8 (2/0,1/0) cyc" when bus counts differ)
//   - TimingRange:  "38-70 (1/0) cyc"
func (t Timing) String() string {
	if t.Primary.Cycles == 0 {
		return "-- cyc"
	}
	var buf [32]byte
	b := buf[:0]
	switch t.Kind {
	case TimingExact:
		b = strconv.AppendUint(b, uint64(t.Primary.Cycles), 10)
		b = append(b, " ("...)
		b = strconv.AppendUint(b, uint64(t.Primary.Reads), 10)
		b = append(b, '/')
		b = strconv.AppendUint(b, uint64(t.Primary.Writes), 10)
		b = append(b, ") cyc"...)
	case TimingBranch:
		b = strconv.AppendUint(b, uint64(t.Primary.Cycles), 10)
		b = append(b, '/')
		b = strconv.AppendUint(b, uint64(t.Secondary.Cycles), 10)
		b = append(b, " ("...)
		b = strconv.AppendUint(b, uint64(t.Primary.Reads), 10)
		b = append(b, '/')
		b = strconv.AppendUint(b, uint64(t.Primary.Writes), 10)
		if t.Secondary.Reads != t.Primary.Reads || t.Secondary.Writes != t.Primary.Writes {
			b = append(b, ',')
			b = strconv.AppendUint(b, uint64(t.Secondary.Reads), 10)
			b = append(b, '/')
			b = strconv.AppendUint(b, uint64(t.Secondary.Writes), 10)
		}
		b = append(b, ") cyc"...)
	case TimingRange:
		b = strconv.AppendUint(b, uint64(t.Primary.Cycles), 10)
		b = append(b, '-')
		b = strconv.AppendUint(b, uint64(t.Secondary.Cycles), 10)
		b = append(b, " ("...)
		b = strconv.AppendUint(b, uint64(t.Primary.Reads), 10)
		b = append(b, '/')
		b = strconv.AppendUint(b, uint64(t.Primary.Writes), 10)
		b = append(b, ") cyc"...)
	}
	return string(b)
}

// Table 1: Effective Address (EA) Cost Table (indexed by EAMode).
var eaCostTable = [16]struct {
	readBW, readL, moveDstBW, moveDstL BusCost
}{
	EADataReg:  {BusCost{0, 0, 0}, BusCost{0, 0, 0}, BusCost{0, 0, 0}, BusCost{0, 0, 0}},
	EAAddrReg:  {BusCost{0, 0, 0}, BusCost{0, 0, 0}, BusCost{0, 0, 0}, BusCost{0, 0, 0}},
	EAAddrInd:  {BusCost{4, 1, 0}, BusCost{8, 2, 0}, BusCost{4, 0, 1}, BusCost{8, 0, 2}},
	EAPostInc:  {BusCost{4, 1, 0}, BusCost{8, 2, 0}, BusCost{4, 0, 1}, BusCost{8, 0, 2}},
	EAPreDec:   {BusCost{6, 1, 0}, BusCost{10, 2, 0}, BusCost{4, 0, 1}, BusCost{8, 0, 2}},
	EADisp16:   {BusCost{8, 2, 0}, BusCost{12, 3, 0}, BusCost{8, 1, 1}, BusCost{12, 1, 2}},
	EAIndex:    {BusCost{10, 2, 0}, BusCost{14, 3, 0}, BusCost{10, 1, 1}, BusCost{14, 1, 2}},
	EAAbsShort: {BusCost{8, 2, 0}, BusCost{12, 3, 0}, BusCost{8, 1, 1}, BusCost{12, 1, 2}},
	EAAbsLong:  {BusCost{12, 3, 0}, BusCost{16, 4, 0}, BusCost{12, 2, 1}, BusCost{16, 2, 2}},
	EAPCDisp16: {BusCost{8, 2, 0}, BusCost{12, 3, 0}, BusCost{}, BusCost{}},
	EAPCIndex:  {BusCost{10, 2, 0}, BusCost{14, 3, 0}, BusCost{}, BusCost{}},
	EAImm:      {BusCost{4, 1, 0}, BusCost{8, 2, 0}, BusCost{}, BusCost{}},
}

func eaRead(m EAMode, isLong bool) BusCost {
	if isLong {
		return eaCostTable[m&0xF].readL
	}
	return eaCostTable[m&0xF].readBW
}

func eaMoveDst(m EAMode, isLong bool) BusCost {
	if isLong {
		return eaCostTable[m&0xF].moveDstL
	}
	return eaCostTable[m&0xF].moveDstBW
}

// Table 3: Address-Only & Multi-Register Table (JMP, JSR, LEA, PEA, MOVEM base).
var addrOnlyTable = [16]struct {
	jmp, jsr, lea, pea, movemMR, movemRM BusCost
}{
	EAAddrInd:  {BusCost{8, 2, 0}, BusCost{16, 2, 2}, BusCost{4, 1, 0}, BusCost{12, 1, 2}, BusCost{12, 3, 0}, BusCost{8, 2, 0}},
	EAPostInc:  {BusCost{}, BusCost{}, BusCost{}, BusCost{}, BusCost{12, 3, 0}, BusCost{}},
	EAPreDec:   {BusCost{}, BusCost{}, BusCost{}, BusCost{}, BusCost{}, BusCost{8, 2, 0}},
	EADisp16:   {BusCost{10, 2, 0}, BusCost{18, 2, 2}, BusCost{8, 2, 0}, BusCost{16, 2, 2}, BusCost{16, 4, 0}, BusCost{12, 3, 0}},
	EAIndex:    {BusCost{14, 3, 0}, BusCost{22, 2, 2}, BusCost{12, 2, 0}, BusCost{20, 2, 2}, BusCost{18, 4, 0}, BusCost{14, 3, 0}},
	EAAbsShort: {BusCost{10, 2, 0}, BusCost{18, 2, 2}, BusCost{8, 2, 0}, BusCost{16, 2, 2}, BusCost{16, 4, 0}, BusCost{12, 3, 0}},
	EAAbsLong:  {BusCost{12, 3, 0}, BusCost{20, 3, 2}, BusCost{12, 3, 0}, BusCost{20, 3, 2}, BusCost{20, 5, 0}, BusCost{16, 4, 0}},
	EAPCDisp16: {BusCost{10, 2, 0}, BusCost{18, 2, 2}, BusCost{8, 2, 0}, BusCost{16, 2, 2}, BusCost{16, 4, 0}, BusCost{}},
	EAPCIndex:  {BusCost{14, 3, 0}, BusCost{22, 2, 2}, BusCost{12, 2, 0}, BusCost{20, 2, 2}, BusCost{18, 4, 0}, BusCost{}},
}

// Timing computes the MC68000 execution timing for the decoded instruction.
func (in *Insn) Timing() Timing {
	isL := in.Suffix == SizeL
	op0, op1 := in.Ops[0], in.Ops[1]

	switch in.Op {
	// --- 2A. Data Movement ---
	case OpMOVE, OpMOVEA:
		if op0.Mode == EASpecialReg {
			if SpecialReg(op0.Reg) == SpecUSP { // MOVE USP,An
				return exactTiming(4, 1, 0)
			}
			// MOVE from SR
			if op1.Mode == EADataReg {
				return exactTiming(6, 1, 0)
			}
			return exactBus(BusCost{8, 1, 1}.add(eaRead(op1.Mode, false)))
		}
		if op1.Mode == EASpecialReg {
			if SpecialReg(op1.Reg) == SpecUSP { // MOVE An,USP
				return exactTiming(4, 1, 0)
			}
			// MOVE to CCR / MOVE to SR
			return exactBus(BusCost{12, 1, 0}.add(eaRead(op0.Mode, false)))
		}
		return exactBus(BusCost{4, 1, 0}.add(eaRead(op0.Mode, isL)).add(eaMoveDst(op1.Mode, isL)))

	case OpMOVEQ, OpSWAP, OpEXT, OpNOP:
		return exactTiming(4, 1, 0)

	case OpEXG:
		return exactTiming(6, 1, 0)

	case OpMOVEP:
		if op0.Mode == EADataReg { // Dn,d16(An)
			if isL {
				return exactTiming(24, 2, 4)
			}
			return exactTiming(16, 2, 2)
		}
		if isL { // d16(An),Dn
			return exactTiming(24, 6, 0)
		}
		return exactTiming(16, 4, 0)

	// --- 2B. Standard Arithmetic & Logical (ALU) ---
	case OpADD, OpSUB, OpAND, OpOR:
		if op1.Mode == EADataReg { // EA,Dn
			base := BusCost{4, 1, 0}
			if isL {
				base.Cycles = 6
				if op0.Mode == EADataReg || op0.Mode == EAAddrReg || op0.Mode == EAImm {
					base.Cycles += 2
				}
			}
			return exactBus(base.add(eaRead(op0.Mode, isL)))
		}
		// Dn,Mem
		base := BusCost{8, 1, 1}
		if isL {
			base = BusCost{12, 1, 2}
		}
		return exactBus(base.add(eaRead(op1.Mode, isL)))

	case OpADDA, OpSUBA:
		base := BusCost{8, 1, 0}
		if isL {
			base.Cycles = 6
			if op0.Mode == EADataReg || op0.Mode == EAAddrReg || op0.Mode == EAImm {
				base.Cycles += 2
			}
		}
		return exactBus(base.add(eaRead(op0.Mode, isL)))

	case OpEOR:
		if op1.Mode == EADataReg {
			if isL {
				return exactTiming(8, 1, 0)
			}
			return exactTiming(4, 1, 0)
		}
		base := BusCost{8, 1, 1}
		if isL {
			base = BusCost{12, 1, 2}
		}
		return exactBus(base.add(eaRead(op1.Mode, isL)))

	case OpCMP:
		base := BusCost{4, 1, 0}
		if isL {
			base.Cycles = 6
		}
		return exactBus(base.add(eaRead(op0.Mode, isL)))

	case OpCMPA:
		return exactBus(BusCost{6, 1, 0}.add(eaRead(op0.Mode, isL)))

	case OpMULU, OpMULS:
		ea := eaRead(op0.Mode, false)
		if op0.Mode == EAImm {
			v := uint16(op0.UVal)
			var n uint8
			if in.Op == OpMULU {
				n = uint8(bits.OnesCount16(v))
			} else {
				n = uint8(bits.OnesCount16(v ^ (v << 1)))
			}
			return exactBus(BusCost{38 + 2*n, 1, 0}.add(ea))
		}
		return rangeTiming(BusCost{38, 1, 0}.add(ea), BusCost{70, 1, 0}.add(ea))

	case OpDIVU:
		ea := eaRead(op0.Mode, false)
		return rangeTiming(BusCost{76, 1, 0}.add(ea), BusCost{140, 1, 0}.add(ea))

	case OpDIVS:
		ea := eaRead(op0.Mode, false)
		return rangeTiming(BusCost{120, 1, 0}.add(ea), BusCost{158, 1, 0}.add(ea))

	// --- 2C. Immediate & Quick ALU ---
	case OpADDI, OpSUBI, OpANDI, OpORI, OpEORI:
		if op1.Mode == EASpecialReg { // #xxx,CCR / #xxx,SR
			return exactTiming(20, 3, 0)
		}
		if op1.Mode == EADataReg {
			if isL {
				return exactTiming(16, 3, 0)
			}
			return exactTiming(8, 2, 0)
		}
		base := BusCost{12, 2, 1}
		if isL {
			base = BusCost{20, 3, 2}
		}
		return exactBus(base.add(eaRead(op1.Mode, isL)))

	case OpCMPI:
		if op1.Mode == EADataReg {
			if isL {
				return exactTiming(14, 3, 0)
			}
			return exactTiming(8, 2, 0)
		}
		base := BusCost{8, 2, 0}
		if isL {
			base = BusCost{12, 3, 0}
		}
		return exactBus(base.add(eaRead(op1.Mode, isL)))

	case OpADDQ, OpSUBQ:
		if op1.Mode == EADataReg {
			if isL {
				return exactTiming(8, 1, 0)
			}
			return exactTiming(4, 1, 0)
		}
		if op1.Mode == EAAddrReg {
			return exactTiming(8, 1, 0)
		}
		base := BusCost{8, 1, 1}
		if isL {
			base = BusCost{12, 1, 2}
		}
		return exactBus(base.add(eaRead(op1.Mode, isL)))

	// --- 2D. Single-Operand, Shift/Rotate, Bit & Multi-Precision ---
	case OpCLR, OpNEG, OpNEGX, OpNOT:
		if op0.Mode == EADataReg {
			if isL {
				return exactTiming(6, 1, 0)
			}
			return exactTiming(4, 1, 0)
		}
		base := BusCost{8, 1, 1}
		if isL {
			base = BusCost{12, 1, 2}
		}
		return exactBus(base.add(eaRead(op0.Mode, isL)))

	case OpNBCD:
		if op0.Mode == EADataReg {
			return exactTiming(6, 1, 0)
		}
		return exactBus(BusCost{8, 1, 1}.add(eaRead(op0.Mode, false)))

	case OpScc:
		if op0.Mode == EADataReg {
			switch in.Cond {
			case 0: // ST Dn
				return exactTiming(6, 1, 0)
			case 1: // SF Dn
				return exactTiming(4, 1, 0)
			default:
				return branchTiming(BusCost{6, 1, 0}, BusCost{4, 1, 0})
			}
		}
		return exactBus(BusCost{8, 1, 1}.add(eaRead(op0.Mode, false)))

	case OpTAS:
		if op0.Mode == EADataReg {
			return exactTiming(4, 1, 0)
		}
		return exactBus(BusCost{10, 1, 1}.add(eaRead(op0.Mode, false)))

	case OpTST:
		if op0.Mode == EADataReg {
			return exactTiming(4, 1, 0)
		}
		return exactBus(BusCost{4, 1, 0}.add(eaRead(op0.Mode, isL)))

	case OpASR, OpASL, OpLSR, OpLSL, OpROXR, OpROXL, OpROR, OpROL:
		if in.NumOps == 1 { // Memory shift by 1 (EA in Ops[0])
			return exactBus(BusCost{8, 1, 1}.add(eaRead(op0.Mode, false)))
		}
		base := uint8(6)
		if isL {
			base = 8
		}
		if op0.Mode == EAImm {
			n := uint8(op0.UVal)
			return exactTiming(base+2*n, 1, 0)
		}
		return rangeTiming(BusCost{base, 1, 0}, BusCost{base + 126, 1, 0})

	case OpBCHG, OpBSET, OpBCLR, OpBTST:
		isStatic := op0.Mode == EAImm
		if op1.Mode == EADataReg { // Register target (Long)
			switch in.Op {
			case OpBTST:
				if isStatic {
					return exactTiming(10, 2, 0)
				}
				return exactTiming(6, 1, 0)
			case OpBCLR:
				if isStatic {
					return exactTiming(14, 2, 0)
				}
				return exactTiming(10, 1, 0)
			default: // OpBCHG, OpBSET
				if isStatic {
					return exactTiming(12, 2, 0)
				}
				return exactTiming(8, 1, 0)
			}
		}
		// Memory target (Byte)
		ea := eaRead(op1.Mode, false)
		if in.Op == OpBTST {
			if isStatic {
				return exactBus(BusCost{8, 2, 0}.add(ea))
			}
			return exactBus(BusCost{4, 1, 0}.add(ea))
		}
		if isStatic {
			return exactBus(BusCost{12, 2, 1}.add(ea))
		}
		return exactBus(BusCost{8, 1, 1}.add(ea))

	case OpADDX, OpSUBX:
		if op0.Mode == EADataReg {
			if isL {
				return exactTiming(8, 1, 0)
			}
			return exactTiming(4, 1, 0)
		}
		if isL {
			return exactTiming(30, 5, 2)
		}
		return exactTiming(18, 3, 1)

	case OpABCD, OpSBCD:
		if op0.Mode == EADataReg {
			return exactTiming(6, 1, 0)
		}
		return exactTiming(18, 3, 1)

	case OpCMPM:
		if isL {
			return exactTiming(20, 5, 0)
		}
		return exactTiming(12, 3, 0)

	// --- 2E. Branches, Subroutines & Miscellaneous ---
	case OpBRA:
		return exactTiming(10, 2, 0)

	case OpBSR:
		return exactTiming(18, 2, 2)

	case OpBcc:
		if in.Suffix == SizeW {
			return branchTiming(BusCost{10, 2, 0}, BusCost{12, 2, 0})
		}
		return branchTiming(BusCost{10, 2, 0}, BusCost{8, 1, 0})

	case OpDBcc:
		if in.Cond == 0 { // DBT (condition always true -> exits immediately)
			return exactTiming(12, 2, 0)
		}
		return branchTiming(BusCost{10, 2, 0}, BusCost{14, 3, 0})

	case OpRTS:
		return exactTiming(16, 4, 0)

	case OpRTE, OpRTR:
		return exactTiming(20, 5, 0)

	case OpLINK:
		return exactTiming(16, 2, 2)

	case OpUNLK:
		return exactTiming(12, 3, 0)

	case OpCHK:
		ea := eaRead(op0.Mode, false)
		return branchTiming(BusCost{10, 1, 0}.add(ea), BusCost{44, 5, 3}.add(ea))

	case OpTRAP:
		return exactTiming(38, 4, 3)

	case OpTRAPV:
		return branchTiming(BusCost{4, 1, 0}, BusCost{34, 4, 3})

	case OpILLEGAL:
		return exactTiming(34, 4, 3)

	case OpSTOP:
		return exactTiming(4, 0, 0)

	case OpRESET:
		return exactTiming(132, 1, 0)

	// --- 3. Address-Only & Multi-Register (JMP, JSR, LEA, PEA, MOVEM) ---
	case OpJMP:
		return exactBus(addrOnlyTable[op0.Mode&0xF].jmp)

	case OpJSR:
		return exactBus(addrOnlyTable[op0.Mode&0xF].jsr)

	case OpLEA:
		return exactBus(addrOnlyTable[op0.Mode&0xF].lea)

	case OpPEA:
		return exactBus(addrOnlyTable[op0.Mode&0xF].pea)

	case OpMOVEM:
		if op1.Mode == EARegList { // Memory -> Register (EA in op0, mask in op1)
			n := uint8(bits.OnesCount16(uint16(op1.UVal)))
			base := addrOnlyTable[op0.Mode&0xF].movemMR
			if isL {
				return exactBus(base.add(BusCost{8 * n, 2 * n, 0}))
			}
			return exactBus(base.add(BusCost{4 * n, n, 0}))
		}
		// Register -> Memory (mask in op0, EA in op1)
		n := uint8(bits.OnesCount16(uint16(op0.UVal)))
		base := addrOnlyTable[op1.Mode&0xF].movemRM
		if isL {
			return exactBus(base.add(BusCost{8 * n, 0, 2 * n}))
		}
		return exactBus(base.add(BusCost{4 * n, 0, n}))
	}

	return Timing{}
}
