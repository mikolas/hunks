// Package m68k implements a zero-allocation Motorola 68000 instruction decoder
// and vasmm68k_mot syntax formatter tailored for static binary analysis.
//
// # Operation Word Architecture
//
// Every Motorola 68000 instruction is encoded as 1 to 5 big-endian 16-bit words
// (2 to 10 bytes) aligned on an even address boundary. The first 16-bit word is
// the operation word:
//
//	Bit:  15  14  13  12 | 11  10   9 |  8   7   6 |  5   4   3 |  2   1   0
//	     [  Opcode Line ] [ Rx / Sub ] [  Op-Mode ] [  EA Mode ] [  EA Reg  ]
//
// Bits 15..12 partition the instruction set into 16 primary functional lines ($0..$F),
// while bits 5..0 encode a 6-bit Effective Address (<ea>) composed of a 3-bit Mode
// (bits 5..3) and 3-bit Register/Sub-mode (bits 2..0). Additional 16-bit extension
// words follow immediately for immediate constants, 16-bit displacements, 8-bit
// indexed brief extension words, absolute addresses, MOVEM register masks, and
// 16-bit branch displacements.
package m68k

import (
	"strconv"
	"strings"
)

// Size represents the operand width or branch displacement size suffix of an instruction.
type Size uint8

const (
	SizeNone Size = iota // Unsized instruction (e.g. RTS, NOP, SWAP, BTST, DBRA)
	SizeB                // .b (8-bit byte)
	SizeW                // .w (16-bit word)
	SizeL                // .l (32-bit longword)
	SizeS                // .s (8-bit short PC-relative branch displacement)
)

// Op identifies the canonical Motorola 68000 operation of a decoded instruction.
type Op uint8

const (
	OpInvalid Op = iota
	// Line $0: Immediate ALU, Bit Manipulation, MOVEP
	OpORI
	OpANDI
	OpSUBI
	OpADDI
	OpEORI
	OpCMPI
	OpBTST
	OpBCHG
	OpBCLR
	OpBSET
	OpMOVEP
	// Lines $1, $2, $3: MOVE / MOVEA
	OpMOVE
	OpMOVEA
	// Line $4: Miscellaneous & System Control
	OpNEGX
	OpCLR
	OpNEG
	OpNOT
	OpTST
	OpNBCD
	OpSWAP
	OpPEA
	OpEXT
	OpMOVEM
	OpTAS
	OpILLEGAL
	OpTRAP
	OpLINK
	OpUNLK
	OpRESET
	OpNOP
	OpSTOP
	OpRTE
	OpRTS
	OpTRAPV
	OpRTR
	OpJSR
	OpJMP
	OpCHK
	OpLEA
	// Line $5: ADDQ, SUBQ, Scc, DBcc
	OpADDQ
	OpSUBQ
	OpScc
	OpDBcc
	// Line $6: BRA, BSR, Bcc
	OpBRA
	OpBSR
	OpBcc
	// Line $7: MOVEQ
	OpMOVEQ
	// Line $8: OR, DIVU, DIVS, SBCD
	OpOR
	OpDIVU
	OpDIVS
	OpSBCD
	// Line $9: SUB, SUBA, SUBX
	OpSUB
	OpSUBA
	OpSUBX
	// Line $B: CMP, CMPA, CMPM, EOR
	OpCMP
	OpCMPA
	OpCMPM
	OpEOR
	// Line $C: AND, MULU, MULS, ABCD, EXG
	OpAND
	OpMULU
	OpMULS
	OpABCD
	OpEXG
	// Line $D: ADD, ADDA, ADDX
	OpADD
	OpADDA
	OpADDX
	// Line $E: Shift and Rotate
	OpASR
	OpASL
	OpLSR
	OpLSL
	OpROXR
	OpROXL
	OpROR
	OpROL
)

var opBaseMnemonics = [...]string{
	OpORI:     "ori",
	OpANDI:    "andi",
	OpSUBI:    "subi",
	OpADDI:    "addi",
	OpEORI:    "eori",
	OpCMPI:    "cmpi",
	OpBTST:    "btst",
	OpBCHG:    "bchg",
	OpBCLR:    "bclr",
	OpBSET:    "bset",
	OpMOVEP:   "movep",
	OpMOVE:    "move",
	OpMOVEA:   "movea",
	OpNEGX:    "negx",
	OpCLR:     "clr",
	OpNEG:     "neg",
	OpNOT:     "not",
	OpTST:     "tst",
	OpNBCD:    "nbcd",
	OpSWAP:    "swap",
	OpPEA:     "pea",
	OpEXT:     "ext",
	OpMOVEM:   "movem",
	OpTAS:     "tas",
	OpILLEGAL: "illegal",
	OpTRAP:    "trap",
	OpLINK:    "link",
	OpUNLK:    "unlk",
	OpRESET:   "reset",
	OpNOP:     "nop",
	OpSTOP:    "stop",
	OpRTE:     "rte",
	OpRTS:     "rts",
	OpTRAPV:   "trapv",
	OpRTR:     "rtr",
	OpJSR:     "jsr",
	OpJMP:     "jmp",
	OpCHK:     "chk",
	OpLEA:     "lea",
	OpADDQ:    "addq",
	OpSUBQ:    "subq",
	OpScc:     "scc",
	OpDBcc:    "dbra",
	OpBRA:     "bra",
	OpBSR:     "bsr",
	OpBcc:     "bne",
	OpMOVEQ:   "moveq",
	OpOR:      "or",
	OpDIVU:    "divu",
	OpDIVS:    "divs",
	OpSBCD:    "sbcd",
	OpSUB:     "sub",
	OpSUBA:    "suba",
	OpSUBX:    "subx",
	OpCMP:     "cmp",
	OpCMPA:    "cmpa",
	OpCMPM:    "cmpm",
	OpEOR:     "eor",
	OpAND:     "and",
	OpMULU:    "mulu",
	OpMULS:    "muls",
	OpABCD:    "abcd",
	OpEXG:     "exg",
	OpADD:     "add",
	OpADDA:    "adda",
	OpADDX:    "addx",
	OpASR:     "asr",
	OpASL:     "asl",
	OpLSR:     "lsr",
	OpLSL:     "lsl",
	OpROXR:    "roxr",
	OpROXL:    "roxl",
	OpROR:     "ror",
	OpROL:     "rol",
}

// String returns the canonical base mnemonic for op (or "" for OpInvalid).
func (op Op) String() string {
	if int(op) < len(opBaseMnemonics) {
		return opBaseMnemonics[op]
	}
	return ""
}

// IsQuickOrShift returns true if op is a quick-immediate or shift/rotate instruction
// whose immediate operand is a small count/constant rather than a 32-bit address.
func (op Op) IsQuickOrShift() bool {
	switch op {
	case OpADDQ, OpSUBQ, OpMOVEQ, OpASR, OpASL, OpLSR, OpLSL, OpROXR, OpROXL, OpROR, OpROL:
		return true
	default:
		return false
	}
}

// HasLongEA returns true if an instruction with operation op and size suffix sz
// can take a 32-bit immediate address operand (e.g. MOVE.L #addr, LEA, PEA).
func (op Op) HasLongEA(sz Size) bool {
	return !op.IsQuickOrShift() && (sz == SizeL || op == OpLEA || op == OpPEA)
}

// mnemonicToOp maps a vasmm68k_mot base mnemonic (no size suffix) to its canonical Op.
// It is derived once from the forward opBaseMnemonics table plus the condition-code name
// tables (bccNames/sccNames/dbccNames), so the name↔Op relation lives in a single place.
//
// Overlap handling: the forward table is inverted first, which maps the distinct branch
// ops "bra"->OpBRA and "bsr"->OpBSR (and the representative "bne"->OpBcc, "scc"->OpScc,
// "dbra"->OpDBcc). The per-condition families are then folded in only for names not
// already present, so "bra"/"bsr" keep their distinct ops while every other condition
// spelling resolves to OpBcc/OpScc/OpDBcc.
var mnemonicToOp = func() map[string]Op {
	m := make(map[string]Op, len(opBaseMnemonics)+40)
	for op, name := range opBaseMnemonics {
		if name != "" {
			m[name] = Op(op)
		}
	}
	addAll := func(names [16]string, op Op) {
		for _, n := range names {
			if _, exists := m[n]; !exists {
				m[n] = op
			}
		}
	}
	addAll(bccNames, OpBcc)   // bhi,bls,bhs,... (bra/bsr already mapped to OpBRA/OpBSR)
	addAll(sccNames, OpScc)   // st,sf,shi,...
	addAll(dbccNames, OpDBcc) // dbt,dbf,dbhi,...
	// Carry-condition Bcc aliases not spelled in bccNames (which uses bhs/blo).
	m["bcc"] = OpBcc
	m["bcs"] = OpBcc
	return m
}()

// ParseMnemonic parses a vasmm68k_mot mnemonic string (with optional ".b"/".w"/".l"/".s" suffix)
// into its canonical (Op, Size) pair.
func ParseMnemonic(mnem string) (Op, Size) {
	base, suf, hasDot := strings.Cut(mnem, ".")
	var sz Size
	if hasDot {
		switch suf {
		case "b":
			sz = SizeB
		case "w":
			sz = SizeW
		case "l":
			sz = SizeL
		case "s":
			sz = SizeS
		}
	}
	if op, ok := mnemonicToOp[base]; ok {
		return op, sz
	}
	return OpInvalid, sz
}

// Suffix returns the lowercase vasmm68k_mot size suffix without a leading dot ("b", "w", "l", "s", or "").
func (s Size) Suffix() string {
	switch s {
	case SizeB:
		return "b"
	case SizeW:
		return "w"
	case SizeL:
		return "l"
	case SizeS:
		return "s"
	default:
		return ""
	}
}

// DotSuffix returns the lowercase vasmm68k_mot size suffix with a leading dot (".b", ".w", ".l", ".s", or "").
func (s Size) DotSuffix() string {
	switch s {
	case SizeB:
		return ".b"
	case SizeW:
		return ".w"
	case SizeL:
		return ".l"
	case SizeS:
		return ".s"
	default:
		return ""
	}
}

// Bytes returns the operand width in bytes (1, 2, or 4), defaulting to 2 for unsized operations.
func (s Size) Bytes() int {
	switch s {
	case SizeB:
		return 1
	case SizeW:
		return 2
	case SizeL:
		return 4
	default:
		return 2
	}
}

// FlowFlags classifies the control-flow behavior of a decoded M68000 instruction.
type FlowFlags uint8

const (
	FlowCall       FlowFlags = 1 << iota // Subroutine call (BSR, JSR)
	FlowBranch                           // Jump or branch (BRA, JMP, Bcc, DBcc)
	FlowCond                             // Conditional branch (Bcc except BRA/BSR, DBcc)
	FlowReturn                           // Subroutine or exception return (RTS, RTE, RTR)
	FlowTrap                             // Exception trap (TRAP, TRAPV, CHK, ILLEGAL)
	FlowStop                             // Processor halt (STOP, ILLEGAL)
	FlowPrivileged                       // Supervisor-only instruction (RTE, RESET, STOP, MOVE USP, ORI/ANDI/EORI/MOVE to SR)
)

// RegMask is a canonical 16-bit bitmask of M68000 general-purpose registers:
//   - Bits 0..7  represent D0..D7
//   - Bits 8..15 represent A0..A7
type RegMask uint16

const (
	RegA4 RegMask = 1 << (8 + 4)
	RegA5 RegMask = 1 << (8 + 5)
	RegA6 RegMask = 1 << (8 + 6)
	RegA7 RegMask = 1 << (8 + 7)
)

var (
	regDNames     = [8]string{"d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7"}
	regANames     = [8]string{"a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"}
	regAIndNames  = [8]string{"(a0)", "(a1)", "(a2)", "(a3)", "(a4)", "(a5)", "(a6)", "(a7)"}
	regAPostNames = [8]string{"(a0)+", "(a1)+", "(a2)+", "(a3)+", "(a4)+", "(a5)+", "(a6)+", "(a7)+"}
	regAPreNames  = [8]string{"-(a0)", "-(a1)", "-(a2)", "-(a3)", "-(a4)", "-(a5)", "-(a6)", "-(a7)"}
	immHexNames   = [16]string{
		"#$0", "#$1", "#$2", "#$3", "#$4", "#$5", "#$6", "#$7",
		"#$8", "#$9", "#$A", "#$B", "#$C", "#$D", "#$E", "#$F",
	}
	opFullMnemonics [len(opBaseMnemonics)][5]string
)

func init() {
	for op, base := range opBaseMnemonics {
		if base == "" {
			continue
		}
		opFullMnemonics[op][SizeNone] = base
		opFullMnemonics[op][SizeB] = base + ".b"
		opFullMnemonics[op][SizeW] = base + ".w"
		opFullMnemonics[op][SizeL] = base + ".l"
		opFullMnemonics[op][SizeS] = base + ".s"
	}
}

// RegD returns the RegMask bit for data register Dn (0..7).
func RegD(n uint8) RegMask {
	return 1 << (n & 7)
}

// RegA returns the RegMask bit for address register An (0..7).
func RegA(n uint8) RegMask {
	return 1 << (8 + (n & 7))
}

// RegDName returns the canonical lowercase register name ("d0".."d7") for data register n & 7.
func RegDName(n uint8) string {
	return regDNames[n&7]
}

// RegAName returns the canonical lowercase register name ("a0".."a7") for address register n & 7.
func RegAName(n uint8) string {
	return regANames[n&7]
}

// FormatRegList formats a canonical 16-bit register mask (bits 0..7 = D0..D7,
// bits 8..15 = A0..A7) into standard Motorola MOVEM range notation
// (e.g. "d0-d3/d7/a0-a2/a6").
func FormatRegList(mask RegMask) string {
	if mask == 0 {
		return ""
	}
	var sb strings.Builder
	writeGroup := func(prefix byte, bits uint8) {
		i := uint8(0)
		for i < 8 {
			if (bits & (1 << i)) == 0 {
				i++
				continue
			}
			start := i
			for i+1 < 8 && (bits&(1<<(i+1))) != 0 {
				i++
			}
			end := i
			if sb.Len() > 0 {
				sb.WriteByte('/')
			}
			sb.WriteByte(prefix)
			sb.WriteByte('0' + start)
			if end > start {
				sb.WriteByte('-')
				sb.WriteByte(prefix)
				sb.WriteByte('0' + end)
			}
			i++
		}
	}
	writeGroup('d', uint8(mask&0xFF))
	writeGroup('a', uint8((mask>>8)&0xFF))
	return sb.String()
}

// EAMode identifies the addressing mode of a decoded M68000 operand.
type EAMode uint8

const (
	EANone       EAMode = iota
	EADataReg           // Mode 000: Dn
	EAAddrReg           // Mode 001: An
	EAAddrInd           // Mode 010: (An)
	EAPostInc           // Mode 011: (An)+
	EAPreDec            // Mode 100: -(An)
	EADisp16            // Mode 101: d16(An)
	EAIndex             // Mode 110: d8(An,Xn.w/.l)
	EAAbsShort          // Mode 111 / Reg 000: (xxx).w
	EAAbsLong           // Mode 111 / Reg 001: (xxx).l
	EAPCDisp16          // Mode 111 / Reg 010: d16(pc)
	EAPCIndex           // Mode 111 / Reg 011: d8(pc,Xn.w/.l)
	EAImm               // Mode 111 / Reg 100 or embedded quick/bit/trap immediate: #<data>
	EABranch            // PC-relative branch target (Bcc, BRA, BSR, DBcc)
	EARegList           // MOVEM 16-bit register list mask (canonical RegMask in UVal)
	EASpecialReg        // Special register (CCR, SR, USP)
)

// String returns the canonical Motorola addressing mode notation (e.g. "(An)", "d16(An)", "d8(PC,Xn)").
func (m EAMode) String() string {
	switch m {
	case EADataReg:
		return "Dn"
	case EAAddrReg:
		return "An"
	case EAAddrInd:
		return "(An)"
	case EAPostInc:
		return "(An)+"
	case EAPreDec:
		return "-(An)"
	case EADisp16:
		return "d16(An)"
	case EAIndex:
		return "d8(An,Xn)"
	case EAAbsShort:
		return "(xxx).w"
	case EAAbsLong:
		return "(xxx).l"
	case EAPCDisp16:
		return "d16(PC)"
	case EAPCIndex:
		return "d8(PC,Xn)"
	case EAImm:
		return "#<data>"
	case EABranch:
		return "<label>"
	case EARegList:
		return "<reglist>"
	case EASpecialReg:
		return "<spec>"
	default:
		return ""
	}
}

// AccessFlags classifies how an instruction accesses an Effective Address operand.
type AccessFlags uint8

const (
	AccessNone  AccessFlags = 0
	AccessRead  AccessFlags = 1 << iota // Operand value is read
	AccessWrite                         // Operand value is written/modified
	AccessAddr                          // Effective address is computed without memory dereference (LEA, PEA, JMP, JSR, Bcc)
)

// SpecialReg identifies the non-general register referenced by an EASpecialReg operand.
type SpecialReg uint8

const (
	SpecNone SpecialReg = iota
	SpecCCR             // Condition Code Register (8-bit low half of SR)
	SpecSR              // Status Register (16-bit)
	SpecUSP             // User Stack Pointer (32-bit)
)

// String returns the lowercase assembler name of the special register ("ccr", "sr", "usp").
func (sr SpecialReg) String() string {
	switch sr {
	case SpecCCR:
		return "ccr"
	case SpecSR:
		return "sr"
	case SpecUSP:
		return "usp"
	default:
		return ""
	}
}

// Operand holds a single decoded M68000 instruction operand without heap allocations.
//
// ExtOffset records the exact byte offset (2, 4, or 6) from the start of the
// instruction where this operand's extension word(s) begin, or 0 if the operand
// is encoded entirely inside the 16-bit operation word.
type Operand struct {
	Mode      EAMode
	Access    AccessFlags
	Reg       uint8  // 0..7 for Dn/An, or uint8(SpecialReg) for EASpecialReg
	IndexReg  uint8  // 0..7 = D0..D7, 8..15 = A0..A7 (for EAIndex / EAPCIndex)
	IndexSize Size   // SizeW or SizeL (for EAIndex / EAPCIndex)
	ImmSize   Size   // SizeB, SizeW, or SizeL (for EAImm)
	ExtOffset uint8  // Byte offset from Insn.Addr (0, 2, 4, 6) of this operand's extension word(s)
	ExtSize   uint8  // Byte length of this operand's extension word(s): 0, 2, or 4
	Disp      int32  // Sign-extended displacement (d8, d16, branch disp, or signed quick/moveq value)
	UVal      uint32 // Unsigned immediate, resolved AbsShort/AbsLong/PC/Branch address, or MOVEM RegMask
}

// IndexRegName returns the lowercase register name ("d0".."d7", "a0".."a7") of the index register.
func (op Operand) IndexRegName() string {
	if op.IndexReg >= 8 {
		return RegAName(op.IndexReg - 8)
	}
	return RegDName(op.IndexReg)
}

const hexUpper = "0123456789ABCDEF"

func appendHexUpper(dst []byte, v uint32) []byte {
	if v == 0 {
		return append(dst, '0')
	}
	var tmp [8]byte
	i := 8
	for v > 0 {
		i--
		tmp[i] = hexUpper[v&0xF]
		v >>= 4
	}
	return append(dst, tmp[i:]...)
}

// FormatASM formats the operand into literal, label-free Motorola vasmm68k_mot syntax
// suitable for direct binary round-trip verification at Insn.Addr.
func (op Operand) FormatASM(insnOp Op) string {
	switch op.Mode {
	case EADataReg:
		return RegDName(op.Reg)
	case EAAddrReg:
		return RegAName(op.Reg)
	case EAAddrInd:
		return regAIndNames[op.Reg&7]
	case EAPostInc:
		return regAPostNames[op.Reg&7]
	case EAPreDec:
		return regAPreNames[op.Reg&7]
	case EADisp16:
		var buf [24]byte
		b := strconv.AppendInt(buf[:0], int64(op.Disp), 10)
		b = append(b, regAIndNames[op.Reg&7]...)
		return string(b)
	case EAIndex:
		var buf [32]byte
		b := strconv.AppendInt(buf[:0], int64(op.Disp), 10)
		b = append(b, '(')
		b = append(b, RegAName(op.Reg)...)
		b = append(b, ',')
		b = append(b, op.IndexRegName()...)
		b = append(b, op.IndexSize.DotSuffix()...)
		b = append(b, ')')
		return string(b)
	case EAAbsShort:
		signedTarget := int16(uint16(op.UVal))
		if signedTarget < 0 {
			if signedTarget == -1 {
				return "(-1).w"
			}
			var buf [24]byte
			b := append(buf[:0], "(-$"...)
			b = appendHexUpper(b, uint32(-int32(signedTarget)))
			b = append(b, ").w"...)
			return string(b)
		}
		var buf [24]byte
		b := append(buf[:0], '$')
		b = appendHexUpper(b, op.UVal)
		b = append(b, ".w"...)
		return string(b)
	case EAAbsLong:
		var buf [16]byte
		b := append(buf[:0], '$')
		b = appendHexUpper(b, op.UVal)
		b = append(b, ".l"...)
		return string(b)
	case EAPCDisp16:
		var buf [16]byte
		b := append(buf[:0], '$')
		b = appendHexUpper(b, op.UVal)
		b = append(b, "(pc)"...)
		return string(b)
	case EAPCIndex:
		var buf [24]byte
		b := append(buf[:0], '$')
		b = appendHexUpper(b, op.UVal)
		b = append(b, "(pc,"...)
		b = append(b, op.IndexRegName()...)
		b = append(b, op.IndexSize.DotSuffix()...)
		b = append(b, ')')
		return string(b)
	case EAImm:
		if insnOp == OpMOVEQ {
			var buf [16]byte
			b := append(buf[:0], '#')
			b = strconv.AppendInt(b, int64(op.Disp), 10)
			return string(b)
		}
		if op.UVal < uint32(len(immHexNames)) {
			return immHexNames[op.UVal]
		}
		var buf [16]byte
		b := append(buf[:0], "#$"...)
		b = appendHexUpper(b, op.UVal)
		return string(b)
	case EABranch:
		var buf [16]byte
		b := append(buf[:0], '$')
		b = appendHexUpper(b, op.UVal)
		return string(b)
	case EARegList:
		return FormatRegList(RegMask(op.UVal))
	case EASpecialReg:
		return SpecialReg(op.Reg).String()
	default:
		return ""
	}
}

// Insn represents a single decoded Motorola 68000 instruction (48 bytes, pointer-free).
// All fields are stored inline so Decode performs zero heap allocations.
type Insn struct {
	Addr      uint32
	Opcode    uint16
	ReadRegs  RegMask    // General registers (D0-D7, A0-A7) read by this instruction
	WriteRegs RegMask    // General registers (D0-D7, A0-A7) written/clobbered by this instruction
	Op        Op         // Canonical operation enum (OpMOVE, OpLEA, OpJSR, OpBcc, ...)
	Size      uint8      // Total instruction length in bytes (2, 4, 6, 8, or 10)
	Suffix    Size       // SizeNone, SizeB, SizeW, SizeL, or SizeS
	Flow      FlowFlags  // Control-flow classification bitmask
	NumOps    uint8      // Number of operands (0, 1, or 2)
	Cond      uint8      // Condition code (0..15) for OpBcc, OpDBcc, OpScc
	Ops       [2]Operand // Inline operands (Ops[0] = source/single, Ops[1] = destination)
}

// Mnemonic returns the lowercase base mnemonic without size suffix
// (e.g. "move", "bra", "bne", "dbra", "rts").
func (in *Insn) Mnemonic() string {
	switch in.Op {
	case OpBcc:
		return bccNames[in.Cond&0xF]
	case OpDBcc:
		return dbccNames[in.Cond&0xF]
	case OpScc:
		return sccNames[in.Cond&0xF]
	default:
		return in.Op.String()
	}
}

// FullMnemonic returns the complete vasmm68k_mot mnemonic including its size suffix
// (e.g. "move.l", "bra.s", "lea.l", "rts") with zero heap allocations.
func (in *Insn) FullMnemonic() string {
	switch in.Op {
	case OpBcc:
		if in.Suffix == SizeS {
			return bccShortNames[in.Cond&0xF]
		}
		if in.Suffix == SizeW {
			return bccWordNames[in.Cond&0xF]
		}
		return bccNames[in.Cond&0xF]
	case OpDBcc:
		return dbccNames[in.Cond&0xF]
	case OpScc:
		return sccNames[in.Cond&0xF]
	default:
		if int(in.Op) < len(opFullMnemonics) && int(in.Suffix) < 5 {
			return opFullMnemonics[in.Op][in.Suffix]
		}
		return ""
	}
}

// Operands returns the active slice of decoded operands (length NumOps).
func (in *Insn) Operands() []Operand {
	return in.Ops[:in.NumOps]
}

// HasRegisterList returns true if any operand is a MOVEM register list (EARegList).
func (in *Insn) HasRegisterList() bool {
	for i := uint8(0); i < in.NumOps; i++ {
		if in.Ops[i].Mode == EARegList {
			return true
		}
	}
	return false
}

// HasSpecialReg returns true if any operand references the given special register (CCR, SR, USP).
func (in *Insn) HasSpecialReg(sr SpecialReg) bool {
	for i := uint8(0); i < in.NumOps; i++ {
		if in.Ops[i].Mode == EASpecialReg && SpecialReg(in.Ops[i].Reg) == sr {
			return true
		}
	}
	return false
}

// IsCall returns true if the instruction is a subroutine call (BSR or JSR).
func (in *Insn) IsCall() bool {
	return (in.Flow & FlowCall) != 0
}

// IsUnconditionalJump returns true if the instruction is an unconditional jump (BRA or JMP).
func (in *Insn) IsUnconditionalJump() bool {
	return (in.Flow&FlowBranch) != 0 && (in.Flow&FlowCond) == 0
}

// IsConditionalBranch returns true if the instruction is a conditional Bcc or DBcc branch.
func (in *Insn) IsConditionalBranch() bool {
	return (in.Flow & FlowCond) != 0
}

// IsBranch returns true if the instruction is an unconditional jump or conditional branch.
func (in *Insn) IsBranch() bool {
	return (in.Flow & FlowBranch) != 0
}

// IsReturn returns true if the instruction is a subroutine or exception return (RTS, RTE, RTR).
func (in *Insn) IsReturn() bool {
	return (in.Flow & FlowReturn) != 0
}

// IsTerminator returns true if the instruction terminates a linear basic block.
func (in *Insn) IsTerminator() bool {
	return in.IsReturn() || in.IsUnconditionalJump() || in.Op == OpILLEGAL
}

// CycleEstimate returns the primary MC68000 execution clock periods for the instruction,
// or 0 when unknown.
func (in *Insn) CycleEstimate() int {
	return int(in.Timing().Primary.Cycles)
}

// FormatASM returns the complete literal Motorola assembly line ("<mnem>\t<ops>")
// without symbolic labels, used for binary round-trip verification.
func (in *Insn) FormatASM() string {
	mnem := in.FullMnemonic()
	if in.NumOps == 0 {
		return mnem
	}
	if in.NumOps == 1 {
		return mnem + "\t" + in.Ops[0].FormatASM(in.Op)
	}
	return mnem + "\t" + in.Ops[0].FormatASM(in.Op) + "," + in.Ops[1].FormatASM(in.Op)
}
