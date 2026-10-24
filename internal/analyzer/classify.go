package analyzer

import (
	"encoding/binary"
	"slices"

	"github.com/mikolas/hunks/internal/amiga"
	"github.com/mikolas/hunks/internal/hunk"
	"github.com/mikolas/hunks/internal/m68k"
)

const (
	ConfDefinite uint8 = 0
	ConfHigh     uint8 = 1
	ConfMedium   uint8 = 2
	ConfLow      uint8 = 3
)

// RefKind identifies the reference category in RefType.
type RefKind uint8

const (
	RefNone RefKind = iota
	RefCodeCall
	RefCodeBranch
	RefDataAddr
	RefDataRead
	RefDataWrite
	RefIndirect
)

// RefType represents a classified control-flow or data reference from an instruction operand.
type RefType struct {
	Kind          RefKind
	Target        uint32
	IsConditional bool
}

// IsASCIIStringAt returns true if data[off:] begins with an ASCII string (>=4 printable + NUL, or >=6 printable).
func IsASCIIStringAt(data []byte, off int) bool {
	if off < 0 || off+4 > len(data) {
		return false
	}
	count := 0
	for _, b := range data[off:] {
		if (b >= 0x20 && b <= 0x7E) || b == '\t' || b == '\r' || b == '\n' {
			count++
		} else if b == 0 {
			return count >= 4
		} else {
			break
		}
	}
	return count >= 6
}

// AbsLongExtAddr returns the exact byte address of the 32-bit extension word for
// operand opIdx of insn at addr, using the operand's recorded ExtOffset.
func AbsLongExtAddr(addr uint32, insn *m68k.Insn, opIdx int) uint32 {
	if opIdx >= 0 && opIdx < int(insn.NumOps) {
		return addr + uint32(insn.Ops[opIdx].ExtOffset)
	}
	return addr + 2
}

func (a *Analyzer) isValidTarget(addr uint32) bool {
	if a.IsInAnyProjectSegment(addr) {
		return true
	}
	_, ok := amiga.GetAmigaHWLabel(addr)
	return ok
}

// ClassifyReference classifies a single operand op (at opIdx) of decoded instruction insn at addr.
//
// In relocatable hunk mode (`len(a.Relocs) > 0`), 32-bit Absolute Long and Immediate operands
// are treated as symbolic address references iff their extension-word address is present in
// `a.Relocs` (or targets a known Amiga hardware register). In flat binary mode, 32-bit
// operands are classified as references when their resolved address falls within a project
// segment or hardware register range.
func (a *Analyzer) ClassifyReference(addr uint32, insn *m68k.Insn, op m68k.Operand, opIdx int) (RefType, bool) {
	isCall := insn.IsCall()
	isBranch := insn.IsBranch()
	isUnconditional := insn.IsUnconditionalJump()
	isAddrCalc := op.Access == m68k.AccessAddr && !isCall && !isBranch
	isWrite := (op.Access & m68k.AccessWrite) != 0
	hunkMode := len(a.Relocs) > 0

	switch op.Mode {
	case m68k.EABranch:
		target := op.UVal
		if !a.IsSameSegment(addr, target) {
			return RefType{}, false
		}
		if isCall {
			return RefType{Kind: RefCodeCall, Target: target}, true
		}
		if isBranch {
			return RefType{Kind: RefCodeBranch, Target: target, IsConditional: !isUnconditional}, true
		}
		return RefType{}, false

	case m68k.EAImm:
		return a.classifyImmOperand(addr, insn, op, hunkMode)

	case m68k.EAPCDisp16, m68k.EAPCIndex:
		if op.Mode == m68k.EAPCIndex && (isCall || isBranch) {
			return RefType{Kind: RefIndirect}, true
		}
		target := op.UVal
		if !a.IsSameSegment(addr, target) {
			return RefType{}, false
		}
		if isCall {
			return RefType{Kind: RefCodeCall, Target: target}, true
		}
		if isBranch {
			return RefType{Kind: RefCodeBranch, Target: target, IsConditional: !isUnconditional}, true
		}
		if isAddrCalc {
			return RefType{Kind: RefDataAddr, Target: target}, true
		}
		if isWrite {
			return RefType{Kind: RefDataWrite, Target: target}, true
		}
		return RefType{Kind: RefDataRead, Target: target}, true

	case m68k.EAAbsLong:
		extAddr := addr + uint32(op.ExtOffset)
		if hunkMode {
			if target, ok := a.Relocs[extAddr]; ok {
				if isCall {
					return RefType{Kind: RefCodeCall, Target: target}, true
				}
				if isBranch {
					return RefType{Kind: RefCodeBranch, Target: target, IsConditional: false}, true
				}
				if isAddrCalc {
					return RefType{Kind: RefDataAddr, Target: target}, true
				}
				if isWrite {
					return RefType{Kind: RefDataWrite, Target: target}, true
				}
				return RefType{Kind: RefDataRead, Target: target}, true
			}
			target := op.UVal
			if _, ok := amiga.GetAmigaHWLabel(target); ok {
				if isWrite {
					return RefType{Kind: RefDataWrite, Target: target}, true
				}
				return RefType{Kind: RefDataRead, Target: target}, true
			}
			return RefType{}, false
		}
		target := op.UVal
		if !a.isValidTarget(target) {
			return RefType{}, false
		}
		if isCall {
			return RefType{Kind: RefCodeCall, Target: target}, true
		}
		if isBranch {
			return RefType{Kind: RefCodeBranch, Target: target, IsConditional: false}, true
		}
		if isAddrCalc {
			return RefType{Kind: RefDataAddr, Target: target}, true
		}
		if isWrite {
			return RefType{Kind: RefDataWrite, Target: target}, true
		}
		return RefType{Kind: RefDataRead, Target: target}, true

	case m68k.EAAbsShort:
		return RefType{}, false

	case m68k.EAAddrInd, m68k.EADisp16, m68k.EAIndex:
		if isCall || isBranch {
			return RefType{Kind: RefIndirect}, true
		}
		return RefType{}, false
	}

	return RefType{}, false
}

func (a *Analyzer) classifyImmOperand(addr uint32, insn *m68k.Insn, op m68k.Operand, hunkMode bool) (RefType, bool) {
	if op.ImmSize != m68k.SizeL || insn.Size < 6 {
		return RefType{}, false
	}
	if hunkMode {
		extAddr := addr + uint32(op.ExtOffset)
		if target, ok := a.Relocs[extAddr]; ok {
			return RefType{Kind: RefDataAddr, Target: target}, true
		}
		return RefType{}, false
	}
	val := op.UVal
	if a.IsInAnyProjectSegment(val) && val%2 == 0 {
		return RefType{Kind: RefDataAddr, Target: val}, true
	}
	return RefType{}, false
}

// CalculatePCTarget returns the exact PC-relative target address for operand opIdx of insn at addr.
func (a *Analyzer) CalculatePCTarget(addr uint32, insn *m68k.Insn, opIdx int) uint32 {
	if opIdx >= 0 && opIdx < int(insn.NumOps) {
		return insn.Ops[opIdx].UVal
	}
	return addr + 2
}

// DecodeValidInsn decodes a single valid M68000 instruction at addr without heap allocations,
// enforcing all hardware encoding rules and relocation non-overlap invariants.
//
// Specifically, an instruction is rejected if:
//   - Its opcode word overlaps any 4-byte `HUNK_RELOC32` site (`[site .. site+4)`).
//   - Any interior byte (`addr+1 .. addr+size-1`) is itself the target of a relocation.
//   - It is an unimplemented/privileged/68020+ opcode (`ILLEGAL`, `RESET`, `STOP`, etc.) or
//     uses non-zero scale/full-extension bits (`extWord & 0x0700 != 0`) in a brief index word.
//   - It is a byte-immediate instruction whose immediate extension word has a non-zero upper byte.
//   - In hunk mode, any `HUNK_RELOC32` entry inside `[addr+1 .. addr+size)` fails to match
//     a valid 32-bit Immediate or Absolute Long extension word of the instruction, or a
//     `JSR`/`JMP abs.L` lacks a relocation entry.
func (a *Analyzer) DecodeValidInsn(addr uint32, strictSandbox bool) (m68k.Insn, bool) {
	if addr%2 != 0 {
		return m68k.Insn{}, false
	}
	seg := a.SegmentAt(addr)
	if seg == nil || seg.HunkType != hunk.HunkTypeCode {
		return m68k.Insn{}, false
	}

	// M68000 Relocation Invariant 1: No instruction may start inside [site_addr .. site_addr + 4)
	for delta := uint32(0); delta < 4; delta++ {
		if addr >= delta {
			if _, ok := a.Relocs[addr-delta]; ok {
				return m68k.Insn{}, false
			}
		}
	}

	off := int(addr - seg.Base)
	if off < 0 || off+2 > len(seg.Data) {
		return m68k.Insn{}, false
	}
	opcode := binary.BigEndian.Uint16(seg.Data[off : off+2])
	if opcode == 0xFFFF {
		return m68k.Insn{}, false
	}
	if strictSandbox && opcode == 0x0000 {
		return m68k.Insn{}, false
	}
	if off+4 <= len(seg.Data) &&
		seg.Data[off] == 0 && seg.Data[off+1] == 0 && seg.Data[off+2] == 0 && seg.Data[off+3] == 0 {
		return m68k.Insn{}, false
	}
	if strictSandbox && IsASCIIStringAt(seg.Data, off) {
		return m68k.Insn{}, false
	}

	end := min(off+10, len(seg.Data))
	chunk := seg.Data[off:end]
	insn, ok := m68k.Decode(chunk, addr)
	if !ok {
		return m68k.Insn{}, false
	}
	size := uint32(insn.Size)
	if size == 0 || size%2 != 0 || addr+size > seg.End || int(size) > len(chunk) {
		return m68k.Insn{}, false
	}

	switch insn.Op {
	case m68k.OpILLEGAL, m68k.OpRESET, m68k.OpSTOP:
		return m68k.Insn{}, false
	}

	// Interior relocation target check: no instruction may swallow a relocated target
	for k := uint32(1); k < size; k++ {
		if _, ok := a.RelocTargets[addr+k]; ok {
			return m68k.Insn{}, false
		}
	}

	hunkMode := len(a.Relocs) > 0
	isJsrOrJmp := insn.Op == m68k.OpJSR || insn.Op == m68k.OpJMP
	var validRelocSites [2]uint32
	numValidSites := 0

	for opIdx := uint8(0); opIdx < insn.NumOps; opIdx++ {
		op := insn.Ops[opIdx]
		switch op.Mode {
		case m68k.EABranch:
			target := op.UVal
			if target%2 != 0 || !a.IsSameSegment(addr, target) {
				return m68k.Insn{}, false
			}
			if strictSandbox && target == addr {
				return m68k.Insn{}, false
			}

		case m68k.EAPCDisp16, m68k.EAPCIndex:
			target := op.UVal
			if !a.IsSameSegment(addr, target) {
				return m68k.Insn{}, false
			}
			if isJsrOrJmp && target%2 != 0 {
				return m68k.Insn{}, false
			}

		case m68k.EAAbsLong:
			extAddr := addr + uint32(op.ExtOffset)
			if numValidSites < 2 {
				validRelocSites[numValidSites] = extAddr
				numValidSites++
			}
			if hunkMode && isJsrOrJmp {
				if _, has := a.Relocs[extAddr]; !has {
					return m68k.Insn{}, false
				}
			}

		case m68k.EAImm:
			if op.ImmSize == m68k.SizeL && op.ExtSize == 4 && size >= 6 && numValidSites < 2 {
				validRelocSites[numValidSites] = addr + uint32(op.ExtOffset)
				numValidSites++
			}
		}
	}

	// M68000 Relocation Invariant 2: Any relocation starting inside (addr .. addr + size)
	// must be a valid 32-bit Immediate or Absolute Long operand of this instruction.
	if hunkMode {
		for k := uint32(1); k < size; k++ {
			checkAddr := addr + k
			if _, ok := a.Relocs[checkAddr]; ok {
				if checkAddr+4 > addr+size {
					return m68k.Insn{}, false
				}
				if !slices.Contains(validRelocSites[:numValidSites], checkAddr) {
					return m68k.Insn{}, false
				}
			}
		}
	}

	return insn, true
}
