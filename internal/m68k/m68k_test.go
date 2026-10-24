package m68k

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unsafe"
)

func TestMovemPredecAndNormalRegMasks(t *testing.T) {
	// movem.l d0-d7/a0-a6,-(a7) -> 48e7 fffe
	rawPush := []byte{0x48, 0xE7, 0xFF, 0xFE}
	insnPush, ok := Decode(rawPush, 0x1000)
	if !ok {
		t.Fatalf("failed to decode movem.l d0-d7/a0-a6,-(a7)")
	}
	if got := insnPush.FormatASM(); got != "movem.l\td0-d7/a0-a6,-(a7)" {
		t.Fatalf("got %q, want %q", got, "movem.l\td0-d7/a0-a6,-(a7)")
	}
	if insnPush.ReadRegs != (RegMask(0x7FFF) | RegA7) {
		t.Fatalf("unexpected ReadRegs: %#04x", insnPush.ReadRegs)
	}
	if insnPush.WriteRegs != RegA7 {
		t.Fatalf("unexpected WriteRegs: %#04x", insnPush.WriteRegs)
	}

	// movem.l (a7)+,d0-d7/a0-a6 -> 4cdf 7fff
	rawPop := []byte{0x4C, 0xDF, 0x7F, 0xFF}
	insnPop, ok := Decode(rawPop, 0x1004)
	if !ok {
		t.Fatalf("failed to decode movem.l (a7)+,d0-d7/a0-a6")
	}
	if got := insnPop.FormatASM(); got != "movem.l\t(a7)+,d0-d7/a0-a6" {
		t.Fatalf("got %q, want %q", got, "movem.l\t(a7)+,d0-d7/a0-a6")
	}
	if insnPop.WriteRegs != (RegMask(0x7FFF) | RegA7) {
		t.Fatalf("unexpected WriteRegs: %#04x", insnPop.WriteRegs)
	}

	// movem.l $12345678.l,d0-d1 -> 4cf9 0003 1234 5678 (EA ExtOffset must be 4)
	rawAbs := []byte{0x4C, 0xF9, 0x00, 0x03, 0x12, 0x34, 0x56, 0x78}
	insnAbs, ok := Decode(rawAbs, 0x2000)
	if !ok {
		t.Fatalf("failed to decode movem.l abs.l,d0-d1")
	}
	if insnAbs.Ops[0].ExtOffset != 4 || insnAbs.Ops[0].ExtSize != 4 {
		t.Fatalf("expected ExtOffset=4 ExtSize=4, got %d/%d", insnAbs.Ops[0].ExtOffset, insnAbs.Ops[0].ExtSize)
	}
	if insnAbs.Ops[1].ExtOffset != 2 || insnAbs.Ops[1].ExtSize != 2 {
		t.Fatalf("expected reglist ExtOffset=2 ExtSize=2, got %d/%d", insnAbs.Ops[1].ExtOffset, insnAbs.Ops[1].ExtSize)
	}
}

func TestRejectInvalid68000(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
	}{
		{"LineA trap", []byte{0xA0, 0x00}},
		{"LineF trap", []byte{0xF0, 0x00}},
		{"68010 MOVE CCR,d0", []byte{0x42, 0xC0}},
		{"68010 RTD", []byte{0x4E, 0x74, 0x00, 0x04}},
		{"68010 BKPT #0", []byte{0x48, 0x48}},
		{"68010 MOVEC", []byte{0x4E, 0x7A, 0x00, 0x00}},
		{"68010 MOVES", []byte{0x0E, 0x00, 0x00, 0x00}},
		{"68020 Bcc.L (disp8 == 0xFF)", []byte{0x60, 0xFF, 0x00, 0x00, 0x00, 0x04}},
		{"68020 EXTB.L d0", []byte{0x49, 0xC0}},
		{"68020 PACK", []byte{0x81, 0x40, 0x00, 0x00}},
		{"68020 UNPK", []byte{0x81, 0x80, 0x00, 0x00}},
		{"68020 BFTST", []byte{0xE8, 0xC0, 0x00, 0x00}},
		{"68020 MULL.L", []byte{0x4C, 0x00, 0x00, 0x00}},
		{"68020 scaled index (ext & 0x0700 != 0)", []byte{0x20, 0x30, 0x02, 0x00}},
		{"68020 full index (ext & 0x0100 != 0)", []byte{0x41, 0xFB, 0x01, 0x00}},
		{"ORI.B #imm with non-zero upper byte", []byte{0x00, 0x00, 0x01, 0x12}},
		{"ORI.B #imm,ccr with non-zero upper byte", []byte{0x00, 0x3C, 0x01, 0x12}},
		{"MOVE.B #imm,d0 with non-zero upper byte", []byte{0x10, 0x3C, 0x01, 0x12}},
		{"BTST #imm,d0 with non-zero upper byte", []byte{0x08, 0x00, 0x01, 0x03}},
		{"BTST #imm,#imm forbidden", []byte{0x08, 0x3C, 0x00, 0x01, 0x00, 0x02}},
		{"MOVE.B a0,d0 forbidden", []byte{0x10, 0x08}},
		{"MOVEA.B d0,a0 forbidden", []byte{0x10, 0x40}},
		{"ADDQ.B #1,a0 forbidden", []byte{0x52, 0x08}},
		{"MOVEM.L with empty register mask", []byte{0x48, 0xE7, 0x00, 0x00}},
		{"MOVEQ with bit 8 set", []byte{0x71, 0x00}},
	}

	for _, tc := range cases {
		if insn, ok := Decode(tc.raw, 0x1000); ok {
			t.Errorf("%s (%x): expected Decode to reject, but got %q", tc.name, tc.raw, insn.FormatASM())
		}
	}
}

func TestOpAccessAndHelpers(t *testing.T) {
	// 1. LEA 16(a4),a0 -> OpLEA, Ops[0].Access == AccessAddr, Ops[1].Access == AccessWrite
	insnLea, ok := Decode([]byte{0x41, 0xEC, 0x00, 0x10}, 0x1000)
	if !ok || insnLea.Op != OpLEA || insnLea.Ops[0].Access != AccessAddr || insnLea.Ops[1].Access != AccessWrite {
		t.Fatalf("unexpected LEA decode: %+v", insnLea)
	}

	// 2. MOVE.W d0,16(a4) -> OpMOVE, Ops[0].Access == AccessRead, Ops[1].Access == AccessWrite
	insnMove, ok := Decode([]byte{0x39, 0x40, 0x00, 0x10}, 0x1000)
	if !ok || insnMove.Op != OpMOVE || insnMove.Ops[0].Access != AccessRead || insnMove.Ops[1].Access != AccessWrite {
		t.Fatalf("unexpected MOVE decode: %+v", insnMove)
	}

	// 3. ADDQ.W #1,16(a4) -> OpADDQ, Ops[1].Access == AccessRead|AccessWrite
	insnAddq, ok := Decode([]byte{0x52, 0x6C, 0x00, 0x10}, 0x1000)
	if !ok || insnAddq.Op != OpADDQ || insnAddq.Ops[1].Access != (AccessRead|AccessWrite) {
		t.Fatalf("unexpected ADDQ decode: %+v", insnAddq)
	}

	// 4. ParseMnemonic & HasLongEA
	if op, sz := ParseMnemonic("move.l"); op != OpMOVE || sz != SizeL || !op.HasLongEA(sz) {
		t.Fatalf("unexpected ParseMnemonic(move.l): op=%v sz=%v", op, sz)
	}
	if op, sz := ParseMnemonic("lea"); op != OpLEA || !op.HasLongEA(sz) {
		t.Fatalf("unexpected ParseMnemonic(lea): op=%v sz=%v", op, sz)
	}
	if op, sz := ParseMnemonic("lsl.l"); op != OpLSL || sz != SizeL || op.HasLongEA(sz) {
		t.Fatalf("lsl.l must not have HasLongEA=true: op=%v sz=%v", op, sz)
	}

	// 5. ClassifyIndirectDispatch & struct layout invariants
	if unsafe.Sizeof(Insn{}) != 48 {
		t.Fatalf("expected sizeof(Insn)=48, got %d", unsafe.Sizeof(Insn{}))
	}
	if unsafe.Sizeof(Operand{}) != 16 {
		t.Fatalf("expected sizeof(Operand)=16, got %d", unsafe.Sizeof(Operand{}))
	}
	if mode, isCall, baseAn, ok := ClassifyIndirectDispatch(0x4EAD); !ok || mode != EADisp16 || !isCall || baseAn != 5 {
		t.Fatalf("unexpected ClassifyIndirectDispatch(jsr d16(a5)): mode=%v isCall=%v baseAn=%v ok=%v", mode, isCall, baseAn, ok)
	}
	if mode, isCall, baseAn, ok := ClassifyIndirectDispatch(0x4EFB); !ok || mode != EAPCIndex || isCall || baseAn != -1 {
		t.Fatalf("unexpected ClassifyIndirectDispatch(jmp d8(pc,xn)): mode=%v isCall=%v baseAn=%v ok=%v", mode, isCall, baseAn, ok)
	}

	// 6. Exhaustive ParseMnemonic round-trip across every Op and all condition tables
	for op := OpORI; op <= OpROL; op++ {
		m := op.String()
		if m == "" {
			t.Fatalf("Op(%d) has empty canonical mnemonic in opBaseMnemonics", op)
		}
		if gotOp, gotSz := ParseMnemonic(m); gotOp != op || gotSz != SizeNone {
			t.Fatalf("ParseMnemonic(%q) = (%v, %v), want (%v, SizeNone)", m, gotOp, gotSz, op)
		}
		if gotOp, gotSz := ParseMnemonic(m + ".l"); gotOp != op || gotSz != SizeL {
			t.Fatalf("ParseMnemonic(%q) = (%v, %v), want (%v, SizeL)", m+".l", gotOp, gotSz, op)
		}
	}
	for _, m := range sccNames {
		if gotOp, _ := ParseMnemonic(m + ".b"); gotOp != OpScc {
			t.Fatalf("ParseMnemonic(%q) = %v, want OpScc", m+".b", gotOp)
		}
	}
	for _, m := range dbccNames {
		if gotOp, _ := ParseMnemonic(m); gotOp != OpDBcc {
			t.Fatalf("ParseMnemonic(%q) = %v, want OpDBcc", m, gotOp)
		}
	}
	for cond := 2; cond < len(bccNames); cond++ {
		m := bccNames[cond]
		if gotOp, gotSz := ParseMnemonic(m + ".s"); gotOp != OpBcc || gotSz != SizeS {
			t.Fatalf("ParseMnemonic(%q) = (%v, %v), want (OpBcc, SizeS)", m+".s", gotOp, gotSz)
		}
	}
	// Verify condition aliases (dbf -> OpDBcc, bcc/bcs -> OpBcc)
	if gotOp, _ := ParseMnemonic("dbf"); gotOp != OpDBcc {
		t.Fatalf("ParseMnemonic(\"dbf\") = %v, want OpDBcc", gotOp)
	}
	for _, alias := range []string{"bcc.w", "bcs.w"} {
		if gotOp, gotSz := ParseMnemonic(alias); gotOp != OpBcc || gotSz != SizeW {
			t.Fatalf("ParseMnemonic(%q) = (%v, %v), want (OpBcc, SizeW)", alias, gotOp, gotSz)
		}
	}
}

func TestExhaustive65536BinaryRoundTrip(t *testing.T) {
	vasmPath, err := exec.LookPath("vasmm68k_mot")
	if err != nil {
		t.Skip("vasmm68k_mot not found in PATH")
	}

	patterns := []struct {
		name string
		ext  [8]byte
	}{
		// Positive displacements, valid byte immediates (high byte 0x00), valid brief index (scale 000, D0.W)
		{"pos_d0w", [8]byte{0x00, 0x0C, 0x00, 0x0A, 0x00, 0x08, 0x00, 0x06}},
		// Address-register long index (A1.L: 0x9804) for second/third extension words, valid byte imm at +2 (0x007E)
		{"idx_a1l", [8]byte{0x00, 0x7E, 0x98, 0x04, 0x98, 0xFC, 0x12, 0x34}},
	}

	const baseAddr = uint32(0x100000)
	tmpDir := t.TempDir()

	for _, pat := range patterns {
		t.Run(pat.name, func(t *testing.T) {
			var asmBuf bytes.Buffer
			var expectedBin bytes.Buffer
			type slotRecord struct {
				opcode uint16
				addr   uint32
				raw    []byte
				asm    string
			}
			var records []slotRecord

			fmt.Fprintf(&asmBuf, "\topt o-,a-\n\torg $%X\n", baseAddr)
			curAddr := baseAddr

			for op := 0; op <= 0xFFFF; op++ {
				var raw [10]byte
				raw[0] = byte(op >> 8)
				raw[1] = byte(op)
				copy(raw[2:], pat.ext[:])

				insn, ok := Decode(raw[:], curAddr)
				if !ok {
					continue
				}
				// vasm warns/errors if a .s branch displacement is odd in strict mode or out of range;
				// verify every decoded instruction reassembles to the exact input bytes.
				asmLine := insn.FormatASM()
				fmt.Fprintf(&asmBuf, "\t%s\n", asmLine)
				rawSlice := append([]byte(nil), raw[:insn.Size]...)
				expectedBin.Write(rawSlice)
				records = append(records, slotRecord{
					opcode: uint16(op),
					addr:   curAddr,
					raw:    rawSlice,
					asm:    asmLine,
				})
				curAddr += uint32(insn.Size)
			}

			asmFile := filepath.Join(tmpDir, pat.name+".asm")
			binFile := filepath.Join(tmpDir, pat.name+".bin")
			if err := os.WriteFile(asmFile, asmBuf.Bytes(), 0644); err != nil {
				t.Fatalf("write asm: %v", err)
			}

			cmd := exec.Command(vasmPath, "-m68000", "-Fbin", "-no-opt", "-quiet", "-o", binFile, asmFile)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("vasmm68k_mot failed: %v\n%s", err, string(out))
			}

			gotBin, err := os.ReadFile(binFile)
			if err != nil {
				t.Fatalf("read bin: %v", err)
			}
			wantBin := expectedBin.Bytes()
			if !bytes.Equal(gotBin, wantBin) {
				// Locate exact instruction record that drifted
				off := 0
				for _, rec := range records {
					end := off + len(rec.raw)
					if end > len(gotBin) || !bytes.Equal(gotBin[off:end], rec.raw) {
						var gotSlice []byte
						if off < len(gotBin) {
							gotSlice = gotBin[off:min(end, len(gotBin))]
						}
						t.Fatalf("binary drift at opcode $%04X (addr $%X, %q): want %x, got %x",
							rec.opcode, rec.addr, rec.asm, rec.raw, gotSlice)
					}
					off = end
				}
				t.Fatalf("binary length mismatch: want %d, got %d", len(wantBin), len(gotBin))
			}
			t.Logf("pattern %s: verified %d / 65536 valid M68000 opcodes byte-for-byte", pat.name, len(records))
		})
	}
}

func TestExhaustive65536ObjdumpAndM68kdisOracle(t *testing.T) {
	objdumpPath, err := exec.LookPath("m68k-elf-objdump")
	if err != nil {
		t.Skip("m68k-elf-objdump not found in PATH")
	}

	const stride = 16
	ext := [8]byte{0x00, 0x0C, 0x00, 0x0A, 0x00, 0x08, 0x00, 0x06}
	buf := make([]byte, 65536*stride)
	for op := 0; op <= 0xFFFF; op++ {
		off := op * stride
		buf[off] = byte(op >> 8)
		buf[off+1] = byte(op)
		copy(buf[off+2:off+10], ext[:])
		// Pad +10..+15 with NOPs (0x4E71) so linear disassembly re-synchronizes before the next 16-byte slot.
		buf[off+10] = 0x4E
		buf[off+11] = 0x71
		buf[off+12] = 0x4E
		buf[off+13] = 0x71
		buf[off+14] = 0x4E
		buf[off+15] = 0x71
	}

	tmpDir := t.TempDir()
	binFile := filepath.Join(tmpDir, "all65536.bin")
	if err := os.WriteFile(binFile, buf, 0644); err != nil {
		t.Fatalf("write bin: %v", err)
	}

	cmd := exec.Command(objdumpPath, "-D", "-b", "binary", "-m", "m68k:68000", "-z", "--insn-width=10", binFile)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("m68k-elf-objdump failed: %v", err)
	}

	type oracleEntry struct {
		valid bool
		size  uint8
		text  string
	}
	oracle := make([]oracleEntry, 65536)

	for _, line := range strings.Split(string(out), "\n") {
		colonIdx := strings.IndexByte(line, ':')
		if colonIdx <= 0 || colonIdx > 10 {
			continue
		}
		addrStr := strings.TrimSpace(line[:colonIdx])
		addr64, err := strconv.ParseUint(addrStr, 16, 32)
		if err != nil || addr64%stride != 0 {
			continue
		}
		opIdx := int(addr64 / stride)
		if opIdx < 0 || opIdx >= 65536 {
			continue
		}
		rest := strings.TrimSpace(line[colonIdx+1:])
		parts := strings.SplitN(rest, "\t", 2)
		if len(parts) < 2 {
			continue
		}
		hexPart := strings.ReplaceAll(strings.TrimSpace(parts[0]), " ", "")
		textPart := strings.TrimSpace(parts[1])
		if idx := strings.LastIndex(textPart, ".short"); idx >= 0 {
			textPart = textPart[idx:]
		}
		isValid := !strings.HasPrefix(textPart, ".short") &&
			!strings.HasPrefix(textPart, ".byte") &&
			!strings.HasPrefix(textPart, "swbeg")
		oracle[opIdx] = oracleEntry{
			valid: isValid,
			size:  uint8(len(hexPart) / 2),
			text:  textPart,
		}
	}

	for op := 0; op <= 0xFFFF; op++ {
		off := op * stride
		addr := uint32(off)
		insn, ok := Decode(buf[off:off+10], addr)
		oe := oracle[op]

		// Note: GNU binutils m68k-opc.c has four known differences on 68000:
		//   1. $4AFD is decoded as SysV PCC switch directive "swbegl" (handled above).
		//   2. ADDQ.B/SUBQ.B #<data>,An ($5x08..$5x0F) is decoded as "addqb/subqb #n,%aN",
		//      even though M68000 silicon and Motorola PRM forbid byte size on An.
		//   3. Bcc with disp8 == 0xFF ($6xFF) is decoded as an odd -1 short branch ("bras")
		//      by objdump in 68000 mode, whereas we reject 0xFF (68020 Bcc.L / odd target).
		//   4. Line $F ($F000..$FFFF) is decoded by objdump as 68851/68881 coprocessor ops.
		if (op&0xF0F8) == 0x5008 || (op&0xF0FF) == 0x60FF || (op&0xF000) == 0xF000 {
			continue
		}

		if ok != oe.valid {
			t.Fatalf("opcode $%04X validity mismatch: Decode=%v (%q) vs objdump=%v (%q)",
				op, ok, insn.FormatASM(), oe.valid, oe.text)
		}
		if ok && insn.Size != oe.size {
			t.Fatalf("opcode $%04X byte size mismatch: Decode=%d (%q) vs objdump=%d (%q)",
				op, insn.Size, insn.FormatASM(), oe.size, oe.text)
		}
	}

	t.Logf("verified all 65,536 opcodes against m68k-elf-objdump -m m68k:68000")
}

func buildBenchStream() []byte {
	ext := [8]byte{0x00, 0x0C, 0x00, 0x0A, 0x00, 0x08, 0x00, 0x06}
	buf := make([]byte, 65536*10)
	for op := 0; op <= 0xFFFF; op++ {
		off := op * 10
		buf[off] = byte(op >> 8)
		buf[off+1] = byte(op)
		copy(buf[off+2:off+10], ext[:])
	}
	return buf
}

func BenchmarkDecodeStream(b *testing.B) {
	buf := buildBenchStream()
	b.ReportAllocs()
	b.ResetTimer()
	var sink uint32
	for i := 0; i < b.N; i++ {
		for op := 0; op <= 0xFFFF; op++ {
			off := op * 10
			if insn, ok := Decode(buf[off:off+10], uint32(off)); ok {
				sink += uint32(insn.Size)
			}
		}
	}
	if sink == 0 {
		b.Fatal("zero decoded instructions")
	}
}

var benchStringSink string

func BenchmarkFullMnemonic(b *testing.B) {
	buf := buildBenchStream()
	var insns []Insn
	for op := 0; op <= 0xFFFF; op++ {
		off := op * 10
		if insn, ok := Decode(buf[off:off+10], uint32(off)); ok {
			insns = append(insns, insn)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		for j := range insns {
			s = insns[j].FullMnemonic()
		}
	}
	benchStringSink = s
}

func BenchmarkFormatASM(b *testing.B) {
	buf := buildBenchStream()
	var insns []Insn
	for op := 0; op <= 0xFFFF; op++ {
		off := op * 10
		if insn, ok := Decode(buf[off:off+10], uint32(off)); ok {
			insns = append(insns, insn)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	var sink int
	for i := 0; i < b.N; i++ {
		for j := range insns {
			sink += len(insns[j].FormatASM())
		}
	}
	if sink == 0 {
		b.Fatal("empty asm")
	}
}
