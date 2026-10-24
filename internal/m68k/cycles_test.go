package m68k

import "testing"

func TestInstructionTimings(t *testing.T) {
	cases := []struct {
		name    string
		raw     []byte
		want    Timing
		wantStr string
	}{
		// --- Table 1 & 2A: MOVE / MOVEA + -(An) Destination Overlap ---
		{
			name:    "move.w d0,d1",
			raw:     []byte{0x32, 0x00},
			want:    exactTiming(4, 1, 0),
			wantStr: "4 (1/0) cyc",
		},
		{
			name:    "move.l d0,d1",
			raw:     []byte{0x22, 0x00},
			want:    exactTiming(4, 1, 0),
			wantStr: "4 (1/0) cyc",
		},
		{
			name:    "move.l -(a0),d0 (src predec = 4 + 10 = 14)",
			raw:     []byte{0x20, 0x20},
			want:    exactTiming(14, 3, 0),
			wantStr: "14 (3/0) cyc",
		},
		{
			name:    "move.l d0,-(a0) (dst predec = 4 + 8 = 12, 2 fewer cycles than src)",
			raw:     []byte{0x21, 0x00},
			want:    exactTiming(12, 1, 2),
			wantStr: "12 (1/2) cyc",
		},
		{
			name:    "move.l -(a0),-(a1) (4 + 10 + 8 = 22)",
			raw:     []byte{0x23, 0x20},
			want:    exactTiming(22, 3, 2),
			wantStr: "22 (3/2) cyc",
		},
		{
			name:    "move.b #$FF,$3CA18.l (4 + 4 + 12 = 20)",
			raw:     []byte{0x13, 0xFC, 0x00, 0xFF, 0x00, 0x03, 0xCA, 0x18},
			want:    exactTiming(20, 4, 1),
			wantStr: "20 (4/1) cyc",
		},
		{
			name:    "move.b 0(a0,d3.w),d3 (4 + 10 + 0 = 14)",
			raw:     []byte{0x16, 0x30, 0x30, 0x00},
			want:    exactTiming(14, 3, 0),
			wantStr: "14 (3/0) cyc",
		},
		{
			name:    "movea.w (a0)+,a1 (4 + 4 + 0 = 8)",
			raw:     []byte{0x32, 0x58},
			want:    exactTiming(8, 2, 0),
			wantStr: "8 (2/0) cyc",
		},
		{
			name:    "move.w sr,d0",
			raw:     []byte{0x40, 0xC0},
			want:    exactTiming(6, 1, 0),
			wantStr: "6 (1/0) cyc",
		},
		{
			name:    "move.w sr,(a0) (8 + 4 = 12)",
			raw:     []byte{0x40, 0xD0},
			want:    exactTiming(12, 2, 1),
			wantStr: "12 (2/1) cyc",
		},
		{
			name:    "move.w d0,ccr",
			raw:     []byte{0x44, 0xC0},
			want:    exactTiming(12, 1, 0),
			wantStr: "12 (1/0) cyc",
		},
		{
			name:    "move.w (a0),sr (12 + 4 = 16)",
			raw:     []byte{0x46, 0xD0},
			want:    exactTiming(16, 2, 0),
			wantStr: "16 (2/0) cyc",
		},
		{
			name:    "move.l a0,usp",
			raw:     []byte{0x4E, 0x60},
			want:    exactTiming(4, 1, 0),
			wantStr: "4 (1/0) cyc",
		},
		{
			name:    "moveq #0,d0",
			raw:     []byte{0x70, 0x00},
			want:    exactTiming(4, 1, 0),
			wantStr: "4 (1/0) cyc",
		},
		{
			name:    "movep.w d0,0(a0) (R->M = 16 (2/2))",
			raw:     []byte{0x01, 0x88, 0x00, 0x00},
			want:    exactTiming(16, 2, 2),
			wantStr: "16 (2/2) cyc",
		},
		{
			name:    "movep.l 0(a0),d0 (M->R = 24 (6/0))",
			raw:     []byte{0x01, 0x48, 0x00, 0x00},
			want:    exactTiming(24, 6, 0),
			wantStr: "24 (6/0) cyc",
		},
		{
			name:    "exg d0,d1",
			raw:     []byte{0xC1, 0x41},
			want:    exactTiming(6, 1, 0),
			wantStr: "6 (1/0) cyc",
		},
		{
			name:    "swap d0",
			raw:     []byte{0x48, 0x40},
			want:    exactTiming(4, 1, 0),
			wantStr: "4 (1/0) cyc",
		},
		{
			name:    "ext.l d0",
			raw:     []byte{0x48, 0xC0},
			want:    exactTiming(4, 1, 0),
			wantStr: "4 (1/0) cyc",
		},

		// --- Table 2B: Standard ALU & .L Register/Immediate Penalty ---
		{
			name:    "add.w d6,d3 (4 + 0 = 4)",
			raw:     []byte{0xD6, 0x46},
			want:    exactTiming(4, 1, 0),
			wantStr: "4 (1/0) cyc",
		},
		{
			name:    "add.l d0,d1 (6 + 0 + 2 penalty = 8)",
			raw:     []byte{0xD2, 0x80},
			want:    exactTiming(8, 1, 0),
			wantStr: "8 (1/0) cyc",
		},
		{
			name:    "add.l (a0),d1 (6 + 8, no penalty = 14)",
			raw:     []byte{0xD2, 0x90},
			want:    exactTiming(14, 3, 0),
			wantStr: "14 (3/0) cyc",
		},
		{
			name:    "add.l d0,(a0) (12 + 8 = 20)",
			raw:     []byte{0xD1, 0x90},
			want:    exactTiming(20, 3, 2),
			wantStr: "20 (3/2) cyc",
		},
		{
			name:    "adda.w (a0),a1 (8 + 4 = 12)",
			raw:     []byte{0xD2, 0xD0},
			want:    exactTiming(12, 2, 0),
			wantStr: "12 (2/0) cyc",
		},
		{
			name:    "adda.l d0,a1 (6 + 0 + 2 penalty = 8)",
			raw:     []byte{0xD3, 0xC0},
			want:    exactTiming(8, 1, 0),
			wantStr: "8 (1/0) cyc",
		},
		{
			name:    "eor.l d0,d1 (8 (1/0))",
			raw:     []byte{0xB1, 0x81},
			want:    exactTiming(8, 1, 0),
			wantStr: "8 (1/0) cyc",
		},
		{
			name:    "cmp.w #$900,d7 (4 + 4 = 8)",
			raw:     []byte{0xBE, 0x7C, 0x09, 0x00},
			want:    exactTiming(8, 2, 0),
			wantStr: "8 (2/0) cyc",
		},
		{
			name:    "cmp.l d0,d1 (6, no .L penalty)",
			raw:     []byte{0xB2, 0x80},
			want:    exactTiming(6, 1, 0),
			wantStr: "6 (1/0) cyc",
		},
		{
			name:    "cmpa.w d0,a0 (6 + 0 = 6)",
			raw:     []byte{0xB0, 0xC0},
			want:    exactTiming(6, 1, 0),
			wantStr: "6 (1/0) cyc",
		},
		{
			name:    "mulu.w #10,d0 (10 = 0b1010 -> n=2 -> 38 + 4 + 4 = 46)",
			raw:     []byte{0xC0, 0xFC, 0x00, 0x0A},
			want:    exactTiming(46, 2, 0),
			wantStr: "46 (2/0) cyc",
		},
		{
			name:    "muls.w #-1,d0 (0xFFFF ^ 0xFFFE = 1 -> n=1 -> 38 + 2 + 4 = 44)",
			raw:     []byte{0xC1, 0xFC, 0xFF, 0xFF},
			want:    exactTiming(44, 2, 0),
			wantStr: "44 (2/0) cyc",
		},
		{
			name:    "mulu.w d1,d0 (range 38-70)",
			raw:     []byte{0xC0, 0xC1},
			want:    rangeTiming(BusCost{38, 1, 0}, BusCost{70, 1, 0}),
			wantStr: "38-70 (1/0) cyc",
		},
		{
			name:    "divu.w (a0),d0 (range 76+4..140+4 = 80-144)",
			raw:     []byte{0x80, 0xD0},
			want:    rangeTiming(BusCost{80, 2, 0}, BusCost{144, 2, 0}),
			wantStr: "80-144 (2/0) cyc",
		},

		// --- Table 2C: Immediate & Quick ALU ---
		{
			name:    "andi.w #$FC00,d3",
			raw:     []byte{0x02, 0x43, 0xFC, 0x00},
			want:    exactTiming(8, 2, 0),
			wantStr: "8 (2/0) cyc",
		},
		{
			name:    "addi.l #1,d0",
			raw:     []byte{0x06, 0x80, 0x00, 0x00, 0x00, 0x01},
			want:    exactTiming(16, 3, 0),
			wantStr: "16 (3/0) cyc",
		},
		{
			name:    "subi.w #1,(a0) (12 + 4 = 16)",
			raw:     []byte{0x04, 0x50, 0x00, 0x01},
			want:    exactTiming(16, 3, 1),
			wantStr: "16 (3/1) cyc",
		},
		{
			name:    "cmpi.l #1,d0",
			raw:     []byte{0x0C, 0x80, 0x00, 0x00, 0x00, 0x01},
			want:    exactTiming(14, 3, 0),
			wantStr: "14 (3/0) cyc",
		},
		{
			name:    "ori.b #1,ccr",
			raw:     []byte{0x00, 0x3C, 0x00, 0x01},
			want:    exactTiming(20, 3, 0),
			wantStr: "20 (3/0) cyc",
		},
		{
			name:    "addq.w #1,d0",
			raw:     []byte{0x52, 0x40},
			want:    exactTiming(4, 1, 0),
			wantStr: "4 (1/0) cyc",
		},
		{
			name:    "addq.w #2,a0 (8 cycles even for .W on An)",
			raw:     []byte{0x54, 0x48},
			want:    exactTiming(8, 1, 0),
			wantStr: "8 (1/0) cyc",
		},

		// --- Table 2D: Single-Operand, Shift/Rotate, Bit & Multi-Precision ---
		{
			name:    "clr.l d0",
			raw:     []byte{0x42, 0x80},
			want:    exactTiming(6, 1, 0),
			wantStr: "6 (1/0) cyc",
		},
		{
			name:    "clr.w (a0) (8 + 4 = 12)",
			raw:     []byte{0x42, 0x50},
			want:    exactTiming(12, 2, 1),
			wantStr: "12 (2/1) cyc",
		},
		{
			name:    "st d0 (Cond 0 = always 6)",
			raw:     []byte{0x50, 0xC0},
			want:    exactTiming(6, 1, 0),
			wantStr: "6 (1/0) cyc",
		},
		{
			name:    "sf d0 (Cond 1 = always 4)",
			raw:     []byte{0x51, 0xC0},
			want:    exactTiming(4, 1, 0),
			wantStr: "4 (1/0) cyc",
		},
		{
			name:    "seq d0 (6/4)",
			raw:     []byte{0x57, 0xC0},
			want:    branchTiming(BusCost{6, 1, 0}, BusCost{4, 1, 0}),
			wantStr: "6/4 (1/0) cyc",
		},
		{
			name:    "tas (a0) (10 + 4 = 14)",
			raw:     []byte{0x4A, 0xD0},
			want:    exactTiming(14, 2, 1),
			wantStr: "14 (2/1) cyc",
		},
		{
			name:    "tst.l (a0) (4 + 8 = 12)",
			raw:     []byte{0x4A, 0x90},
			want:    exactTiming(12, 3, 0),
			wantStr: "12 (3/0) cyc",
		},
		{
			name:    "lsl.w #3,d3 (6 + 2*3 = 12)",
			raw:     []byte{0xE7, 0x4B},
			want:    exactTiming(12, 1, 0),
			wantStr: "12 (1/0) cyc",
		},
		{
			name:    "lsr.w #8,d3 (6 + 2*8 = 22)",
			raw:     []byte{0xE0, 0x4B},
			want:    exactTiming(22, 1, 0),
			wantStr: "22 (1/0) cyc",
		},
		{
			name:    "asl.w (a0) (memory shift by 1: 8 + 4 = 12)",
			raw:     []byte{0xE1, 0xD0},
			want:    exactTiming(12, 2, 1),
			wantStr: "12 (2/1) cyc",
		},
		{
			name:    "btst #5,d0 (static reg = 10)",
			raw:     []byte{0x08, 0x00, 0x00, 0x05},
			want:    exactTiming(10, 2, 0),
			wantStr: "10 (2/0) cyc",
		},
		{
			name:    "bclr #5,(a0) (static mem = 12 + 4 = 16)",
			raw:     []byte{0x08, 0x90, 0x00, 0x05},
			want:    exactTiming(16, 3, 1),
			wantStr: "16 (3/1) cyc",
		},
		{
			name:    "addx.l -(a0),-(a1)",
			raw:     []byte{0xD3, 0x88},
			want:    exactTiming(30, 5, 2),
			wantStr: "30 (5/2) cyc",
		},
		{
			name:    "cmpm.l (a0)+,(a1)+",
			raw:     []byte{0xB3, 0x88},
			want:    exactTiming(20, 5, 0),
			wantStr: "20 (5/0) cyc",
		},

		// --- Table 2E: Branches, Subroutines & Miscellaneous ---
		{
			name:    "beq.s +8 (10 taken / 8 not taken)",
			raw:     []byte{0x67, 0x08},
			want:    branchTiming(BusCost{10, 2, 0}, BusCost{8, 1, 0}),
			wantStr: "10/8 (2/0,1/0) cyc",
		},
		{
			name:    "beq.w +256 (10 taken / 12 not taken)",
			raw:     []byte{0x67, 0x00, 0x01, 0x00},
			want:    branchTiming(BusCost{10, 2, 0}, BusCost{12, 2, 0}),
			wantStr: "10/12 (2/0) cyc",
		},
		{
			name:    "bra.w +256",
			raw:     []byte{0x60, 0x00, 0x01, 0x00},
			want:    exactTiming(10, 2, 0),
			wantStr: "10 (2/0) cyc",
		},
		{
			name:    "bsr.w +256",
			raw:     []byte{0x61, 0x00, 0x01, 0x00},
			want:    exactTiming(18, 2, 2),
			wantStr: "18 (2/2) cyc",
		},
		{
			name:    "dbra d0,-4 (10 looping / 14 expired)",
			raw:     []byte{0x51, 0xC8, 0xFF, 0xFC},
			want:    branchTiming(BusCost{10, 2, 0}, BusCost{14, 3, 0}),
			wantStr: "10/14 (2/0,3/0) cyc",
		},
		{
			name:    "rts",
			raw:     []byte{0x4E, 0x75},
			want:    exactTiming(16, 4, 0),
			wantStr: "16 (4/0) cyc",
		},
		{
			name:    "rte",
			raw:     []byte{0x4E, 0x73},
			want:    exactTiming(20, 5, 0),
			wantStr: "20 (5/0) cyc",
		},
		{
			name:    "link.w a5,#-16",
			raw:     []byte{0x4E, 0x55, 0xFF, 0xF0},
			want:    exactTiming(16, 2, 2),
			wantStr: "16 (2/2) cyc",
		},
		{
			name:    "unlk a5",
			raw:     []byte{0x4E, 0x5D},
			want:    exactTiming(12, 3, 0),
			wantStr: "12 (3/0) cyc",
		},
		{
			name:    "nop",
			raw:     []byte{0x4E, 0x71},
			want:    exactTiming(4, 1, 0),
			wantStr: "4 (1/0) cyc",
		},

		// --- Table 3: JMP, JSR, LEA, PEA, MOVEM ---
		{
			name:    "jmp $12345678.l",
			raw:     []byte{0x4E, 0xF9, 0x12, 0x34, 0x56, 0x78},
			want:    exactTiming(12, 3, 0),
			wantStr: "12 (3/0) cyc",
		},
		{
			name:    "jsr 498(a5)",
			raw:     []byte{0x4E, 0xAD, 0x01, 0xF2},
			want:    exactTiming(18, 2, 2),
			wantStr: "18 (2/2) cyc",
		},
		{
			name:    "lea 16(pc),a0",
			raw:     []byte{0x41, 0xFA, 0x00, 0x10},
			want:    exactTiming(8, 2, 0),
			wantStr: "8 (2/0) cyc",
		},
		{
			name:    "pea (a0)",
			raw:     []byte{0x48, 0x50},
			want:    exactTiming(12, 1, 2),
			wantStr: "12 (1/2) cyc",
		},
		{
			name:    "movem.l (a7)+,d2/d4-d5/a0-a1 (M->R, n=5 -> 12 + 8*5 = 52 (13/0))",
			raw:     []byte{0x4C, 0xDF, 0x03, 0x34},
			want:    exactTiming(52, 13, 0),
			wantStr: "52 (13/0) cyc",
		},
		{
			name:    "movem.l d2/d4-d5/a0-a1,-(a7) (R->M, n=5 -> 8 + 8*5 = 48 (2/10))",
			raw:     []byte{0x48, 0xE7, 0x2C, 0xC0},
			want:    exactTiming(48, 2, 10),
			wantStr: "48 (2/10) cyc",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			insn, ok := Decode(tc.raw, 0x1000)
			if !ok {
				t.Fatalf("Decode(%x) failed", tc.raw)
			}
			got := insn.Timing()
			if got != tc.want {
				t.Fatalf("%s: Timing() = %+v, want %+v", tc.name, got, tc.want)
			}
			if gotStr := got.String(); gotStr != tc.wantStr {
				t.Fatalf("%s: Timing().String() = %q, want %q", tc.name, gotStr, tc.wantStr)
			}
			if est := insn.CycleEstimate(); est != int(tc.want.Primary.Cycles) {
				t.Fatalf("%s: CycleEstimate() = %d, want %d", tc.name, est, tc.want.Primary.Cycles)
			}
		})
	}
}

func TestExhaustiveAll65536OpcodesHaveNonZeroTiming(t *testing.T) {
	// Every valid M68000 instruction decoded by Decode across all 65,536 opcode words
	// must produce a non-zero cycle count.
	raw := [10]byte{0, 0, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04}
	validCount := 0
	for op := range 0x10000 {
		raw[0] = byte(op >> 8)
		raw[1] = byte(op)
		insn, ok := Decode(raw[:], 0x1000)
		if !ok {
			continue
		}
		validCount++
		tm := insn.Timing()
		if tm.Primary.Cycles == 0 {
			t.Fatalf("opcode $%04X (%s) returned 0 cycles: %+v", op, insn.FormatASM(), tm)
		}
		if tm.Kind != TimingExact && tm.Secondary.Cycles == 0 {
			t.Fatalf("opcode $%04X (%s) has Kind=%d but Secondary.Cycles=0: %+v", op, insn.FormatASM(), tm.Kind, tm)
		}
	}
	if validCount < 40000 {
		t.Fatalf("expected >40000 valid M68000 opcodes, got %d", validCount)
	}
}

