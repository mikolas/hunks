package amiga

import "testing"

func TestDecodeCustomRegWrite(t *testing.T) {
	cases := []struct {
		offset uint32
		val    uint16
		want   string
	}{
		{0x096, 0x0000, ""}, // No-op DMACON mask
		{0x096, 0x8000, ""}, // No-op DMACON SET with 0 mask
		{0x096, 0x83C0, "SET|DMAEN|BPLEN|COPEN|BLTEN"},
		{0x096, 0x01FF, "CLR|BPLEN|COPEN|BLTEN|SPREN|DSKEN|AUD3EN|AUD2EN|AUD1EN|AUD0EN"},
		{0x09A, 0x4000, "CLR|INTEN"},
		{0x09A, 0xC030, "SET|INTEN|VERTB|COPER"},
		{0x09C, 0x0060, "CLR|BLIT|VERTB"},
		{0x09E, 0x9500, "SET|MFMPREC|WORDSYNC|FAST"},
		{0x100, 0x4200, "4BPU (16c)|COLOR"},
		{0x100, 0x9204, "HIRES|1BPU (2c)|COLOR|LACE"},
		{0x100, 0x6200, "6BPU (EHB 64c)|COLOR"},
		{0x100, 0x6A00, "6BPU (HAM6)|HAM|COLOR"},
		{0x040, 0x09F0, "USEA|USED|LF=$F0 (D=A)"},
		{0x040, 0x4FCA, "ASH=4|USEA|USEB|USEC|USED|LF=$CA (D=AB+~AC)"},
		{0x042, 0x0000, ""},
		{0x042, 0x0002, "DESC"},
		{0x042, 0x0043, "LINE|SIGN|SING"},
		{0x058, (64 << 6) | 20, "20w x 64h (320x64 px)"},
		{0x058, 0x0000, "64w x 1024h (1024x1024 px)"},
	}
	for _, tc := range cases {
		if got := DecodeCustomRegWrite(tc.offset, tc.val); got != tc.want {
			t.Errorf("DecodeCustomRegWrite(0x%03X, 0x%04X) = %q, want %q", tc.offset, tc.val, got, tc.want)
		}
	}

	gotLong := DecodeCustomRegLongWrite(0x040, 0x09F00002)
	wantLong := "BLTCON0: USEA|USED|LF=$F0 (D=A) | BLTCON1: DESC"
	if gotLong != wantLong {
		t.Errorf("DecodeCustomRegLongWrite(0x040, 0x09F00002) = %q, want %q", gotLong, wantLong)
	}
}
