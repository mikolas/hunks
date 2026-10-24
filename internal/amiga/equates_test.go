package amiga

import "testing"

type mockHWRefProvider struct {
	ops []string
}

func (m mockHWRefProvider) OpStrsWithHWRefs() []string { return m.ops }

func TestCustomRegisterOffsets(t *testing.T) {
	regs := GetCustomRegs()
	checks := map[uint32]string{
		0x07E: "DSKSYNC",
		0x088: "COPJMP1",
		0x08A: "COPJMP2",
		0x08C: "COPINS",
		0x08E: "DIWSTRT",
		0x090: "DIWSTOP",
		0x092: "DDFSTRT",
		0x094: "DDFSTOP",
		0x096: "DMACON",
		0x098: "CLXCON",
		0x09A: "INTENA",
		0x09C: "INTREQ",
		0x09E: "ADKCON",
		0x120: "SPR0PTH",
		0x122: "SPR0PTL",
		0x124: "SPR1PTH",
		0x126: "SPR1PTL",
		0x13C: "SPR7PTH",
		0x13E: "SPR7PTL",
		0x140: "SPR0POS",
		0x142: "SPR0CTL",
		0x144: "SPR0DATA",
		0x146: "SPR0DATB",
		0x148: "SPR1POS",
		0x178: "SPR7POS",
		0x17E: "SPR7DATB",
	}
	for off, want := range checks {
		if got := regs[off]; got != want {
			t.Errorf("regs[0x%03X] = %q, want %q", off, got, want)
		}
	}

	if lbl, ok := GetAmigaHWLabel(0xDFF096); !ok || lbl != "DMACON" {
		t.Errorf("GetAmigaHWLabel(0xDFF096) = %q, %v", lbl, ok)
	}
	if lbl, ok := GetAmigaHWLabel(0xDFF098); !ok || lbl != "CLXCON" {
		t.Errorf("GetAmigaHWLabel(0xDFF098) = %q, %v", lbl, ok)
	}
	if lbl, ok := GetAmigaHWLabel(0xDFF124); !ok || lbl != "SPR1PTH" {
		t.Errorf("GetAmigaHWLabel(0xDFF124) = %q, %v", lbl, ok)
	}
	if lbl, ok := GetAmigaHWLabel(0xDFF140); !ok || lbl != "SPR0POS" {
		t.Errorf("GetAmigaHWLabel(0xDFF140) = %q, %v", lbl, ok)
	}
}

func TestSubRegisterByteOffsets(t *testing.T) {
	if lbl, ok := GetAmigaHWLabel(0xDFF01E); !ok || lbl != "INTREQR" {
		t.Errorf("GetAmigaHWLabel(0xDFF01E) = %q, %v", lbl, ok)
	}
	if lbl, ok := GetAmigaHWLabelSub(0xDFF01E); !ok || lbl != "INTREQR" {
		t.Errorf("GetAmigaHWLabelSub(0xDFF01E) = %q, %v", lbl, ok)
	}
	if lbl, ok := GetAmigaHWLabel(0xDFF01F); !ok || lbl != "CUSTOM_01F" {
		t.Errorf("GetAmigaHWLabel(0xDFF01F) = %q, %v", lbl, ok)
	}
	subChecks := map[uint32]string{
		0xDFF01F: "INTREQR+1",
		0xDFF021: "DSKPTH+1",
		0xDFF097: "DMACON+1",
		0xDFF001: "BLTDDAT+1",
	}
	for addr, want := range subChecks {
		if got, ok := GetAmigaHWLabelSub(addr); !ok || got != want {
			t.Errorf("GetAmigaHWLabelSub(0x%X) = %q, %v; want %q", addr, got, ok, want)
		}
	}
	if _, ok := GetAmigaHWLabelSub(0x00012345); ok {
		t.Errorf("expected false for 0x00012345")
	}
}

func TestParseHWLabelAndCollectEquates(t *testing.T) {
	if addr, ok := ParseHWLabelAddr("CUSTOM_005"); !ok || addr != 0xDFF005 {
		t.Errorf("ParseHWLabelAddr(CUSTOM_005) = 0x%X, %v", addr, ok)
	}
	if addr, ok := ParseHWLabelAddr("DMACON"); !ok || addr != 0xDFF096 {
		t.Errorf("ParseHWLabelAddr(DMACON) = 0x%X, %v", addr, ok)
	}
	if addr, ok := ParseHWLabelAddr("_custom"); !ok || addr != 0xDFF000 {
		t.Errorf("ParseHWLabelAddr(_custom) = 0x%X, %v", addr, ok)
	}
	if _, ok := ParseHWLabelAddr("INVALID"); ok {
		t.Errorf("expected false for INVALID")
	}

	equates := GetAllEquates()
	if equates["DMACON"] != 0x096 || equates["_custom"] != 0xDFF000 || equates["_ciaa"] != 0xBFE001 || equates["_ciab"] != 0xBFD000 {
		t.Errorf("unexpected base equates: DMACON=0x%X _custom=0x%X", equates["DMACON"], equates["_custom"])
	}
	if _, exists := equates["CUSTOM_005"]; exists {
		t.Errorf("did not expect CUSTOM_005 in initial equates")
	}

	CollectUsedHWEquates(mockHWRefProvider{ops: []string{"#$0,_custom+CUSTOM_005.l"}}, equates)
	if equates["CUSTOM_005"] != 0x005 {
		t.Errorf("equates[CUSTOM_005] = 0x%X, want 0x005", equates["CUSTOM_005"])
	}
}
