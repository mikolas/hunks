package analyzer

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/mikolas/hunks/internal/db"
	"github.com/mikolas/hunks/internal/hunk"
	"github.com/mikolas/hunks/internal/m68k"
	"github.com/mikolas/hunks/internal/project"
)

func TestDeliverableIPLRespectsPriorityAndVectorGuard(t *testing.T) {
	cs := NewChipset()
	mem := make([]byte, 0x200)

	// Enable master + L1 (DSKBLK) + L3 (VERTB) + L5 (DSKSYNC), and request all three.
	cs.WriteCustomWord(0x00DFF09A, 0x8000|IntMASTER|IntDSKBLK|IntVERTB|IntDSKSYNC, mem)
	cs.WriteCustomWord(0x00DFF09C, 0x8000|IntDSKBLK|IntVERTB|IntDSKSYNC, mem)

	// Raw INTREQR always reflects all three bits even with no vectors installed.
	if got := cs.ReadCustomWord(0x00DFF01E); got != (IntDSKBLK | IntVERTB | IntDSKSYNC) {
		t.Fatalf("expected INTREQR=%#04X, got %#04X", IntDSKBLK|IntVERTB|IntDSKSYNC, got)
	}
	// Byte read of $DFF01F (low byte of INTREQR) sees DSKBLK (bit 1) and VERTB (bit 5).
	if got := cs.ReadCustomByte(0x00DFF01F); got != uint8(IntDSKBLK|IntVERTB) {
		t.Fatalf("expected low INTREQR=%#02X, got %#02X", uint8(IntDSKBLK|IntVERTB), got)
	}
	// With all autovectors ($64..$78) zeroed, DeliverableIPL must be 0.
	if got := cs.DeliverableIPL(mem); got != 0 {
		t.Fatalf("expected DeliverableIPL=0, got %d", got)
	}

	// Install only Level 3 vector ($6C = 0x60 + 3*4): L5 has higher priority,
	// but its vector ($74) is 0, so L3 is delivered.
	binary.BigEndian.PutUint32(mem[0x6C:0x70], 0x00012340)
	if got := cs.DeliverableIPL(mem); got != 3 {
		t.Fatalf("expected DeliverableIPL=3, got %d", got)
	}

	// Install Level 5 vector ($74 = 0x60 + 5*4): now L5 wins over L3.
	binary.BigEndian.PutUint32(mem[0x74:0x78], 0x00015000)
	if got := cs.DeliverableIPL(mem); got != 5 {
		t.Fatalf("expected DeliverableIPL=5, got %d", got)
	}

	// Clear INT_DSKSYNC via SET/CLR write to INTREQ: falls back to L3.
	cs.WriteCustomWord(0x00DFF09C, IntDSKSYNC, mem)
	if got := cs.DeliverableIPL(mem); got != 3 {
		t.Fatalf("expected DeliverableIPL=3 after clearing L5, got %d", got)
	}
}

func TestAgnusBeamAdvancesVposVhposAndRaisesVertB(t *testing.T) {
	cs := NewChipset()
	mem := make([]byte, 64)

	if got := cs.ReadCustomWord(0x00DFF004); got != 0x8000 {
		t.Fatalf("expected initial VPOSR=0x8000, got %#04X", got)
	}
	if got := cs.ReadCustomWord(0x00DFF006); got != 0x0000 {
		t.Fatalf("expected initial VHPOSR=0x0000, got %#04X", got)
	}

	// Advance by 256 lines + 10 color clocks (20 CPU cycles): vpos=0x100, hpos=10.
	cs.Tick(256*CyclesPerLine+20, mem)
	if got := cs.ReadCustomWord(0x00DFF004); got != 0x8001 {
		t.Fatalf("expected VPOSR=0x8001, got %#04X", got)
	}
	if got := cs.ReadCustomWord(0x00DFF006); got != 0x000A {
		t.Fatalf("expected VHPOSR=0x000A, got %#04X", got)
	}
	if cs.ReadCustomWord(0x00DFF01E)&IntVERTB != 0 {
		t.Fatalf("expected INT_VERTB not yet set")
	}

	// Advance across the end of the 313-line PAL frame: wraps and raises INT_VERTB.
	cs.Tick(57*CyclesPerLine, mem)
	if cs.ReadCustomWord(0x00DFF01E)&IntVERTB == 0 {
		t.Fatalf("expected INT_VERTB set after frame wrap")
	}
	if cs.Agnus.VPos != 0 || cs.Agnus.HPos != 10 {
		t.Fatalf("expected vpos=0 hpos=10, got vpos=%d hpos=%d", cs.Agnus.VPos, cs.Agnus.HPos)
	}
}

func TestPaulaDsklenDoubleWriteRaisesDskSyncAndDskBlk(t *testing.T) {
	cs := NewChipset()
	mem := make([]byte, 64)

	cs.WriteCustomWord(0x00DFF024, 0x8002, mem)
	if cs.Paula.DskCycles != 0 {
		t.Fatalf("expected DskCycles=0 after first write, got %d", cs.Paula.DskCycles)
	}
	if cs.ReadCustomWord(0x00DFF01A)&(1<<14) != 0 {
		t.Fatalf("expected DMAON=0 after first write")
	}

	cs.WriteCustomWord(0x00DFF024, 0x8002, mem)
	if cs.Paula.DskCycles != 256 {
		t.Fatalf("expected DskCycles=256 after second write, got %d", cs.Paula.DskCycles)
	}
	if cs.ReadCustomWord(0x00DFF01A)&0x5000 != 0x5000 {
		t.Fatalf("expected DMAON|WORDEQUAL in DSKBYTR")
	}

	cs.Tick(64, mem)
	if cs.ReadCustomWord(0x00DFF01E)&IntDSKSYNC == 0 {
		t.Fatalf("expected INT_DSKSYNC after 64 cycles")
	}
	if cs.ReadCustomWord(0x00DFF01E)&IntDSKBLK != 0 {
		t.Fatalf("expected INT_DSKBLK not set yet")
	}

	cs.Tick(192, mem)
	if cs.ReadCustomWord(0x00DFF01E)&IntDSKBLK == 0 {
		t.Fatalf("expected INT_DSKBLK after 256 total cycles")
	}
	if cs.ReadCustomWord(0x00DFF01A)&(1<<14) != 0 {
		t.Fatalf("expected DMAON cleared")
	}
}

func TestPaulaSerialAndAudioStateMachines(t *testing.T) {
	cs := NewChipset()
	mem := make([]byte, 64)

	if got := cs.ReadCustomWord(0x00DFF018); got != 0x3000 {
		t.Fatalf("expected idle SERDATR=0x3000, got %#04X", got)
	}

	cs.WriteCustomWord(0x00DFF032, 9, mem)
	cs.WriteCustomWord(0x00DFF030, 0x0141, mem)
	if cs.ReadCustomWord(0x00DFF01E)&IntTBE == 0 {
		t.Fatalf("expected INT_TBE after SERDAT write")
	}
	if cs.ReadCustomWord(0x00DFF018)&(1<<12) != 0 {
		t.Fatalf("expected TSRE=0 while shifting")
	}
	cs.WriteCustomWord(0x00DFF09C, IntTBE, mem)
	if cs.ReadCustomWord(0x00DFF01E)&IntTBE != 0 {
		t.Fatalf("expected INT_TBE cleared")
	}
	cs.Tick(200, mem)
	if cs.ReadCustomWord(0x00DFF01E)&IntTBE == 0 {
		t.Fatalf("expected INT_TBE re-asserted after shift completes")
	}
	if got := cs.ReadCustomWord(0x00DFF018); got != 0x3000 {
		t.Fatalf("expected SERDATR=0x3000 after shift completes, got %#04X", got)
	}

	cs.WriteCustomWord(0x00DFF0A4, 4, mem)
	cs.WriteCustomWord(0x00DFF0A6, 124, mem)
	cs.WriteCustomWord(0x00DFF096, 0x8000|DmaMASTER|0x0001, mem)
	cs.Tick(CyclesPerLine, mem)
	if cs.ReadCustomWord(0x00DFF01E)&IntAUD0 == 0 {
		t.Fatalf("expected INT_AUD0 after 1 line")
	}

	cs.WriteCustomWord(0x00DFF0B6, 20, mem)
	cs.WriteCustomWord(0x00DFF0BA, 0x1234, mem)
	cs.Tick(80, mem)
	if cs.ReadCustomWord(0x00DFF01E)&IntAUD1 == 0 {
		t.Fatalf("expected INT_AUD1 after 80 cycles")
	}
}

func TestCustomReadonlyAndWriteonlySemantics(t *testing.T) {
	cs := NewChipset()
	mem := make([]byte, 64)

	if got := cs.ReadCustomWord(0x00DFF016); got != 0x5500 {
		t.Fatalf("expected POTGOR=0x5500, got %#04X", got)
	}
	if got := cs.ReadCustomWord(0x00DFF07C); got != 0xFFFF {
		t.Fatalf("expected DENISEID=0xFFFF, got %#04X", got)
	}
	cs.WriteCustomWord(0x00DFF096, 0x8200, mem)
	if got := cs.ReadCustomWord(0x00DFF096); got != 0x0000 {
		t.Fatalf("expected write-only DMACON read=0, got %#04X", got)
	}
	if got := cs.ReadCustomWord(0x00DFF002); got != (0x0200 | dmaconrBZERO) {
		t.Fatalf("expected DMACONR=%#04X, got %#04X", 0x0200|dmaconrBZERO, got)
	}
	if got := cs.ReadCustomWord(0x00DFF180); got != 0x0000 {
		t.Fatalf("expected write-only COLOR00 read=0, got %#04X", got)
	}
}

func TestCIATimersCascadeICRAndLevelRelatch(t *testing.T) {
	cs := NewChipset()
	mem := make([]byte, 64)

	cs.WriteCIAByte(0x00BFE401, 4)
	cs.WriteCIAByte(0x00BFE501, 0)
	cs.WriteCIAByte(0x00BFED01, 0x80|IcrTA)
	cs.WriteCIAByte(0x00BFEE01, CraSTART)

	cs.WriteCIAByte(0x00BFEF01, 0x40|CrbRUNMODE)
	cs.WriteCIAByte(0x00BFE601, 2)
	cs.WriteCIAByte(0x00BFE701, 0)
	if cs.ReadCIAByte(0x00BFEF01)&CrbSTART == 0 {
		t.Fatalf("expected CRB_START set after one-shot TBHI write")
	}

	cs.Tick(40, mem)
	if cs.ReadCustomWord(0x00DFF01E)&IntPORTS == 0 {
		t.Fatalf("expected INT_PORTS set after Timer A underflow")
	}

	cs.WriteCustomWord(0x00DFF09C, IntPORTS, mem)
	if cs.ReadCustomWord(0x00DFF01E)&IntPORTS == 0 {
		t.Fatalf("expected INT_PORTS relatched while CIA-A /IRQ is asserted")
	}

	icr := cs.ReadCIAByte(0x00BFED01)
	if icr != (0x80 | IcrTA) {
		t.Fatalf("expected CIA-A ICR=%#02X, got %#02X", 0x80|IcrTA, icr)
	}
	if got := cs.ReadCIAByte(0x00BFED01); got != 0x00 {
		t.Fatalf("expected cleared CIA-A ICR=0x00, got %#02X", got)
	}

	cs.WriteCustomWord(0x00DFF09C, IntPORTS, mem)
	if cs.ReadCustomWord(0x00DFF01E)&IntPORTS != 0 {
		t.Fatalf("expected INT_PORTS cleared after reading ICR")
	}

	cs.Tick(40, mem)
	icr2 := cs.ReadCIAByte(0x00BFED01)
	if icr2 != (0x80 | IcrTA | IcrTB) {
		t.Fatalf("expected cascaded ICR=%#02X, got %#02X", 0x80|IcrTA|IcrTB, icr2)
	}
	if cs.ReadCIAByte(0x00BFEF01)&CrbSTART != 0 {
		t.Fatalf("expected one-shot Timer B stopped after underflow")
	}
}

func TestCIATODAlarmAndFloppyStepperTrack0(t *testing.T) {
	cs := NewChipset()
	mem := make([]byte, 64)

	cs.WriteCIAByte(0x00BFDF00, CrbALARM)
	cs.WriteCIAByte(0x00BFD800, 3)
	cs.WriteCIAByte(0x00BFD900, 0)
	cs.WriteCIAByte(0x00BFDA00, 0)
	cs.WriteCIAByte(0x00BFDD00, 0x80|IcrALRM)

	cs.Tick(3*CyclesPerLine, mem)
	if cs.ReadCustomWord(0x00DFF01E)&IntEXTER == 0 {
		t.Fatalf("expected INT_EXTER after TOD alarm")
	}
	if got := cs.ReadCIAByte(0x00BFDD00); got != (0x80 | IcrALRM) {
		t.Fatalf("expected CIA-B ICR=%#02X, got %#02X", 0x80|IcrALRM, got)
	}

	pra0 := cs.ReadCIAByte(0x00BFE001)
	if pra0&0xC0 != 0xC0 || pra0&0x10 != 0x00 {
		t.Fatalf("unexpected initial CIAA_PRA=%#02X", pra0)
	}

	cs.WriteCIAByte(0x00BFD100, 0x71)
	cs.WriteCIAByte(0x00BFD100, 0x70)
	cs.WriteCIAByte(0x00BFD100, 0x71)
	if cs.HeadCyl != 1 {
		t.Fatalf("expected HeadCyl=1, got %d", cs.HeadCyl)
	}
	if cs.ReadCIAByte(0x00BFE001)&0x10 != 0x10 {
		t.Fatalf("expected /TK0=1 off track 0")
	}

	cs.WriteCIAByte(0x00BFD100, 0x73)
	cs.WriteCIAByte(0x00BFD100, 0x72)
	if cs.HeadCyl != 0 {
		t.Fatalf("expected HeadCyl=0, got %d", cs.HeadCyl)
	}
	if cs.ReadCIAByte(0x00BFE001)&0x10 != 0x00 {
		t.Fatalf("expected /TK0=0 on track 0")
	}
}

func TestBlitterCopyMintermShiftMaskAndBZero(t *testing.T) {
	cs := NewChipset()
	mem := make([]byte, 0x400)

	csWriteBeU16(mem, 0x100, 0x1234)
	csWriteBeU16(mem, 0x102, 0x5678)

	cs.WriteCustomWord(0x00DFF040, 0x49F0, mem)
	cs.WriteCustomWord(0x00DFF042, 0x0000, mem)
	cs.WriteCustomWord(0x00DFF044, 0xFFF0, mem)
	cs.WriteCustomWord(0x00DFF046, 0x0FFF, mem)
	cs.WriteCustomWord(0x00DFF050, 0x0000, mem)
	cs.WriteCustomWord(0x00DFF052, 0x0100, mem)
	cs.WriteCustomWord(0x00DFF054, 0x0000, mem)
	cs.WriteCustomWord(0x00DFF056, 0x0200, mem)
	cs.WriteCustomWord(0x00DFF064, 0x0000, mem)
	cs.WriteCustomWord(0x00DFF066, 0x0000, mem)
	cs.WriteCustomWord(0x00DFF058, 0x0042, mem)

	if got := csReadBeU16(mem, 0x200); got != 0x0123 {
		t.Fatalf("expected word 0 = 0x0123, got %#04X", got)
	}
	if got := csReadBeU16(mem, 0x202); got != 0x0067 {
		t.Fatalf("expected word 1 = 0x0067, got %#04X", got)
	}
	if cs.Blitter.APT != 0x104 || cs.Blitter.DPT != 0x204 {
		t.Fatalf("unexpected APT=%#X DPT=%#X", cs.Blitter.APT, cs.Blitter.DPT)
	}
	if cs.ReadCustomWord(0x00DFF002)&dmaconrBZERO != 0 {
		t.Fatalf("expected BZERO=0 for non-zero blit")
	}
	if cs.ReadCustomWord(0x00DFF002)&dmaconrBBUSY == 0 {
		t.Fatalf("expected BBUSY=1 before tick")
	}

	cs.Tick(64, mem)
	if cs.ReadCustomWord(0x00DFF01E)&IntBLIT == 0 {
		t.Fatalf("expected INT_BLIT after blit completion")
	}

	cs.WriteCustomWord(0x00DFF040, 0x0100, mem)
	cs.WriteCustomWord(0x00DFF056, 0x0200, mem)
	cs.WriteCustomWord(0x00DFF058, 0x0042, mem)
	if csReadBeU16(mem, 0x200) != 0 || csReadBeU16(mem, 0x202) != 0 {
		t.Fatalf("expected cleared words at 0x200..0x204")
	}
	if cs.ReadCustomWord(0x00DFF002)&dmaconrBZERO == 0 {
		t.Fatalf("expected BZERO=1 after clearblit")
	}
}

func TestBlitterDescendingAndInclusiveExclusiveFill(t *testing.T) {
	cs := NewChipset()
	mem := make([]byte, 0x400)

	csWriteBeU16(mem, 0x100, 0x0022)
	cs.WriteCustomWord(0x00DFF044, 0xFFFF, mem)
	cs.WriteCustomWord(0x00DFF046, 0xFFFF, mem)
	cs.WriteCustomWord(0x00DFF040, 0x09F0, mem)

	cs.WriteCustomWord(0x00DFF042, 0x000A, mem) // IFE | DESC
	cs.WriteCustomWord(0x00DFF052, 0x0100, mem)
	cs.WriteCustomWord(0x00DFF056, 0x0200, mem)
	cs.WriteCustomWord(0x00DFF058, 0x0041, mem)
	if got := csReadBeU16(mem, 0x200); got != 0x003E {
		t.Fatalf("expected inclusive fill 0x003E, got %#04X", got)
	}
	if cs.Blitter.APT != 0x0FE {
		t.Fatalf("expected APT=0x0FE after descending blit, got %#X", cs.Blitter.APT)
	}

	cs.WriteCustomWord(0x00DFF042, 0x0012, mem) // EFE | DESC
	cs.WriteCustomWord(0x00DFF052, 0x0100, mem)
	cs.WriteCustomWord(0x00DFF056, 0x0202, mem)
	cs.WriteCustomWord(0x00DFF058, 0x0041, mem)
	if got := csReadBeU16(mem, 0x202); got != 0x001E {
		t.Fatalf("expected exclusive fill 0x001E, got %#04X", got)
	}
}

func TestCopperMoveWalkGuardsAndBlitterIntreqDispatch(t *testing.T) {
	cs := NewChipset()
	mem := make([]byte, 0x800)

	cs.WriteCustomWord(0x00DFF096, 0x8000|DmaMASTER|DmaCOPPER, mem)

	// Guard (a): before COP1LC is written, VBlank must NOT walk address 0.
	csWriteBeU16(mem, 0x000, 0x009C)
	csWriteBeU16(mem, 0x002, 0x8004)
	cs.Tick(CyclesPerFrame, mem)
	if cs.ReadCustomWord(0x00DFF01E)&IntSOFT != 0 {
		t.Fatalf("expected guard (a) to prevent walking uninitialized COP1LC=0")
	}

	coplist1 := [][2]uint16{
		{0x0084, 0x0000}, // MOVE #0, COP2LCH
		{0x0086, 0x0400}, // MOVE #$0400, COP2LCL
		{0x2C01, 0xFFFE}, // WAIT vpos=$2C
		{0x008A, 0x0000}, // MOVE #0, COPJMP2
	}
	for i, pair := range coplist1 {
		a := uint32(0x300 + i*4)
		csWriteBeU16(mem, a, pair[0])
		csWriteBeU16(mem, a+2, pair[1])
	}

	coplist2 := [][2]uint16{
		{0x0074, 0xCAFE}, // MOVE #$CAFE, BLTADAT
		{0x0054, 0x0000}, // MOVE #0, BLTDPTH
		{0x0056, 0x0500}, // MOVE #$0500, BLTDPTL
		{0x0040, 0x01F0}, // MOVE #$01F0, BLTCON0 (USED, D=A)
		{0x0042, 0x0000}, // MOVE #0, BLTCON1
		{0x0058, 0x0041}, // MOVE #$0041, BLTSIZE (1x1)
		{0x009C, 0x8010}, // MOVE #$8010, INTREQ (INT_COPER)
		{0x008A, 0x0000}, // Self-loop via COPJMP2 (must terminate via 1024-step cap)
	}
	for i, pair := range coplist2 {
		a := uint32(0x400 + i*4)
		csWriteBeU16(mem, a, pair[0])
		csWriteBeU16(mem, a+2, pair[1])
	}

	cs.WriteCustomWord(0x00DFF080, 0x0000, mem)
	cs.WriteCustomWord(0x00DFF082, 0x0300, mem)
	cs.Tick(CyclesPerFrame, mem)

	if got := csReadBeU16(mem, 0x500); got != 0xCAFE {
		t.Fatalf("expected Copper-triggered Blitter write 0xCAFE at 0x500, got %#04X", got)
	}
	if cs.ReadCustomWord(0x00DFF01E)&IntCOPER == 0 {
		t.Fatalf("expected Copper-triggered INT_COPER")
	}
}

func TestTraceObservesTrampolineDispatch(t *testing.T) {
	base := uint32(0x1000)
	img := []byte{
		0x20, 0x7C, 0x00, 0x00, 0x10, 0x0A, // move.l #$100A,a0
		0x4E, 0xD0, // jmp (a0)
		0x4E, 0x71, // nop
		0x4E, 0x75, // rts
	}
	opts := TraceOptions{Budget: 10000, StuckN: 1000}
	r := RunTrace(img, base, base, opts)
	var site *DispatchSite
	for i := range r.Sites {
		if r.Sites[i].Addr == 0x1006 {
			site = &r.Sites[i]
			break
		}
	}
	if site == nil {
		t.Fatalf("jmp (a0) site not observed; sites=%+v", r.Sites)
	}
	if site.Mode != m68k.EAAddrInd {
		t.Fatalf("expected Mode=(An), got %q", site.Mode)
	}
	if _, ok := site.Targets[0x100A]; !ok {
		t.Fatalf("target 0x100A not recorded in %+v", site.Targets)
	}
}

func TestTraceDetectsStuckWait(t *testing.T) {
	base := uint32(0x2000)
	img := []byte{0x60, 0xFE} // bra.s -2
	opts := TraceOptions{Budget: 1000000, StuckN: 500}
	r := RunTrace(img, base, base, opts)
	if r.Stop.Kind != StopStuckWait {
		t.Fatalf("expected StopStuckWait, got %s", r.Stop)
	}
	if r.Instructions >= 10000 {
		t.Fatalf("expected instructions near stuck_n, got %d", r.Instructions)
	}
}

func newTestTraceAnalyzer(t *testing.T, code []byte, base uint32) (*Analyzer, *db.Controller) {
	t.Helper()
	tmp := t.TempDir()
	binPath := filepath.Join(tmp, "t.bin")
	if err := os.WriteFile(binPath, code, 0o644); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(tmp, "t.db")
	ctrl, err := db.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ctrl.Close() })

	proj := project.New(filepath.Join(tmp, "project.json"))
	fileStr := binPath
	proj.Data.Segments = append(proj.Data.Segments, project.Segment{
		Name:        "hunk0",
		HunkIndex:   0,
		HunkType:    hunk.HunkTypeCode,
		MemoryType:  hunk.MemoryPublic,
		AllocSize:   uint32(len(code)),
		File:        &fileStr,
		Base:        base,
		DB:          dbPath,
		Relocatable: false,
	})
	proj.Data.Spaces = append(proj.Data.Spaces, project.Space{
		Name:     "default",
		Segments: []string{"hunk0"},
	})
	proj.Data.ActiveSpace = "default"

	a, err := New(proj, ctrl)
	if err != nil {
		t.Fatal(err)
	}
	return a, ctrl
}

func TestTraceSeedAndAnnotateTrampoline(t *testing.T) {
	// 10000: 4E D1  jmp (a1)
	// 10002: 4E 75  rts
	code := []byte{0x4E, 0xD1, 0x4E, 0x75}
	a, ctrl := newTestTraceAnalyzer(t, code, 0x10000)

	sites := []DispatchSite{{
		Addr:   0x10000,
		Mode:   m68k.EAAddrInd,
		IsCall: false,
		BaseAn: 1,
		Targets: map[uint32]uint64{
			0x10002: 3,
			0x99999: 1,
		},
	}}

	seeds := a.TraceSeedTargets(sites)
	if !slices.Equal(seeds, []uint32{0x10002}) {
		t.Fatalf("expected seeds=[0x10002], got %v", seeds)
	}

	a.Analyze([]uint32{0x10000, 0x10002})
	a.ApplyTraceDispatches(sites)

	tgt, ok := ctrl.FirstControlEdgeTarget(0x10000)
	if !ok || tgt != 0x10002 {
		t.Fatalf("expected dispatch edge 0x10000 -> 0x10002, got %#X (ok=%v)", tgt, ok)
	}
	cell, err := ctrl.GetCell(0x10000)
	cmt := ctrl.GetAddressComment(0x10000).EffectiveComment()
	if err != nil || cell == nil || !strings.Contains(cmt, "observed") {
		t.Fatalf("expected site comment containing 'observed', got cell=%+v cmt=%q", cell, cmt)
	}
}

func TestTraceSeedIndexedComputedDispatch(t *testing.T) {
	// 10000: 4E B0 A0 00  jsr (0,a0,a2.w)
	// 10004: 4E 75        rts
	code := []byte{0x4E, 0xB0, 0xA0, 0x00, 0x4E, 0x75}
	a, ctrl := newTestTraceAnalyzer(t, code, 0x10000)

	sites := []DispatchSite{{
		Addr:   0x10000,
		Mode:   m68k.EAIndex,
		IsCall: true,
		BaseAn: 0,
		Targets: map[uint32]uint64{
			0x10004: 5,
		},
	}}

	seeds := a.TraceSeedTargets(sites)
	if !slices.Equal(seeds, []uint32{0x10004}) {
		t.Fatalf("expected seeds=[0x10004], got %v", seeds)
	}

	a.Analyze([]uint32{0x10000, 0x10004})
	a.ApplyTraceDispatches(sites)

	tgt, ok := ctrl.FirstControlEdgeTarget(0x10000)
	if !ok || tgt != 0x10004 {
		t.Fatalf("expected CALL edge 0x10000 -> 0x10004, got %#X (ok=%v)", tgt, ok)
	}
}

func TestTraceVectorSeedAndAnnotate(t *testing.T) {
	// 10000: 4E 73  rte
	// 10002: 4E 71  nop
	code := []byte{0x4E, 0x73, 0x4E, 0x71}
	a, ctrl := newTestTraceAnalyzer(t, code, 0x10000)

	vectors := []VectorEntry{
		{Vec: 27, Handler: 0x10000},
		{Vec: 2, Handler: 0x99999},
	}

	vseeds := a.TraceVectorSeeds(vectors)
	if !slices.Equal(vseeds, []uint32{0x10000}) {
		t.Fatalf("expected vseeds=[0x10000], got %v", vseeds)
	}

	a.Analyze([]uint32{0x10000})
	a.ApplyTraceVectors(vectors)

	cell, err := ctrl.GetCell(0x10000)
	cmt := ctrl.GetAddressComment(0x10000).EffectiveComment()
	if err != nil || cell == nil || !strings.Contains(cmt, "Level_3_Interrupt") {
		t.Fatalf("expected Level_3_Interrupt annotation, got cell=%+v cmt=%q", cell, cmt)
	}
}

func TestTraceServicesSelfInstalledTrap(t *testing.T) {
	base := uint32(0x1000)
	img := []byte{
		0x41, 0xFA, 0x00, 0x12, // lea (0x12,pc),a0 -> 0x1014
		0x23, 0xC8, 0x00, 0x00, 0x00, 0x80, // move.l a0,$80
		0x4E, 0x40, // trap #0
		0x70, 0x01, // moveq #1,d0
		0x4E, 0x72, 0x27, 0x00, // stop #$2700
		0x00, 0x00, // padding
		0x4E, 0x73, // handler: rte
	}
	opts := TraceOptions{Budget: 10000, StuckN: 1000}
	r := RunTrace(img, base, base, opts)
	if r.ServicedExcs < 1 {
		t.Fatalf("trap not serviced (serviced_excs=%d), stop=%s", r.ServicedExcs, r.Stop)
	}
	if r.Stop.Kind == StopTrap {
		t.Fatalf("trap caused a hard stop: %s", r.Stop)
	}
}

func TestTraceAnnotatesObservedHWRegister(t *testing.T) {
	// 10000: 3D 40 00 1E  move.w d0,$1E(a6)
	// 10004: 4E 75        rts
	code := []byte{0x3D, 0x40, 0x00, 0x1E, 0x4E, 0x75}
	a, ctrl := newTestTraceAnalyzer(t, code, 0x10000)

	regs := make(RegContext)
	var r [16]uint32
	r[14] = 0x00DFF000 // A6
	regs[0x10000] = r

	a.Analyze([]uint32{0x10000})
	a.ApplyTraceHWRegs(regs)

	cell, err := ctrl.GetCell(0x10000)
	cmt := ctrl.GetAddressComment(0x10000).EffectiveComment()
	if err != nil || cell == nil || !strings.Contains(cmt, "INTREQR") {
		t.Fatalf("expected INTREQR annotation, got cell=%+v cmt=%q", cell, cmt)
	}
}

func TestTraceStopWakesOnEnabledInterruptAndPreservesDispatch(t *testing.T) {
	base := uint32(0x1000)
	img := []byte{
		0x41, 0xFA, 0x00, 0x24, // 1000: lea isr(pc),a0
		0x21, 0xC8, 0x00, 0x6C, // 1004: move.l a0,$006C.w
		0x33, 0xFC, 0xC0, 0x20, 0x00, 0xDF, 0xF0, 0x9A, // 1008: move.w #$C020,$DFF09A
		0x43, 0xFA, 0x00, 0x0E, // 1010: lea sub(pc),a1
		0x4E, 0x72, 0x20, 0x00, // 1014: stop #$2000
		0x4E, 0x91, // 1018: jsr (a1)
		0x4E, 0x72, 0x27, 0x00, // 101A: stop #$2700
		0x4E, 0x71, // 101E: nop
		0x52, 0x40, // 1020: addq.w #1,d0
		0x4E, 0x75, // 1022: rts
		0x4E, 0x71, // 1024: nop
		0x33, 0xFC, 0x00, 0x20, 0x00, 0xDF, 0xF0, 0x9C, // 1026: move.w #$0020,$DFF09C
		0x70, 0x01, // 102E: moveq #1,d0
		0x4E, 0x73, // 1030: rte
	}
	opts := TraceOptions{Budget: 10000, StuckN: 1000}
	r := RunTrace(img, base, base, opts)

	if r.ServicedInts[2] < 1 {
		t.Fatalf("expected L3 interrupt serviced, got %v", r.ServicedInts)
	}
	if r.Stop.Kind != StopStopped || r.Stop.AtPC != 0x101A {
		t.Fatalf("expected Stopped at 0x101A, got %s", r.Stop)
	}
	var site *DispatchSite
	for i := range r.Sites {
		if r.Sites[i].Addr == 0x1018 {
			site = &r.Sites[i]
			break
		}
	}
	if site == nil {
		t.Fatalf("jsr (a1) site at 0x1018 not found in %+v", r.Sites)
	}
	if len(site.Targets) != 1 || site.Targets[0x1020] == 0 {
		t.Fatalf("expected jsr (a1) target 0x1020 only, got %+v", site.Targets)
	}
}
