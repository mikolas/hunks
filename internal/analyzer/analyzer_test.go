package analyzer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mikolas/hunks/internal/db"
	"github.com/mikolas/hunks/internal/hunk"
	"github.com/mikolas/hunks/internal/m68k"
	"github.com/mikolas/hunks/internal/project"
)

func TestIsASCIIStringAt(t *testing.T) {
	s1 := []byte("Normal vector error !\x00")
	if !IsASCIIStringAt(s1, 0) {
		t.Fatalf("expected IsASCIIStringAt(%q) = true", string(s1))
	}

	s2 := []byte(":Files/mod.harddrivin")
	if !IsASCIIStringAt(s2, 0) {
		t.Fatalf("expected IsASCIIStringAt(%q) = true", string(s2))
	}

	c1 := []byte{0x4E, 0x56, 0xFF, 0xF0} // link.w a6,#-16
	if IsASCIIStringAt(c1, 0) {
		t.Fatalf("expected IsASCIIStringAt(link.w) = false")
	}

	c2 := []byte{0x48, 0xE7, 0x3F, 0x3E} // movem.l
	if IsASCIIStringAt(c2, 0) {
		t.Fatalf("expected IsASCIIStringAt(movem.l) = false")
	}

	c3 := []byte{0x70, 0x00, 0x4E, 0x75} // moveq #0,d0 ; rts
	if IsASCIIStringAt(c3, 0) {
		t.Fatalf("expected IsASCIIStringAt(moveq;rts) = false")
	}
}

func TestFormatCMPMAndSignedAbsShort(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "test.bin")
	// 0x0000: B3 08       -> cmpm.b (a0)+,(a1)+
	// 0x0002: C3 08       -> abcd -(a0),-(a1)
	// 0x0004: D3 48       -> addx.w -(a0),-(a1)
	// 0x0006: 45 F8 FF FF -> lea.l (-1).w,a2
	// 0x000A: 4E 75       -> rts
	codeBytes := []byte{
		0xB3, 0x08, 0xC3, 0x08, 0xD3, 0x48, 0x45, 0xF8, 0xFF, 0xFF, 0x4E, 0x75,
	}
	if err := os.WriteFile(binPath, codeBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	dbPath := filepath.Join(tmpDir, "test.db")
	database, err := db.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	proj := project.New(filepath.Join(tmpDir, "project.json"))
	proj.Data.Segments = append(proj.Data.Segments, project.Segment{
		Name:        "hunk0",
		HunkIndex:   0,
		HunkType:    hunk.HunkTypeCode,
		MemoryType:  hunk.MemoryPublic,
		AllocSize:   uint32(len(codeBytes)),
		File:        &binPath,
		Base:        0x10000,
		DB:          dbPath,
		Relocatable: true,
	})
	proj.Data.Spaces = append(proj.Data.Spaces, project.Space{
		Name:     "default",
		Segments: []string{"hunk0"},
	})
	proj.Data.ActiveSpace = "default"

	a, err := New(proj, database)
	if err != nil {
		t.Fatal(err)
	}
	a.Analyze([]uint32{0x10000})

	c0, err := database.GetCell(0x10000)
	if err != nil || c0 == nil || c0.MnemonicStr() != "cmpm.b" || c0.OpStrVal() != "(a0)+,(a1)+" {
		t.Fatalf("0x10000: got (%q, %q), want (cmpm.b, (a0)+,(a1)+)", c0.MnemonicStr(), c0.OpStrVal())
	}

	c2, err := database.GetCell(0x10002)
	if err != nil || c2 == nil || c2.MnemonicStr() != "abcd.b" || c2.OpStrVal() != "-(a0),-(a1)" {
		t.Fatalf("0x10002: got (%q, %q), want (abcd.b, -(a0),-(a1))", c2.MnemonicStr(), c2.OpStrVal())
	}

	c4, err := database.GetCell(0x10004)
	if err != nil || c4 == nil || c4.MnemonicStr() != "addx.w" || c4.OpStrVal() != "-(a0),-(a1)" {
		t.Fatalf("0x10004: got (%q, %q), want (addx.w, -(a0),-(a1))", c4.MnemonicStr(), c4.OpStrVal())
	}

	c6, err := database.GetCell(0x10006)
	if err != nil || c6 == nil || c6.MnemonicStr() != "lea.l" || c6.OpStrVal() != "(-1).w,a2" {
		t.Fatalf("0x10006: got (%q, %q), want (lea.l, (-1).w,a2)", c6.MnemonicStr(), c6.OpStrVal())
	}
}

func TestFormatSBCDAndMoveUSP(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "test.bin")
	// 0x0000: 81 09 -> sbcd.b -(a1),-(a0)
	// 0x0002: 81 09 -> sbcd.b -(a1),-(a0)
	// 0x0004: 4E 67 -> move.l a7,usp
	// 0x0006: 4E 6F -> move.l usp,a7
	// 0x0008: 4E 75 -> rts
	codeBytes := []byte{
		0x81, 0x09, 0x81, 0x09, 0x4E, 0x67, 0x4E, 0x6F, 0x4E, 0x75,
	}
	if err := os.WriteFile(binPath, codeBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	dbPath := filepath.Join(tmpDir, "test.db")
	database, err := db.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	proj := project.New(filepath.Join(tmpDir, "project.json"))
	proj.Data.Segments = append(proj.Data.Segments, project.Segment{
		Name:        "hunk0",
		HunkIndex:   0,
		HunkType:    hunk.HunkTypeCode,
		MemoryType:  hunk.MemoryPublic,
		AllocSize:   uint32(len(codeBytes)),
		File:        &binPath,
		Base:        0x10000,
		DB:          dbPath,
		Relocatable: true,
	})
	proj.Data.Spaces = append(proj.Data.Spaces, project.Space{
		Name:     "default",
		Segments: []string{"hunk0"},
	})
	proj.Data.ActiveSpace = "default"

	a, err := New(proj, database)
	if err != nil {
		t.Fatal(err)
	}
	a.Analyze([]uint32{0x10000})

	c0, err := database.GetCell(0x10000)
	if err != nil || c0 == nil || c0.Size != 2 || c0.MnemonicStr() != "sbcd.b" || c0.OpStrVal() != "-(a1),-(a0)" {
		t.Fatalf("0x10000: got size=%d (%q, %q), want 2 (sbcd.b, -(a1),-(a0))", c0.Size, c0.MnemonicStr(), c0.OpStrVal())
	}

	c2, err := database.GetCell(0x10002)
	if err != nil || c2 == nil || c2.Size != 2 || c2.MnemonicStr() != "sbcd.b" || c2.OpStrVal() != "-(a1),-(a0)" {
		t.Fatalf("0x10002: got size=%d (%q, %q), want 2 (sbcd.b, -(a1),-(a0))", c2.Size, c2.MnemonicStr(), c2.OpStrVal())
	}

	c4, err := database.GetCell(0x10004)
	if err != nil || c4 == nil || c4.MnemonicStr() != "move.l" || c4.OpStrVal() != "a7,usp" {
		t.Fatalf("0x10004: got (%q, %q), want (move.l, a7,usp)", c4.MnemonicStr(), c4.OpStrVal())
	}

	c6, err := database.GetCell(0x10006)
	if err != nil || c6 == nil || c6.MnemonicStr() != "move.l" || c6.OpStrVal() != "usp,a7" {
		t.Fatalf("0x10006: got (%q, %q), want (move.l, usp,a7)", c6.MnemonicStr(), c6.OpStrVal())
	}
}

func TestStage2ProtectsCarvesHintsAndCodeComments(t *testing.T) {
	tmpDir := t.TempDir()
	code := []byte{
		0x70, 0x00, 0x60, 0x08, 0x4E, 0x71, 0x4E, 0x71,
		0x4E, 0x55, 0x00, 0x00, 0x4E, 0x75, 0x00, 0x00,
	}
	binPath := filepath.Join(tmpDir, "t.bin")
	if err := os.WriteFile(binPath, code, 0o644); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(tmpDir, "t.db")
	database, err := db.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	database.SetActiveSeg("hunk0")

	if err := database.InsertCell(&db.Cell{
		Addr:       0x10008,
		Size:       4,
		Type:       db.CellIncbin,
		Confidence: 255,
		RawBytes:   []byte{0x4E, 0x55, 0x00, 0x00},
	}); err != nil {
		t.Fatal(err)
	}
	_ = database.UpdateComment(0x10008, "user carve")

	if err := database.InsertCell(&db.Cell{
		Addr:       0x10000,
		Size:       2,
		Type:       db.CellCode,
		Confidence: 0,
		Mnemonic:   db.StrPtr("moveq"),
		OpStr:      db.StrPtr("#0,d0"),
		RawBytes:   []byte{0x70, 0x00},
	}); err != nil {
		t.Fatal(err)
	}
	_ = database.UpdateComment(0x10000, "entry point")

	proj := project.New(filepath.Join(tmpDir, "project.json"))
	proj.Data.Segments = append(proj.Data.Segments, project.Segment{
		Name:        "hunk0",
		HunkIndex:   0,
		HunkType:    hunk.HunkTypeCode,
		MemoryType:  hunk.MemoryPublic,
		AllocSize:   uint32(len(code)),
		File:        &binPath,
		Base:        0x10000,
		DB:          dbPath,
		Relocatable: true,
	})
	proj.Data.Spaces = append(proj.Data.Spaces, project.Space{
		Name:     "default",
		Segments: []string{"hunk0"},
	})
	proj.Data.ActiveSpace = "default"

	a, err := New(proj, database)
	if err != nil {
		t.Fatal(err)
	}
	a.Analyze([]uint32{0x10000})

	carve, err := database.GetCell(0x10008)
	if err != nil || carve == nil || carve.Type != db.CellIncbin || carve.Confidence != 255 || database.GetAddressComment(0x10008).Comment != "user carve" {
		t.Fatalf("carve at 0x10008 did not survive intact: %+v", carve)
	}

	if cInside, _ := database.GetCell(0x1000A); cInside != nil {
		t.Fatalf("expected nil cell at 0x1000A inside carve, got %+v", cInside)
	}

	r := db.AddrRange{Start: 0x10008, End: 0x1000C}
	labelsInCarve := database.LabelAddrs(&r)
	if len(labelsInCarve) > 0 {
		t.Fatalf("expected no labels inside carve, got %v", labelsInCarve)
	}

	entry, err := database.GetCell(0x10000)
	if err != nil || entry == nil || entry.Type != db.CellCode || database.GetAddressComment(0x10000).Comment != "entry point" {
		t.Fatalf("entry code cell comment lost: %+v", entry)
	}
}

func TestPerSegmentFlatAnalysisOpStrPurity(t *testing.T) {
	tmpDir := t.TempDir()

	mainBytes := []byte{
		0x21, 0xFC, 0x00, 0x03, 0x00, 0x00, 0x00, 0x88,
		0x4E, 0xB9, 0x00, 0x03, 0x00, 0x00,
		0x4E, 0x75,
	}
	eff03Bytes := []byte{0x70, 0x03, 0x4E, 0x75}
	eff11Bytes := []byte{0x70, 0x0B, 0x4E, 0x75}

	mainPath := filepath.Join(tmpDir, "main.bin")
	eff03Path := filepath.Join(tmpDir, "eff03.bin")
	eff11Path := filepath.Join(tmpDir, "eff11.bin")
	_ = os.WriteFile(mainPath, mainBytes, 0o644)
	_ = os.WriteFile(eff03Path, eff03Bytes, 0o644)
	_ = os.WriteFile(eff11Path, eff11Bytes, 0o644)

	dbPath := filepath.Join(tmpDir, "project.db")
	database, err := db.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	proj := project.New(filepath.Join(tmpDir, "project.json"))
	proj.Data.Segments = []project.Segment{
		{Name: "main", HunkIndex: 0, HunkType: hunk.HunkTypeCode, MemoryType: hunk.MemoryPublic, AllocSize: 16, File: &mainPath, Base: 0x28000, DB: dbPath, Relocatable: false},
		{Name: "eff03_t2", HunkIndex: 1, HunkType: hunk.HunkTypeCode, MemoryType: hunk.MemoryPublic, AllocSize: 4, File: &eff03Path, Base: 0x30000, DB: dbPath, Relocatable: false},
		{Name: "eff11_t97", HunkIndex: 2, HunkType: hunk.HunkTypeCode, MemoryType: hunk.MemoryPublic, AllocSize: 4, File: &eff11Path, Base: 0x30000, DB: dbPath, Relocatable: false},
	}
	proj.Data.Spaces = []project.Space{
		{Name: "eff03", Segments: []string{"main", "eff03_t2"}},
		{Name: "eff11", Segments: []string{"main", "eff11_t97"}},
	}
	proj.Data.ActiveSpace = "eff11"
	proj.Data.EntryPoints = []project.EntryPoint{
		{Addr: 0x28000, Name: "dispatcher", Segment: "main"},
		{Addr: 0x30000, Name: "eff03_entry", Segment: "eff03_t2"},
		{Addr: 0x30000, Name: "eff11_entry", Segment: "eff11_t97"},
	}

	for _, segName := range []string{"main", "eff03_t2", "eff11_t97"} {
		a, err := NewForSegment(proj, database, segName)
		if err != nil {
			t.Fatal(err)
		}
		a.Analyze(nil)
	}
	proj.RefreshCoverageStats(database)

	database.SetActiveSeg("main")
	cellMov, _ := database.GetCell(0x28000)
	if cellMov == nil || cellMov.OpStrVal() != "#$30000,$88.w" {
		t.Fatalf("main 0x28000: got %q, want #$30000,$88.w", cellMov.OpStrVal())
	}
	cellJsr, _ := database.GetCell(0x28008)
	if cellJsr == nil || cellJsr.OpStrVal() != "$30000.l" {
		t.Fatalf("main 0x28008: got %q, want $30000.l", cellJsr.OpStrVal())
	}

	if tgt, ok := database.FirstControlEdgeTarget(0x28008); !ok || tgt != 0x30000 {
		t.Fatalf("FirstControlEdgeTarget: got (%x, %v), want (0x30000, true)", tgt, ok)
	}
	if tgt, ok := database.FirstXrefTargetIn(0x28000, 0x28008); !ok || tgt != 0x30000 {
		t.Fatalf("FirstXrefTargetIn: got (%x, %v), want (0x30000, true)", tgt, ok)
	}

	database.SetSpaceSegs([]db.SpaceSeg{{Name: "main", Base: 0x28000, End: 0x28010}})
	if lbl, ok, _ := database.GetLabel(0x30000); ok || lbl != "" {
		t.Fatalf("expected no label at 0x30000 in main scope, got %q", lbl)
	}
}

func TestMovemCrossFamilyAndBriefIndexExtValidation(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "test.bin")
	// 0x0000: 48 E7 E0 10 -> movem.l d0-d2/a3,-(a7)
	// 0x0004: 4C DF 04 02 -> movem.l (a7)+,d1/a2
	// 0x0008: 4E 75       -> rts
	codeBytes := []byte{
		0x48, 0xE7, 0xE0, 0x10,
		0x4C, 0xDF, 0x04, 0x02,
		0x4E, 0x75,
	}
	if err := os.WriteFile(binPath, codeBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	dbPath := filepath.Join(tmpDir, "test.db")
	database, err := db.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	proj := project.New(filepath.Join(tmpDir, "project.json"))
	proj.Data.Segments = append(proj.Data.Segments, project.Segment{
		Name:        "hunk0",
		HunkIndex:   0,
		HunkType:    hunk.HunkTypeCode,
		MemoryType:  hunk.MemoryPublic,
		AllocSize:   uint32(len(codeBytes)),
		File:        &binPath,
		Base:        0x10000,
		DB:          dbPath,
		Relocatable: true,
	})
	proj.Data.Spaces = append(proj.Data.Spaces, project.Space{
		Name:     "default",
		Segments: []string{"hunk0"},
	})
	proj.Data.ActiveSpace = "default"

	a, err := New(proj, database)
	if err != nil {
		t.Fatal(err)
	}
	a.Analyze([]uint32{0x10000})

	c0, err := database.GetCell(0x10000)
	if err != nil || c0 == nil || c0.MnemonicStr() != "movem.l" || c0.OpStrVal() != "d0-d2/a3,-(a7)" {
		t.Fatalf("0x10000: got (%q, %q), want (movem.l, d0-d2/a3,-(a7))", c0.MnemonicStr(), c0.OpStrVal())
	}

	c4, err := database.GetCell(0x10004)
	if err != nil || c4 == nil || c4.MnemonicStr() != "movem.l" || c4.OpStrVal() != "(a7)+,d1/a2" {
		t.Fatalf("0x10004: got (%q, %q), want (movem.l, (a7)+,d1/a2)", c4.MnemonicStr(), c4.OpStrVal())
	}

	// 68000 brief index extension word with non-zero bits 10..8 (0x9DC1) must be rejected by DecodeValidInsn
	a.Segments[0].Data = []byte{0x3A, 0xF0, 0x9D, 0xC1, 0x4E, 0x75}
	a.Segments[0].End = 0x10006
	if _, ok := a.DecodeValidInsn(0x10000, false); ok {
		t.Errorf("expected DecodeValidInsn to reject brief index word 0x9DC1 with non-zero scale/full-ext bits")
	}

	// Valid 68000 brief index extension word (bits 10..8 == 0: 0x98C1) must be accepted
	a.Segments[0].Data = []byte{0x3A, 0xF0, 0x98, 0xC1, 0x4E, 0x75}
	if _, ok := a.DecodeValidInsn(0x10000, false); !ok {
		t.Errorf("expected DecodeValidInsn to accept valid 68000 brief index word 0x98C1")
	}
}

func TestStructuredClassificationAndPCRelativeOffsets(t *testing.T) {
	tmpDir := t.TempDir()
	codeBytes := []byte{
		0x31, 0x7A, 0x00, 0x0C, 0x00, 0x0C, // +0x00: move.w 12(pc),12(a0) -> PC base is +0x02, target = 0x1000E
		0x4C, 0xFA, 0x00, 0x03, 0x00, 0x06, // +0x06: movem.l 6(pc),d0-d1  -> PC base is +0x0A, target = 0x10010
		0x08, 0x3A, 0x00, 0x03, 0x00, 0x02, // +0x0C: btst #3,2(pc)        -> PC base is +0x10, target = 0x10012
		0x66, 0x02, // +0x12: bne.s +2 -> 0x10016
		0x4E, 0x75, // +0x14: rts
		0x4E, 0x75, // +0x16: rts
	}
	binPath := filepath.Join(tmpDir, "code.bin")
	if err := os.WriteFile(binPath, codeBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	dbPath := filepath.Join(tmpDir, "test.db")
	database, err := db.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	proj := project.New(filepath.Join(tmpDir, "project.json"))
	proj.Data.Segments = append(proj.Data.Segments, project.Segment{
		Name:        "hunk0",
		HunkIndex:   0,
		HunkType:    hunk.HunkTypeCode,
		MemoryType:  hunk.MemoryPublic,
		AllocSize:   uint32(len(codeBytes)),
		File:        &binPath,
		Base:        0x10000,
		DB:          dbPath,
		Relocatable: true,
	})
	proj.Data.Spaces = append(proj.Data.Spaces, project.Space{
		Name:     "default",
		Segments: []string{"hunk0"},
	})
	proj.Data.ActiveSpace = "default"

	a, err := New(proj, database)
	if err != nil {
		t.Fatal(err)
	}

	// 1. move.w 12(pc),12(a0) at 0x10000: opIdx=0 is 12(pc) at offset +2 => target 0x1000E
	dMove, ok := a.DecodeValidInsn(0x10000, false)
	if !ok {
		t.Fatal("failed to decode move.w 12(pc),12(a0)")
	}
	if got := a.CalculatePCTarget(0x10000, &dMove, 0); got != 0x1000E {
		t.Fatalf("move.w 12(pc),12(a0) PC target: got %#x, want 0x1000e", got)
	}

	// 2. movem.l 6(pc),d0-d1 at 0x10006: opIdx=0 is 6(pc) after mask word at offset +4 => target 0x10010
	dMovem, ok := a.DecodeValidInsn(0x10006, false)
	if !ok || !dMovem.HasRegisterList() {
		t.Fatal("failed to decode movem.l 6(pc),d0-d1 with register list")
	}
	if got := a.CalculatePCTarget(0x10006, &dMovem, 0); got != 0x10010 {
		t.Fatalf("movem.l 6(pc),d0-d1 PC target: got %#x, want 0x10010", got)
	}

	// 3. btst #3,2(pc) at 0x1000C: opIdx=1 is 2(pc) at offset +4 => target 0x10012; must not be conditional branch
	dBtst, ok := a.DecodeValidInsn(0x1000C, false)
	if !ok {
		t.Fatal("failed to decode btst #3,2(pc)")
	}
	if dBtst.IsConditionalBranch() || dBtst.IsBranch() {
		t.Fatal("btst must not be classified as a branch")
	}
	if got := a.CalculatePCTarget(0x1000C, &dBtst, 1); got != 0x10012 {
		t.Fatalf("btst #3,2(pc) PC target: got %#x, want 0x10012", got)
	}

	// 4. bne.s at 0x10012 must be a conditional branch
	dBne, ok := a.DecodeValidInsn(0x10012, false)
	if !ok || !dBne.IsConditionalBranch() || !dBne.IsBranch() || dBne.IsTerminator() {
		t.Fatal("bne.s must be classified as conditional branch and non-terminator")
	}
}

func TestZeroRelocHunkDoesNotSymbolizeUnrelocatedLongs(t *testing.T) {
	tmpDir := t.TempDir()
	// Relocatable hunk segment at base 0x0 with 0 HUNK_RELOC32 entries:
	//   +0x00: jsr $00000100.l    (unrelocated absolute long targeting +0x100)
	//   +0x06: move.l #$00000100,d0 (unrelocated immediate long matching +0x100)
	//   +0x0C: rts
	//   ...
	//   +0x100: rts
	codeBytes := make([]byte, 0x102)
	copy(codeBytes[0x00:], []byte{
		0x4E, 0xB9, 0x00, 0x00, 0x01, 0x00,
		0x20, 0x3C, 0x00, 0x00, 0x01, 0x00,
		0x4E, 0x75,
	})
	// Place 3 aligned 32-bit words in the gap at +0x1E..+0x2A pointing to 0x100
	copy(codeBytes[0x1E:], []byte{
		0x00, 0x00, 0x01, 0x00,
		0x00, 0x00, 0x01, 0x00,
		0x00, 0x00, 0x01, 0x00,
	})
	copy(codeBytes[0x100:], []byte{0x4E, 0x75})

	binPath := filepath.Join(tmpDir, "hunk0.bin")
	if err := os.WriteFile(binPath, codeBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	dbPath := filepath.Join(tmpDir, "test.db")
	database, err := db.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	proj := project.New(filepath.Join(tmpDir, "project.json"))
	proj.Data.Segments = append(proj.Data.Segments, project.Segment{
		Name:        "hunk0",
		HunkIndex:   0,
		HunkType:    hunk.HunkTypeCode,
		MemoryType:  hunk.MemoryPublic,
		AllocSize:   uint32(len(codeBytes)),
		File:        &binPath,
		Base:        0x0,
		DB:          dbPath,
		Relocatable: true,
	})
	proj.Data.Spaces = append(proj.Data.Spaces, project.Space{
		Name:     "default",
		Segments: []string{"hunk0"},
	})
	proj.Data.ActiveSpace = "default"

	a, err := New(proj, database)
	if err != nil {
		t.Fatal(err)
	}
	a.Analyze([]uint32{0x0})

	// 1. Code discovery still follows jsr $100.l to discover 0x100 as CODE
	c100, err := database.GetCell(0x100)
	if err != nil || c100 == nil || c100.Type != db.CellCode {
		t.Fatalf("expected 0x100 to be discovered as CODE, got %+v", c100)
	}

	// 2. Unrelocated .l and #imm operands in a Relocatable hunk must stay numeric ($100.l / #$100)
	c0, err := database.GetCell(0x0)
	if err != nil || c0 == nil || c0.OpStrVal() != "$100.l" {
		t.Fatalf("0x0 jsr op_str: got %q, want %q", c0.OpStrVal(), "$100.l")
	}
	c6, err := database.GetCell(0x6)
	if err != nil || c6 == nil || c6.OpStrVal() != "#$100,d0" {
		t.Fatalf("0x6 move.l op_str: got %q, want %q", c6.OpStrVal(), "#$100,d0")
	}

	// 3. Unrelocated gap words in a Relocatable hunk must not be harvested as CellPointer
	c1e, err := database.GetCell(0x1E)
	if err != nil || c1e == nil || c1e.Type != db.CellDataL {
		t.Fatalf("0x1E in relocatable hunk with 0 relocs must be CellDataL (not CellPointer), got %+v", c1e)
	}
}

func TestBaseRegCustomEASubstitutionRequiresDFF000Base(t *testing.T) {
	tmpDir := t.TempDir()
	// 0x400: 49 F9 00 DF F0 00 -> lea.l $DFF000.l,a4
	// 0x406: 39 7C 04 00 00 96 -> move.w #$400,$96(a4)  (base=$DFF000 -> substitute DMACON(a4))
	// 0x40C: 49 F9 00 DF F0 02 -> lea.l $DFF002.l,a4
	// 0x412: 39 7C 04 00 00 94 -> move.w #$400,$94(a4)  (base=$DFF002 -> must stay 148(a4), comment DMACON)
	// 0x418: 4E 75             -> rts
	codeBytes := []byte{
		0x49, 0xF9, 0x00, 0xDF, 0xF0, 0x00,
		0x39, 0x7C, 0x04, 0x00, 0x00, 0x96,
		0x49, 0xF9, 0x00, 0xDF, 0xF0, 0x02,
		0x39, 0x7C, 0x04, 0x00, 0x00, 0x94,
		0x4E, 0x75,
	}
	binPath := filepath.Join(tmpDir, "flat.bin")
	if err := os.WriteFile(binPath, codeBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	dbPath := filepath.Join(tmpDir, "test.db")
	database, err := db.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	proj := project.New(filepath.Join(tmpDir, "project.json"))
	proj.Data.Segments = append(proj.Data.Segments, project.Segment{
		Name:        "main",
		HunkIndex:   0,
		HunkType:    hunk.HunkTypeCode,
		MemoryType:  hunk.MemoryPublic,
		AllocSize:   uint32(len(codeBytes)),
		File:        &binPath,
		Base:        0x400,
		DB:          dbPath,
		Relocatable: false,
	})
	proj.Data.Spaces = append(proj.Data.Spaces, project.Space{
		Name:     "default",
		Segments: []string{"main"},
	})
	proj.Data.ActiveSpace = "default"

	a, err := New(proj, database)
	if err != nil {
		t.Fatal(err)
	}
	a.Analyze([]uint32{0x400})

	c406, err := database.GetCell(0x406)
	if err != nil || c406 == nil || c406.OpStrVal() != "#$400,DMACON(a4)" {
		t.Fatalf("0x406 op_str: got %q, want %q", c406.OpStrVal(), "#$400,DMACON(a4)")
	}
	c412, err := database.GetCell(0x412)
	if err != nil || c412 == nil || c412.OpStrVal() != "#$400,148(a4)" {
		t.Fatalf("0x412 op_str (base=$DFF002): got %q, want %q", c412.OpStrVal(), "#$400,148(a4)")
	}
	cmt412 := database.GetAddressComment(0x412).EffectiveComment()
	if !strings.Contains(cmt412, "148(a4) = DMACON") {
		t.Fatalf("0x412 comment: got %q, want to contain %q", cmt412, "148(a4) = DMACON")
	}
}

func TestRegFileTransferOrderAndStrictPromotion(t *testing.T) {
	tmpDir := t.TempDir()
	// Function 1 at 0x1000:
	//   +0x00: 41 F9 00 DF F0 00 -> lea.l $DFF000.l,a0      (const load a0 = $DFF000)
	//   +0x06: 41 E8 00 20       -> lea.l 32(a0),a0         (self-updating relative base: a0 = $DFF020, dynamic write to a0)
	//   +0x0A: 31 7C 04 00 00 76 -> move.w #$400,118(a0)    ($DFF020 + $76 = $DFF096 = DMACON comment, no CustomEA sub)
	//   +0x10: 45 F9 00 DF F0 00 -> lea.l $DFF000.l,a2      (const load a2 = $DFF000, zero dynamic writes program-wide -> promoted!)
	//   +0x16: 61 00 00 0E       -> bsr.w 0x1026            (call clobbers local a0, preserves callee-saved a2)
	//   +0x1A: 31 7C 04 00 00 96 -> move.w #$400,150(a0)    (a0 was clobbered by bsr and not promoted -> no DMACON comment)
	//   +0x20: 20 68 00 10       -> movea.l 16(a0),a0       (dynamic write to a0)
	//   +0x24: 4E 75             -> rts
	// Function 2 at 0x1026:
	//   +0x26: 35 7C 04 00 00 96 -> move.w #$400,150(a2)    (a2 promoted globally to $DFF000 -> CustomEA DMACON(a2))
	//   +0x2C: 24 6A 00 96       -> movea.l 150(a2),a2      (Wait: don't write a2 if we want a2 promoted; use move.w 2(a2),d0: 30 2A 00 02 = DMACONR(a2))
	//   +0x30: 4E 75             -> rts
	codeBytes := []byte{
		0x41, 0xF9, 0x00, 0xDF, 0xF0, 0x00, // 0x1000: lea.l $DFF000.l,a0
		0x41, 0xE8, 0x00, 0x20, // 0x1006: lea.l 32(a0),a0
		0x31, 0x7C, 0x04, 0x00, 0x00, 0x76, // 0x100A: move.w #$400,118(a0)
		0x45, 0xF9, 0x00, 0xDF, 0xF0, 0x00, // 0x1010: lea.l $DFF000.l,a2
		0x61, 0x00, 0x00, 0x0E, // 0x1016: bsr.w 0x1026
		0x31, 0x7C, 0x04, 0x00, 0x00, 0x96, // 0x101A: move.w #$400,150(a0)
		0x20, 0x68, 0x00, 0x10, // 0x1020: movea.l 16(a0),a0
		0x4E, 0x75, // 0x1024: rts
		0x35, 0x7C, 0x04, 0x00, 0x00, 0x96, // 0x1026: move.w #$400,150(a2)
		0x30, 0x2A, 0x00, 0x02, // 0x102C: move.w 2(a2),d0
		0x4E, 0x75, // 0x1030: rts
	}
	binPath := filepath.Join(tmpDir, "flat.bin")
	if err := os.WriteFile(binPath, codeBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	dbPath := filepath.Join(tmpDir, "test.db")
	database, err := db.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	proj := project.New(filepath.Join(tmpDir, "project.json"))
	proj.Data.Segments = append(proj.Data.Segments, project.Segment{
		Name:        "main",
		HunkIndex:   0,
		HunkType:    hunk.HunkTypeCode,
		MemoryType:  hunk.MemoryPublic,
		AllocSize:   uint32(len(codeBytes)),
		File:        &binPath,
		Base:        0x1000,
		DB:          dbPath,
		Relocatable: false,
	})
	proj.Data.Spaces = append(proj.Data.Spaces, project.Space{
		Name:     "default",
		Segments: []string{"main"},
	})
	proj.Data.ActiveSpace = "default"

	a, err := New(proj, database)
	if err != nil {
		t.Fatal(err)
	}
	a.Analyze([]uint32{0x1000})

	// 1. Self-updating lea 32(a0),a0 preserves pre-instruction a0 ($DFF000) -> $DFF020 + 118 = DMACON
	c100A, err := database.GetCell(0x100A)
	if err != nil || c100A == nil {
		t.Fatal("missing cell at 0x100A")
	}
	cmt100A := database.GetAddressComment(0x100A).EffectiveComment()
	if !strings.Contains(cmt100A, "118(a0) = DMACON") {
		t.Fatalf("0x100A comment after self-updating lea 32(a0),a0: got %q, want 118(a0) = DMACON", cmt100A)
	}
	if c100A.OpStrVal() != "#$400,118(a0)" {
		t.Fatalf("0x100A op_str (sub-offset base $DFF020): got %q, want #$400,118(a0)", c100A.OpStrVal())
	}

	// 2. Strict promotion: a2 (zero dynamic writes) is promoted; a0 (has dynamic writes) is NOT promoted
	brs, err := database.GetAllBaseRegs()
	if err != nil {
		t.Fatal(err)
	}
	promoted := make(map[string]uint32)
	for _, br := range brs {
		promoted[br.Reg] = br.BaseAddr
	}
	if promoted["a2"] != 0xDFF000 {
		t.Fatalf("expected a2 to be promoted to 0xDFF000, got %+v", promoted)
	}
	if _, hasA0 := promoted["a0"]; hasA0 {
		t.Fatalf("expected a0 NOT to be promoted due to dynamic writes, got %+v", promoted)
	}

	// 3. Call clobber: bsr at 0x1016 invalidates local scratch a0, so 0x101A has no DMACON comment
	c101A, err := database.GetCell(0x101A)
	if err != nil || c101A == nil {
		t.Fatal("missing cell at 0x101A")
	}
	cmt101A := database.GetAddressComment(0x101A).EffectiveComment()
	if strings.Contains(cmt101A, "DMACON") {
		t.Fatalf("expected bsr to clobber local scratch a0 before 0x101A, got comment %q", cmt101A)
	}

	// 4. Promoted a2 resolves in Function 2 (after rts terminator of Function 1)
	c1026, err := database.GetCell(0x1026)
	if err != nil || c1026 == nil || c1026.OpStrVal() != "#$400,DMACON(a2)" {
		t.Fatalf("0x1026 op_str with promoted a2: got %q, want #$400,DMACON(a2)", c1026.OpStrVal())
	}
}

func TestRegisterIndirectDispatchResolution(t *testing.T) {
	tmpDir := t.TempDir()
	// 0x2000: 41 FA 00 1E       lea.l 0x2020(pc),a0      (target = 0x2002 + 0x1E = 0x2020)
	// 0x2004: 4E 90             jsr (a0)                 (indirect call -> 0x2020)
	// 0x2006: 43 FA 00 0E       lea.l 0x2016(pc),a1      (table = 0x2008 + 0x0E = 0x2016)
	// 0x200A: 0C 40 00 01       cmpi.w #1,d0             (bounds = 2 entries)
	// 0x200E: 62 04             bhi.s 0x2014
	// 0x2010: 4E F1 00 00       jmp 0(a1,d0.w)           (indexed jump through a1 -> 0x2016)
	// 0x2014: 4E 75             rts
	// 0x2016: 00 0E             dc.w 0x2024 - 0x2016     (entry 0 -> 0x2024)
	// 0x2018: 00 12             dc.w 0x2028 - 0x2016     (entry 1 -> 0x2028)
	// 0x201A: FF FF FF FF FF FF (unreferenced padding so gap sweep stops before 0x2020)
	// 0x2020: 70 0A             moveq #10,d0             (reached ONLY via jsr (a0))
	// 0x2022: 4E 75             rts
	// 0x2024: 70 14             moveq #20,d0             (case 0 reached via jmp 0(a1,d0.w))
	// 0x2026: 4E 75             rts
	// 0x2028: 70 1E             moveq #30,d0             (case 1 reached via jmp 0(a1,d0.w))
	// 0x202A: 4E 75             rts
	codeBytes := []byte{
		0x41, 0xFA, 0x00, 0x1E, // 0x2000
		0x4E, 0x90, // 0x2004
		0x43, 0xFA, 0x00, 0x0E, // 0x2006
		0x0C, 0x40, 0x00, 0x01, // 0x200A
		0x62, 0x04, // 0x200E
		0x4E, 0xF1, 0x00, 0x00, // 0x2010
		0x4E, 0x75, // 0x2014
		0x00, 0x0E, // 0x2016
		0x00, 0x12, // 0x2018
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 0x201A..0x2020
		0x70, 0x0A, 0x4E, 0x75, // 0x2020
		0x70, 0x14, 0x4E, 0x75, // 0x2024
		0x70, 0x1E, 0x4E, 0x75, // 0x2028
	}
	binPath := filepath.Join(tmpDir, "indirect.bin")
	if err := os.WriteFile(binPath, codeBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	dbPath := filepath.Join(tmpDir, "test.db")
	database, err := db.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	proj := project.New(filepath.Join(tmpDir, "project.json"))
	proj.Data.Segments = append(proj.Data.Segments, project.Segment{
		Name:        "main",
		HunkIndex:   0,
		HunkType:    hunk.HunkTypeCode,
		MemoryType:  hunk.MemoryPublic,
		AllocSize:   uint32(len(codeBytes)),
		File:        &binPath,
		Base:        0x2000,
		DB:          dbPath,
		Relocatable: false,
	})
	proj.Data.Spaces = append(proj.Data.Spaces, project.Space{
		Name:     "default",
		Segments: []string{"main"},
	})
	proj.Data.ActiveSpace = "default"

	a, err := New(proj, database)
	if err != nil {
		t.Fatal(err)
	}
	a.Analyze([]uint32{0x2000})

	// 1. jsr (a0) at 0x2004 resolved 0x2020 as CODE + CALL edge + comment
	if tgt, ok := database.FirstControlEdgeTarget(0x2004); !ok || tgt != 0x2020 {
		t.Fatalf("expected CALL edge from 0x2004 -> 0x2020, got (%#x, %v)", tgt, ok)
	}
	c2004, _ := database.GetCell(0x2004)
	cmt2004 := database.GetAddressComment(0x2004).EffectiveComment()
	if c2004 == nil || !strings.Contains(cmt2004, "-> LAB_02020") {
		t.Fatalf("expected -> LAB_02020 comment on 0x2004, got cell=%+v cmt=%q", c2004, cmt2004)
	}

	// 2. jmp 0(a1,d0.w) at 0x2010 resolved both 0x2024 and 0x2028 as CODE
	for _, caseAddr := range []uint32{0x2020, 0x2024, 0x2028} {
		cell, err := database.GetCell(caseAddr)
		if err != nil || cell == nil || cell.Type != db.CellCode {
			t.Fatalf("expected %#x to be discovered as CODE, got %+v", caseAddr, cell)
		}
	}
}

func BenchmarkAnalyzePipeline(b *testing.B) {
	// Build a synthetic 200-subroutine binary (~3,200 instructions + data tail)
	var codeBytes []byte
	const numFuncs = 200
	// Each function is 32 bytes:
	//   +0x00: 48 E7 3F 3E             movem.l d2-d7/a2-a6,-(sp)
	//   +0x04: 49 F9 00 DF F0 00       lea.l $DFF000.l,a4
	//   +0x0A: 39 7C 04 00 00 96       move.w #$400,$96(a4)
	//   +0x10: 70 01                   moveq.l #1,d0
	//   +0x12: 61 00 00 0C             bsr.w +12 (calls next func or rts)
	//   +0x16: 4C DF 7C FC             movem.l (sp)+,d2-d7/a2-a6
	//   +0x1A: 4E 75                   rts
	//   +0x1C: 00 00 12 34             dc.l $00001234
	fnTemplate := []byte{
		0x48, 0xE7, 0x3F, 0x3E,
		0x49, 0xF9, 0x00, 0xDF, 0xF0, 0x00,
		0x39, 0x7C, 0x04, 0x00, 0x00, 0x96,
		0x70, 0x01,
		0x61, 0x00, 0x00, 0x0C,
		0x4C, 0xDF, 0x7C, 0xFC,
		0x4E, 0x75,
		0x00, 0x00, 0x12, 0x34,
	}
	for i := 0; i < numFuncs; i++ {
		codeBytes = append(codeBytes, fnTemplate...)
	}
	// Fix last function bsr.w to nop+nop
	lastOff := (numFuncs - 1) * len(fnTemplate)
	codeBytes[lastOff+0x12] = 0x4E
	codeBytes[lastOff+0x13] = 0x71
	codeBytes[lastOff+0x14] = 0x4E
	codeBytes[lastOff+0x15] = 0x71

	tmpDir := b.TempDir()
	binPath := filepath.Join(tmpDir, "bench.bin")
	if err := os.WriteFile(binPath, codeBytes, 0o644); err != nil {
		b.Fatal(err)
	}
	dbPath := filepath.Join(tmpDir, "bench.db")
	ctrl, err := db.New(dbPath)
	if err != nil {
		b.Fatal(err)
	}
	defer ctrl.Close()

	proj := project.New(filepath.Join(tmpDir, "project.json"))
	proj.Data.Segments = append(proj.Data.Segments, project.Segment{
		Name:        "main",
		HunkIndex:   0,
		HunkType:    hunk.HunkTypeCode,
		MemoryType:  hunk.MemoryPublic,
		AllocSize:   uint32(len(codeBytes)),
		File:        &binPath,
		Base:        0x10000,
		DB:          dbPath,
		Relocatable: false,
	})
	proj.Data.Spaces = append(proj.Data.Spaces, project.Space{
		Name:     "default",
		Segments: []string{"main"},
	})
	proj.Data.ActiveSpace = "default"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		an, err := New(proj, ctrl)
		if err != nil {
			b.Fatal(err)
		}
		an.Analyze([]uint32{0x10000})
	}
}

// TestExtractJumpTableBoundsIndexMatching covers R3 (ANALYZER_HEURISTICS_SPEC.md §3.4):
// the range-check immediate must constrain the register that actually indexes the dispatch,
// and a two-instruction offset table must follow the index one hop
// (jmp indexes d1, but the cmp bounds the source index d0 feeding move.w tbl(pc,d0),d1).
func TestExtractJumpTableBoundsIndexMatching(t *testing.T) {
	const base uint32 = 0x10000

	// Two-instruction PC-relative offset-table dispatch (leading nops keep the backward
	// scan window — which stops at seg.Base+2 — clear of the segment start):
	//   +0x00 nop                   4E 71
	//   +0x02 nop                   4E 71
	//   +0x04 cmpi.w #7,d0          0C 40 00 07
	//   +0x08 add.w  d0,d0          D0 40
	//   +0x0A move.w $10(pc,d0.w),d1 32 3B 00 10   (dst d1, src d8(pc,D0.w))
	//   +0x0E jmp    $00(pc,d1.w)   4E FB 10 00     (dispatch index = d1)
	code := []byte{
		0x4E, 0x71,
		0x4E, 0x71,
		0x0C, 0x40, 0x00, 0x07,
		0xD0, 0x40,
		0x32, 0x3B, 0x00, 0x10,
		0x4E, 0xFB, 0x10, 0x00,
	}
	a, _ := newTestTraceAnalyzer(t, code, base)

	// Sanity: confirm the synthetic encodings decode as intended before asserting bounds.
	cmpInsn, ok := m68k.Decode(code[4:8], base+4)
	if !ok || cmpInsn.Op != m68k.OpCMPI || cmpInsn.Ops[1].Mode != m68k.EADataReg || cmpInsn.Ops[1].Reg != 0 {
		t.Fatalf("setup: expected cmpi.w #7,d0; got %+v", cmpInsn)
	}
	mvInsn, ok := m68k.Decode(code[10:14], base+10)
	if !ok || mvInsn.Op != m68k.OpMOVE || mvInsn.Suffix != m68k.SizeW ||
		mvInsn.Ops[0].Mode != m68k.EAPCIndex || mvInsn.Ops[0].IndexReg != 0 ||
		mvInsn.Ops[1].Mode != m68k.EADataReg || mvInsn.Ops[1].Reg != 1 {
		t.Fatalf("setup: expected move.w d8(pc,d0.w),d1; got %+v", mvInsn)
	}
	jmpInsn, ok := m68k.Decode(code[14:18], base+14)
	if !ok || jmpInsn.Op != m68k.OpJMP || jmpInsn.Ops[0].Mode != m68k.EAPCIndex || jmpInsn.Ops[0].IndexReg != 1 {
		t.Fatalf("setup: expected jmp d8(pc,d1.w) with index d1; got %+v", jmpInsn)
	}

	siteAddr := base + 14 // the jmp dispatch site, indexed by d1

	// With the provenance follow (d1 -> d0 via the move.w), cmpi.w #7,d0 bounds the table: 7+1 = 8.
	if b, ok := a.extractJumpTableBounds(siteAddr, jmpInsn.Ops[0].IndexReg); !ok || b != 8 {
		t.Fatalf("expected index-provenance follow to yield bound 8, got (%d, %v)", b, ok)
	}

	// Negative control: a compare that constrains an unrelated register (d3) must NOT bound,
	// even though it is within the scan window (leading nops keep it clear of seg.Base+2).
	//   +0x00 nop / nop            4E 71 4E 71
	//   +0x04 cmpi.w #7,d3          0C 43 00 07
	//   +0x08 jmp    $00(pc,d1.w)   4E FB 10 00
	code2 := []byte{
		0x4E, 0x71, 0x4E, 0x71,
		0x0C, 0x43, 0x00, 0x07,
		0x4E, 0xFB, 0x10, 0x00,
	}
	a2, _ := newTestTraceAnalyzer(t, code2, base)
	jmp2, ok := m68k.Decode(code2[8:12], base+8)
	if !ok || jmp2.Ops[0].IndexReg != 1 {
		t.Fatalf("setup: expected jmp d8(pc,d1.w); got %+v", jmp2)
	}
	if _, ok := a2.extractJumpTableBounds(base+8, jmp2.Ops[0].IndexReg); ok {
		t.Fatalf("expected no bound when cmp constrains an unrelated register (d3 vs index d1)")
	}

	// Address-register index must be left unbounded regardless of nearby compares.
	if _, ok := a.extractJumpTableBounds(siteAddr, 8 /* a0 */); ok {
		t.Fatalf("expected address-register index (idxReg>=8) to be unbounded")
	}

	// Instruction-boundary walk via codeCells must not mis-decode an interior extension word
	// as a bogus instruction when preceding instructions are in codeCells.
	tree := newCodeBTree()
	tree.ReplaceOrInsert(db.Cell{Addr: base + 4, Size: 4, Type: db.CellCode, RawBytes: code[4:8]})
	tree.ReplaceOrInsert(db.Cell{Addr: base + 8, Size: 2, Type: db.CellCode, RawBytes: code[8:10]})
	tree.ReplaceOrInsert(db.Cell{Addr: base + 10, Size: 4, Type: db.CellCode, RawBytes: code[10:14]})
	if b, ok := a.extractJumpTableBoundsIn(siteAddr, jmpInsn.Ops[0].IndexReg, tree); !ok || b != 8 {
		t.Fatalf("expected codeCells-walked bound 8, got (%d, %v)", b, ok)
	}
}

// TestFunctionMetaAndNoreturnPruning covers R4 (ANALYZER_HEURISTICS_SPEC.md §3.5):
// the post-traversal pass records end_addr / is_noreturn / stack_frame, drops the
// FALLTHROUGH edge inserted after a bsr to a no-return function, and does not misclassify
// a function that has both an error ILLEGAL branch and a normal tail-call branch as no-return.
func TestFunctionMetaAndNoreturnPruning(t *testing.T) {
	const base uint32 = 0x10000
	// 0x10000 main:       bsr.w normalFn      61 00 00 0C   (-> 0x1000E)
	// 0x10004             bsr.w noreturnFn    61 00 00 10   (-> 0x10016)
	// 0x10008             bsr.w tailCallFn    61 00 00 0E   (-> 0x10018)
	// 0x1000C             rts                 4E 75
	// 0x1000E normalFn:   link a5,#-4         4E 55 FF FC
	// 0x10012             unlk a5             4E 5D
	// 0x10014             rts                 4E 75
	// 0x10016 noreturnFn: bra.s self          60 FE         (infinite self-loop)
	// 0x10018 tailCallFn: beq.s .err          67 02         (-> 0x1001C)
	// 0x1001A             bra.s normalFn      60 F2         (tail-call -> 0x1000E)
	// 0x1001C .err:       illegal             4A FC         (halt on error path only)
	code := []byte{
		0x61, 0x00, 0x00, 0x0C,
		0x61, 0x00, 0x00, 0x10,
		0x61, 0x00, 0x00, 0x0E,
		0x4E, 0x75,
		0x4E, 0x55, 0xFF, 0xFC,
		0x4E, 0x5D,
		0x4E, 0x75,
		0x60, 0xFE,
		0x67, 0x02,
		0x60, 0xF2,
		0x4A, 0xFC,
	}
	a, ctrl := newTestTraceAnalyzer(t, code, base)
	a.Analyze([]uint32{base})

	const normalFn = base + 0x0E   // 0x1000E
	const noreturnFn = base + 0x16 // 0x10016
	const tailCallFn = base + 0x18 // 0x10018

	// normalFn: not no-return, frame = -4 (LINK a5,#-4), end_addr past its rts (0x10016).
	nm, ok := ctrl.GetFunctionMeta(normalFn)
	if !ok {
		t.Fatalf("normalFn: expected a functions row")
	}
	if nm.IsNoreturn {
		t.Errorf("normalFn: expected is_noreturn=false")
	}
	if !nm.HasFrame || nm.StackFrame != -4 {
		t.Errorf("normalFn: expected stack_frame=-4, got %d (has=%v)", nm.StackFrame, nm.HasFrame)
	}
	if !nm.HasEnd || nm.EndAddr != 0x10016 {
		t.Errorf("normalFn: expected end_addr=0x10016, got %#X (has=%v)", nm.EndAddr, nm.HasEnd)
	}

	// noreturnFn: no-return (infinite self bra), no LINK frame.
	nr, ok := ctrl.GetFunctionMeta(noreturnFn)
	if !ok {
		t.Fatalf("noreturnFn: expected a functions row")
	}
	if !nr.IsNoreturn {
		t.Errorf("noreturnFn: expected is_noreturn=true")
	}
	if nr.HasFrame {
		t.Errorf("noreturnFn: expected no stack_frame, got %d", nr.StackFrame)
	}

	// tailCallFn: has an error ILLEGAL path AND a tail-call bra.s normalFn path -> NOT no-return.
	tc, ok := ctrl.GetFunctionMeta(tailCallFn)
	if !ok {
		t.Fatalf("tailCallFn: expected a functions row")
	}
	if tc.IsNoreturn {
		t.Errorf("tailCallFn: expected is_noreturn=false because of tail-call exit to normalFn")
	}

	// The FALLTHROUGH edge after the bsr to the no-return function (0x10004 -> 0x10008)
	// must have been pruned; the fallthroughs after normalFn (0x10000 -> 0x10004) and
	// tailCallFn (0x10008 -> 0x1000C) must remain.
	var ftAfterNoreturn, ftAfterNormal, ftAfterTailCall bool
	for _, e := range ctrl.AllEdges() {
		if e.Kind != db.EdgeFallthrough {
			continue
		}
		if e.Source == 0x10004 && e.Target == 0x10008 {
			ftAfterNoreturn = true
		}
		if e.Source == 0x10000 && e.Target == 0x10004 {
			ftAfterNormal = true
		}
		if e.Source == 0x10008 && e.Target == 0x1000C {
			ftAfterTailCall = true
		}
	}
	if ftAfterNoreturn {
		t.Errorf("expected FALLTHROUGH 0x10004->0x10008 (after bsr to no-return fn) to be pruned")
	}
	if !ftAfterNormal {
		t.Errorf("expected FALLTHROUGH 0x10000->0x10004 (after bsr to returning fn) to remain")
	}
	if !ftAfterTailCall {
		t.Errorf("expected FALLTHROUGH 0x10008->0x1000C (after bsr to tail-calling fn) to remain")
	}
}

// TestApplyTraceRegDispatchesResolvesFromRegContext covers R6/§3.6: an indirect
// jmp (a0) that static analysis cannot resolve is resolved from the trace's observed
// register file and recorded as a control-flow edge.
func TestApplyTraceRegDispatchesResolvesFromRegContext(t *testing.T) {
	const base uint32 = 0x10000
	// 0x10000: jmp (a0)   4E D0   (indirect; a0 unknown statically)
	// 0x10002: rts        4E 75   (the observed target)
	code := []byte{0x4E, 0xD0, 0x4E, 0x75}
	a, ctrl := newTestTraceAnalyzer(t, code, base)
	a.Analyze([]uint32{base})

	// Static analysis leaves the jmp (a0) site unresolved (no control edge).
	if _, resolved := ctrl.FirstControlEdgeTarget(base); resolved {
		t.Fatalf("precondition: expected jmp (a0) to be statically unresolved")
	}

	// Trace observed a0 = 0x10002 at the dispatch PC.
	var regvals [16]uint32
	regvals[8+0] = base + 2 // a0
	regs := RegContext{base: regvals}
	a.ApplyTraceRegDispatches(regs)

	tgt, ok := ctrl.FirstControlEdgeTarget(base)
	if !ok || tgt != base+2 {
		t.Fatalf("expected trace-resolved edge 0x10000 -> 0x10002, got %#X (ok=%v)", tgt, ok)
	}
}

// TestValidateCandidateLivenessSuspect covers R6/§3.7: a candidate that reads an address
// register as a memory base before writing it in-window is flagged suspect (but still
// accepted), whereas one that writes the base first is not.
func TestValidateCandidateLivenessSuspect(t *testing.T) {
	const base uint32 = 0x10000
	var noHints [8]bool
	empty := make(map[uint32]struct{})

	// Use-before-def: move.w (a3),d0 ; rts  -> reads (a3) with a3 never written -> suspect.
	//   move.w (a3),d0   30 13
	//   rts              4E 75
	useBeforeDef := []byte{0x30, 0x13, 0x4E, 0x75}
	a1, _ := newTestTraceAnalyzer(t, useBeforeDef, base)
	ok, suspect := a1.validateCandidate(base, newCodeBTree(), empty, nil, noHints)
	if !ok {
		t.Fatalf("use-before-def: expected ok=true (never hard-reject)")
	}
	if !suspect {
		t.Fatalf("use-before-def: expected suspect=true (reads (a3) before a3 written)")
	}

	// Def-before-use: movea.l #$10000,a3 ; move.w (a3),d0 ; rts -> a3 written first -> not suspect.
	//   movea.l #$00010000,a3   26 7C 00 01 00 00
	//   move.w  (a3),d0         30 13
	//   rts                     4E 75
	defBeforeUse := []byte{0x26, 0x7C, 0x00, 0x01, 0x00, 0x00, 0x30, 0x13, 0x4E, 0x75}
	a2, _ := newTestTraceAnalyzer(t, defBeforeUse, base)
	// sanity: first instruction writes a3
	mv, dok := m68k.Decode(defBeforeUse[0:6], base)
	if !dok || mv.Op != m68k.OpMOVEA || (mv.WriteRegs&m68k.RegA(3)) == 0 {
		t.Fatalf("setup: expected movea.l #...,a3 writing a3; got %+v", mv)
	}
	ok2, suspect2 := a2.validateCandidate(base, newCodeBTree(), empty, nil, noHints)
	if !ok2 {
		t.Fatalf("def-before-use: expected ok=true")
	}
	if suspect2 {
		t.Fatalf("def-before-use: expected suspect=false (a3 written before read)")
	}

	// A hinted global base read before write must NOT be suspect.
	a3, _ := newTestTraceAnalyzer(t, useBeforeDef, base)
	var hintA3 [8]bool
	hintA3[3] = true
	ok3, suspect3 := a3.validateCandidate(base, newCodeBTree(), empty, nil, hintA3)
	if !ok3 || suspect3 {
		t.Fatalf("hinted-global base: expected ok=true, suspect=false; got ok=%v suspect=%v", ok3, suspect3)
	}

	// Post-increment store through uninitialized base: move.b d0,(a3)+ ; rts -> suspect.
	//   move.b d0,(a3)+   16 C0
	//   rts               4E 75
	storeBeforeDef := []byte{0x16, 0xC0, 0x4E, 0x75}
	a4, _ := newTestTraceAnalyzer(t, storeBeforeDef, base)
	ok4, suspect4 := a4.validateCandidate(base, newCodeBTree(), empty, nil, noHints)
	if !ok4 || !suspect4 {
		t.Fatalf("postinc-store-before-def: expected ok=true, suspect=true; got ok=%v suspect=%v", ok4, suspect4)
	}
}

func TestCustomRegBitfieldAutoComments(t *testing.T) {
	const base uint32 = 0x10000
	// 0x10000: move.w #$83C0,$DFF096.l     33 FC 83 C0 00 DF F0 96  (8B) -> direct DMACON word write
	// 0x10008: move.l #$09F00002,$DFF040.l 23 FC 09 F0 00 02 00 DF F0 40 (10B) -> direct BLTCON0+BLTCON1 long write
	// 0x10012: lea.l  $DFF000.l,a5         4B F9 00 DF F0 00        (6B)
	// 0x10018: move.w #$4200,$100(a5)      3B 7C 42 00 01 00        (6B) -> base-reg BPLCON0 word write
	// 0x1001E: rts                         4E 75                    (2B)
	code := []byte{
		0x33, 0xFC, 0x83, 0xC0, 0x00, 0xDF, 0xF0, 0x96,
		0x23, 0xFC, 0x09, 0xF0, 0x00, 0x02, 0x00, 0xDF, 0xF0, 0x40,
		0x4B, 0xF9, 0x00, 0xDF, 0xF0, 0x00,
		0x3B, 0x7C, 0x42, 0x00, 0x01, 0x00,
		0x4E, 0x75,
	}
	a, ctrl := newTestTraceAnalyzer(t, code, base)
	a.Analyze([]uint32{base})

	cDmacon := ctrl.GetAddressComment(0x10000).AutoComment
	if !strings.Contains(cDmacon, "SET|DMAEN|BPLEN|COPEN|BLTEN") {
		t.Fatalf("expected DMACON bitfield auto-comment at 0x10000, got %q", cDmacon)
	}

	cBltcon := ctrl.GetAddressComment(0x10008).AutoComment
	if !strings.Contains(cBltcon, "BLTCON0: USEA|USED|LF=$F0 (D=A) | BLTCON1: DESC") {
		t.Fatalf("expected paired BLTCON0+BLTCON1 bitfield auto-comment at 0x10008, got %q", cBltcon)
	}

	cBplcon := ctrl.GetAddressComment(0x10018).AutoComment
	if !strings.Contains(cBplcon, "4BPU (16c)|COLOR") {
		t.Fatalf("expected BPLCON0 bitfield auto-comment at 0x10018, got %q", cBplcon)
	}
}

func TestAbsShortXrefsAndRangeRollup(t *testing.T) {
	const base uint32 = 0x10000
	// 0x10000: move.w $1034.w,d0   30 38 10 34
	// 0x10004: move.w d0,$1038.w   31 C0 10 38
	// 0x10008: lea.l  $1178.w,a0   41 F8 11 78
	// 0x1000C: pea.l  $0020.w      48 78 00 20 (small constant push — must not record xref)
	// 0x10010: rts                 4E 75
	code := []byte{
		0x30, 0x38, 0x10, 0x34,
		0x31, 0xC0, 0x10, 0x38,
		0x41, 0xF8, 0x11, 0x78,
		0x48, 0x78, 0x00, 0x20,
		0x4E, 0x75,
	}
	a, ctrl := newTestTraceAnalyzer(t, code, base)
	a.Analyze([]uint32{base})

	if xrefs := ctrl.GetXrefsToRange(0x1034, 0x1035, false); len(xrefs) != 1 || xrefs[0].Source != 0x10000 || xrefs[0].Kind != db.XrefDataRead {
		t.Fatalf("expected 1 XrefDataRead to 0x1034 from 0x10000, got %+v", xrefs)
	}
	if xrefs := ctrl.GetXrefsToRange(0x1038, 0x1039, false); len(xrefs) != 1 || xrefs[0].Source != 0x10004 || xrefs[0].Kind != db.XrefDataWrite {
		t.Fatalf("expected 1 XrefDataWrite to 0x1038 from 0x10004, got %+v", xrefs)
	}
	if xrefs := ctrl.GetXrefsToRange(0x1178, 0x1179, false); len(xrefs) != 1 || xrefs[0].Source != 0x10008 || xrefs[0].Kind != db.XrefDataAddr {
		t.Fatalf("expected 1 XrefDataAddr to 0x1178 from 0x10008, got %+v", xrefs)
	}
	if xrefs := ctrl.GetXrefsToRange(0x0020, 0x0021, false); len(xrefs) != 0 {
		t.Fatalf("expected pea $0020.w not to record xref, got %+v", xrefs)
	}
	rangeXrefs := ctrl.GetXrefsToRange(0x1000, 0x1200, true)
	if len(rangeXrefs) != 3 {
		t.Fatalf("expected 3 xrefs in range 0x1000..0x1200, got %+v", rangeXrefs)
	}
}

func TestStaticMemorySlotTrampolineResolution(t *testing.T) {
	const base uint32 = 0x10000
	// 0x10000: move.w #$4EF9,$1032.w        31 FC 4E F9 10 32
	// 0x10006: move.l #$00010014,$1034.w    21 FC 00 01 00 14 10 34
	// 0x1000E: jsr    $1032.w               4E B8 10 32
	// 0x10012: rts                          4E 75
	// 0x10014: moveq  #$2A,d0               70 2A
	// 0x10016: rts                          4E 75
	code := []byte{
		0x31, 0xFC, 0x4E, 0xF9, 0x10, 0x32,
		0x21, 0xFC, 0x00, 0x01, 0x00, 0x14, 0x10, 0x34,
		0x4E, 0xB8, 0x10, 0x32,
		0x4E, 0x75,
		0x70, 0x2A,
		0x4E, 0x75,
	}
	a, ctrl := newTestTraceAnalyzer(t, code, base)
	a.Analyze([]uint32{base})

	cTarget, err := ctrl.GetCell(0x10014)
	if err != nil || cTarget == nil || cTarget.Type != db.CellCode {
		t.Fatalf("expected target 0x10014 to be discovered as CODE via static trampoline slot, got %+v", cTarget)
	}
	if tgt, ok := ctrl.FirstControlEdgeTarget(0x1000E); !ok || tgt != 0x10014 {
		t.Fatalf("expected jsr $1032.w at 0x1000E to have EdgeCall to 0x10014, got (%#x, %v)", tgt, ok)
	}
	if autoCmt := ctrl.GetAddressComment(0x1000E).AutoComment; !strings.Contains(autoCmt, "-> LAB_0_00014 (via $1032)") {
		t.Fatalf("expected auto-comment at 0x1000E to contain '-> LAB_0_00014 (via $1032)', got %q", autoCmt)
	}
}

func TestTraceLowRAMTrampolineBouncing(t *testing.T) {
	const base uint32 = 0x10000
	code := []byte{
		0x31, 0xFC, 0x4E, 0xF9, 0x10, 0x32,
		0x21, 0xFC, 0x00, 0x01, 0x00, 0x14, 0x10, 0x34,
		0x4E, 0xB8, 0x10, 0x32,
		0x4E, 0x75,
		0x70, 0x2A,
		0x4E, 0x75,
	}
	res := RunTrace(code, base, base, TraceOptions{Budget: 100, StuckN: 50})
	var found bool
	for _, site := range res.Sites {
		if site.Addr == 0x1000E && site.Targets[0x10014] > 0 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected RunTrace to bounce through low-RAM trampoline $1032.w and resolve 0x10014, got %+v", res.Sites)
	}
}

func TestSMCAutoCommentAnnotation(t *testing.T) {
	const base uint32 = 0x10000
	// 0x10000: move.w #$1234,$0001000A.l    33 FC 12 34 00 01 00 0A (patches immediate word inside 0x10008!)
	// 0x10008: move.w #$0000,d0             30 3C 00 00
	// 0x1000C: rts                          4E 75
	code := []byte{
		0x33, 0xFC, 0x12, 0x34, 0x00, 0x01, 0x00, 0x0A,
		0x30, 0x3C, 0x00, 0x00,
		0x4E, 0x75,
	}
	a, ctrl := newTestTraceAnalyzer(t, code, base)
	a.Analyze([]uint32{base})

	autoCmt := ctrl.GetAddressComment(0x10000).AutoComment
	if !strings.Contains(autoCmt, "[SMC] writes code at") {
		t.Fatalf("expected SMC auto-comment at 0x10000, got %q", autoCmt)
	}
}

func TestScopedRegisterAliasAndFieldTypeStripping(t *testing.T) {
	const base uint32 = 0x10000
	// 0x10000: bsr.s  $10008        61 06
	// 0x10002: move.w 2(a0),d0      30 28 00 02
	// 0x10006: rts                  4E 75
	// 0x10008: move.w 2(a0),d0      30 28 00 02
	// 0x1000C: rts                  4E 75
	code := []byte{
		0x61, 0x06,
		0x30, 0x28, 0x00, 0x02,
		0x4E, 0x75,
		0x30, 0x28, 0x00, 0x02,
		0x4E, 0x75,
	}
	a, ctrl := newTestTraceAnalyzer(t, code, base)
	a.Proj.Data.Structs = map[string]map[string]string{
		"Model": {
			"2":     "vx.w",
			"_size": "18",
		},
	}
	a.Proj.Data.RegisterAliases = map[string]string{
		"LAB_10008:a0": "Model",
	}
	a.Analyze([]uint32{base})

	cMain, _ := ctrl.GetCell(0x10002)
	if cMain == nil || cMain.OpStrVal() != "2(a0),d0" {
		t.Fatalf("expected un-aliased 2(a0),d0 at 0x10002, got %+v", cMain)
	}
	cSub, _ := ctrl.GetCell(0x10008)
	if cSub == nil || cSub.OpStrVal() != "vx(a0),d0" {
		t.Fatalf("expected function-scoped alias vx(a0),d0 at 0x10008, got %+v", cSub)
	}
}
