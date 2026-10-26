package emitter

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mikolas/hunks/internal/analyzer"
	"github.com/mikolas/hunks/internal/db"
	"github.com/mikolas/hunks/internal/hunk"
	"github.com/mikolas/hunks/internal/project"
)

func TestModularHunkDataBssTailEmission(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	ctrl, err := db.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.Close()
	ctrl.SetActiveSeg("hunk1")

	// 4008 bytes on disk, 60424 total alloc
	binPath := filepath.Join(dir, "hunk1.bin")
	if err := os.WriteFile(binPath, bytes.Repeat([]byte{0x12}, 4008), 0o644); err != nil {
		t.Fatal(err)
	}

	// Add label in tail at offset 0x7FFE (32766) from base 0x10000 -> 0x17FFE
	if err := ctrl.SetLabel(0x10000+32766, "LAB_1_07FFE", db.LabelLab, true); err != nil {
		t.Fatal(err)
	}
	if err := ctrl.MarkExported(0x10000 + 32766); err != nil {
		t.Fatal(err)
	}

	fileDataLen := uint32(4008)
	proj := project.New(filepath.Join(dir, "project.json"))
	proj.Data.Segments = append(proj.Data.Segments, project.Segment{
		Name:        "hunk1",
		HunkIndex:   1,
		HunkType:    hunk.HunkTypeData,
		MemoryType:  hunk.MemoryPublic,
		AllocSize:   60424,
		FileDataLen: &fileDataLen,
		File:        &binPath,
		Base:        0x10000,
		DB:          dbPath,
		Relocatable: true,
	})
	proj.Data.Spaces = append(proj.Data.Spaces, project.Space{
		Name:     "default",
		Segments: []string{"hunk1"},
	})
	proj.Data.ActiveSpace = "default"
	proj.ActiveSegmentName = "hunk1"

	em, err := New(proj, ctrl)
	if err != nil {
		t.Fatal(err)
	}
	if err := em.GenerateModularHunkItems(); err != nil {
		t.Fatal(err)
	}
	lines := em.FormatLines()
	text := strings.Join(lines, "\n")

	if !strings.Contains(text, "SECTION\tS_1,data") {
		t.Errorf("Should contain SECTION S_1,data:\n%s", text)
	}
	if !strings.Contains(text, "XDEF\tLAB_1_07FFE") {
		t.Errorf("Should export LAB_1_07FFE:\n%s", text)
	}
	if !strings.Contains(text, "dx.w\t14379") {
		t.Errorf("Should contain dx.w 14379:\n%s", text)
	}
	if !strings.Contains(text, "LAB_1_07FFE:") {
		t.Errorf("Should contain LAB_1_07FFE:\n%s", text)
	}
	if !strings.Contains(text, "dx.w\t13829") {
		t.Errorf("Should contain dx.w 13829:\n%s", text)
	}
}

func TestPointerMidcellTargetEmitsRawNotDanglingLabel(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	ctrl, err := db.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.Close()
	ctrl.SetActiveSeg("flat")

	binPath := filepath.Join(dir, "flat.bin")
	rawBytes := make([]byte, 24)
	binary.BigEndian.PutUint32(rawBytes[0x10:0x14], 0x00001002)
	binary.BigEndian.PutUint32(rawBytes[0x14:0x18], 0x00001008)
	if err := os.WriteFile(binPath, rawBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	mk := func(addr, size uint32, ty db.CellType, raw []byte) *db.Cell {
		var mnem, opStr *string
		if ty == db.CellCode {
			m := "nop"
			o := ""
			mnem = &m
			opStr = &o
		}
		return &db.Cell{
			Seg:        ctrl.ActiveSeg(),
			Addr:       addr,
			Size:       size,
			Type:       ty,
			Confidence: 100,
			Mnemonic:   mnem,
			OpStr:      opStr,
			RawBytes:   raw,
		}
	}

	_ = ctrl.InsertCell(mk(0x1000, 4, db.CellCode, []byte{0x4E, 0x71, 0x4E, 0x71}))
	_ = ctrl.InsertCell(mk(0x1008, 2, db.CellCode, []byte{0x4E, 0x71}))
	_ = ctrl.InsertCell(mk(0x1010, 4, db.CellPointer, []byte{0x00, 0x00, 0x10, 0x02}))
	_ = ctrl.InsertCell(mk(0x1014, 4, db.CellPointer, []byte{0x00, 0x00, 0x10, 0x08}))

	_ = ctrl.SetLabel(0x1002, "LAB_01002", db.LabelLab, true)
	_ = ctrl.SetLabel(0x1008, "LAB_01008", db.LabelLab, true)

	fileDataLen := uint32(24)
	proj := project.New(filepath.Join(dir, "project.json"))
	proj.Data.Segments = append(proj.Data.Segments, project.Segment{
		Name:        "flat",
		HunkIndex:   0,
		HunkType:    hunk.HunkTypeCode,
		MemoryType:  hunk.MemoryPublic,
		AllocSize:   24,
		FileDataLen: &fileDataLen,
		File:        &binPath,
		Base:        0x1000,
		DB:          dbPath,
		Relocatable: false,
	})
	proj.Data.Spaces = append(proj.Data.Spaces, project.Space{
		Name:     "default",
		Segments: []string{"flat"},
	})
	proj.Data.ActiveSpace = "default"
	proj.ActiveSegmentName = "flat"

	em, err := New(proj, ctrl)
	if err != nil {
		t.Fatal(err)
	}
	if err := em.GenerateItems(false); err != nil {
		t.Fatal(err)
	}
	text := strings.Join(em.FormatLines(), "\n")

	if !strings.Contains(text, "dc.l\t$00001002") {
		t.Errorf("mid-cell pointer must emit raw $00001002, got:\n%s", text)
	}
	if strings.Contains(text, "dc.l\tLAB_01002") {
		t.Errorf("mid-cell pointer must NOT emit dangling LAB_01002, got:\n%s", text)
	}
	if !strings.Contains(text, "dc.l\tLAB_01008") {
		t.Errorf("cell-start pointer should symbolize to LAB_01008, got:\n%s", text)
	}
}

func TestFlatCrossSegOperandResolutionAndShapes(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	ctrl, err := db.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.Close()

	mainBin := filepath.Join(dir, "main.bin")
	resBin := filepath.Join(dir, "res_0400.bin")
	eff03Bin := filepath.Join(dir, "eff03.bin")
	eff11Bin := filepath.Join(dir, "eff11.bin")
	_ = os.WriteFile(mainBin, make([]byte, 64), 0o644)
	_ = os.WriteFile(resBin, make([]byte, 16), 0o644)
	_ = os.WriteFile(eff03Bin, make([]byte, 16), 0o644)
	_ = os.WriteFile(eff11Bin, make([]byte, 16), 0o644)

	proj := project.New(filepath.Join(dir, "project.json"))
	type segSpec struct {
		idx  int
		name string
		base uint32
		size uint32
		file string
	}
	for _, s := range []segSpec{
		{0, "main", 0x28000, 64, mainBin},
		{1, "res_0400", 0x400, 16, resBin},
		{2, "eff03_t2", 0x30000, 16, eff03Bin},
		{3, "eff11_t97", 0x30000, 16, eff11Bin},
	} {
		sz := s.size
		f := s.file
		proj.Data.Segments = append(proj.Data.Segments, project.Segment{
			Name:        s.name,
			HunkIndex:   s.idx,
			HunkType:    hunk.HunkTypeCode,
			MemoryType:  hunk.MemoryPublic,
			AllocSize:   s.size,
			FileDataLen: &sz,
			File:        &f,
			Base:        s.base,
			DB:          dbPath,
			Relocatable: false,
		})
	}
	proj.Data.Spaces = []project.Space{
		{Name: "main", Segments: []string{"main", "res_0400"}},
		{Name: "eff03", Segments: []string{"main", "res_0400", "eff03_t2"}},
		{Name: "eff11", Segments: []string{"main", "res_0400", "eff11_t97"}},
	}

	mkCode := func(seg string, addr, size uint32, mnem, op string) *db.Cell {
		m := mnem
		o := op
		return &db.Cell{
			Seg:        seg,
			Addr:       addr,
			Size:       size,
			Type:       db.CellCode,
			Confidence: 100,
			Mnemonic:   &m,
			OpStr:      &o,
			RawBytes:   []byte{0x4E, 0x71},
		}
	}

	// Populate res_0400 with a label at $400
	proj.Data.ActiveSpace = "main"
	proj.ActiveSegmentName = "res_0400"
	proj.SyncDBScope(ctrl)
	_ = ctrl.InsertCell(mkCode("res_0400", 0x400, 2, "rts", ""))
	_ = ctrl.SetLabel(0x400, "res_init", db.LabelFun, false)

	// Populate eff03_t2 at $30000 (4-byte insn at $30000 so $30002 is mid-cell)
	proj.Data.ActiveSpace = "eff03"
	proj.ActiveSegmentName = "eff03_t2"
	proj.SyncDBScope(ctrl)
	_ = ctrl.InsertCell(mkCode("eff03_t2", 0x30000, 4, "moveq", "#3,d0"))
	_ = ctrl.SetLabel(0x30000, "LAB_30000", db.LabelFun, true)
	_ = ctrl.SetRename("LAB_30000", "eff03_entry")
	_ = ctrl.SetLabel(0x30002, "LAB_30002_MID", db.LabelLab, true)

	// Populate eff11_t97 at $30000
	proj.Data.ActiveSpace = "eff11"
	proj.ActiveSegmentName = "eff11_t97"
	proj.SyncDBScope(ctrl)
	_ = ctrl.InsertCell(mkCode("eff11_t97", 0x30000, 2, "moveq", "#11,d0"))
	_ = ctrl.SetLabel(0x30000, "LAB_30000", db.LabelFun, true)
	_ = ctrl.SetRename("LAB_30000", "eff11_entry")

	// Populate main with numeric out-of-segment operands and edge-case shapes
	proj.Data.ActiveSpace = "main"
	proj.ActiveSegmentName = "main"
	proj.SyncDBScope(ctrl)
	_ = ctrl.InsertCell(mkCode("main", 0x28000, 8, "move.l", "#$30000,$88.w"))
	_ = ctrl.InsertCell(mkCode("main", 0x28008, 6, "jsr", "$30000.l"))
	_ = ctrl.InsertCell(mkCode("main", 0x2800E, 4, "move.w", "#$400,d0"))
	_ = ctrl.InsertCell(mkCode("main", 0x28012, 4, "move.w", "$400.w,d0"))
	_ = ctrl.InsertCell(mkCode("main", 0x28016, 4, "move.l", "-$400(a5),d0"))
	_ = ctrl.InsertCell(mkCode("main", 0x2801A, 4, "move.l", "4(a0,d0.w),d1"))
	_ = ctrl.InsertCell(mkCode("main", 0x2801E, 6, "jsr", "$30002.l"))
	_ = ctrl.InsertCell(mkCode("main", 0x28024, 6, "jsr", "$400.l"))

	// 1. Emit main in space eff03
	proj.Data.ActiveSpace = "eff03"
	proj.ActiveSegmentName = "main"
	em03, err := New(proj, ctrl)
	if err != nil {
		t.Fatal(err)
	}
	if err := em03.GenerateItems(false); err != nil {
		t.Fatal(err)
	}
	text03 := strings.Join(em03.FormatLines(), "\n")
	for _, want := range []string{
		"eff03_entry\tequ\t$30000",
		"move.l\t#eff03_entry,$88.w\t; -> eff03_t2:eff03_entry",
		"jsr\teff03_entry.l\t; -> eff03_t2:eff03_entry",
		"move.w\t#$400,d0",
		"move.w\t$400.w,d0",
		"move.l\t-$400(a5),d0",
		"move.l\t4(a0,d0.w),d1",
		"jsr\t$30002.l",
		"jsr\tres_init.l\t; -> res_0400:res_init",
	} {
		if !strings.Contains(text03, want) {
			t.Errorf("missing %q in eff03 output:\n%s", want, text03)
		}
	}

	// 2. Emit main in space eff11 (zero re-analysis!)
	proj.Data.ActiveSpace = "eff11"
	proj.ActiveSegmentName = "main"
	em11, err := New(proj, ctrl)
	if err != nil {
		t.Fatal(err)
	}
	if err := em11.GenerateItems(false); err != nil {
		t.Fatal(err)
	}
	text11 := strings.Join(em11.FormatLines(), "\n")
	for _, want := range []string{
		"eff11_entry\tequ\t$30000",
		"move.l\t#eff11_entry,$88.w\t; -> eff11_t97:eff11_entry",
		"jsr\teff11_entry.l\t; -> eff11_t97:eff11_entry",
	} {
		if !strings.Contains(text11, want) {
			t.Errorf("missing %q in eff11 output:\n%s", want, text11)
		}
	}
	if strings.Contains(text11, "eff03_entry") {
		t.Errorf("eff03_entry leaked into eff11:\n%s", text11)
	}

	// 3. Emit main in space main (no $30000 segment in space)
	proj.Data.ActiveSpace = "main"
	proj.ActiveSegmentName = "main"
	emMain, err := New(proj, ctrl)
	if err != nil {
		t.Fatal(err)
	}
	if err := emMain.GenerateItems(false); err != nil {
		t.Fatal(err)
	}
	textMain := strings.Join(emMain.FormatLines(), "\n")
	for _, want := range []string{
		"move.l\t#$30000,$88.w",
		"jsr\t$30000.l",
		"jsr\tres_init.l\t; -> res_0400:res_init",
	} {
		if !strings.Contains(textMain, want) {
			t.Errorf("missing %q in main output:\n%s", want, textMain)
		}
	}

	// 4. Relocatable hunk via GenerateModularHunkItems must NEVER rewrite un-relocated $HEX.l operands
	proj.Data.Segments[0].Relocatable = true
	proj.Data.ActiveSpace = "eff03"
	proj.ActiveSegmentName = "main"
	emHunk, err := New(proj, ctrl)
	if err != nil {
		t.Fatal(err)
	}
	if err := emHunk.GenerateModularHunkItems(); err != nil {
		t.Fatal(err)
	}
	textHunk := strings.Join(emHunk.FormatLines(), "\n")
	if !strings.Contains(textHunk, "jsr\t$30000.l") || !strings.Contains(textHunk, "jsr\t$400.l") {
		t.Errorf("relocatable hunk must keep un-relocated .l operands numeric:\n%s", textHunk)
	}
}

func TestPerSegmentFlatAnalysisOpStrPurityAndViewResolution(t *testing.T) {
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
	ctrl, err := db.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.Close()

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
		a, err := analyzer.NewForSegment(proj, ctrl, segName)
		if err != nil {
			t.Fatal(err)
		}
		a.Analyze(nil)
	}
	proj.RefreshCoverageStats(ctrl)

	// View/emit-time resolution under space eff03
	proj.Data.ActiveSpace = "eff03"
	proj.ActiveSegmentName = "main"
	em03, err := New(proj, ctrl)
	if err != nil {
		t.Fatal(err)
	}
	if err := em03.GenerateItems(false); err != nil {
		t.Fatal(err)
	}
	text03 := strings.Join(em03.FormatLines(), "\n")
	if !strings.Contains(text03, "move.l\t#eff03_entry,$88.w\t; -> eff03_t2:eff03_entry") {
		t.Errorf("eff03 space should resolve #$30000 to #eff03_entry, got:\n%s", text03)
	}
	if !strings.Contains(text03, "jsr\teff03_entry.l\t; -> eff03_t2:eff03_entry") {
		t.Errorf("eff03 space should resolve $30000.l to eff03_entry.l, got:\n%s", text03)
	}

	// View/emit-time resolution under space eff11 (zero re-analysis!)
	proj.Data.ActiveSpace = "eff11"
	proj.ActiveSegmentName = "main"
	em11, err := New(proj, ctrl)
	if err != nil {
		t.Fatal(err)
	}
	if err := em11.GenerateItems(false); err != nil {
		t.Fatal(err)
	}
	text11 := strings.Join(em11.FormatLines(), "\n")
	if !strings.Contains(text11, "move.l\t#eff11_entry,$88.w\t; -> eff11_t97:eff11_entry") {
		t.Errorf("eff11 space should resolve #$30000 to #eff11_entry, got:\n%s", text11)
	}
	if !strings.Contains(text11, "jsr\teff11_entry.l\t; -> eff11_t97:eff11_entry") {
		t.Errorf("eff11 space should resolve $30000.l to eff11_entry.l, got:\n%s", text11)
	}
}

func BenchmarkEmitPipeline(b *testing.B) {
	var codeBytes []byte
	const numFuncs = 200
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

	an, err := analyzer.New(proj, ctrl)
	if err != nil {
		b.Fatal(err)
	}
	an.Analyze([]uint32{0x10000})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		em, err := New(proj, ctrl)
		if err != nil {
			b.Fatal(err)
		}
		if err := em.GenerateItems(false); err != nil {
			b.Fatal(err)
		}
		_ = em.FormatLines()
	}
}

func TestStructEquatesAndABIEmission(t *testing.T) {
	tmpDir := t.TempDir()
	// 0x10000: move.w 2(a0),d0  30 28 00 02
	// 0x10004: rts              4E 75
	codeBytes := []byte{0x30, 0x28, 0x00, 0x02, 0x4E, 0x75}
	binPath := filepath.Join(tmpDir, "main.bin")
	if err := os.WriteFile(binPath, codeBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(tmpDir, "main.db")
	ctrl, err := db.New(dbPath)
	if err != nil {
		t.Fatal(err)
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
	proj.Data.Structs = map[string]map[string]string{
		"Model": {
			"0":     "Model_Radius.w",
			"2":     "Model_VX.w",
			"_size": "18",
		},
	}
	proj.Data.RegisterAliases = map[string]string{
		"a0": "Model",
	}

	an, err := analyzer.New(proj, ctrl)
	if err != nil {
		t.Fatal(err)
	}
	an.Analyze([]uint32{0x10000})
	if err := ctrl.SetFunctionABI(0x10000, "LAB_10000", "(a0=Model*) -> d0=vx"); err != nil {
		t.Fatal(err)
	}

	em, err := New(proj, ctrl)
	if err != nil {
		t.Fatal(err)
	}
	if err := em.GenerateItems(false); err != nil {
		t.Fatal(err)
	}
	text := strings.Join(em.FormatLines(), "\n")
	if !strings.Contains(text, "Model_Radius\tequ\t$0") {
		t.Fatalf("expected Model_Radius equ $0 in emitted asm:\n%s", text)
	}
	if !strings.Contains(text, "Model_VX\tequ\t$2") {
		t.Fatalf("expected Model_VX equ $2 in emitted asm:\n%s", text)
	}
	if !strings.Contains(text, "Model_SIZEOF\tequ\t$12") {
		t.Fatalf("expected Model_SIZEOF equ $12 in emitted asm:\n%s", text)
	}
	if !strings.Contains(text, "; ABI: (a0=Model*) -> d0=vx") {
		t.Fatalf("expected ABI comment in emitted asm:\n%s", text)
	}
	if !strings.Contains(text, "move.w\tModel_VX(a0),d0") {
		t.Fatalf("expected Model_VX(a0),d0 in emitted asm:\n%s", text)
	}
}
