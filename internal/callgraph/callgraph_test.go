package callgraph

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/mikolas/hunks/internal/db"
	"github.com/mikolas/hunks/internal/hunk"
	"github.com/mikolas/hunks/internal/project"
)

func TestCallGraphInferenceAndModes(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_hunks_callgraph.db")
	dbCtrl, err := db.New(dbPath)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer dbCtrl.Close()

	// Setup 3 functions:
	// Func A at 0x1000 (calls Func B at 0x1020, references string at 0x1040)
	// Func B at 0x1020 (leaf, touches BLTSIZE, returns via rts)
	// Func C at 0x1030 (suspect fallthrough into DATA_L at 0x1034 without rts!)
	dbCtrl.SetActiveSeg("hunk0")
	if err := dbCtrl.SetLabel(0x1000, "LAB_01000", db.LabelLab, true); err != nil {
		t.Fatalf("SetLabel: %v", err)
	}
	if err := dbCtrl.SetLabel(0x1020, "LAB_01020", db.LabelLab, true); err != nil {
		t.Fatalf("SetLabel: %v", err)
	}
	if err := dbCtrl.SetLabel(0x1030, "LAB_01030", db.LabelLab, true); err != nil {
		t.Fatalf("SetLabel: %v", err)
	}

	strPtr := func(s string) *string { return &s }

	cells := []*db.Cell{
		{
			Addr:       0x1000,
			Size:       4,
			Type:       db.CellCode,
			Confidence: 100,
			Mnemonic:   strPtr("lea"),
			OpStr:      strPtr("LAB_01040(pc),a0"),
			RawBytes:   []byte{0x41, 0xFA, 0x00, 0x3E}, // lea $1040(pc),a0 -> 8 cyc
		},
		{
			Addr:       0x1004,
			Size:       4,
			Type:       db.CellCode,
			Confidence: 100,
			Mnemonic:   strPtr("bsr.w"),
			OpStr:      strPtr("LAB_01020"),
			RawBytes:   []byte{0x61, 0x00, 0x00, 0x1A}, // bsr.w $1020 -> 18 cyc
		},
		{
			Addr:       0x1008,
			Size:       2,
			Type:       db.CellCode,
			Confidence: 100,
			Mnemonic:   strPtr("rts"),
			OpStr:      strPtr(""),
			RawBytes:   []byte{0x4E, 0x75}, // rts -> 16 cyc
		},
		// Func B (leaf touching BLTSIZE)
		{
			Addr:       0x1020,
			Size:       6,
			Type:       db.CellCode,
			Confidence: 100,
			Mnemonic:   strPtr("move.w"),
			OpStr:      strPtr("d0,BLTSIZE.l"),
			RawBytes:   []byte{0x33, 0xC0, 0x00, 0xDF, 0xF0, 0x58}, // move.w d0,$DFF058.l -> 16 cyc
		},
		{
			Addr:       0x1026,
			Size:       2,
			Type:       db.CellCode,
			Confidence: 100,
			Mnemonic:   strPtr("rts"),
			OpStr:      strPtr(""),
			RawBytes:   []byte{0x4E, 0x75}, // rts -> 16 cyc
		},
		// Func C (suspect fallthrough into DATA_L)
		{
			Addr:       0x1030,
			Size:       4,
			Type:       db.CellCode,
			Confidence: 100,
			Mnemonic:   strPtr("moveq"),
			OpStr:      strPtr("#5,d0"),
			RawBytes:   []byte{0x70, 0x05}, // moveq #5,d0 -> 4 cyc
		},
		{
			Addr:       0x1034,
			Size:       4,
			Type:       db.CellDataL,
			Confidence: 50,
			Mnemonic:   strPtr("dc.l"),
			OpStr:      strPtr("$4EAD0192"),
		},
		// String cell at 0x1040
		{
			Addr:       0x1040,
			Size:       6,
			Type:       db.CellStr,
			Confidence: 100,
			Mnemonic:   strPtr("dc.b"),
			OpStr:      strPtr("'Hello',0"),
		},
	}
	for _, c := range cells {
		if err := dbCtrl.InsertCell(c); err != nil {
			t.Fatalf("InsertCell: %v", err)
		}
	}
	if err := dbCtrl.UpdateBlockComment(0x1020, "Starts blitter operation"); err != nil {
		t.Fatalf("UpdateBlockComment: %v", err)
	}

	if err := dbCtrl.InsertEdge(0x1004, 0x1020, db.EdgeCall); err != nil {
		t.Fatalf("InsertEdge: %v", err)
	}
	if err := dbCtrl.InsertXref(0x1000, 0x1040, db.XrefDataRead); err != nil {
		t.Fatalf("InsertXref: %v", err)
	}
	if err := dbCtrl.SetRename("LAB_01020", "StartBlit"); err != nil {
		t.Fatalf("SetRename: %v", err)
	}

	projPath := filepath.Join(tmpDir, "test_hunks_cg_proj.json")
	proj := project.New(projPath)
	proj.Data.Segments = append(proj.Data.Segments, project.Segment{
		Name:        "hunk0",
		HunkIndex:   0,
		HunkType:    hunk.HunkTypeCode,
		MemoryType:  hunk.MemoryPublic,
		AllocSize:   0x100,
		Base:        0x1000,
		DB:          dbPath,
		Relocatable: true,
	})
	proj.Data.Spaces = append(proj.Data.Spaces, project.Space{
		Name:     "default",
		Segments: []string{"hunk0"},
	})
	proj.Data.ActiveSpace = "default"

	cg, err := Build(proj)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(cg.Functions) != 3 {
		t.Fatalf("len(cg.Functions) = %d, want 3", len(cg.Functions))
	}

	fa := cg.Functions[0x1000]
	if len(fa.Callees) != 1 {
		t.Fatalf("len(fa.Callees) = %d, want 1", len(fa.Callees))
	}
	if fa.Callees[0].TargetFunc != 0x1020 {
		t.Fatalf("fa.Callees[0].TargetFunc = 0x%x, want 0x1020", fa.Callees[0].TargetFunc)
	}
	if len(fa.Strings) != 1 {
		t.Fatalf("len(fa.Strings) = %d, want 1", len(fa.Strings))
	}
	if !cg.IsReadyBottomUp(fa) {
		t.Fatalf("Func A should be ready since its only callee StartBlit is renamed")
	}

	fb := cg.Functions[0x1020]
	if fb.Name != "StartBlit" {
		t.Fatalf("fb.Name = %q, want StartBlit", fb.Name)
	}
	if !fb.IsRenamed {
		t.Fatalf("fb.IsRenamed = false, want true")
	}
	if !fb.IsLeaf() {
		t.Fatalf("fb.IsLeaf() = false, want true")
	}
	if !slices.Contains(fb.HWRegs, "BLTSIZE") {
		t.Fatalf("fb.HWRegs = %v, want to contain BLTSIZE", fb.HWRegs)
	}
	if fb.SelfMinCycles != 32 || fb.InclMinCycles != 32 {
		t.Fatalf("fb cycles: self=%d incl=%d, want 32/32", fb.SelfMinCycles, fb.InclMinCycles)
	}
	if fa.SelfMinCycles != 42 || fa.InclMinCycles != 74 {
		t.Fatalf("fa cycles: self=%d incl=%d, want 42/74", fa.SelfMinCycles, fa.InclMinCycles)
	}
	if got := fa.FormatCycles(); got != "42 cyc [incl: 74 cyc]" {
		t.Fatalf("fa.FormatCycles() = %q, want %q", got, "42 cyc [incl: 74 cyc]")
	}

	fc := cg.Functions[0x1030]
	if fc.SuspectCutoff == nil || fc.SuspectCutoff.Addr != 0x1034 || fc.SuspectCutoff.Text != "DATA_L" {
		t.Fatalf("fc.SuspectCutoff = %+v, want (0x1034, DATA_L)", fc.SuspectCutoff)
	}

	// Verify AutoLabel and ResolveTarget on relocatable hunk project
	if got := proj.AutoLabel(0x1000); got != "LAB_0_00000" {
		t.Fatalf("AutoLabel(0x1000) = %q, want LAB_0_00000", got)
	}
	if got := proj.AutoLabel(0x1020); got != "LAB_0_00020" {
		t.Fatalf("AutoLabel(0x1020) = %q, want LAB_0_00020", got)
	}
	if got, ok := proj.ResolveTarget(dbCtrl, "hunk0:StartBlit"); !ok || got != 0x1020 {
		t.Fatalf("ResolveTarget(hunk0:StartBlit) = (0x%x, %v), want (0x1020, true)", got, ok)
	}
	if got, ok := proj.ResolveTarget(dbCtrl, "hunk0:+20"); !ok || got != 0x1020 {
		t.Fatalf("ResolveTarget(hunk0:+20) = (0x%x, %v), want (0x1020, true)", got, ok)
	}
	if got, ok := proj.ResolveTarget(dbCtrl, "LAB_0_00030"); !ok || got != 0x1030 {
		t.Fatalf("ResolveTarget(LAB_0_00030) = (0x%x, %v), want (0x1030, true)", got, ok)
	}
	if got := fa.QualifiedName(); got != "hunk0:LAB_01000" {
		t.Fatalf("fa.QualifiedName() = %q, want hunk0:LAB_01000", got)
	}

	// Verify bare hunk number normalization (--hunk 0 -> hunk0) and Module Overview rendering
	if got := NormalizeSegmentFilter("0"); got != "hunk0" {
		t.Fatalf("NormalizeSegmentFilter(0) = %q, want hunk0", got)
	}
	if got := NormalizeSegmentFilter("hunk0"); got != "hunk0" {
		t.Fatalf("NormalizeSegmentFilter(hunk0) = %q, want hunk0", got)
	}

	overview, err := cg.Render(proj, &Options{
		Segment: "0",
		Depth:   2,
		UpDepth: 2,
		Limit:   50,
		Format:  "text",
	})
	if err != nil {
		t.Fatalf("cg.Render: %v", err)
	}
	if !strings.Contains(overview, "Module Functions in hunk0 (offset order)") {
		t.Fatalf("overview missing header: %s", overview)
	}
	if !strings.Contains(overview, "──► callees: hunk0:StartBlit") {
		t.Fatalf("overview missing callees: %s", overview)
	}
	if !strings.Contains(overview, "◄── callers: hunk0:LAB_01000") {
		t.Fatalf("overview missing callers: %s", overview)
	}
}

func TestCallGraphStaticRegsABIAndDualOffsets(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "project.db")

	// 0x1000: movem.l d2-d3,-(a7)    48 E7 30 00 (4B)
	// 0x1004: move.w  2(a0),d0       30 28 00 02 (4B) -> reads a0, writes d0
	// 0x1008: add.w   $1034.w,d0     D0 78 10 34 (4B) -> reads $1034, rw d0
	// 0x100C: move.w  d0,$1038.w     31 C0 10 38 (4B) -> reads d0, writes $1038
	// 0x1010: movem.l (a7)+,d2-d3    4C DF 00 0C (4B)
	// 0x1014: rts                    4E 75       (2B)
	rawBytes := []byte{
		0x48, 0xE7, 0x30, 0x00,
		0x30, 0x28, 0x00, 0x02,
		0xD0, 0x78, 0x10, 0x34,
		0x31, 0xC0, 0x10, 0x38,
		0x4C, 0xDF, 0x00, 0x0C,
		0x4E, 0x75,
	}
	binPath := filepath.Join(tmpDir, "seg.bin")
	if err := os.WriteFile(binPath, rawBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	proj := project.New(filepath.Join(tmpDir, "project.json"))
	proj.Data.Segments = []project.Segment{
		{
			Name:        "main",
			HunkIndex:   0,
			HunkType:    hunk.HunkTypeCode,
			MemoryType:  hunk.MemoryPublic,
			AllocSize:   uint32(len(rawBytes)),
			File:        &binPath,
			Base:        0x1000,
			DB:          dbPath,
			Relocatable: false,
		},
	}
	proj.Data.Spaces = []project.Space{{Name: "default", Segments: []string{"main"}}}
	proj.Data.ActiveSpace = "default"
	proj.Data.EntryPoints = []project.EntryPoint{{Addr: 0x1000, Name: "CalcStep", Segment: "main"}}

	ctrl, err := db.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.Close()
	proj.SyncDBScope(ctrl)

	_ = ctrl.SetLabel(0x1000, "CalcStep", db.LabelLab, false)
	_ = ctrl.InsertFunction(0x1000, "CalcStep", 0)
	proj.SetFunctionABI("CalcStep", "(a0=obj, a1=unused) -> d0 | clobbers: d0, d4")

	insns := []struct {
		addr uint32
		size uint32
		mnem string
		op   string
	}{
		{0x1000, 4, "movem.l", "d2-d3,-(a7)"},
		{0x1004, 4, "move.w", "2(a0),d0"},
		{0x1008, 4, "add.w", "$1034.w,d0"},
		{0x100C, 4, "move.w", "d0,$1038.w"},
		{0x1010, 4, "movem.l", "(a7)+,d2-d3"},
		{0x1014, 2, "rts", ""},
	}
	for _, in := range insns {
		m := in.mnem
		o := in.op
		_ = ctrl.InsertCell(&db.Cell{
			Seg:      "main",
			Addr:     in.addr,
			Size:     in.size,
			Type:     db.CellCode,
			Mnemonic: &m,
			OpStr:    &o,
			RawBytes: rawBytes[in.addr-0x1000 : in.addr-0x1000+in.size],
		})
		if in.addr < 0x1014 {
			_ = ctrl.InsertEdge(in.addr, in.addr+in.size, db.EdgeFallthrough)
		}
	}
	_ = ctrl.InsertXref(0x1008, 0x1034, db.XrefDataRead)
	_ = ctrl.InsertXref(0x100C, 0x1038, db.XrefDataWrite)

	cg, err := Build(proj)
	if err != nil {
		t.Fatal(err)
	}
	fn := cg.Functions[0x1000]
	if fn == nil {
		t.Fatalf("missing function at 0x1000")
	}
	if !slices.Equal(fn.InRegs, []string{"a0"}) {
		t.Fatalf("expected InRegs=[a0], got %v", fn.InRegs)
	}
	if !slices.Equal(fn.ModRegs, []string{"d0"}) {
		t.Fatalf("expected ModRegs=[d0], got %v", fn.ModRegs)
	}
	if !slices.Equal(fn.SavedRegs, []string{"d2", "d3"}) {
		t.Fatalf("expected SavedRegs=[d2 d3], got %v", fn.SavedRegs)
	}
	warnings := VerifyABI(fn.ABI, fn.InRegs, fn.ModRegs, fn.SavedRegs)
	if len(warnings) != 2 {
		t.Fatalf("expected 2 ABI verification warnings (a1 never read, d4 never modified), got %v", warnings)
	}
	rangeWarnings := VerifyABI("(a0=obj, d7=count) -> d0 | clobbers: d0-d2", fn.InRegs, fn.ModRegs, fn.SavedRegs)
	if len(rangeWarnings) != 3 {
		t.Fatalf("expected 3 warnings for d7 input and d1/d2 range clobbers, got %v", rangeWarnings)
	}

	rendered, err := cg.Render(proj, &Options{
		Target:  "CalcStep",
		Code:    true,
		Depth:   2,
		UpDepth: 2,
		Limit:   50,
		Format:  "text",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rendered, "=== Globals & Memory Flow ===") {
		t.Fatalf("missing Globals & Memory Flow section:\n%s", rendered)
	}
	if !strings.Contains(rendered, "+00004 (+004)  move.w") {
		t.Fatalf("missing dual offset +00004 (+004) in disassembly:\n%s", rendered)
	}
}
