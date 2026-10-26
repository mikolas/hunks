package callgraph

import (
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
