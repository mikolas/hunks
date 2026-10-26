package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mikolas/hunks/internal/db"
	"github.com/mikolas/hunks/internal/hunk"
	"github.com/mikolas/hunks/internal/project"
)

func strPtr(s string) *string { return &s }

func TestTUIHunkVsFlatBinary(t *testing.T) {
	tmp := t.TempDir()
	proj := project.New(filepath.Join(tmp, "project.json"))
	proj.Data.Segments = append(proj.Data.Segments,
		project.Segment{
			Name:        "hunk5",
			HunkIndex:   5,
			HunkType:    hunk.HunkTypeCode,
			MemoryType:  hunk.MemoryPublic,
			AllocSize:   8,
			Base:        0x76010,
			DB:          ":memory:",
			Relocatable: true,
		},
		project.Segment{
			Name:        "main",
			HunkIndex:   0,
			HunkType:    hunk.HunkTypeCode,
			MemoryType:  hunk.MemoryPublic,
			AllocSize:   8,
			Base:        0x400,
			DB:          ":memory:",
			Relocatable: false,
		},
	)
	proj.Data.Spaces = append(proj.Data.Spaces, project.Space{
		Name:     "default",
		Segments: []string{"hunk5", "main"},
	})
	proj.Data.ActiveSpace = "default"

	// 1. Test relocatable hunk segment (hunk5)
	proj.ActiveSegmentName = "hunk5"
	ctrl, err := db.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ctrl.Close() })
	proj.SyncDBScope(ctrl)
	_ = ctrl.SetLabel(0x00100, "LAB_00100", db.LabelLab, true)
	_ = ctrl.SetLabel(0x76010, "LAB_76010", db.LabelLab, true)
	_ = ctrl.MarkExported(0x76010)

	app, err := NewApp(proj, ctrl)
	if err != nil {
		t.Fatal(err)
	}
	if !app.IsRelocatable {
		t.Fatalf("expected IsRelocatable=true")
	}
	for _, r := range app.DisasmRows {
		if r.Mnem == "equ" {
			t.Fatalf("TUI must not contain equ rows")
		}
		if r.Mnem == "org" {
			t.Fatalf("relocatable hunk must not contain org")
		}
	}
	if app.DisasmRows[0].Mnem != "SECTION" || app.DisasmRows[0].Addr != nil {
		t.Fatalf("unexpected row 0: %+v", app.DisasmRows[0])
	}
	if got := app.FormatAddr(0x76010); got != "+00000" {
		t.Fatalf("expected +00000, got %q", got)
	}
	if got := app.FormatAddr(0x76014); got != "+00004" {
		t.Fatalf("expected +00004, got %q", got)
	}

	// 2. Test flat binary segment (main at $400)
	proj.ActiveSegmentName = "main"
	ctrl2, err := db.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ctrl2.Close() })
	proj.SyncDBScope(ctrl2)
	app2, err := NewApp(proj, ctrl2)
	if err != nil {
		t.Fatal(err)
	}
	if app2.IsRelocatable {
		t.Fatalf("expected IsRelocatable=false")
	}
	for _, r := range app2.DisasmRows {
		if r.Mnem == "equ" {
			t.Fatalf("TUI must not contain equ rows")
		}
	}
	if app2.DisasmRows[0].Mnem != "org" || app2.DisasmRows[0].Operands != "$400" || app2.DisasmRows[0].Addr != nil {
		t.Fatalf("unexpected flat row 0: %+v", app2.DisasmRows[0])
	}
	if got := app2.FormatAddr(0x400); got != "$00400" {
		t.Fatalf("expected $00400, got %q", got)
	}
	if got := app2.FormatAddr(0x404); got != "$00404" {
		t.Fatalf("expected $00404, got %q", got)
	}
}

func TestHexPaneMarkStringAndSplitOverlap(t *testing.T) {
	tmp := t.TempDir()
	proj := project.New(filepath.Join(tmp, "project.json"))
	proj.Data.Segments = append(proj.Data.Segments, project.Segment{
		Name:        "hunk0",
		HunkIndex:   0,
		HunkType:    hunk.HunkTypeCode,
		MemoryType:  hunk.MemoryPublic,
		AllocSize:   8,
		Base:        0x1000,
		DB:          ":memory:",
		Relocatable: true,
	})
	proj.Data.Spaces = append(proj.Data.Spaces, project.Space{
		Name:     "default",
		Segments: []string{"hunk0"},
	})
	proj.Data.ActiveSpace = "default"
	proj.ActiveSegmentName = "hunk0"

	ctrl, err := db.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ctrl.Close() })
	proj.SyncDBScope(ctrl)
	_ = ctrl.MarkData(0x1000, 4, db.CellDataL)
	_ = ctrl.MarkData(0x1004, 4, db.CellDataL)

	app, err := NewApp(proj, ctrl)
	if err != nil {
		t.Fatal(err)
	}
	app.BinaryData = []byte{0xFF, 'H', 'i', '!', 0x00, 0x11, 0x22, 0x33}
	if err := app.LoadData(); err != nil {
		t.Fatal(err)
	}

	rowIdx := -1
	for i, r := range app.DisasmRows {
		if r.Addr != nil && r.IsPrimary && *r.Addr == 0x1000 {
			rowIdx = i
			break
		}
	}
	if rowIdx < 0 {
		t.Fatalf("row at 0x1000 not found")
	}
	app.SelectedIdx = rowIdx
	app.HandleKey("right")
	if app.DataByteOff != 1 {
		t.Fatalf("expected DataByteOff=1, got %d", app.DataByteOff)
	}
	if cur, ok := app.CursorAddr(); !ok || cur != 0x1001 {
		t.Fatalf("expected CursorAddr=0x1001, got %#X (ok=%v)", cur, ok)
	}

	app.HandleKey("s")

	c0, err := app.DB.GetCell(0x1000)
	if err != nil || c0 == nil || c0.Type != db.CellDataB || c0.Size != 1 {
		t.Fatalf("expected 0x1000 split into 1-byte DATA_B, got %+v", c0)
	}
	cs, err := app.DB.GetCell(0x1001)
	if err != nil || cs == nil || cs.Type != db.CellStr || cs.Size != 4 {
		t.Fatalf("expected 0x1001 4-byte STRING, got %+v", cs)
	}
	c5, err := app.DB.GetCell(0x1005)
	if err != nil || c5 == nil || c5.Type != db.CellDataB || c5.Size != 1 {
		t.Fatalf("expected 0x1005 split into 1-byte DATA_B, got %+v", c5)
	}

	// Verify ';' on a STRING row opens ModalBlockComment (never inline EOL comment)
	app.GotoAddress(0x1001)
	app.HandleKey(";")
	if app.Modal.Kind != ModalBlockComment {
		t.Fatalf("expected ';' on SubRowString to open ModalBlockComment, got %v", app.Modal.Kind)
	}
	app.HandleKey("esc")

	// Verify 'l' marks a 4-byte DATA_L
	row0 := -1
	for i, r := range app.DisasmRows {
		if r.Addr != nil && r.IsPrimary && *r.Addr == 0x1000 {
			row0 = i
			break
		}
	}
	app.SelectedIdx = row0
	app.DataByteOff = 0
	app.HandleKey("l")
	cl, err := app.DB.GetCell(0x1000)
	if err != nil || cl == nil || cl.Type != db.CellDataL || cl.Size != 4 {
		t.Fatalf("expected 0x1000 to be 4-byte DATA_L, got %+v", cl)
	}
}

func TestTUICarveGuardAndRoundtrip(t *testing.T) {
	tmp := t.TempDir()
	proj := project.New(filepath.Join(tmp, "project.json"))
	proj.WorkspaceRoot = tmp
	proj.Data.Segments = append(proj.Data.Segments, project.Segment{
		Name:        "main",
		HunkIndex:   0,
		HunkType:    hunk.HunkTypeCode,
		MemoryType:  hunk.MemoryPublic,
		AllocSize:   8,
		Base:        0x2000,
		DB:          ":memory:",
		Relocatable: false,
	})
	proj.Data.Spaces = append(proj.Data.Spaces, project.Space{Name: "default", Segments: []string{"main"}})
	proj.Data.ActiveSpace = "default"
	proj.ActiveSegmentName = "main"

	ctrl, err := db.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ctrl.Close() })
	proj.SyncDBScope(ctrl)
	_ = ctrl.MarkData(0x2000, 4, db.CellDataL)
	_ = ctrl.MarkData(0x2004, 4, db.CellDataB)

	app, err := NewApp(proj, ctrl)
	if err != nil {
		t.Fatal(err)
	}
	app.BinaryData = []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	_ = app.LoadData()

	app.CarveRange(0x2002, 0x2005, "FlatBlob", "Header description\nLine 2")
	cell, err := app.DB.GetCell(0x2002)
	if err != nil || cell == nil || cell.Type != db.CellIncbin || cell.Size != 4 {
		t.Fatalf("unexpected carved cell: %+v", cell)
	}
	if lbl, ok, _ := app.DB.GetLabel(0x2002); !ok || lbl != "FlatBlob" {
		t.Fatalf("expected label 'FlatBlob', got %q", lbl)
	}
	if bc := app.DB.GetAddressComment(0x2002).BlockComment; bc != "Header description\nLine 2" {
		t.Fatalf("expected block comment, got %q", bc)
	}

	// Pressing 'w' or 'l' on a folded incbin must be refused without destroying the incbin.
	app.GotoAddress(0x2002)
	app.HandleKey("w")
	if !strings.Contains(app.StatusMsg, "Folded incbin") {
		t.Fatalf("expected Folded incbin refusal on 'w', got %q", app.StatusMsg)
	}
	if cCheck, _ := app.DB.GetCell(0x2002); cCheck == nil || cCheck.Type != db.CellIncbin {
		t.Fatalf("expected CellIncbin intact after refused 'w', got %+v", cCheck)
	}

	// Pressing 'b' on a folded incbin unfolds it back into bytes (deletes the CellIncbin), and Ctrl+Z folds it back.
	app.HandleKey("b")
	if cAfterB, _ := app.DB.GetCell(0x2002); cAfterB != nil && cAfterB.Type == db.CellIncbin {
		t.Fatalf("expected CellIncbin unfolded after 'b', got %+v", cAfterB)
	}
	// Pressing 'K' on the now-unfolded dc.b data row must refuse ("No carve at cursor") and not crash.
	app.HandleKey("K")
	if app.StatusMsg != "No carve at cursor" {
		t.Fatalf("expected 'No carve at cursor' when pressing K on dc.b row, got %q", app.StatusMsg)
	}
	// Undo the 'b' unfold -> restores CellIncbin
	app.Undo()
	if cRestoredB, _ := app.DB.GetCell(0x2002); cRestoredB == nil || cRestoredB.Type != db.CellIncbin {
		t.Fatalf("expected CellIncbin restored after undoing 'b' unfold, got %+v", cRestoredB)
	}

	// TUI reload must NOT write the incbin sidecar to disk.
	sidecar := filepath.Join(app.Proj.WorkspaceRoot, "assets/FlatBlob.bin")
	_ = os.Remove(sidecar)
	app.ReloadAtCursor()
	if _, err := os.Stat(sidecar); !os.IsNotExist(err) {
		t.Fatalf("TUI reload must not write incbin sidecar to disk")
	}

	// Undo carve with Ctrl-z (must also restore the straddling 4-byte CellDataL at 0x2000 with no 1-byte remnant at 0x2001)
	app.Undo()
	cellUndone, _ := app.DB.GetCell(0x2002)
	if cellUndone != nil && cellUndone.Type == db.CellIncbin {
		t.Fatalf("expected CellIncbin gone after undoing carve")
	}
	straddlingRestored, _ := app.DB.GetCell(0x2000)
	if straddlingRestored == nil || straddlingRestored.Type != db.CellDataL || straddlingRestored.Size != 4 {
		t.Fatalf("expected straddling 4-byte CellDataL at 0x2000 restored after undo, got %+v", straddlingRestored)
	}
	if remnant, _ := app.DB.GetCell(0x2001); remnant != nil {
		t.Fatalf("expected no remnant cell at 0x2001 after undo, got %+v", remnant)
	}
	if lbl, ok, _ := app.DB.GetLabel(0x2002); ok && lbl != "" {
		t.Fatalf("expected label gone after undoing carve, got %q", lbl)
	}
	if bc := app.DB.GetAddressComment(0x2002).BlockComment; bc != "" {
		t.Fatalf("expected block comment gone after undoing carve, got %q", bc)
	}

	// Re-carve to test overlapping re-carve (0x2000..0x2005 replacing 0x2002..0x2005) and its undo
	app.CarveRange(0x2002, 0x2005, "FlatBlob", "Header description\nLine 2")
	app.CarveRange(0x2000, 0x2005, "WiderBlob", "Wider header")
	if wider, _ := app.DB.GetCell(0x2000); wider == nil || wider.Type != db.CellIncbin || wider.Size != 6 {
		t.Fatalf("expected single replaced CellIncbin at 0x2000, got %+v", wider)
	}
	if lbl, ok, _ := app.DB.GetLabel(0x2002); ok && lbl != "" {
		t.Fatalf("expected interior overlapped label at 0x2002 cleaned up, got %q", lbl)
	}
	app.Undo()
	if prev, _ := app.DB.GetCell(0x2002); prev == nil || prev.Type != db.CellIncbin || prev.Size != 4 {
		t.Fatalf("expected previous CellIncbin at 0x2002 restored after undo, got %+v", prev)
	}
	if lbl, ok, _ := app.DB.GetLabel(0x2002); !ok || lbl != "FlatBlob" {
		t.Fatalf("expected label 'FlatBlob' at 0x2002 restored after undo, got %q", lbl)
	}
	app.GotoAddress(0x2002)
	app.UncarveAtCursor()
	after, _ := app.DB.GetCell(0x2002)
	if after != nil && after.Type == db.CellIncbin {
		t.Fatalf("INCBIN cell must be gone after uncarve")
	}
	if lbl, ok, _ := app.DB.GetLabel(0x2002); ok && lbl != "" {
		t.Fatalf("expected label gone after uncarve, got %q", lbl)
	}
	if bc := app.DB.GetAddressComment(0x2002).BlockComment; bc != "" {
		t.Fatalf("expected block comment gone after uncarve, got %q", bc)
	}

	// Undo uncarve with Ctrl-z
	app.Undo()
	cellReRestored, _ := app.DB.GetCell(0x2002)
	if cellReRestored == nil || cellReRestored.Type != db.CellIncbin {
		t.Fatalf("expected CellIncbin restored after undoing uncarve")
	}
	if lbl, ok, _ := app.DB.GetLabel(0x2002); !ok || lbl != "FlatBlob" {
		t.Fatalf("expected label 'FlatBlob' restored after undoing uncarve, got %q", lbl)
	}
	if bc := app.DB.GetAddressComment(0x2002).BlockComment; bc != "Header description\nLine 2" {
		t.Fatalf("expected block comment restored after undoing uncarve, got %q", bc)
	}

	// Relocatable segment: carve across an interior reloc is refused.
	proj2 := project.New(filepath.Join(tmp, "project2.json"))
	proj2.Data.Segments = append(proj2.Data.Segments, project.Segment{
		Name:        "hunk0",
		HunkIndex:   0,
		HunkType:    hunk.HunkTypeCode,
		MemoryType:  hunk.MemoryPublic,
		AllocSize:   8,
		Base:        0x3000,
		DB:          ":memory:",
		Relocatable: true,
	})
	proj2.Data.Spaces = append(proj2.Data.Spaces, project.Space{Name: "default", Segments: []string{"hunk0"}})
	proj2.Data.ActiveSpace = "default"
	proj2.ActiveSegmentName = "hunk0"
	ctrl2, err := db.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ctrl2.Close() })
	proj2.SyncDBScope(ctrl2)
	_ = ctrl2.MarkData(0x3000, 8, db.CellDataL)
	_ = ctrl2.InsertReloc(0x3002, 0x9999)
	app2, err := NewApp(proj2, ctrl2)
	if err != nil {
		t.Fatal(err)
	}
	app2.BinaryData = make([]byte, 8)
	_ = app2.LoadData()
	app2.CarveRange(0x3000, 0x3005, "ShouldRefuse", "")
	if refused, _ := app2.DB.GetCell(0x3000); refused != nil && refused.Type == db.CellIncbin {
		t.Fatalf("carve over interior reloc must be refused")
	}
}

func TestUndoRestoresFullCellState(t *testing.T) {
	tmp := t.TempDir()
	proj := project.New(filepath.Join(tmp, "project.json"))
	proj.Data.Segments = append(proj.Data.Segments, project.Segment{
		Name:        "main",
		HunkIndex:   0,
		HunkType:    hunk.HunkTypeCode,
		MemoryType:  hunk.MemoryPublic,
		AllocSize:   8,
		Base:        0x1000,
		DB:          ":memory:",
		Relocatable: false,
	})
	proj.Data.Spaces = append(proj.Data.Spaces, project.Space{Name: "default", Segments: []string{"main"}})
	proj.Data.ActiveSpace = "default"
	proj.ActiveSegmentName = "main"

	ctrl, err := db.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ctrl.Close() })
	proj.SyncDBScope(ctrl)
	_ = ctrl.InsertCell(&db.Cell{
		Addr:       0x1000,
		Size:       2,
		Type:       db.CellCode,
		Confidence: 0,
		Mnemonic:   strPtr("moveq"),
		OpStr:      strPtr("#0,d0"),
		RawBytes:   []byte{0x70, 0x00},
	})
	_ = ctrl.UpdateComment(0x1000, "init counter")
	_ = ctrl.UpdateBlockComment(0x1000, "entry")
	_ = ctrl.InsertCell(&db.Cell{
		Addr:       0x1002,
		Size:       2,
		Type:       db.CellCode,
		Confidence: 0,
		Mnemonic:   strPtr("rts"),
		RawBytes:   []byte{0x4E, 0x75},
	})

	app, err := NewApp(proj, ctrl)
	if err != nil {
		t.Fatal(err)
	}
	app.BinaryData = []byte{0x70, 0x00, 0x4E, 0x75, 0, 0, 0, 0}
	_ = app.LoadData()

	app.GotoAddress(0x1000)
	app.MarkType(db.CellDataL, 4)
	if c, _ := app.DB.GetCell(0x1000); c == nil || c.Type != db.CellDataL {
		t.Fatalf("expected DATA_L at 0x1000")
	}
	if c, _ := app.DB.GetCell(0x1002); c != nil {
		t.Fatalf("expected 0x1002 cleared")
	}

	app.Undo()
	c0, _ := app.DB.GetCell(0x1000)
	ac0 := app.DB.GetAddressComment(0x1000)
	if c0 == nil || c0.Type != db.CellCode || c0.Mnemonic == nil || *c0.Mnemonic != "moveq" ||
		c0.OpStr == nil || *c0.OpStr != "#0,d0" ||
		ac0.Comment != "init counter" ||
		ac0.BlockComment != "entry" {
		t.Fatalf("0x1000 not fully restored: %+v ac=%+v", c0, ac0)
	}
	c1, _ := app.DB.GetCell(0x1002)
	if c1 == nil || c1.Type != db.CellCode || c1.Mnemonic == nil || *c1.Mnemonic != "rts" {
		t.Fatalf("0x1002 not restored: %+v", c1)
	}
}

func TestUndoClearsFullMarkedRangeNoRemainder(t *testing.T) {
	tmp := t.TempDir()
	proj := project.New(filepath.Join(tmp, "project.json"))
	proj.Data.Segments = append(proj.Data.Segments, project.Segment{
		Name:        "main",
		HunkIndex:   0,
		HunkType:    hunk.HunkTypeCode,
		MemoryType:  hunk.MemoryPublic,
		AllocSize:   16,
		Base:        0x1000,
		DB:          ":memory:",
		Relocatable: false,
	})
	proj.Data.Spaces = append(proj.Data.Spaces, project.Space{Name: "default", Segments: []string{"main"}})
	proj.Data.ActiveSpace = "default"

	ctrl, err := db.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ctrl.Close() })
	proj.SyncDBScope(ctrl)
	_ = ctrl.MarkData(0x1000, 2, db.CellDataW)

	app, err := NewApp(proj, ctrl)
	if err != nil {
		t.Fatal(err)
	}
	app.BinaryData = make([]byte, 16)
	_ = app.LoadData()

	app.GotoAddress(0x1000)
	app.MarkType(db.CellDataL, 8)
	if c, _ := app.DB.GetCell(0x1000); c == nil || c.Size != 8 {
		t.Fatalf("expected 8-byte cell at 0x1000")
	}

	app.Undo()
	restored, _ := app.DB.GetCell(0x1000)
	if restored == nil || restored.Size != 2 || restored.Type != db.CellDataW {
		t.Fatalf("expected original 2-byte DATA_W restored, got %+v", restored)
	}
	for a := uint32(0x1002); a < 0x1008; a += 2 {
		if c, _ := app.DB.GetCell(a); c != nil {
			t.Fatalf("unexpected remainder cell at %#X: %+v", a, c)
		}
	}
}

func TestTUIOverlappingSpacesAndCrossSegNavAndSearch(t *testing.T) {
	tmp := t.TempDir()
	proj := project.New(filepath.Join(tmp, "project.json"))
	specs := []struct {
		idx  int
		name string
		base uint32
	}{
		{0, "main", 0x28000},
		{1, "res_58000", 0x58000},
		{2, "eff03_t2", 0x30000},
		{3, "eff11_t97", 0x30000},
	}
	for _, sp := range specs {
		proj.Data.Segments = append(proj.Data.Segments, project.Segment{
			Name:        sp.name,
			HunkIndex:   sp.idx,
			HunkType:    hunk.HunkTypeCode,
			MemoryType:  hunk.MemoryPublic,
			AllocSize:   8,
			Base:        sp.base,
			DB:          ":memory:",
			Relocatable: false,
		})
	}
	proj.Data.Spaces = append(proj.Data.Spaces,
		project.Space{Name: "eff03", Segments: []string{"main", "res_58000", "eff03_t2"}},
		project.Space{Name: "eff11", Segments: []string{"main", "res_58000", "eff11_t97"}},
	)

	ctrl, err := db.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ctrl.Close() })

	proj.Data.ActiveSpace = "eff03"
	proj.ActiveSegmentName = "eff03_t2"
	proj.SyncDBScope(ctrl)
	_ = ctrl.InsertCell(&db.Cell{
		Seg:        "res_58000",
		Addr:       0x58000,
		Size:       2,
		Type:       db.CellCode,
		Confidence: 100,
		Mnemonic:   strPtr("nop"),
		OpStr:      strPtr(""),
		RawBytes:   []byte{0x4E, 0x71},
	})
	_ = ctrl.InsertCell(&db.Cell{
		Seg:        "eff03_t2",
		Addr:       0x30000,
		Size:       2,
		Type:       db.CellCode,
		Confidence: 100,
		Mnemonic:   strPtr("moveq"),
		OpStr:      strPtr("#3,d0"),
		RawBytes:   []byte{0x70, 0x03},
	})
	_ = ctrl.SetLabel(0x30000, "LAB_30000", db.LabelFun, true)
	_ = ctrl.SetRename("LAB_30000", "eff03_entry")

	proj.Data.ActiveSpace = "eff11"
	proj.ActiveSegmentName = "eff11_t97"
	proj.SyncDBScope(ctrl)
	_ = ctrl.InsertCell(&db.Cell{
		Seg:        "eff11_t97",
		Addr:       0x30000,
		Size:       2,
		Type:       db.CellCode,
		Confidence: 100,
		Mnemonic:   strPtr("moveq"),
		OpStr:      strPtr("#11,d0"),
		RawBytes:   []byte{0x70, 0x0B},
	})
	_ = ctrl.SetLabel(0x30000, "LAB_30000", db.LabelFun, true)
	_ = ctrl.SetRename("LAB_30000", "eff11_entry")

	app, err := NewApp(proj, ctrl)
	if err != nil {
		t.Fatal(err)
	}
	app.BinaryData = []byte{0x70, 0x0B, 0x4E, 0x75, 0, 0, 0, 0}
	_ = app.LoadData()

	var row11 *ListingRow
	for i := range app.DisasmRows {
		if app.DisasmRows[i].Addr != nil && app.DisasmRows[i].IsPrimary && *app.DisasmRows[i].Addr == 0x30000 {
			row11 = &app.DisasmRows[i]
			break
		}
	}
	if row11 == nil || row11.Operands != "#11,d0" {
		t.Fatalf("expected #11,d0 at $30000 in eff11_t97, got %+v", row11)
	}

	hits03 := app.DoSearch("o:eff03_t2/#3,d0")
	if len(hits03) != 1 || hits03[0].Addr != 0x30000 || !strings.Contains(hits03[0].Text, "#3,d0") {
		t.Fatalf("unexpected hits03: %+v", hits03)
	}

	nav03 := app.DoSearch("eff03_t2:eff03_entry")
	if len(nav03) != 1 || nav03[0].Addr != 0x30000 || nav03[0].Text != "eff03_entry" {
		t.Fatalf("unexpected nav03: %+v", nav03)
	}

	app.GotoAddress(0x58000)
	if app.Proj.ActiveSegmentName != "res_58000" || app.BaseAddr != 0x58000 {
		t.Fatalf("expected active segment res_58000 at 0x58000, got %s at %#X", app.Proj.ActiveSegmentName, app.BaseAddr)
	}
}

func TestCellCustomOffsetLiteralAndNamed(t *testing.T) {
	checkSome := func(op string, cmt *string, want uint16) {
		t.Helper()
		got, ok := cellCustomOffset(op, cmt)
		if !ok || got != want {
			t.Fatalf("cellCustomOffset(%q, %v) = (%#03X, %v), want (%#03X, true)", op, cmt, got, ok, want)
		}
	}
	checkNone := func(op string, cmt *string) {
		t.Helper()
		if got, ok := cellCustomOffset(op, cmt); ok {
			t.Fatalf("cellCustomOffset(%q, %v) = (%#03X, true), want false", op, cmt, got)
		}
	}

	checkSome("d0,$DFF096", nil, 0x096)
	checkSome("#$8020,$00DFF09A", nil, 0x09A)
	checkSome("d0,DMACON", nil, 0x096)
	checkSome("#$4200,BPLCON0", nil, 0x100)
	checkSome("#$7FFF,_custom+INTENA.l", nil, 0x09A)
	checkSome("DMACON(a6)", nil, 0x096)
	checkSome("156(a6)", strPtr("156(a6) = INTREQ"), 0x09C)
	checkSome("168(a6)", strPtr("168(a6) = AUD0VOL"), 0x0A8)
	checkSome("31(a6)", strPtr("31(a6) = INTREQR+1"), 0x01E)
	checkSome("226(a6)", strPtr("226(a6) = CUSTOM_0E2"), 0x0E2)
	checkSome("150(a6)", strPtr("150(a6) = DMACON (observed a6=0x00DFF000)"), 0x096)
	checkSome("154(a6)", strPtr("-> foo; 154(a6) = INTENA"), 0x09A)
	checkNone("d0,d1", strPtr("foo = DMACON"))
	checkNone("d0,d1", nil)
	checkNone("LAB_1234", nil)
}

func TestInRangeBounds(t *testing.T) {
	rng := db.AddrRange{Start: 0x1000, End: 0x2000}
	if !inRange(0x1500, &rng) {
		t.Fatalf("expected 0x1500 in range")
	}
	if inRange(0x2000, &rng) {
		t.Fatalf("expected exclusive hi 0x2000 out of range")
	}
	if inRange(0x0FFF, &rng) {
		t.Fatalf("expected 0x0FFF out of range")
	}
	if !inRange(0x9999, nil) {
		t.Fatalf("expected nil range to be unbounded")
	}
}

func stripANSI(s string) string {
	var sb strings.Builder
	inEsc := false
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			inEsc = true
			i++
			continue
		}
		if inEsc {
			if (s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= 'a' && s[i] <= 'z') {
				inEsc = false
			}
			continue
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

func TestRenderUILayoutFloatingModalsAndScrollbar(t *testing.T) {
	tmp := t.TempDir()
	proj := project.New(filepath.Join(tmp, "project.json"))
	proj.Data.Segments = append(proj.Data.Segments, project.Segment{
		Name:        "main",
		HunkIndex:   0,
		HunkType:    hunk.HunkTypeCode,
		MemoryType:  hunk.MemoryPublic,
		AllocSize:   32,
		Base:        0x1000,
		DB:          ":memory:",
		Relocatable: false,
	})
	proj.Data.Spaces = append(proj.Data.Spaces, project.Space{Name: "default", Segments: []string{"main"}})
	proj.Data.ActiveSpace = "default"
	proj.ActiveSegmentName = "main"

	ctrl, err := db.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ctrl.Close() })
	proj.SyncDBScope(ctrl)

	longComment := strings.Repeat("VERY_LONG_ANNOTATION_THAT_MUST_NEVER_WRAP_TERMINAL_LINES_", 5)
	_ = ctrl.InsertCell(&db.Cell{
		Addr:       0x1000,
		Size:       2,
		Type:       db.CellCode,
		Confidence: 100,
		Mnemonic:   strPtr("moveq"),
		OpStr:      strPtr("#0,d0"),
		RawBytes:   []byte{0x70, 0x00},
	})
	_ = ctrl.UpdateComment(0x1000, longComment)
	_ = ctrl.InsertCell(&db.Cell{
		Addr:       0x1002,
		Size:       2,
		Type:       db.CellCode,
		Confidence: 100,
		Mnemonic:   strPtr("rts"),
		RawBytes:   []byte{0x4E, 0x75},
	})

	app, err := NewApp(proj, ctrl)
	if err != nil {
		t.Fatal(err)
	}
	app.BinaryData = make([]byte, 32)
	app.BinaryData[0] = 0x70
	app.BinaryData[2] = 0x4E
	app.BinaryData[3] = 0x75
	_ = app.LoadData()
	app.Width = 100
	app.Height = 26

	// 1. Verify strict dimensions (exact Height lines) and scrollbar presence.
	out := RenderUI(app)
	lines := strings.Split(out, "\n")
	if len(lines) != app.Height {
		t.Fatalf("expected exact %d lines, got %d", app.Height, len(lines))
	}
	plain := stripANSI(out)
	if !strings.Contains(plain, " Disassembly ") || !strings.Contains(plain, "Space: default") || !strings.Contains(plain, "Segment: main") {
		t.Fatalf("expected top border title with Disassembly, Space, and Segment, got:\n%s", plain)
	}
	if !strings.Contains(plain, "4 (1/0) cyc") {
		t.Fatalf("expected '4 (1/0) cyc' in compact status bar, got:\n%s", plain)
	}
	if !strings.Contains(plain, "↑") || !strings.Contains(plain, "█") || !strings.Contains(plain, "║") || !strings.Contains(plain, "↓") {
		t.Fatalf("expected scrollbar symbols (↑, █, ║, ↓) in rendered UI")
	}

	// 2. Verify floating modal overlays background without wiping menu bar, status bar, or side borders.
	app.HandleKey("?")
	if app.Modal.Kind != ModalHelp {
		t.Fatalf("expected ModalHelp open")
	}
	modalOut := RenderUI(app)
	modalLines := strings.Split(modalOut, "\n")
	if len(modalLines) != app.Height {
		t.Fatalf("expected exact %d lines with modal open, got %d", app.Height, len(modalLines))
	}
	plainModal := stripANSI(modalOut)
	if !strings.Contains(plainModal, "[?]Help") {
		t.Fatalf("expected top menu bar preserved while modal is floating")
	}
	if !strings.Contains(plainModal, " Disassembly ") {
		t.Fatalf("expected background pane borders preserved while modal is floating")
	}
	if !strings.Contains(plainModal, " Help (? to close) ") {
		t.Fatalf("expected Help modal rendered on top")
	}
	app.HandleKey("?")

	// 3. Verify resize re-anchors cursor to the previously selected address even when sub-rows re-wrap.
	_ = ctrl.UpdateBlockComment(0x1000, strings.Repeat("word ", 30))
	_ = app.LoadData()
	app.GotoAddress(0x1002)
	if cur, ok := app.CursorAddr(); !ok || cur != 0x1002 {
		t.Fatalf("expected cursor at 0x1002 before resize, got %#X", cur)
	}
	app.Width = 80
	_ = RenderUI(app)
	if cur, ok := app.CursorAddr(); !ok || cur != 0x1002 {
		t.Fatalf("expected cursor re-anchored at 0x1002 after resize to 80, got %#X", cur)
	}
	statusAt1002 := app.GetStatusLine()
	if !strings.Contains(statusAt1002, "16 (4/0) cyc") {
		t.Fatalf("expected '16 (4/0) cyc' in status bar for rts at 0x1002, got %q", statusAt1002)
	}
	app.GotoAddress(0x1004)
	app.DataByteOff = 12
	statusAt1004 := app.GetStatusLine()
	if len(statusAt1002) != len(statusAt1004) {
		t.Fatalf("expected fixed-width status line, got len %d (%q) vs %d (%q)", len(statusAt1002), statusAt1002, len(statusAt1004), statusAt1004)
	}

	// 4. Verify list modal scrolling keeps selected item in view when list exceeds modal height.
	var funcs []FuncItem
	for i := range 40 {
		funcs = append(funcs, FuncItem{Addr: 0x1000 + uint32(i*2), Name: "FUNC_ITEM_" + string(rune('A'+(i%26)))})
	}
	funcs[39].Name = "FUNC_ITEM_LAST_39"
	app.Modal = Modal{
		Kind:       ModalFunctions,
		AllFuncs:   funcs,
		ListSelect: 39,
	}
	funcModalPlain := stripANSI(RenderUI(app))
	if !strings.Contains(funcModalPlain, "FUNC_ITEM_LAST_39") {
		t.Fatalf("expected scrolled list modal to display selected item 39")
	}
}

func TestThemeLoadAndTokenization(t *testing.T) {
	def := DefaultTheme()
	if def.Flow.fg != "38;2;224;175;104" || !def.Flow.bold {
		t.Fatalf("unexpected default Flow style: %+v", def.Flow)
	}
	if def.Aut.fg != "38;2;110;115;141" || !def.Aut.italic {
		t.Fatalf("unexpected default Aut style: %+v", def.Aut)
	}

	// Partial ~/.config/hunks/theme.json override preserves untouched defaults.
	tmp := t.TempDir()
	t.Setenv("HUNKS_THEME", "")
	t.Setenv("XDG_CONFIG_HOME", tmp)
	cfgDir := filepath.Join(tmp, "hunks")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "theme.json"), []byte(`{"flow": "#FF00AA italic", "cursor": "#000000 bg:#FFFFFF bold"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	loaded := LoadTheme()
	if loaded.Flow.fg != "38;2;255;0;170" || !loaded.Flow.italic || loaded.Flow.bold {
		t.Fatalf("expected overridden Flow style, got %+v", loaded.Flow)
	}
	if loaded.Cursor.fg != "38;2;0;0;0" || loaded.Cursor.bg != "48;2;255;255;255" || !loaded.Cursor.bold {
		t.Fatalf("expected overridden Cursor style, got %+v", loaded.Cursor)
	}
	if loaded.Op != def.Op {
		t.Fatalf("expected non-overridden Op style preserved, got %+v vs %+v", loaded.Op, def.Op)
	}

	// Flow vs ALU mnemonic classification.
	for _, m := range []string{"beq.s", "bhs.s", "blo.s", "bra.w", "bsr.s", "jsr", "jmp", "rts", "rte", "dbf", "dbra"} {
		if !isFlowMnemonic(m) {
			t.Errorf("expected %q to be classified as flow mnemonic", m)
		}
	}
	for _, m := range []string{"move.b", "cmp.w", "lea.l", "lsl.w", "andi.w", "add.w", "movem.l"} {
		if isFlowMnemonic(m) {
			t.Errorf("expected %q to be classified as standard op mnemonic", m)
		}
	}

	// Per-token operand styling.
	spans := tokenizeOperands("0(a0,d3.w),d3", 20, &def)
	var concat string
	for _, sp := range spans {
		concat += sp.text
	}
	if len(concat) != 20 || !strings.HasPrefix(concat, "0(a0,d3.w),d3") {
		t.Fatalf("unexpected tokenized operand text %q (len %d)", concat, len(concat))
	}
	if spans[0].text != "0" || spans[0].style != def.Imm {
		t.Fatalf("expected leading displacement '0' in Imm style, got %+v", spans[0])
	}
	if spans[2].text != "a0" || spans[2].style != def.AReg {
		t.Fatalf("expected 'a0' in AReg style, got %+v", spans[2])
	}

	// Auto-comment string literal highlighting.
	cSpans := commentSpans("; ", `ptr "HMAP_SIN_LUT_v2\0" (at $657B4)`, CommentStyleAuto, &def)
	if len(cSpans) != 3 || cSpans[1].text != `"HMAP_SIN_LUT_v2\0"` || cSpans[1].style != def.Str {
		t.Fatalf("expected quoted string highlighted in Str style, got %+v", cSpans)
	}
}

func TestBitplaneViewerInteractive(t *testing.T) {
	tmpDir := t.TempDir()
	proj := project.New(filepath.Join(tmpDir, "project.json"))
	proj.Data.Segments = append(proj.Data.Segments, project.Segment{
		Name:        "seg0",
		AllocSize:   4096,
		Base:        0x1000,
		Relocatable: false,
	})
	proj.ActiveSegmentName = "seg0"

	dbCtrl, err := db.New(filepath.Join(tmpDir, "project.db"))
	if err != nil {
		t.Fatalf("failed to create db: %v", err)
	}
	defer dbCtrl.Close()
	proj.SyncDBScope(dbCtrl)

	app, err := NewApp(proj, dbCtrl)
	if err != nil {
		t.Fatalf("failed to create app: %v", err)
	}
	app.Width = 100
	app.Height = 30
	app.BaseAddr = 0x1000
	app.BinaryData = make([]byte, 4096)
	for i := 0; i < 4096; i++ {
		app.BinaryData[i] = byte(i)
	}

	// 1. Press B to open bitplane viewer
	app.HandleKey("B")
	if app.Modal.Kind != ModalBitplane {
		t.Fatalf("expected ModalBitplane, got %v", app.Modal.Kind)
	}
	st := app.Modal.Bitplane
	if st == nil {
		t.Fatalf("expected Bitplane state to be non-nil")
	}
	if st.Planes != 1 {
		t.Fatalf("expected initial Planes 1, got %d", st.Planes)
	}
	if st.Scale < 1 {
		t.Fatalf("expected initial Scale >= 1, got %d", st.Scale)
	}
	if st.CachedEscapeSeq == "" && app.Modal.PixelProtocol != ProtocolHalfBlock {
		t.Fatalf("expected CachedEscapeSeq to be populated")
	}

	// 2. Render UI and verify output contains Bitplanes title, registers, both indicator groups, and CachedEscapeSeq
	out := RenderUI(app)
	plain := stripANSI(out)
	if !strings.Contains(plain, "Bitplanes") {
		t.Fatalf("expected Bitplanes in rendered output: %q", plain)
	}
	if !strings.Contains(plain, "Synced:") {
		t.Fatalf("expected Synced: indicator group in rendered output: %q", plain)
	}
	if !strings.Contains(plain, "BPU:") {
		t.Fatalf("expected BPU: indicator group in rendered output: %q", plain)
	}
	if !strings.Contains(plain, "BPLCON0:") {
		t.Fatalf("expected BPLCON0: in rendered output: %q", plain)
	}
	if !strings.Contains(plain, "DIW:") {
		t.Fatalf("expected DIW: in rendered output: %q", plain)
	}
	if !strings.Contains(plain, "DDF:") {
		t.Fatalf("expected DDF: in rendered output: %q", plain)
	}
	if strings.Contains(plain, "#") || strings.Contains(plain, "0CAF5") || strings.Contains(plain, "0AF68") {
		t.Fatalf("corrupted raw ANSI color token leaked into plain text: %q", plain)
	}
	if strings.Contains(out, "\x1b[#") {
		t.Fatalf("invalid ANSI CSI sequence with # found in output: %q", out)
	}
	if app.Modal.PixelProtocol != ProtocolHalfBlock && !strings.Contains(out, "\x1b[6;2H") {
		t.Fatalf("expected initial pixel placement at row 6 col 2 (\\x1b[6;2H) in rendered output")
	}

	// 3. Adjust geometry: increase width (+1 word = +16 px = +2 bytes)
	origBytes := st.RowBytes
	app.HandleKey("right")
	if st.RowBytes != origBytes+2 {
		t.Fatalf("expected RowBytes %d, got %d", origBytes+2, st.RowBytes)
	}

	// 4. Adjust planes: increase to 2 planes
	app.HandleKey("+")
	if st.Planes != 2 {
		t.Fatalf("expected Planes 2, got %d", st.Planes)
	}

	// 5. Plane control selection and visibility groups
	// Toggle plane 1 out of control selection
	app.HandleKey("1")
	if (st.ControlMask & 1) != 0 {
		t.Fatalf("expected plane 1 to be unarmed from control selection")
	}
	if (st.ControlMask & 2) == 0 {
		t.Fatalf("expected plane 2 to remain armed in control selection")
	}
	bpl0 := st.BPL[0]
	bpl1 := st.BPL[1]
	app.HandleKey(".") // Step control-selected planes by +2
	if st.BPL[0] != bpl0 {
		t.Fatalf("unarmed plane 1 should not move: got %d vs %d", st.BPL[0], bpl0)
	}
	if st.BPL[1] != bpl1+2 {
		t.Fatalf("armed plane 2 should advance: got %d vs %d", st.BPL[1], bpl1+2)
	}

	// Toggle depth with direct keys (BPU 1..7)
	// Depth 1: !
	app.HandleKey("!")
	if st.BPU() != 1 {
		t.Fatalf("expected BPU 1 after '!', got %d", st.BPU())
	}
	// Depth 4: Nordic ¤ or US $
	app.HandleKey("¤")
	if st.BPU() != 4 {
		t.Fatalf("expected BPU 4 after '¤', got %d", st.BPU())
	}
	// Depth 7: /
	app.HandleKey("/")
	if st.BPU() != 7 {
		t.Fatalf("expected BPU 7 after '/', got %d", st.BPU())
	}
	if st.BPLCON0Hex() != 0x7200 {
		t.Fatalf("expected BPLCON0 $7200 for 7 planes, got $%04X", st.BPLCON0Hex())
	}

	// Toggle 1 vs 6 with ')'
	app.HandleKey(")")
	if st.BPU() != 1 {
		t.Fatalf("expected BPU 1 after first ')', got %d", st.BPU())
	}
	app.HandleKey(")")
	if st.BPU() != 6 {
		t.Fatalf("expected BPU 6 after second ')', got %d", st.BPU())
	}

	// Test '0' toggling: from all armed (0x3F) -> solo plane 1 (1) -> all armed (0x3F)
	app.HandleKey("0")
	if st.ControlMask != 1 {
		t.Fatalf("expected solo plane 1 after first '0', got %d", st.ControlMask)
	}
	app.HandleKey("0")
	if st.ControlMask != 0x3F {
		t.Fatalf("expected all planes armed after second '0', got %d", st.ControlMask)
	}

	// 6. Direct Geometry Input prompt
	app.HandleKey("g")
	if app.Modal.Kind != ModalBitplaneGeometry {
		t.Fatalf("expected ModalBitplaneGeometry, got %v", app.Modal.Kind)
	}
	// Type 640x256x4 and press enter
	app.Modal.Input = NewTextInput("640x256x4")
	app.HandleKey("enter")
	if app.Modal.Kind != ModalBitplane {
		t.Fatalf("expected return to ModalBitplane, got %v", app.Modal.Kind)
	}
	if st.WidthPx() != 640 || st.Height != 256 || st.Planes != 4 {
		t.Fatalf("expected 640x256x4, got %dx%dx%d", st.WidthPx(), st.Height, st.Planes)
	}

	// 7. Save PNG and IFF, verify status message is visible in rendered status bar
	t.Cleanup(func() { _ = os.RemoveAll("assets") })
	app.HandleKey("w")
	if !strings.Contains(app.StatusMsg, "Saved PNG") {
		t.Fatalf("expected Saved PNG status msg, got %q", app.StatusMsg)
	}
	if !strings.Contains(stripANSI(RenderUI(app)), "Saved PNG") {
		t.Fatalf("expected Saved PNG to be visible in rendered status bar")
	}
	app.HandleKey("W")
	if !strings.Contains(app.StatusMsg, "Saved IFF") {
		t.Fatalf("expected Saved IFF status msg, got %q", app.StatusMsg)
	}

	// Carve with K -> ModalCarveName -> esc returns to ModalBitplane; K -> enter carves, and verify Modulo/Masks/Palette round-trip on B
	st.RowBytes = 2
	st.Height = 2
	st.Modulo = 6
	st.SetBPU(2)
	st.VisibleMask = 0x01
	st.ControlMask = 0x02
	st.PaletteMode = PaletteHighContrast
	st.Invert = true
	st.Brightness = 2
	st.AutoSnapPlanes()
	app.HandleKey("K")
	if app.Modal.Kind != ModalCarveName {
		t.Fatalf("expected ModalCarveName after K in bitplane viewer, got %v", app.Modal.Kind)
	}
	app.HandleKey("esc")
	if app.Modal.Kind != ModalBitplane {
		t.Fatalf("expected return to ModalBitplane on esc from ModalCarveName, got %v", app.Modal.Kind)
	}
	app.HandleKey("K")
	if !strings.HasPrefix(app.Modal.Input.Value, "gfx_") {
		t.Fatalf("expected default label starting with gfx_, got %q", app.Modal.Input.Value)
	}
	if !strings.Contains(app.Modal.CarveBlockComment, "Bitmap:") {
		t.Fatalf("expected CarveBlockComment to contain Bitmap:, got %q", app.Modal.CarveBlockComment)
	}
	app.HandleKey("enter")
	if !strings.Contains(app.StatusMsg, "Carved") {
		t.Fatalf("expected Carved status msg, got %q", app.StatusMsg)
	}
	if app.Modal.Kind != ModalNone {
		t.Fatalf("expected ModalNone after carving, got %v", app.Modal.Kind)
	}

	// Verify round-trip on 'B': reopen bitplane viewer on the carved row
	app.HandleKey("B")
	if app.Modal.Kind != ModalBitplane {
		t.Fatalf("expected ModalBitplane after pressing B, got %v", app.Modal.Kind)
	}
	rb := app.Modal.Bitplane
	if rb.RowBytes != 2 || rb.Height != 2 || rb.BPU() != 2 || rb.Modulo != 6 {
		t.Fatalf("expected restored geometry 2x2x2 modulo 6, got %dx%dx%d modulo %d",
			rb.RowBytes, rb.Height, rb.BPU(), rb.Modulo)
	}
	if rb.VisibleMask != 0x01 || rb.ControlMask != 0x02 {
		t.Fatalf("expected restored masks VIS=$01 SYNC=$02, got VIS=$%02X SYNC=$%02X",
			rb.VisibleMask, rb.ControlMask)
	}
	if rb.PaletteMode != PaletteHighContrast || !rb.Invert || rb.Brightness != 2 {
		t.Fatalf("expected restored High-Contrast inv bias=+2, got mode=%v inv=%v bias=%d",
			rb.PaletteMode, rb.Invert, rb.Brightness)
	}
	app.HandleKey("esc")

	// Undo the carve with 'ctrl+z'
	app.HandleKey("ctrl+z")
	if app.StatusMsg != "Undone" {
		t.Fatalf("expected Undone after 'ctrl+z', got %q", app.StatusMsg)
	}
}

func TestMusicRipperModalAndCarve(t *testing.T) {
	tmp := t.TempDir()
	proj := project.New(filepath.Join(tmp, "project.json"))
	proj.WorkspaceRoot = tmp
	proj.Data.Segments = append(proj.Data.Segments, project.Segment{
		Name:        "main",
		HunkIndex:   0,
		HunkType:    hunk.HunkTypeCode,
		MemoryType:  hunk.MemoryPublic,
		AllocSize:   4096,
		Base:        0x10000,
		DB:          ":memory:",
		Relocatable: false,
	})
	proj.Data.Spaces = append(proj.Data.Spaces, project.Space{Name: "default", Segments: []string{"main"}})
	proj.Data.ActiveSpace = "default"
	proj.ActiveSegmentName = "main"

	ctrl, err := db.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ctrl.Close() })
	proj.SyncDBScope(ctrl)

	app, err := NewApp(proj, ctrl)
	if err != nil {
		t.Fatal(err)
	}

	// Create a synthetic ProTracker module at offset 256
	mod := make([]byte, 1084+1024+100)
	copy(mod[0:min(len("TestTune"), 20)], "TestTune")
	mod[952] = 0 // max pattern index
	mod[42] = 0
	mod[43] = 50 // 50 words = 100 bytes sample
	copy(mod[1080:1084], "M.K.")

	modOffset := 256
	app.BinaryData = make([]byte, 4096)
	copy(app.BinaryData[modOffset:], mod)
	_ = app.LoadData()

	// 1. Press 'M' to open Music Ripper
	app.HandleKey("M")
	if app.Modal.Kind != ModalMusicRipper {
		t.Fatalf("expected ModalMusicRipper, got %v", app.Modal.Kind)
	}
	st := &app.Modal.MusicRipper
	if len(st.Items) != 1 {
		t.Fatalf("expected 1 detected module item, got %d", len(st.Items))
	}
	it := st.Items[0]
	if it.Name != "ProTracker" || it.Variant != "ProTracker" || it.Start != modOffset {
		t.Fatalf("unexpected module item: %+v", it)
	}

	// 2. Press 'w' to save / rip module to <WorkspaceRoot>/assets/
	app.HandleKey("w")
	if !strings.Contains(app.StatusMsg, "Saved music module") {
		t.Fatalf("expected Saved music module status, got %q", app.StatusMsg)
	}

	// 3. Press 'K' to carve as incbin, test 'esc' returns to ModalMusicRipper, then 'K' again
	app.HandleKey("K")
	if app.Modal.Kind != ModalCarveName {
		t.Fatalf("expected ModalCarveName after K, got %v", app.Modal.Kind)
	}
	app.HandleKey("esc")
	if app.Modal.Kind != ModalMusicRipper {
		t.Fatalf("expected return to ModalMusicRipper on esc from ModalCarveName, got %v", app.Modal.Kind)
	}
	app.HandleKey("K")
	if !strings.HasPrefix(app.Modal.Input.Value, "mod_protracker_") {
		t.Fatalf("expected label starting with mod_protracker_, got %q", app.Modal.Input.Value)
	}
	if !strings.Contains(app.Modal.CarveBlockComment, "Music:  ProTracker") {
		t.Fatalf("expected Music block comment, got %q", app.Modal.CarveBlockComment)
	}

	// 4. Press 'enter' to confirm carve and verify cursor jumped to carved start
	app.HandleKey("enter")
	if app.Modal.Kind != ModalNone {
		t.Fatalf("expected ModalNone after carve, got %v", app.Modal.Kind)
	}
	if cur, ok := app.CursorAddr(); !ok || cur != uint32(0x10000+modOffset) {
		t.Fatalf("expected cursor to jump to carved start 0x%X, got 0x%X (ok=%v)", 0x10000+modOffset, cur, ok)
	}
	cell, err := app.DB.GetCell(uint32(0x10000 + modOffset))
	if err != nil || cell == nil || cell.Type != db.CellIncbin {
		t.Fatalf("expected CellIncbin at carve start, got %+v", cell)
	}
	bc := app.DB.GetAddressComment(uint32(0x10000 + modOffset)).BlockComment
	if !strings.Contains(bc, "Music:  ProTracker") {
		t.Fatalf("expected BlockComment on carved cell, got %q", bc)
	}

	// 5. Undo carve with 'ctrl+z'
	app.HandleKey("ctrl+z")
	cellAfter, _ := app.DB.GetCell(uint32(0x10000 + modOffset))
	if cellAfter != nil && cellAfter.Type == db.CellIncbin {
		t.Fatalf("expected CellIncbin gone after undo")
	}

	// 6. Test Enter navigation: reopen 'M', press 'enter', verify cursor jump
	app.HandleKey("M")
	if app.Modal.Kind != ModalMusicRipper {
		t.Fatalf("expected ModalMusicRipper, got %v", app.Modal.Kind)
	}
	app.HandleKey("enter")
	if app.Modal.Kind != ModalNone {
		t.Fatalf("expected ModalNone after enter, got %v", app.Modal.Kind)
	}
	curAddr, ok := app.CursorAddr()
	if !ok || curAddr != uint32(0x10000+modOffset) {
		t.Fatalf("expected cursor at 0x%X, got 0x%X (ok=%v)", 0x10000+modOffset, curAddr, ok)
	}
}

func TestBlockAndSubroutineCycles(t *testing.T) {
	// Subroutine 1 at 0x10000:
	//   0x10000: moveq #0,d0    (0x7000) -> 4 (1/0) cyc
	//   0x10002: addq.w #1,d0   (0x5240) -> 4 (1/0) cyc
	//   0x10004: rts            (0x4E75) -> 16 (4/0) cyc
	// Total Subroutine 1 = 6B, 3 insns, 24 (6/0) cyc
	//
	// Subroutine 2 at 0x10006 (contains variable-timing muls.w):
	//   0x10006: muls.w d1,d0   (0xC1C1) -> 38-70 (1/0) cyc
	//   0x10008: rts            (0x4E75) -> 16 (4/0) cyc
	// Total Subroutine 2 = 4B, 2 insns, 54-86 (5/0) cyc
	//
	// Subroutine 3 at 0x1000A (has internal branch label LAB_10014 and a jmp skipped by beq.s):
	//   0x1000A: tst.w d0       (0x4A40)
	//   0x1000C: beq.s $10014   (0x6706) -> branches past jmp to 0x10014
	//   0x1000E: jmp $10000.l   (0x4EF9 0x00010000) -> skipped by beq.s, must NOT end Sub3!
	//   0x10014: addq.w #1,d0   (0x5240) [LAB_10014 with XrefCodeBranch]
	//   0x10016: rts            (0x4E75) -> actual end of Sub3
	//
	// Subroutine 4 at 0x10018 (ends via unskipped tail-call jmp):
	//   0x10018: moveq #1,d0    (0x7001)
	//   0x1001A: jmp $10000.l   (0x4EF9 0x00010000) -> unskipped tail-call jmp ends Sub4!
	//
	// Trailing data at 0x10020..0x10023 (4 bytes)
	raw := []byte{
		0x70, 0x00,
		0x52, 0x40,
		0x4E, 0x75,
		0xC1, 0xC1,
		0x4E, 0x75,
		0x4A, 0x40,
		0x67, 0x06,
		0x4E, 0xF9, 0x00, 0x01, 0x00, 0x00,
		0x52, 0x40,
		0x4E, 0x75,
		0x70, 0x01,
		0x4E, 0xF9, 0x00, 0x01, 0x00, 0x00,
		0xAA, 0xBB, 0xCC, 0xDD,
	}

	tmpDir := t.TempDir()
	proj := project.New(filepath.Join(tmpDir, "project.json"))
	proj.WorkspaceRoot = tmpDir
	proj.Data.Segments = []project.Segment{{
		Name:      "hunk0",
		HunkIndex: 0,
		HunkType:  hunk.HunkTypeCode,
		Base:      0x10000,
		AllocSize: uint32(len(raw)),
	}}
	proj.Data.Spaces = []project.Space{{Name: "default", Segments: []string{"hunk0"}}}
	proj.Data.ActiveSpace = "default"
	proj.ActiveSegmentName = "hunk0"

	ctrl, err := db.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ctrl.Close() })
	proj.SyncDBScope(ctrl)

	mustInsertCode := func(addr uint32, rawBytes []byte, mnem, op string) {
		m := mnem
		o := op
		if err := ctrl.InsertCell(&db.Cell{
			Seg:      "hunk0",
			Addr:     addr,
			Size:     uint32(len(rawBytes)),
			Type:     db.CellCode,
			Mnemonic: &m,
			OpStr:    &o,
			RawBytes: rawBytes,
		}); err != nil {
			t.Fatal(err)
		}
	}
	mustInsertCode(0x10000, raw[0:2], "moveq", "#0,d0")
	mustInsertCode(0x10002, raw[2:4], "addq.w", "#1,d0")
	mustInsertCode(0x10004, raw[4:6], "rts", "")
	mustInsertCode(0x10006, raw[6:8], "muls.w", "d1,d0")
	mustInsertCode(0x10008, raw[8:10], "rts", "")
	mustInsertCode(0x1000A, raw[10:12], "tst.w", "d0")
	mustInsertCode(0x1000C, raw[12:14], "beq.s", "LAB_10014")
	mustInsertCode(0x1000E, raw[14:20], "jmp", "$10000.l")
	mustInsertCode(0x10014, raw[20:22], "addq.w", "#1,d0")
	mustInsertCode(0x10016, raw[22:24], "rts", "")
	mustInsertCode(0x10018, raw[24:26], "moveq", "#1,d0")
	mustInsertCode(0x1001A, raw[26:32], "jmp", "$10000.l")

	_ = ctrl.SetLabel(0x10014, "LAB_10014", db.LabelLab, true)
	_ = ctrl.InsertXref(0x1000C, 0x10014, db.XrefCodeBranch)

	_ = ctrl.InsertFunction(0x10000, "Sub1", 255)
	_ = ctrl.UpdateFunctionMetadataBatch([]db.FunctionMeta{{
		Entry:   0x10000,
		EndAddr: 0x10006,
		HasEnd:  true,
	}})

	app, err := NewApp(proj, ctrl)
	if err != nil {
		t.Fatal(err)
	}
	app.BinaryData = raw
	if err := app.LoadData(); err != nil {
		t.Fatal(err)
	}

	// 1. Manual range selection ('v' + move down 1 row) across first 2 instructions of Sub1
	app.GotoAddress(0x10000)
	app.HandleKey("v")
	app.HandleKey("j")
	status := app.GetStatusLine()
	if !strings.Contains(status, "(4B, 2 insns) │ 8 (2/0) cyc") {
		t.Fatalf("expected 4B, 2 insns, 8 (2/0) cyc in status line, got %q", status)
	}
	app.HandleKey("esc")
	if app.SelectionStart != nil {
		t.Fatalf("expected selection cleared on esc")
	}

	// 2. Press 'V' inside Sub1 (at 0x10002) -> selects [0x10000..0x10004]
	app.GotoAddress(0x10002)
	app.HandleKey("V")
	selStart, selEnd, ok := app.GetSelectionRange()
	if !ok || selStart != 0x10000 || selEnd != 0x10004 {
		t.Fatalf("expected Sub1 selection [0x10000..0x10004], got [0x%X..0x%X] ok=%v", selStart, selEnd, ok)
	}
	status = app.GetStatusLine()
	if !strings.Contains(status, "(6B, 3 insns) │ 24 (6/0) cyc") {
		t.Fatalf("expected Sub1 status '(6B, 3 insns) │ 24 (6/0) cyc', got %q", status)
	}

	// Pressing 'V' again toggles/cancels the subroutine selection
	app.HandleKey("V")
	if app.SelectionStart != nil {
		t.Fatalf("expected second 'V' to cancel selection")
	}

	// 3. Press 'V' inside Sub2 (at 0x10008) -> selects [0x10006..0x10008]
	app.GotoAddress(0x10008)
	app.HandleKey("V")
	selStart, selEnd, ok = app.GetSelectionRange()
	if !ok || selStart != 0x10006 || selEnd != 0x10008 {
		t.Fatalf("expected Sub2 selection [0x10006..0x10008], got [0x%X..0x%X] ok=%v", selStart, selEnd, ok)
	}
	status = app.GetStatusLine()
	if !strings.Contains(status, "(4B, 2 insns) │ 54-86 (5/0) cyc") {
		t.Fatalf("expected Sub2 variable timing '(4B, 2 insns) │ 54-86 (5/0) cyc', got %q", status)
	}
	app.HandleKey("esc")

	// 4. Press 'V' inside Sub3 (at 0x1000A) -> walks across LAB_10014 and skipped jmp to rts at 0x10016
	app.GotoAddress(0x1000A)
	app.HandleKey("V")
	selStart, selEnd, ok = app.GetSelectionRange()
	if !ok || selStart != 0x1000A || selEnd != 0x10016 {
		t.Fatalf("expected Sub3 selection [0x1000A..0x10016] across internal label and skipped jmp, got [0x%X..0x%X] ok=%v", selStart, selEnd, ok)
	}
	app.HandleKey("esc")

	// 5. Press 'V' inside Sub4 (at 0x10018) -> stops at unskipped tail-call jmp at 0x1001A
	app.GotoAddress(0x10018)
	app.HandleKey("V")
	selStart, selEnd, ok = app.GetSelectionRange()
	if !ok || selStart != 0x10018 || selEnd != 0x1001A {
		t.Fatalf("expected Sub4 selection [0x10018..0x1001A] ending at tail-call jmp, got [0x%X..0x%X] ok=%v", selStart, selEnd, ok)
	}
	app.HandleKey("esc")

	// 6. Press 'V' on data-only row -> clears/refuses with "No subroutine at cursor"
	app.GotoAddress(0x10020)
	app.HandleKey("V")
	if app.SelectionStart != nil || app.StatusMsg != "No subroutine at cursor" {
		t.Fatalf("expected 'No subroutine at cursor' on data row, got StatusMsg=%q", app.StatusMsg)
	}
}
