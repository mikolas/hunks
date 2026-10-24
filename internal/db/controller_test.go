package db

import (
	"reflect"
	"testing"
)

func TestExportedLabels(t *testing.T) {
	db, err := New(":memory:")
	if err != nil {
		t.Fatalf("New(:memory:) failed: %v", err)
	}
	defer db.Close()

	// 1. Initial label is not exported
	if err := db.SetLabel(0x1000, "LAB_1000", LabelDat, true); err != nil {
		t.Fatalf("SetLabel failed: %v", err)
	}
	l1, err := db.GetLabelFull(0x1000)
	if err != nil || l1 == nil {
		t.Fatalf("GetLabelFull(0x1000) = %v, %v", l1, err)
	}
	if l1.Name != "LAB_1000" || l1.IsExported {
		t.Errorf("l1 = %+v", l1)
	}

	// 2. Mark exported
	if err := db.MarkExported(0x1000); err != nil {
		t.Fatalf("MarkExported failed: %v", err)
	}
	l2, err := db.GetLabelFull(0x1000)
	if err != nil || l2 == nil || !l2.IsExported {
		t.Fatalf("GetLabelFull after MarkExported = %+v, %v", l2, err)
	}

	// 3. SetLabel again preserves IsExported
	if err := db.SetLabel(0x1000, "LAB_1000_NEW", LabelDat, false); err != nil {
		t.Fatalf("SetLabel 2 failed: %v", err)
	}
	l3, err := db.GetLabelFull(0x1000)
	if err != nil || l3 == nil || l3.Name != "LAB_1000_NEW" || !l3.IsExported {
		t.Fatalf("GetLabelFull after SetLabel 2 = %+v, %v", l3, err)
	}

	// 4. Multiple exported labels
	if err := db.SetLabelExported(0x2000, "LAB_2000", LabelFun, true, true); err != nil {
		t.Fatalf("SetLabelExported failed: %v", err)
	}
	if err := db.SetLabel(0x3000, "LAB_3000", LabelDat, true); err != nil {
		t.Fatalf("SetLabel 0x3000 failed: %v", err)
	}

	exported, err := db.GetExportedLabels()
	if err != nil {
		t.Fatalf("GetExportedLabels failed: %v", err)
	}
	want := []string{"LAB_1000_NEW", "LAB_2000"}
	if !reflect.DeepEqual(exported, want) {
		t.Errorf("GetExportedLabels() = %v, want %v", exported, want)
	}
}

func TestBaseRegsRoundtripAndClear(t *testing.T) {
	db, err := New(":memory:")
	if err != nil {
		t.Fatalf("New(:memory:) failed: %v", err)
	}
	defer db.Close()

	if err := db.SetBaseReg("global", "", "a6", 0xDFF000, "auto"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetBaseReg("global", "", "a4", 0x20000, "hint"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetBaseReg("segment", "hunk0", "a5", 0x12345, "auto"); err != nil {
		t.Fatal(err)
	}

	all, err := db.GetAllBaseRegs()
	if err != nil || len(all) != 3 {
		t.Fatalf("GetAllBaseRegs() = %v, %v", all, err)
	}

	if err := db.ClearAutoBaseRegs(); err != nil {
		t.Fatal(err)
	}
	after, err := db.GetAllBaseRegs()
	if err != nil || len(after) != 1 || after[0].Reg != "a4" || after[0].Source != "hint" {
		t.Fatalf("after ClearAutoBaseRegs() = %+v, %v", after, err)
	}

	// Uppercase reg name normalizes to lowercase on insert
	if err := db.SetBaseReg("global", "", "A6", 0x100, "auto"); err != nil {
		t.Fatal(err)
	}
	all2, err := db.GetAllBaseRegs()
	if err != nil {
		t.Fatal(err)
	}
	var foundA6 bool
	for _, b := range all2 {
		if b.Reg == "a6" && b.BaseAddr == 0x100 {
			foundA6 = true
		}
	}
	if !foundA6 {
		t.Errorf("expected normalized lowercase a6 in %+v", all2)
	}
}

func TestDeleteCodeCellsPreservesCarvesAndHints(t *testing.T) {
	db, err := New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Discovered CODE cell with user comment
	if err := db.InsertCell(&Cell{
		Addr: 0x1000, Size: 2, Type: CellCode, Confidence: 0,
		Mnemonic: StrPtr("rts"), RawBytes: []byte{0x4E, 0x75},
	}); err != nil {
		t.Fatal(err)
	}
	_ = db.UpdateComment(0x1000, "code user comment")
	// Carve (INCBIN, conf 255) with comment
	if err := db.InsertCell(&Cell{
		Addr: 0x2000, Size: 16, Type: CellIncbin, Confidence: 255,
		RawBytes: make([]byte, 16),
	}); err != nil {
		t.Fatal(err)
	}
	_ = db.UpdateComment(0x2000, "carved block")
	// Data hint (conf 100) with comment
	if err := db.InsertCell(&Cell{
		Addr: 0x3000, Size: 4, Type: CellDataL, Confidence: 100,
		RawBytes: make([]byte, 4),
	}); err != nil {
		t.Fatal(err)
	}
	_ = db.UpdateComment(0x3000, "pointer hint")
	// Low-confidence data cell (conf 0)
	if err := db.InsertCell(&Cell{
		Addr: 0x4000, Size: 2, Type: CellDataW, Confidence: 0,
		RawBytes: make([]byte, 2),
	}); err != nil {
		t.Fatal(err)
	}

	if err := db.DeleteCodeCells(); err != nil {
		t.Fatal(err)
	}

	if c, err := db.GetCell(0x1000); err != nil || c != nil {
		t.Errorf("expected CODE cell deleted, got %+v, %v", c, err)
	}
	if ac := db.GetAddressComment(0x1000); ac.Comment != "code user comment" {
		t.Errorf("expected user comment at 0x1000 to survive DeleteCodeCells, got %+v", ac)
	}
	carve, err := db.GetCell(0x2000)
	if err != nil || carve == nil || carve.Type != CellIncbin || db.GetAddressComment(0x2000).Comment != "carved block" {
		t.Errorf("carve did not survive: %+v, %v", carve, err)
	}
	hint, err := db.GetCell(0x3000)
	if err != nil || hint == nil || db.GetAddressComment(0x3000).Comment != "pointer hint" {
		t.Errorf("hint did not survive: %+v, %v", hint, err)
	}
	if low, err := db.GetCell(0x4000); err != nil || low == nil {
		t.Errorf("low-conf cell should remain until Stage 3 prunes")
	}

	prot := db.ProtectedNoncodeRanges(100)
	wantProt := []AddrRange{{Start: 0x2000, End: 0x2010}, {Start: 0x3000, End: 0x3004}}
	if !reflect.DeepEqual(prot, wantProt) {
		t.Errorf("ProtectedNoncodeRanges(100) = %+v, want %+v", prot, wantProt)
	}
}

func TestSearchCodeAndStringsScoped(t *testing.T) {
	db, err := New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	code := func(addr uint32, m, o string) *Cell {
		return &Cell{
			Addr: addr, Size: 2, Type: CellCode, Confidence: 100,
			Mnemonic: StrPtr(m), OpStr: StrPtr(o),
		}
	}
	_ = db.InsertCell(code(0x1000, "jsr", "(a0)"))
	_ = db.InsertCell(code(0x1002, "move.w", "d0,DMACON"))
	_ = db.InsertCell(code(0x2000, "jsr", "LAB_x"))
	_ = db.InsertCell(code(0x2002, "rts", ""))
	_ = db.InsertCell(&Cell{
		Addr: 0x3000, Size: 11, Type: CellStr, Confidence: 100,
		RawBytes: []byte("SEND_RS232\x00"),
	})

	jsrs := db.SearchCode("m", "jsr", nil, 100)
	if len(jsrs) != 2 || jsrs[0].Addr != 0x1000 || jsrs[1].Addr != 0x2000 {
		t.Errorf("SearchCode(m, jsr, nil) = %+v", jsrs)
	}
	scoped := db.SearchCode("m", "jsr", &AddrRange{Start: 0x1000, End: 0x2000}, 100)
	if len(scoped) != 1 || scoped[0].Addr != 0x1000 {
		t.Errorf("SearchCode(m, jsr, scoped) = %+v", scoped)
	}
	ops := db.SearchCode("o", "DMACON", nil, 100)
	if len(ops) != 1 || ops[0].Addr != 0x1002 {
		t.Errorf("SearchCode(o, DMACON) = %+v", ops)
	}
	strs := db.SearchStrings("rs232", &AddrRange{Start: 0x2000, End: 0x4000}, 100)
	if len(strs) != 1 || strs[0].Addr != 0x3000 {
		t.Errorf("SearchStrings(rs232, scoped) = %+v", strs)
	}
	if empty := db.SearchStrings("rs232", &AddrRange{Start: 0x0, End: 0x1000}, 100); len(empty) != 0 {
		t.Errorf("expected empty SearchStrings in [0, 0x1000), got %+v", empty)
	}
}

func TestOverlappingSegmentsIsolatedInSharedDB(t *testing.T) {
	db, err := New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	spaceEff03 := []SpaceSeg{
		{Name: "main", Base: 0x28000, End: 0x28800},
		{Name: "eff03_t2", Base: 0x30000, End: 0x31000},
	}
	spaceEff11 := []SpaceSeg{
		{Name: "main", Base: 0x28000, End: 0x28800},
		{Name: "eff11_t97", Base: 0x30000, End: 0x31000},
	}

	// 1. Populate eff03_t2 in space eff03
	db.SetSpaceSegs(spaceEff03)
	db.SetActiveSeg("eff03_t2")
	_ = db.InsertCell(&Cell{
		Addr: 0x30000, Size: 6, Type: CellCode, Confidence: 100,
		Mnemonic: StrPtr("lea.l"), OpStr: StrPtr("LAB_39A38.l,a0"),
		RawBytes: []byte{0x41, 0xF9, 0x00, 0x03, 0x9A, 0x38},
	})
	_ = db.InsertCell(&Cell{
		Addr: 0x30854, Size: 4, Type: CellCode, Confidence: 100,
		Mnemonic: StrPtr("lea.l"), OpStr: StrPtr("1024(a6),a6"),
		RawBytes: []byte{0x4D, 0xEE, 0x04, 0x00},
	})
	_ = db.SetLabel(0x30000, "LAB_30000", LabelLab, true)
	_ = db.SetRename("LAB_30000", "Eff03_Entry")

	// 2. Populate eff11_t97 in space eff11 at the SAME $30000 base
	db.SetSpaceSegs(spaceEff11)
	db.SetActiveSeg("eff11_t97")
	_ = db.InsertCell(&Cell{
		Addr: 0x30000, Size: 10, Type: CellCode, Confidence: 100,
		Mnemonic: StrPtr("move.l"), OpStr: StrPtr("#LAB_30154,_custom+COP1LCH.l"),
		RawBytes: []byte{0x23, 0xFC, 0x00, 0x03, 0x01, 0x54, 0x00, 0xDF, 0xF0, 0x80},
	})
	_ = db.InsertCell(&Cell{
		Addr: 0x30855, Size: 1, Type: CellDataB, Confidence: 50,
		RawBytes: []byte{0x00},
	})
	_ = db.SetLabel(0x30000, "LAB_30000", LabelLab, true)
	_ = db.SetRename("LAB_30000", "Eff11_Entry")

	// 3. Verify eff11 sees eff11_t97's cells and rename
	c11, err := db.GetCell(0x30000)
	if err != nil || c11 == nil || c11.Seg != "eff11_t97" || c11.MnemonicStr() != "move.l" {
		t.Fatalf("eff11 cell at $30000 = %+v, %v", c11, err)
	}
	labels11, err := db.GetAllLabelsResolved()
	if err != nil || labels11[0x30000] != "Eff11_Entry" {
		t.Fatalf("labels11[0x30000] = %q, %v", labels11[0x30000], err)
	}

	// 4. Switch back to eff03 and verify eff03_t2 was NOT clobbered
	db.SetSpaceSegs(spaceEff03)
	db.SetActiveSeg("eff03_t2")
	c03, err := db.GetCell(0x30000)
	if err != nil || c03 == nil || c03.Seg != "eff03_t2" || c03.MnemonicStr() != "lea.l" {
		t.Fatalf("eff03 cell at $30000 = %+v, %v", c03, err)
	}
	mid03, err := db.GetCellContaining(0x30855)
	if err != nil || mid03 == nil || mid03.Addr != 0x30854 || mid03.OpStrVal() != "1024(a6),a6" {
		t.Fatalf("eff03 cell containing $30855 = %+v, %v", mid03, err)
	}
	labels03, err := db.GetAllLabelsResolved()
	if err != nil || labels03[0x30000] != "Eff03_Entry" {
		t.Fatalf("labels03[0x30000] = %q, %v", labels03[0x30000], err)
	}

	// 5. DeleteCodeCells in eff11 must NOT delete eff03_t2's code cells
	db.SetSpaceSegs(spaceEff11)
	db.SetActiveSeg("eff11_t97")
	_ = db.DeleteCodeCells()
	if c, _ := db.GetCell(0x30000); c != nil {
		t.Errorf("expected eff11 code cell deleted")
	}

	db.SetSpaceSegs(spaceEff03)
	db.SetActiveSeg("eff03_t2")
	if c, _ := db.GetCell(0x30000); c == nil {
		t.Errorf("eff03 code cell at $30000 should survive eff11 DeleteCodeCells")
	}
	if c, _ := db.GetCell(0x30854); c == nil {
		t.Errorf("eff03 code cell at $30854 should survive eff11 DeleteCodeCells")
	}

	// 6. DeleteSegment("eff11_t97") removes eff11_t97 without touching eff03_t2
	if err := db.DeleteSegment("eff11_t97"); err != nil {
		t.Fatal(err)
	}
	ren, ok, err := db.GetRename("LAB_30000")
	if err != nil || !ok || ren != "Eff03_Entry" {
		t.Errorf("GetRename(LAB_30000) in eff03 = %q, %v, %v", ren, ok, err)
	}
}

func TestCommentsTableDedupAndLifecycle(t *testing.T) {
	db, err := New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// 1. AppendAutoComment deduplicates '; '-separated fragments idempotently
	_ = db.AppendAutoComment(0x1000, "150(a2) = DMACON")
	_ = db.AppendAutoComment(0x1000, "150(a2) = DMACON")
	_ = db.AppendAutoComment(0x1000, "-> LAB_2000 (observed)")
	_ = db.AppendAutoComment(0x1000, "150(a2) = DMACON")
	ac := db.GetAddressComment(0x1000)
	wantAuto := "150(a2) = DMACON; -> LAB_2000 (observed)"
	if ac.AutoComment != wantAuto {
		t.Fatalf("AutoComment = %q, want %q", ac.AutoComment, wantAuto)
	}
	if ac.EffectiveComment() != wantAuto {
		t.Fatalf("EffectiveComment() = %q, want %q", ac.EffectiveComment(), wantAuto)
	}

	// 2. User comment combines with AutoComment in EffectiveComment()
	_ = db.UpdateComment(0x1000, "Enable DMA")
	_ = db.UpdateBlockComment(0x1000, "Header doc")
	ac = db.GetAddressComment(0x1000)
	if ac.EffectiveComment() != "Enable DMA; "+wantAuto || ac.BlockComment != "Header doc" {
		t.Fatalf("after user comment: %+v", ac)
	}

	// 3. ClearOverlaps clears auto_comment but preserves user comment and block_comment
	_ = db.ClearOverlaps(0x1000, 4)
	ac = db.GetAddressComment(0x1000)
	if ac.AutoComment != "" || ac.Comment != "Enable DMA" || ac.BlockComment != "Header doc" {
		t.Fatalf("after ClearOverlaps: %+v", ac)
	}

	// 4. Clearing user comment and block comment removes the empty row
	_ = db.UpdateComment(0x1000, "")
	_ = db.UpdateBlockComment(0x1000, "")
	m, err := db.GetCommentsInRange(0x1000, 0x1010)
	if err != nil || len(m) != 0 {
		t.Fatalf("expected empty comments map after clearing all fields, got %+v, %v", m, err)
	}
}
