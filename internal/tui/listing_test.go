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

func TestBuildListingRowsSubRowOrderXrefsCoalescingAndPriority(t *testing.T) {
	tmp := t.TempDir()
	binPath := filepath.Join(tmp, "main.bin")

	// Layout (base $1000, 48 bytes = $1000..$1030):
	// $1000 (4B): 61 00 00 04 -> bsr.w LAB_01006
	// $1004 (2B): 4E 75       -> rts
	// $1006 (6B): 13 FC 00 FF 00 00 10 10 (wait: 23 C0 00 00 10 10 = move.l d0,$1010.l, 6B)
	// $100C (2B): 4E 75       -> rts
	// $100E (2B): 00 00       -> ConfLow filler (2B)
	// $1010 (16B): "TEST" + 12 binary bytes -> ConfLow filler (coalesced into 16-byte dc.b at $1010 because $1010 has label/xref!)
	// $1020 (4B): 00 00 10 06 -> CellPointer to $1006
	// $1024 (12B): "Hello Amiga\x00" -> CellStr (12B)
	bin := make([]byte, 0x30)
	copy(bin[0x00:], []byte{0x61, 0x00, 0x00, 0x04})             // $1000: bsr.w $1006
	copy(bin[0x04:], []byte{0x4E, 0x75})                         // $1004: rts
	copy(bin[0x06:], []byte{0x23, 0xC0, 0x00, 0x00, 0x10, 0x10}) // $1006: move.l d0,$1010.l
	copy(bin[0x0C:], []byte{0x4E, 0x75})                         // $100C: rts
	copy(bin[0x0E:], []byte{0xAA, 0xBB})                         // $100E: 2 filler bytes
	copy(bin[0x10:], []byte("TEST\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B"))
	copy(bin[0x20:], []byte{0x00, 0x00, 0x10, 0x06}) // $1020: pointer to $1006
	copy(bin[0x24:], []byte("Hello Amiga\x00"))      // $1024: CellStr

	if err := os.WriteFile(binPath, bin, 0o644); err != nil {
		t.Fatal(err)
	}

	proj := project.New(filepath.Join(tmp, "project.json"))
	proj.Data.Segments = append(proj.Data.Segments, project.Segment{
		Name:        "main",
		HunkIndex:   0,
		HunkType:    hunk.HunkTypeCode,
		MemoryType:  hunk.MemoryPublic,
		AllocSize:   uint32(len(bin)),
		File:        &binPath,
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
	defer ctrl.Close()
	proj.SyncDBScope(ctrl)

	// Insert CODE cells at $1000, $1004, $1006, $100C
	_ = ctrl.InsertCell(&db.Cell{
		Addr: 0x1000, Size: 4, Type: db.CellCode, Confidence: 0,
		Mnemonic: db.StrPtr("bsr.w"), OpStr: db.StrPtr("SubTarget"),
		RawBytes: bin[0x00:0x04],
	})
	_ = ctrl.InsertCell(&db.Cell{
		Addr: 0x1004, Size: 2, Type: db.CellCode, Confidence: 0,
		Mnemonic: db.StrPtr("rts"), RawBytes: bin[0x04:0x06],
	})
	_ = ctrl.InsertCell(&db.Cell{
		Addr: 0x1006, Size: 6, Type: db.CellCode, Confidence: 0,
		Mnemonic: db.StrPtr("move.l"), OpStr: db.StrPtr("d0,LAB_01010.l"),
		RawBytes: bin[0x06:0x0C],
	})
	_ = ctrl.InsertCell(&db.Cell{
		Addr: 0x100C, Size: 2, Type: db.CellCode, Confidence: 0,
		Mnemonic: db.StrPtr("rts"), RawBytes: bin[0x0C:0x0E],
	})

	// Insert Stage 3 ConfLow filler cells at $100E..$1020 (must coalesce at runtime!)
	_ = ctrl.InsertCell(&db.Cell{
		Addr: 0x100E, Size: 2, Type: db.CellDataW, Confidence: 3,
		RawBytes: bin[0x0E:0x10],
	})
	for off := uint32(0x1010); off < 0x1020; off += 4 {
		_ = ctrl.InsertCell(&db.Cell{
			Addr: off, Size: 4, Type: db.CellDataL, Confidence: 3,
			RawBytes: bin[off-0x1000 : off-0x1000+4],
		})
	}

	// Insert explicit CellPointer at $1020 and CellStr at $1024
	_ = ctrl.InsertCell(&db.Cell{
		Addr: 0x1020, Size: 4, Type: db.CellPointer, Confidence: 1,
		RawBytes: bin[0x20:0x24],
	})
	_ = ctrl.InsertCell(&db.Cell{
		Addr: 0x1024, Size: 12, Type: db.CellStr, Confidence: 2,
		RawBytes: bin[0x24:0x30],
	})

	// Labels, edges, xrefs, and comments
	_ = ctrl.SetLabel(0x1000, "Entry", db.LabelFun, false)
	_ = ctrl.SetLabel(0x1006, "SubTarget", db.LabelFun, false)
	_ = ctrl.SetLabel(0x1010, "LAB_01010", db.LabelDat, true)
	_ = ctrl.SetLabel(0x1020, "PtrTable", db.LabelDat, false)
	_ = ctrl.SetLabel(0x1024, "StrHello", db.LabelDat, false)

	_ = ctrl.InsertEdge(0x1000, 0x1006, db.EdgeCall)
	_ = ctrl.InsertXref(0x1000, 0x1006, db.XrefCodeCall)
	_ = ctrl.InsertXref(0x1020, 0x1006, db.XrefDataAddr)
	_ = ctrl.InsertXref(0x1006, 0x1010, db.XrefDataWrite)

	// SubTarget ($1006) has a BlockComment -> $1000 (bsr.w SubTarget) should echo it as Priority 2 (CommentStyleRef)!
	_ = ctrl.UpdateBlockComment(0x1006, "Writes D0 into LAB_01010\nSecond line of doc")
	// $1006 has both an AutoComment and a User Comment -> Priority 1 (CommentStyleUser) wins on $1006
	_ = ctrl.AppendAutoComment(0x1006, "auto note")
	_ = ctrl.UpdateComment(0x1006, "user override")
	// $1004 has only an AutoComment -> Priority 3 (CommentStyleAuto)
	_ = ctrl.AppendAutoComment(0x1004, "return to caller")
	// $1024 (CellStr) has a Comment -> routed to SubRowBlockComment above the string, NO EOL comment on SubRowString!
	_ = ctrl.UpdateComment(0x1024, "Greeting banner")

	seg := proj.CurrentSegment()
	rows, codeBytes, err := BuildListingRows(proj, ctrl, seg, 120)
	if err != nil {
		t.Fatalf("BuildListingRows failed: %v", err)
	}
	if codeBytes != 14 {
		t.Fatalf("codeBytes = %d, want 14", codeBytes)
	}

	// 1. Verify sub-row sequence at $1006: SubRowBlockComment (2 lines) -> SubRowLabel ("SubTarget:" with inline Xrefs) -> SubRowCode
	var sub1006 []ListingRow
	for _, r := range rows {
		if r.Addr != nil && *r.Addr == 0x1006 {
			sub1006 = append(sub1006, r)
		}
	}
	if len(sub1006) != 4 {
		t.Fatalf("expected 4 sub-rows at $1006, got %d: %+v", len(sub1006), sub1006)
	}
	if sub1006[0].Kind != SubRowBlockComment || sub1006[0].Comment != "Writes D0 into LAB_01010" ||
		sub1006[1].Kind != SubRowBlockComment || sub1006[1].Comment != "Second line of doc" {
		t.Fatalf("unexpected block comment sub-rows at $1006: %+v", sub1006[:2])
	}
	if sub1006[2].Kind != SubRowLabel || sub1006[2].Label != "SubTarget:" || sub1006[2].XrefTotal != 2 || len(sub1006[2].Xrefs) != 2 {
		t.Fatalf("expected SubRowLabel 'SubTarget:' with 2 XrefBadges at $1006, got %+v", sub1006[2])
	}
	if sub1006[2].Xrefs[0].Text != "Entry:1000(bsr.w)" || sub1006[2].Xrefs[1].Text != "PtrTable:1020(*)" {
		t.Fatalf("unexpected XrefBadges at $1006: %+v", sub1006[2].Xrefs)
	}
	if sub1006[3].Kind != SubRowCode || !sub1006[3].IsPrimary || sub1006[3].Operands != "d0,LAB_01010.l" || sub1006[3].CommentStyle != CommentStyleUser || sub1006[3].Comment != "user override" {
		t.Fatalf("unexpected SubRowCode at $1006: %+v", sub1006[3])
	}

	// 2. Verify 3-tier comment priority on $1000 (CommentStyleRef echoing $1006's BlockComment) and $1004 (CommentStyleAuto)
	var row1000, row1004 *ListingRow
	for i := range rows {
		if rows[i].Addr != nil && *rows[i].Addr == 0x1000 && rows[i].IsPrimary {
			row1000 = &rows[i]
		}
		if rows[i].Addr != nil && *rows[i].Addr == 0x1004 && rows[i].IsPrimary {
			row1004 = &rows[i]
		}
	}
	if row1000 == nil || row1000.CommentStyle != CommentStyleRef || row1000.Comment != "Writes D0 into LAB_01010" {
		t.Fatalf("$1000 expected CommentStyleRef 'Writes D0 into LAB_01010', got %+v", row1000)
	}
	if row1004 == nil || row1004.CommentStyle != CommentStyleAuto || row1004.Comment != "return to caller" {
		t.Fatalf("$1004 expected CommentStyleAuto 'return to caller', got %+v", row1004)
	}

	// 3. Verify ConfLow filler cells at $100E (2B before split at $1010) and $1010 (16B coalesced dc.b with (W) xref and "TEST" run mask)
	var sub1010 []ListingRow
	for _, r := range rows {
		if r.Addr != nil && *r.Addr == 0x1010 {
			sub1010 = append(sub1010, r)
		}
	}
	if len(sub1010) != 2 { // SubRowLabel (with inline Xrefs) + SubRowData (16B)
		t.Fatalf("expected 2 sub-rows at $1010, got %d: %+v", len(sub1010), sub1010)
	}
	if sub1010[0].Kind != SubRowLabel || len(sub1010[0].Xrefs) != 1 || sub1010[0].Xrefs[0].Text != "SubTarget:1006(W)" {
		t.Fatalf("expected SubTarget:1006(W) xref on SubRowLabel at $1010, got %+v", sub1010[0])
	}
	data1010 := sub1010[1]
	if data1010.Kind != SubRowData || data1010.Mnem != "dc.b" || data1010.Size != 16 {
		t.Fatalf("expected 16-byte coalesced dc.b SubRowData at $1010, got %+v", data1010)
	}
	if !strings.HasPrefix(data1010.ASCIIBox, "│TEST............│") {
		t.Fatalf("expected ASCIIBox '│TEST............│', got %q", data1010.ASCIIBox)
	}
	if data1010.PrintableRunMask != 0x000F {
		t.Fatalf("expected PrintableRunMask 0x000F for 4-char 'TEST' prefix, got 0x%04X", data1010.PrintableRunMask)
	}

	// 4. Verify CellStr at $1024: SubRowBlockComment ("Greeting banner") -> SubRowLabel ("StrHello:") -> SubRowString (`"Hello Amiga",0`), with NO hex bytes, NO ASCIIBox, NO EOL comment
	var sub1024 []ListingRow
	for _, r := range rows {
		if r.Addr != nil && *r.Addr == 0x1024 {
			sub1024 = append(sub1024, r)
		}
	}
	if len(sub1024) != 3 {
		t.Fatalf("expected 3 sub-rows at $1024, got %d: %+v", len(sub1024), sub1024)
	}
	if sub1024[0].Kind != SubRowBlockComment || sub1024[0].Comment != "Greeting banner" {
		t.Fatalf("expected comment routed to SubRowBlockComment above string, got %+v", sub1024[0])
	}
	strRow := sub1024[2]
	if strRow.Kind != SubRowString || strRow.Mnem != "dc.b" || strRow.Operands != `"Hello Amiga",0` ||
		len(strRow.RawBytes) != 0 || strRow.ASCIIBox != "" || strRow.Comment != "" {
		t.Fatalf("unexpected SubRowString at $1024: %+v", strRow)
	}

	// 5. Verify FunctionABI header row at $1006 and call-site [ABI: ...] hint at $1000
	_ = ctrl.InsertFunction(0x1006, "SubTarget", 0)
	proj.SetFunctionABI("SubTarget", "(d0.l=val) -> void")
	rowsABI, _, err := BuildListingRows(proj, ctrl, seg, 120)
	if err != nil {
		t.Fatalf("BuildListingRows with ABI failed: %v", err)
	}
	var foundABIHeader, foundCallABI bool
	for _, r := range rowsABI {
		if r.Addr != nil && *r.Addr == 0x1006 && r.Kind == SubRowBlockComment && strings.Contains(r.Comment, "ABI: (d0.l=val) -> void") {
			foundABIHeader = true
		}
		if r.Addr != nil && *r.Addr == 0x1000 && r.IsPrimary && strings.Contains(r.Comment, "[ABI: (d0.l=val) -> void]") {
			foundCallABI = true
		}
	}
	if !foundABIHeader || !foundCallABI {
		t.Fatalf("expected ABI header at $1006 (%v) and call-site ABI at $1000 (%v)", foundABIHeader, foundCallABI)
	}
}
