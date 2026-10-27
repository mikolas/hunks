package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mikolas/hunks/internal/analyzer"
	"github.com/mikolas/hunks/internal/callgraph"
	"github.com/mikolas/hunks/internal/db"
	"github.com/mikolas/hunks/internal/hunk"
	"github.com/mikolas/hunks/internal/project"
)

func TestAgentWorkflowCommands(t *testing.T) {
	tmpDir := t.TempDir()
	// 0x10000: move.w $1034.w,d0   30 38 10 34
	// 0x10004: muls.w d1,d0        C1 C1
	// 0x10006: divs.w d2,d0        81 C2
	// 0x10008: muls.w d3,d0        C1 C3
	// 0x1000A: rts                 4E 75
	// 0x1000C: Copper list:
	//   0x0180, 0x0000 ->dc.w $0180,$0000 (MOVE #$0000 -> COLOR00)
	//   0xFFDF, 0xFFFE ->dc.w $FFDF,$FFFE (WAIT v=255, h=222)
	//   0xFFFF, 0xFFFE ->dc.w $FFFF,$FFFE (END)
	raw := []byte{
		0x30, 0x38, 0x10, 0x34,
		0xC1, 0xC1,
		0x81, 0xC2,
		0xC1, 0xC3,
		0x4E, 0x75,
		0x01, 0x80, 0x00, 0x00,
		0xFF, 0xDF, 0xFF, 0xFE,
		0xFF, 0xFF, 0xFF, 0xFE,
	}
	binPath := filepath.Join(tmpDir, "seg.bin")
	if err := os.WriteFile(binPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(tmpDir, "seg.db")
	ctrl, err := db.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.Close()

	proj := project.New(filepath.Join(tmpDir, "project.json"))
	proj.Data.TargetName = "test_mod"
	proj.Data.Segments = []project.Segment{
		{
			Name:        "main",
			HunkIndex:   0,
			HunkType:    hunk.HunkTypeCode,
			MemoryType:  hunk.MemoryPublic,
			AllocSize:   uint32(len(raw)),
			File:        &binPath,
			Base:        0x10000,
			DB:          dbPath,
			Relocatable: false,
		},
	}
	proj.Data.Spaces = []project.Space{{Name: "default", Segments: []string{"main"}}}
	proj.Data.ActiveSpace = "default"
	proj.Data.EntryPoints = []project.EntryPoint{{Addr: 0x10000, Name: "MathKernel", Segment: "main"}}
	proj.Data.Structs = map[string]map[string]string{
		"CopMove": {
			"0":     "reg.w",
			"2":     "val.w",
			"_size": "4",
		},
	}

	an, err := analyzer.New(proj, ctrl)
	if err != nil {
		t.Fatal(err)
	}
	an.Analyze([]uint32{0x10000})
	_ = ctrl.SetLabel(0x10000, "MathKernel", db.LabelLab, false)
	_ = ctrl.UpdateComment(0x10004, "scale X")
	_ = ctrl.UpdateBlockComment(0x10000, "3D math kernel")

	cg, err := callgraph.Build(proj)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Test `xref` single address & range
	xrefSingle, err := runXrefCommand(proj, ctrl, cg, "0x1034", "text")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(xrefSingle, "[MathKernel+0]") || !strings.Contains(xrefSingle, "READ") {
		t.Fatalf("unexpected xref single output:\n%s", xrefSingle)
	}
	xrefRange, err := runXrefCommand(proj, ctrl, cg, "$1000..$1100", "json")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(xrefRange, "\"0x1034\"") {
		t.Fatalf("unexpected xref range json output:\n%s", xrefRange)
	}

	// 2. Test `data --copper`, `data --struct`, and out-of-segment error
	if _, err := renderDataInspection(proj, ctrl, cg, 0x6B6E, 16, false, "", 1, "text"); err == nil {
		t.Fatalf("expected out-of-segment data 0x6B6E to return an error")
	}
	copOut, err := renderDataInspection(proj, ctrl, cg, 0x1000C, 12, true, "", 1, "text")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(copOut, "MOVE $0000 -> COLOR00") || !strings.Contains(copOut, "End of Copperlist") {
		t.Fatalf("unexpected copper decode output:\n%s", copOut)
	}
	structOut, err := renderDataInspection(proj, ctrl, cg, 0x1000C, 12, false, "CopMove", 2, "text")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(structOut, "reg") || !strings.Contains(structOut, "$0180") {
		t.Fatalf("unexpected struct decode output:\n%s", structOut)
	}
	if got := formatFnOffset(0x464A8, 0x465E6); got != "-13E" {
		t.Fatalf("expected formatFnOffset(0x464A8, 0x465E6) == \"-13E\", got %q", got)
	}
	if warns := callgraph.VerifyABI("(d0=bogus) -> void", []string{"d1", "d2", "d3"}, []string{"d0"}, nil); len(warns) == 0 {
		t.Fatalf("expected VerifyABI to warn when claimed input d0 is overwritten before being read")
	}

	// 3. Test `resolveStrictCommentAddr`
	resolvedAddr, note, err := resolveStrictCommentAddr(proj, ctrl, cg, "MathKernel+4")
	if err != nil || resolvedAddr != 0x10004 || note != "" {
		t.Fatalf("expected MathKernel+4 -> (0x10004, \"\"), got (%#x, %q, %v)", resolvedAddr, note, err)
	}
	if _, _, err := resolveStrictCommentAddr(proj, ctrl, cg, "MathKernel+2"); err == nil {
		t.Fatalf("expected misaligned offset MathKernel+2 (inside 4-byte move.w) to return an error")
	}

	// 4. Test `dump` JSON
	dumpJSON, err := runDumpCommand(proj, "", "json")
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(dumpJSON), &parsed); err != nil {
		t.Fatalf("invalid dump JSON: %v\n%s", err, dumpJSON)
	}
	if parsed["target_name"] != "test_mod" {
		t.Fatalf("unexpected target_name in dump: %v", parsed["target_name"])
	}
	if !strings.Contains(dumpJSON, "\"scale X\"") || !strings.Contains(dumpJSON, "\"3D math kernel\"") {
		t.Fatalf("expected user comments in dump JSON:\n%s", dumpJSON)
	}
}
