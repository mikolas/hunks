package analyzer

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/mikolas/hunks/internal/amiga"
	"github.com/mikolas/hunks/internal/db"
	"github.com/mikolas/hunks/internal/hunk"
	"github.com/mikolas/hunks/internal/project"
)

func TestSeedFromSnapshotAndTraceResume(t *testing.T) {
	tmpDir := t.TempDir()
	chipBytes := make([]byte, 0x4000)
	slowBytes := make([]byte, 0x2000)

	// Zero-page Level 3 Interrupt vector ($6C) -> 0x00000400
	binary.BigEndian.PutUint32(chipBytes[0x6C:], 0x00000400)
	// Level 3 handler at 0x0400: move.w #$0020,$DFF09C (INTREQ); rte
	copy(chipBytes[0x0400:], []byte{
		0x33, 0xFC, 0x00, 0x20, 0x00, 0xDF, 0xF0, 0x9C,
		0x4E, 0x73,
	})

	// Caller in Chip RAM at 0x0200: bsr.w 0x0300 (6100 00FE); rts (4E75) at 0x0204
	copy(chipBytes[0x0200:], []byte{0x61, 0x00, 0x00, 0xFE, 0x4E, 0x75})

	// Paused PC at 0x0300: jsr (a2) (where a2 = 0xC00100 in Slow RAM!); rts
	copy(chipBytes[0x0300:], []byte{0x4E, 0x92, 0x4E, 0x75})

	// Target in Slow RAM ($C00100): move.w #$0020,$9C(a5) (where a5 = $DFF000); rts
	copy(slowBytes[0x0100:], []byte{0x3B, 0x7C, 0x00, 0x20, 0x00, 0x9C, 0x4E, 0x75})

	// Stack at A7 = 0x3F00 holds return address 0x00000204 (right after bsr.w at 0x0200)
	binary.BigEndian.PutUint32(chipBytes[0x3F00:], 0x00000204)

	var customSnap amiga.CustomSnapshot
	binary.BigEndian.PutUint16(customSnap[0x096:], 0x03E0) // DMACON
	binary.BigEndian.PutUint16(customSnap[0x09A:], 0x4020) // INTENA: MASTER | VERTB
	binary.BigEndian.PutUint32(customSnap[0x080:], 0x00001000)
	binary.BigEndian.PutUint16(customSnap[0x100:], 0x1200) // 1 plane
	binary.BigEndian.PutUint32(customSnap[0x0E0:], 0x00002000)

	chipFile := filepath.Join(tmpDir, "chip.bin")
	slowFile := filepath.Join(tmpDir, "slow.bin")
	customFile := filepath.Join(tmpDir, "custom.bin")
	if err := os.WriteFile(chipFile, chipBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(slowFile, slowBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(customFile, customSnap[:], 0o644); err != nil {
		t.Fatal(err)
	}

	dbPath := filepath.Join(tmpDir, "project.db")
	ctrl, err := db.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.Close()

	proj := project.New(filepath.Join(tmpDir, "project.json"))
	chipLen := uint32(len(chipBytes))
	slowLen := uint32(len(slowBytes))
	proj.Data.Segments = []project.Segment{
		{
			Name:        "chip",
			HunkIndex:   0,
			HunkType:    hunk.HunkTypeCode,
			MemoryType:  hunk.MemoryChip,
			AllocSize:   chipLen,
			FileDataLen: &chipLen,
			File:        &chipFile,
			Base:        0x000000,
			DB:          dbPath,
			Relocatable: false,
		},
		{
			Name:        "slow",
			HunkIndex:   1,
			HunkType:    hunk.HunkTypeCode,
			MemoryType:  hunk.MemoryFast,
			AllocSize:   slowLen,
			FileDataLen: &slowLen,
			File:        &slowFile,
			Base:        0xC00000,
			DB:          dbPath,
			Relocatable: false,
		},
	}
	proj.Data.Spaces = []project.Space{{Name: "default", Segments: []string{"chip", "slow"}}}
	proj.Data.ActiveSpace = "default"
	proj.Data.Snapshot = &project.SnapshotState{
		PC:         0x00000300,
		SR:         0x2000,
		A:          [8]uint32{0, 0, 0x00C00100, 0, 0, 0x00DFF000, 0, 0x00003F00},
		CustomFile: "custom.bin",
	}
	proj.SyncDBScope(ctrl)

	summary := SeedFromSnapshot(proj, ctrl)
	if summary.EntryPC != 0x00000300 {
		t.Fatalf("expected EntryPC 0x300, got 0x%X", summary.EntryPC)
	}
	if len(summary.VectorSeeds) != 1 {
		t.Fatalf("expected 1 vector seed, got %v", summary.VectorSeeds)
	}
	if len(summary.StackSeeds) != 1 || summary.StackSeeds[0] != 0x00000204 {
		t.Fatalf("expected stack seed 0x204, got %v", summary.StackSeeds)
	}
	if len(summary.BaseRegHints) != 1 || summary.BaseRegHints[0] != "a5=0xDFF000" {
		t.Fatalf("expected a5=0xDFF000 base reg hint, got %v", summary.BaseRegHints)
	}
	if len(summary.CustomLabels) != 2 {
		t.Fatalf("expected CopperList_1 and Bitplane_1 labels, got %v", summary.CustomLabels)
	}

	opts := DefaultTraceOptions()
	opts.Budget = 500
	opts.Snapshot = proj.Data.Snapshot
	opts.CustomSnap = &customSnap
	opts.Segments = []TraceSegment{
		{Base: 0x000000, Data: chipBytes},
		{Base: 0xC00000, Data: slowBytes},
	}
	report := RunTrace(chipBytes, 0, 0x0300, opts)
	if len(report.Sites) == 0 {
		t.Fatalf("expected indirect jsr (a2) at 0x300 to be recorded in trace sites")
	}
	if report.Sites[0].Targets[0x00C00100] == 0 {
		t.Fatalf("expected jsr (a2) to resolve to 0x00C00100 in Slow RAM, got %v", report.Sites[0].Targets)
	}
}
