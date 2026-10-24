package project

import (
	"path/filepath"
	"testing"

	"github.com/mikolas/hunks/internal/hunk"
)

func TestDeduceTargetName(t *testing.T) {
	cases := map[string]string{
		"assets/frontier":      "frontier",
		"assets/intro.exe":     "intro",
		"assets/bootblock.bin": "bootblock",
		"assets/Game.slave":    "Game",
		"assets/Disk.1":        "Disk_1",
		"assets/Disk.2":        "Disk_2",
	}
	for input, want := range cases {
		if got := DeduceTargetName(input); got != want {
			t.Errorf("DeduceTargetName(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestSharedDBUnifiesSegmentTopology(t *testing.T) {
	proj := New("/tmp/test_shared_db.json")
	if got := proj.SharedDB(); got != "project.db" {
		t.Fatalf("SharedDB() on empty project = %q, want project.db", got)
	}

	proj.Data.Segments = append(proj.Data.Segments, Segment{
		Name:        "hunk0",
		HunkIndex:   0,
		HunkType:    hunk.HunkTypeCode,
		MemoryType:  hunk.MemoryPublic,
		Base:        0,
		DB:          "project.db",
		Relocatable: true,
	})
	if got := proj.SharedDB(); got != "project.db" {
		t.Fatalf("SharedDB() = %q, want project.db", got)
	}

	shared := proj.SharedDB()
	proj.Data.Segments = append(proj.Data.Segments, Segment{
		Name:        "extra",
		HunkIndex:   1,
		HunkType:    hunk.HunkTypeCode,
		MemoryType:  hunk.MemoryPublic,
		Base:        0x10000,
		DB:          shared,
		Relocatable: false,
	})
	for i, s := range proj.Data.Segments {
		if s.DB != "project.db" {
			t.Errorf("segment %d DB = %q, want project.db", i, s.DB)
		}
	}
}

func TestSaveLoadRoundtrip(t *testing.T) {
	tmpDir := t.TempDir()
	projFile := filepath.Join(tmpDir, "project.json")

	p := New(projFile)
	p.Data.TargetName = "frontier"
	p.Data.ActiveSpace = "default"
	p.Data.Output = "disasm/frontier.asm"
	f := "work/frontier/hunk0.bin"
	p.Data.Segments = []Segment{
		{
			Name:        "hunk0",
			HunkIndex:   0,
			HunkType:    hunk.HunkTypeCode,
			MemoryType:  hunk.MemoryPublic,
			AllocSize:   116,
			File:        &f,
			Base:        0,
			DB:          "project.db",
			Relocatable: true,
		},
	}
	p.Data.Spaces = []Space{{Name: "default", Segments: []string{"hunk0"}}}
	p.Data.EntryPoints = []EntryPoint{{Addr: 0, Name: "_start", Segment: "hunk0"}}

	if err := p.Save(); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	p2 := New(projFile)
	if err := p2.Load(); err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if p2.Data.TargetName != "frontier" || len(p2.Data.Segments) != 1 || p2.Data.Segments[0].AllocSize != 116 {
		t.Errorf("loaded project mismatch: %+v", p2.Data)
	}
}
