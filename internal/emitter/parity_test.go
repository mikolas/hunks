package emitter

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"github.com/mikolas/hunks/internal/analyzer"
	"github.com/mikolas/hunks/internal/db"
	"github.com/mikolas/hunks/internal/hunk"
	"github.com/mikolas/hunks/internal/project"
)

func buildSyntheticHunkExecutable() []byte {
	var raw []byte
	push := func(val uint32) {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], val)
		raw = append(raw, buf[:]...)
	}

	// HUNK_HEADER: 3 hunks (CODE public 28B, DATA chip 8B on disk / 16B alloc, BSS chip 32B)
	push(hunk.HunkHeader)
	push(0)              // resident libs
	push(3)              // table_size = 3
	push(0)              // first_hunk = 0
	push(2)              // last_hunk = 2
	push(7)              // hunk0: 7 longs (28B) CODE public
	push((1 << 30) | 4)  // hunk1: 4 longs (16B alloc) DATA chip
	push((1 << 30) | 8)  // hunk2: 8 longs (32B alloc) BSS chip

	// Hunk 0: CODE (28 bytes = 7 longs)
	//   +0x00: 48 E7 40 20          movem.l d1/a2,-(a7)
	//   +0x04: 45 F9 00 00 00 04    lea.l   LAB_1_00004.l,a2   (reloc -> hunk 1 +0x04)
	//   +0x0A: 23 C8 00 00 00 08    move.l  a0,LAB_2_00008.l   (reloc -> hunk 2 +0x08)
	//   +0x10: 4E B9 00 00 00 1A    jsr     LAB_0_0001A.l      (reloc -> hunk 0 +0x1A)
	//   +0x16: 4C DF 04 02          movem.l (a7)+,d1/a2
	//   +0x1A: 4E 75                rts
	codeBytes := []byte{
		0x48, 0xE7, 0x40, 0x20,
		0x45, 0xF9, 0x00, 0x00, 0x00, 0x04,
		0x23, 0xC8, 0x00, 0x00, 0x00, 0x08,
		0x4E, 0xB9, 0x00, 0x00, 0x00, 0x1A,
		0x4C, 0xDF, 0x04, 0x02,
		0x4E, 0x75,
	}
	push(hunk.HunkCode)
	push(uint32(len(codeBytes) / 4))
	raw = append(raw, codeBytes...)

	push(hunk.HunkReloc32)
	push(1)    // 1 offset to hunk 0
	push(0)    // target hunk 0
	push(0x12) // site +0x12
	push(1)    // 1 offset to hunk 1
	push(1)    // target hunk 1
	push(0x06) // site +0x06
	push(1)    // 1 offset to hunk 2
	push(2)    // target hunk 2
	push(0x0C) // site +0x0C
	push(0)    // end relocs
	push(hunk.HunkEnd)

	// Hunk 1: DATA (2 longs = 8B on disk, 4 longs = 16B alloc -> 8B DataBss tail)
	push(hunk.HunkData)
	push(2)
	push(0x12345678)
	push(0x9ABCDEF0)
	push(hunk.HunkEnd)

	// Hunk 2: BSS (8 longs = 32B)
	push(hunk.HunkBss)
	push(8)
	push(hunk.HunkEnd)

	return raw
}

func initHunkProjectForTest(t *testing.T, workDir, targetName, hunkFilePath string) (*project.Project, *db.Controller) {
	t.Helper()
	rawBytes, err := os.ReadFile(hunkFilePath)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := hunk.ParseHunkFile(rawBytes)
	if err != nil {
		t.Fatal(err)
	}
	bases := parsed.CalculateSyntheticBases()

	relocatedData := make([][]byte, len(parsed.Hunks))
	for i, h := range parsed.Hunks {
		relocatedData[i] = slices.Clone(h.Data)
	}
	for _, h := range parsed.Hunks {
		srcIdx := h.Index - parsed.FirstHunk
		for _, reloc := range h.Reloc32 {
			tgtLocal := reloc.TargetHunk - parsed.FirstHunk
			if tgtLocal < 0 || tgtLocal >= len(bases) {
				continue
			}
			tgtBase := bases[tgtLocal]
			for _, offset := range reloc.Offsets {
				off := int(offset)
				if srcIdx >= 0 && srcIdx < len(relocatedData) && off+4 <= len(relocatedData[srcIdx]) {
					initialVal := binary.BigEndian.Uint32(relocatedData[srcIdx][off : off+4])
					syntheticVal := tgtBase + initialVal
					binary.BigEndian.PutUint32(relocatedData[srcIdx][off:off+4], syntheticVal)
				}
			}
		}
	}

	dbPath := filepath.Join(workDir, "project.db")
	ctrl, err := db.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}

	proj := project.New(filepath.Join(workDir, "project.json"))
	proj.WorkspaceRoot = workDir
	proj.Data.TargetName = targetName
	proj.Data.Output = fmt.Sprintf("disasm/%s.asm", targetName)

	var spaceSegNames []string
	for _, h := range parsed.Hunks {
		segName := fmt.Sprintf("hunk%d", h.Index)
		spaceSegNames = append(spaceSegNames, segName)
		var binFile *string
		if h.HunkType != hunk.HunkTypeBss {
			filename := filepath.Join(workDir, fmt.Sprintf("%s.bin", segName))
			local := h.Index - parsed.FirstHunk
			slice := relocatedData[local]
			if h.FileDataLen < len(slice) {
				slice = slice[:h.FileDataLen]
			}
			if err := os.WriteFile(filename, slice, 0o644); err != nil {
				t.Fatal(err)
			}
			binFile = &filename
		}
		fdl := uint32(h.FileDataLen)
		var base uint32
		if local := h.Index - parsed.FirstHunk; local >= 0 && local < len(bases) {
			base = bases[local]
		}
		proj.Data.Segments = append(proj.Data.Segments, project.Segment{
			Name:        segName,
			HunkIndex:   h.Index,
			HunkType:    h.HunkType,
			MemoryType:  h.MemoryType,
			AllocSize:   h.AllocSize,
			FileDataLen: &fdl,
			File:        binFile,
			Base:        base,
			DB:          dbPath,
			Relocatable: true,
		})
	}

	proj.Data.Spaces = append(proj.Data.Spaces, project.Space{
		Name:     "default",
		Segments: spaceSegNames,
	})
	proj.Data.ActiveSpace = "default"
	proj.SyncDBScope(ctrl)

	ctrl.Begin()

	for _, h := range parsed.Hunks {
		if h.HunkType == hunk.HunkTypeCode {
			segName := fmt.Sprintf("hunk%d", h.Index)
			base := bases[h.Index-parsed.FirstHunk]
			if len(h.Data) >= 2 && h.Index == 0 {
				epName := fmt.Sprintf("LAB_%d_%05X", h.Index, 0)
				proj.Data.EntryPoints = append(proj.Data.EntryPoints, project.EntryPoint{
					Addr:    base,
					Name:    epName,
					Segment: segName,
				})
				_ = ctrl.SetLabel(base, epName, db.LabelLab, true)
			}
		}
	}

	for _, h := range parsed.Hunks {
		srcIdx := h.Index
		srcLocal := srcIdx - parsed.FirstHunk
		if srcLocal < 0 || srcLocal >= len(bases) {
			continue
		}
		srcBase := bases[srcLocal]

		for _, reloc := range h.Reloc32 {
			tgtIdx := reloc.TargetHunk
			tgtLocal := tgtIdx - parsed.FirstHunk
			if tgtLocal < 0 || tgtLocal >= len(bases) {
				continue
			}
			tgtBase := bases[tgtLocal]
			isCrossHunk := srcIdx != tgtIdx

			for _, offset := range reloc.Offsets {
				off := int(offset)
				if off+4 <= len(h.Data) {
					initialVal := binary.BigEndian.Uint32(h.Data[off : off+4])
					srcAddr := srcBase + offset
					targetAddr := tgtBase + initialVal
					labelName := fmt.Sprintf("LAB_%d_%05X", tgtIdx, initialVal)

					_ = ctrl.InsertReloc(srcAddr, targetAddr)
					if _, exists, _ := ctrl.GetLabel(targetAddr); !exists {
						_ = ctrl.SetLabel(targetAddr, labelName, db.LabelLab, true)
					}
					if isCrossHunk {
						_ = ctrl.MarkExported(targetAddr)
					}
					_ = ctrl.InsertXref(srcAddr, targetAddr, db.XrefDataAddr)
				}
			}
		}
	}

	ctrl.Commit()
	if err := proj.Save(); err != nil {
		t.Fatal(err)
	}
	return proj, ctrl
}

func TestSyntheticMultiHunkParity(t *testing.T) {
	if _, err := exec.LookPath("vasmm68k_mot"); err != nil {
		t.Skip("vasmm68k_mot not in PATH; skipping parity test")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not in PATH; skipping parity test")
	}

	workDir := t.TempDir()
	origExe := filepath.Join(workDir, "synth.exe")
	if err := os.WriteFile(origExe, buildSyntheticHunkExecutable(), 0o644); err != nil {
		t.Fatal(err)
	}

	proj, ctrl := initHunkProjectForTest(t, workDir, "synth", origExe)
	defer ctrl.Close()

	a, err := analyzer.New(proj, ctrl)
	if err != nil {
		t.Fatal(err)
	}
	a.Analyze(nil)

	if err := EmitAllAmiga(proj, workDir, true); err != nil {
		t.Fatal(err)
	}

	masterAsm := filepath.Join(workDir, "disasm", "synth.asm")
	outExe := filepath.Join(workDir, "synth.rebuilt")
	cmd := exec.Command(
		"vasmm68k_mot",
		"-Fhunkexe",
		"-kick1hunks",
		"-nosym",
		"-no-opt",
		"-I", workDir,
		"-I", filepath.Join(workDir, "src"),
		"-o", outExe,
		masterAsm,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("vasmm68k_mot failed: %v\nOutput:\n%s", err, string(out))
	}

	scriptPath := filepath.Join("..", "..", "scripts", "verify_parity.py")
	verifyCmd := exec.Command("python3", scriptPath, outExe, origExe)
	if out, err := verifyCmd.CombinedOutput(); err != nil {
		t.Fatalf("verify_parity.py failed: %v\n%s", err, string(out))
	}
}
