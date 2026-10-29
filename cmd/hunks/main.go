package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"

	"github.com/mikolas/hunks/internal/analyzer"
	"github.com/mikolas/hunks/internal/callgraph"
	"github.com/mikolas/hunks/internal/db"
	"github.com/mikolas/hunks/internal/emitter"
	"github.com/mikolas/hunks/internal/hunk"
	"github.com/mikolas/hunks/internal/m68k"
	"github.com/mikolas/hunks/internal/modules"
	"github.com/mikolas/hunks/internal/project"
	"github.com/mikolas/hunks/internal/tui"
	"github.com/spf13/cobra"
)

var version = "v1.2.0"

func parseHex(val string) (uint32, error) {
	return project.ParseUint32(val)
}

func resolveAddrOrLabel(proj *project.Project, ctrl *db.Controller, val string) (uint32, error) {
	if addr, ok := proj.ResolveTarget(ctrl, val); ok {
		return addr, nil
	}
	return project.ParseUint32(val)
}

func listWorkspaceTargets(workspaceRoot string) []string {
	var targets []string
	seen := make(map[string]bool)
	scanDir := func(dir string) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, entry := range entries {
			if entry.IsDir() && !seen[entry.Name()] {
				p := filepath.Join(dir, entry.Name(), "project.json")
				if _, err := os.Stat(p); err == nil {
					seen[entry.Name()] = true
					targets = append(targets, entry.Name())
				}
			}
		}
	}
	scanDir(filepath.Join(workspaceRoot, "work"))
	scanDir(workspaceRoot)
	scanDir(filepath.Join(workspaceRoot, "work", "work"))
	slices.Sort(targets)
	return targets
}

func loadTargetProject(workspaceRoot string, moduleOpt string) (*project.Project, error) {
	available := listWorkspaceTargets(workspaceRoot)
	var availHint string
	if len(available) > 0 {
		availHint = fmt.Sprintf(" Available modules in workspace: %s", strings.Join(available, ", "))
	}

	rawTarget := strings.TrimSpace(moduleOpt)
	if rawTarget == "" {
		return nil, fmt.Errorf("--module (-m <name>) is required. Example: hunks -m <module> <command>.%s", availHint)
	}

	targetName := strings.TrimPrefix(rawTarget, "work/")
	targetName = strings.TrimSuffix(targetName, "/")
	targetWorkDir := filepath.Join(workspaceRoot, "work", targetName)
	projJSON := filepath.Join(targetWorkDir, "project.json")
	effectiveRoot := workspaceRoot
	if _, err := os.Stat(projJSON); err != nil {
		altDir := filepath.Join(workspaceRoot, targetName)
		altJSON := filepath.Join(altDir, "project.json")
		nestedDir := filepath.Join(workspaceRoot, "work", "work", targetName)
		nestedJSON := filepath.Join(nestedDir, "project.json")
		if _, errAlt := os.Stat(altJSON); errAlt == nil {
			targetWorkDir = altDir
			projJSON = altJSON
			if filepath.Base(workspaceRoot) == "work" {
				effectiveRoot = filepath.Dir(workspaceRoot)
			}
		} else if _, errNested := os.Stat(nestedJSON); errNested == nil {
			targetWorkDir = nestedDir
			projJSON = nestedJSON
			effectiveRoot = filepath.Join(workspaceRoot, "work")
		} else {
			return nil, fmt.Errorf("Module '%s' not found at %s. Run 'hunks init' first.%s", targetName, projJSON, availHint)
		}
	}

	if err := os.Chdir(targetWorkDir); err != nil {
		return nil, err
	}
	proj := project.New("project.json")
	if err := proj.Load(); err != nil {
		return nil, err
	}
	proj.WorkspaceRoot = effectiveRoot
	if proj.Data.TargetName == "" {
		proj.Data.TargetName = targetName
	}
	return proj, nil
}

func requireSegment(proj *project.Project) (project.Segment, error) {
	seg := proj.CurrentSegment()
	if seg == nil {
		return project.Segment{}, fmt.Errorf("module '%s' has no segments; run `hunks init` first or re-initialize the workspace", proj.Data.TargetName)
	}
	return *seg, nil
}

func applyCodeHintsBatch(proj *project.Project, ctrl *db.Controller, rawAddrs []uint32) ([]uint32, error) {
	if len(rawAddrs) == 0 {
		return nil, nil
	}
	aligned := make([]uint32, 0, len(rawAddrs))
	var singleSegName string
	multiOrReloc := false
	segDataCache := make(map[string][]byte)

	for i, rawAddr := range rawAddrs {
		addr := rawAddr &^ 1
		aligned = append(aligned, addr)
		autoLbl := proj.AutoLabel(addr)

		var segName string
		isReloc := false
		var segData []byte
		var segBase uint32
		if targetSeg := proj.SegmentAtAddr(addr); targetSeg != nil {
			segName = targetSeg.Name
			isReloc = targetSeg.IsRelocatable()
			segBase = targetSeg.Base
			data, ok := segDataCache[segName]
			if !ok {
				data = targetSeg.LoadBinaryData()
				segDataCache[segName] = data
			}
			segData = data
		}
		if i == 0 {
			singleSegName = segName
			if isReloc || segName == "" {
				multiOrReloc = true
			}
		} else if isReloc || segName == "" || !strings.EqualFold(segName, singleSegName) {
			multiOrReloc = true
		}

		cur := addr
		for step := 0; step < 32; step++ {
			insnSize := uint32(2)
			var decoded m68k.Insn
			hasDecoded := false
			if len(segData) > 0 && cur >= segBase {
				off := int(cur - segBase)
				if off < 0 || off+2 > len(segData) {
					break
				}
				end := min(off+10, len(segData))
				if insn, ok := m68k.Decode(segData[off:end], cur); ok && insn.Size >= 2 {
					insnSize = uint32(insn.Size)
					decoded = insn
					hasDecoded = true
				} else if step > 0 {
					break
				}
			} else if step > 0 {
				break
			}
			if step > 0 {
				if existing, err := ctrl.GetCell(cur); err == nil && existing != nil && existing.Type == db.CellCode && existing.Size == insnSize {
					break
				}
			}
			_ = ctrl.DeleteCellsInRange(cur, cur+insnSize)
			_ = ctrl.ClearOverlaps(cur, insnSize)
			for inner := cur + 1; inner < cur+insnSize; inner++ {
				selfTarget := false
				if hasDecoded {
					for opIdx := uint8(0); opIdx < decoded.NumOps; opIdx++ {
						if decoded.Ops[opIdx].UVal == inner {
							selfTarget = true
							break
						}
					}
				}
				if !selfTarget {
					_ = ctrl.DeleteLabelAndRename(inner)
					_ = ctrl.DeleteEdgesAndXrefsTo(inner)
				}
			}
			if !hasDecoded || decoded.IsTerminator() {
				break
			}
			cur += insnSize
		}

		hasEP := false
		for _, ep := range proj.Data.EntryPoints {
			if (ep.Segment == "" || strings.EqualFold(ep.Segment, segName)) && ep.Addr == addr {
				hasEP = true
				break
			}
		}
		if !hasEP {
			proj.Data.EntryPoints = append(proj.Data.EntryPoints, project.EntryPoint{
				Addr:    addr,
				Name:    autoLbl,
				Segment: segName,
			})
		}

		if lbl, err := ctrl.GetLabelFull(addr); err != nil || lbl == nil || lbl.IsAuto {
			_ = ctrl.SetLabel(addr, autoLbl, db.LabelLab, true)
		}
	}
	_ = proj.Save()

	var an *analyzer.Analyzer
	var err error
	if multiOrReloc || singleSegName == "" {
		an, err = analyzer.New(proj, ctrl)
	} else {
		an, err = analyzer.NewForSegment(proj, ctrl, singleSegName)
	}
	if err != nil {
		proj.SyncDBScope(ctrl)
		return aligned, err
	}
	an.AnalyzeIncremental(aligned)
	if !multiOrReloc && singleSegName != "" {
		proj.RefreshCoverageStats(ctrl)
		_ = proj.Save()
	} else {
		proj.SyncDBScope(ctrl)
	}
	return aligned, nil
}

func runTraceAnalysis(proj *project.Project, ctrl *db.Controller, budget uint64) error {
	segs := proj.ActiveSegments()
	if len(segs) == 0 {
		return fmt.Errorf("no segments to trace")
	}
	base := segs[0].Base
	var top uint32
	for _, s := range segs {
		if s.Base < base {
			base = s.Base
		}
		sz := s.AllocSize
		if sz == 0 {
			sz = uint32(len(s.LoadBinaryData()))
		}
		if s.Base+sz > top {
			top = s.Base + sz
		}
	}
	image := make([]byte, top-base)
	for _, s := range segs {
		data := s.LoadBinaryData()
		off := int(s.Base - base)
		end := min(off+len(data), len(image))
		if off < end {
			copy(image[off:end], data[:end-off])
		}
	}
	entry := base
	if len(proj.Data.EntryPoints) > 0 {
		entry = proj.Data.EntryPoints[0].Addr
	}

	opts := analyzer.DefaultTraceOptions()
	if budget > 0 {
		opts.Budget = budget
	}

	fmt.Printf("Trace-driven analysis for module '%s':\n", proj.Data.TargetName)
	fmt.Printf("  image %#08X..%#08X (%d bytes), entry %#08X, budget %d\n",
		base, top, len(image), entry, opts.Budget)

	report := analyzer.RunTrace(image, base, entry, opts)
	fmt.Printf("\n  stop reason     : %s\n", report.Stop)
	fmt.Printf("  instructions    : %d\n", report.Instructions)
	fmt.Printf("  distinct PCs    : %d\n", report.DistinctPCs)
	fmt.Printf("  PC span reached : %#08X..%#08X\n", report.PCLo, report.PCHi)
	fmt.Printf("  serviced ints   : L1=%d L2=%d L3=%d L4=%d L5=%d L6=%d\n",
		report.ServicedInts[0], report.ServicedInts[1], report.ServicedInts[2],
		report.ServicedInts[3], report.ServicedInts[4], report.ServicedInts[5])
	fmt.Printf("  serviced traps  : %d (self-installed TRAP/A-line/F-line)\n", report.ServicedExcs)
	fmt.Printf("  indirect sites  : %d observed\n", len(report.Sites))

	an, err := analyzer.New(proj, ctrl)
	if err != nil {
		return err
	}
	seeds := an.TraceSeedTargets(report.Sites)
	vecSeeds := an.TraceVectorSeeds(report.Vectors)
	fmt.Printf("  trace seeds     : %d dispatch + %d vector-handler code target(s)\n", len(seeds), len(vecSeeds))
	if len(vecSeeds) > 0 {
		var vlist []string
		for _, v := range report.Vectors {
			if slices.Contains(vecSeeds, v.Handler) {
				vlist = append(vlist, fmt.Sprintf("$%X->%#08X", uint32(v.Vec)*4, v.Handler))
			}
		}
		fmt.Printf("  handlers        : %s\n", strings.Join(vlist, ", "))
	}

	var entries []uint32
	for _, ep := range an.Proj.Data.EntryPoints {
		if ep.Segment == "" {
			entries = append(entries, ep.Addr)
			continue
		}
		for _, s := range an.Segments {
			if strings.EqualFold(s.Name, ep.Segment) {
				entries = append(entries, ep.Addr)
				break
			}
		}
	}
	entries = append(entries, seeds...)
	entries = append(entries, vecSeeds...)
	slices.Sort(entries)
	entries = slices.Compact(entries)

	an.Analyze(entries)
	ctrl.Begin()
	an.ApplyTraceDispatches(report.Sites)
	an.ApplyTraceRegDispatches(report.Regs)
	an.ApplyTraceVectors(report.Vectors)
	an.ApplyTraceHWRegs(report.Regs)
	ctrl.Commit()

	if err := proj.Save(); err != nil {
		return err
	}
	fmt.Println("\n  trace-seeded analysis complete (dispatch edges + register-resolved indirect calls + handler labels + hw-reg annotations applied).")
	return nil
}

func runProjectAnalysis(proj *project.Project, ctrl *db.Controller, segFilter string) error {
	isReloc := false
	for i := range proj.Data.Segments {
		if proj.Data.Segments[i].IsRelocatable() {
			isReloc = true
			break
		}
	}
	if isReloc && segFilter == "" {
		fmt.Printf("Running unified multi-stage analysis for module '%s' across %d segment(s)...\n", proj.Data.TargetName, len(proj.Data.Segments))
		an, err := analyzer.New(proj, ctrl)
		if err != nil {
			return err
		}
		an.Analyze(nil)
		if err := proj.Save(); err != nil {
			return err
		}
		fmt.Println("Unified analysis complete.")
	} else {
		var segNames []string
		if segFilter != "" {
			s := proj.SegmentByName(segFilter)
			if s == nil {
				return fmt.Errorf("segment '%s' not found", segFilter)
			}
			segNames = []string{s.Name}
		} else {
			for _, s := range proj.Data.Segments {
				segNames = append(segNames, s.Name)
			}
		}
		fmt.Printf("Running per-segment multi-stage analysis for module '%s' across %d segment(s)...\n", proj.Data.TargetName, len(segNames))
		for _, segName := range segNames {
			an, err := analyzer.NewForSegment(proj, ctrl, segName)
			if err != nil {
				return err
			}
			an.Analyze(nil)
		}
		proj.RefreshCoverageStats(ctrl)
		if err := proj.Save(); err != nil {
			return err
		}
		fmt.Println("Per-segment analysis complete.")
	}
	return nil
}

func main() {
	var workspacePath string
	var moduleName string

	callerCWD, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	resolveCallerPath := func(p string) string {
		if filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(callerCWD, p)
	}
	getWorkspaceRoot := func() string {
		if filepath.IsAbs(workspacePath) {
			return workspacePath
		}
		return filepath.Join(callerCWD, workspacePath)
	}

	rootCmd := &cobra.Command{
		Use:          "hunks",
		Short:        "hunks — Amiga M68k Reverse Engineering System",
		Version:      version,
		SilenceUsage: true,
	}
	rootCmd.PersistentFlags().StringVarP(&workspacePath, "path", "p", ".", "Workspace root directory (defaults to current working directory)")
	rootCmd.PersistentFlags().StringVar(&workspacePath, "project", ".", "Alias for --path")
	_ = rootCmd.PersistentFlags().MarkHidden("project")
	rootCmd.PersistentFlags().StringVarP(&moduleName, "module", "m", "", "Module namespace inside the workspace (deduced from binary name on init; required on other commands)")

	// --- rip ---
	ripCmd := &cobra.Command{
		Use:   "rip <file>",
		Short: "Scan a raw binary file for embedded music modules and report them",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			file := args[0]
			path := resolveCallerPath(file)
			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("cannot read '%s': %w", path, err)
			}
			matches := modules.Scan(data)
			if len(matches) == 0 {
				fmt.Printf("No modules found in '%s' (%d bytes).\n", file, len(data))
			} else {
				fmt.Printf("Found %d module(s) in '%s':\n", len(matches), file)
				for _, m := range matches {
					var multi string
					if len(m.Regions) > 1 {
						multi = fmt.Sprintf("  [%d regions, %d bytes total]", len(m.Regions), m.TotalLen())
					}
					fmt.Printf("  %-12s (%-12s) offset $%08X  length %d bytes (end $%08X)%s\n",
						m.Name, m.Variant, m.Start(), m.PrimaryLen(), m.PrimaryEnd(), multi)
					if len(m.Regions) > 1 {
						for i, r := range m.Regions {
							fmt.Printf("      region %d: %s $%08X..$%08X (%d bytes)\n",
								i, r.Role, r.Start, r.End(), r.Len)
						}
					}
				}
			}
			return nil
		},
	}
	rootCmd.AddCommand(ripCmd)

	// --- init ---
	var initBinary, initBase, initOutput, initHunkFile string
	var initForce bool
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize a module workspace from an AmigaDOS hunk file or raw binary",
		RunE: func(_ *cobra.Command, _ []string) error {
			workspaceRoot := getWorkspaceRoot()
			var rawTarget string
			switch {
			case moduleName != "":
				rawTarget = moduleName
			case initHunkFile != "":
				rawTarget = project.DeduceTargetName(initHunkFile)
			case initBinary != "":
				rawTarget = project.DeduceTargetName(initBinary)
			default:
				return fmt.Errorf("must provide either --hunk-file <path> or both --binary <path> and --base <hex>")
			}
			targetName := strings.TrimPrefix(rawTarget, "work/")
			targetName = strings.TrimSuffix(targetName, "/")

			if workspacePath == "." && filepath.Base(workspaceRoot) == "work" {
				workspaceRoot = filepath.Dir(workspaceRoot)
			}
			targetWorkDir := filepath.Join(workspaceRoot, "work", targetName)
			projJSON := filepath.Join(targetWorkDir, "project.json")
			if _, err := os.Stat(projJSON); err == nil && !initForce {
				return fmt.Errorf("Module '%s' already exists at %s. Pass --force to re-initialize.", targetName, projJSON)
			}

			var resolvedHunkPath, resolvedBinPath string
			if initHunkFile != "" {
				resolvedHunkPath = resolveCallerPath(initHunkFile)
			}
			if initBinary != "" {
				resolvedBinPath = resolveCallerPath(initBinary)
			}
			outFile := fmt.Sprintf("disasm/%s.asm", targetName)
			if initOutput != "" {
				outFile = resolveCallerPath(initOutput)
			}

			if err := os.MkdirAll(targetWorkDir, 0o755); err != nil {
				return err
			}
			if err := os.Chdir(targetWorkDir); err != nil {
				return err
			}

			proj := project.New("project.json")
			proj.WorkspaceRoot = workspaceRoot
			proj.Data.TargetName = targetName
			proj.Data.Output = outFile

			if initHunkFile != "" {
				bytes, err := os.ReadFile(resolvedHunkPath)
				if err != nil {
					return err
				}
				parsed, err := hunk.ParseHunkFile(bytes)
				if err != nil {
					return err
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

				sharedDBName := "project.db"
				_ = os.Remove(sharedDBName)
				ctrl, err := db.New(sharedDBName)
				if err != nil {
					return err
				}
				defer ctrl.Close()

				for _, h := range parsed.Hunks {
					segName := fmt.Sprintf("hunk%d", h.Index)
					var binFile *string
					if h.HunkType != hunk.HunkTypeBss {
						filename := fmt.Sprintf("%s.bin", segName)
						local := h.Index - parsed.FirstHunk
						slice := relocatedData[local]
						if h.FileDataLen < len(slice) {
							slice = slice[:h.FileDataLen]
						}
						if err := os.WriteFile(filename, slice, 0o644); err != nil {
							return err
						}
						binFile = &filename
					}

					fileDataLen := uint32(h.FileDataLen)
					var segBase uint32
					if local := h.Index - parsed.FirstHunk; local >= 0 && local < len(bases) {
						segBase = bases[local]
					}
					proj.Data.Segments = append(proj.Data.Segments, project.Segment{
						Name:        segName,
						HunkIndex:   h.Index,
						HunkType:    h.HunkType,
						MemoryType:  h.MemoryType,
						AllocSize:   h.AllocSize,
						FileDataLen: &fileDataLen,
						File:        binFile,
						Base:        segBase,
						DB:          sharedDBName,
						Relocatable: true,
					})
				}

				spaceSegs := make([]string, len(parsed.Hunks))
				for i, h := range parsed.Hunks {
					spaceSegs[i] = fmt.Sprintf("hunk%d", h.Index)
				}
				proj.Data.Spaces = append(proj.Data.Spaces, project.Space{
					Name:     "default",
					Segments: spaceSegs,
				})
				proj.Data.ActiveSpace = "default"
				proj.SyncDBScope(ctrl)

				ctrl.Begin()

				for _, h := range parsed.Hunks {
					local := h.Index - parsed.FirstHunk
					if local < 0 || local >= len(bases) {
						continue
					}
					base := bases[local]
					for _, sym := range h.Symbols {
						kind := db.LabelDat
						if h.HunkType == hunk.HunkTypeCode {
							kind = db.LabelLab
						}
						_ = ctrl.SetLabel(base+sym.Offset, sym.Name, kind, false)
					}
				}

				hasEntryAt := func(addr uint32) bool {
					for _, ep := range proj.Data.EntryPoints {
						if ep.Addr == addr {
							return true
						}
					}
					return false
				}

				for _, h := range parsed.Hunks {
					if h.HunkType == hunk.HunkTypeCode {
						segName := fmt.Sprintf("hunk%d", h.Index)
						var base uint32
						if local := h.Index - parsed.FirstHunk; local >= 0 && local < len(bases) {
							base = bases[local]
						}

						if len(h.Data) >= 2 {
							b0, b1 := h.Data[0], h.Data[1]
							isCodeStart := h.Index == 0 ||
								(b0 == 0x48 && b1 == 0xE7) ||
								(b0 == 0x4E && b1 == 0x56) ||
								(b0 == 0x32 && b1 == 0x2E)
							if isCodeStart {
								epName := fmt.Sprintf("LAB_%d_%05X", h.Index, 0)
								if !hasEntryAt(base) {
									proj.Data.EntryPoints = append(proj.Data.EntryPoints, project.EntryPoint{
										Addr:    base,
										Name:    epName,
										Segment: segName,
									})
								}
								if existing, ok, _ := ctrl.GetLabel(base); !ok || existing == "" {
									_ = ctrl.SetLabel(base, epName, db.LabelLab, true)
								}
							}
						}

						hasVec4 := len(h.Data) >= 8 && h.Data[4] == 0x60 && h.Data[5] == 0x00
						if hasVec4 {
							vecBase := base + 4
							vecName := fmt.Sprintf("LAB_%d_%05X", h.Index, 4)
							if !hasEntryAt(vecBase) {
								proj.Data.EntryPoints = append(proj.Data.EntryPoints, project.EntryPoint{
									Addr:    vecBase,
									Name:    vecName,
									Segment: segName,
								})
							}
							if existing, ok, _ := ctrl.GetLabel(vecBase); !ok || existing == "" {
								_ = ctrl.SetLabel(vecBase, vecName, db.LabelLab, true)
							}
						}

						if !hasVec4 && len(h.Data) >= 0x2C && ((h.Data[0x28] == 0x4E && h.Data[0x29] == 0x75) || (h.Data[0x28] == 0x60 && h.Data[0x29] == 0x00)) {
							v28Base := base + 0x28
							v28Name := fmt.Sprintf("LAB_%d_%05X", h.Index, 0x28)
							if !hasEntryAt(v28Base) {
								proj.Data.EntryPoints = append(proj.Data.EntryPoints, project.EntryPoint{
									Addr:    v28Base,
									Name:    v28Name,
									Segment: segName,
								})
							}
							if existing, ok, _ := ctrl.GetLabel(v28Base); !ok || existing == "" {
								_ = ctrl.SetLabel(v28Base, v28Name, db.LabelLab, true)
							}
						}
					}
				}

				seededRelocs := 0
				exportedLabels := 0

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
							offUsize := int(offset)
							if offUsize+4 <= len(h.Data) {
								initialVal := binary.BigEndian.Uint32(h.Data[offUsize : offUsize+4])
								srcAddr := srcBase + offset
								targetAddr := tgtBase + initialVal
								labelName := fmt.Sprintf("LAB_%d_%05X", tgtIdx, initialVal)

								if err := ctrl.InsertReloc(srcAddr, targetAddr); err != nil {
									return err
								}
								if existing, ok, err := ctrl.GetLabel(targetAddr); err != nil {
									return err
								} else if !ok || existing == "" {
									if err := ctrl.SetLabel(targetAddr, labelName, db.LabelLab, true); err != nil {
										return err
									}
								}
								if isCrossHunk {
									if err := ctrl.MarkExported(targetAddr); err != nil {
										return err
									}
									exportedLabels++
								}
								if err := ctrl.InsertXref(srcAddr, targetAddr, db.XrefDataAddr); err != nil {
									return err
								}
								seededRelocs++
							}
						}
					}
				}

				ctrl.Commit()
				if err := proj.Save(); err != nil {
					return err
				}

				var codeCount, dataCount, bssCount int
				for _, h := range parsed.Hunks {
					switch h.HunkType {
					case hunk.HunkTypeCode:
						codeCount++
					case hunk.HunkTypeData:
						dataCount++
					case hunk.HunkTypeBss:
						bssCount++
					}
				}
				fmt.Printf("Initialized multi-hunk module '%s' (work/%s/) from '%s':\n", targetName, targetName, initHunkFile)
				fmt.Printf("  Hunks: %d (%d code, %d data, %d bss)\n", len(parsed.Hunks), codeCount, dataCount, bssCount)
				fmt.Printf("  Relocations seeded: %d\n", seededRelocs)
				fmt.Printf("  Cross-hunk symbols exported: %d\n", exportedLabels)
				return nil
			} else if initBinary != "" && initBase != "" {
				baseVal, err := parseHex(initBase)
				if err != nil {
					return err
				}
				_ = os.Remove("main.db")
				ctrl, err := db.New("main.db")
				if err != nil {
					return err
				}
				_ = ctrl.Close()

				var flatSize uint32
				if info, err := os.Stat(resolvedBinPath); err == nil {
					flatSize = uint32(info.Size())
				}
				proj.Data.Segments = append(proj.Data.Segments, project.Segment{
					Name:        "main",
					HunkIndex:   0,
					HunkType:    hunk.HunkTypeCode,
					MemoryType:  hunk.MemoryPublic,
					AllocSize:   flatSize,
					File:        &resolvedBinPath,
					Base:        baseVal,
					DB:          "main.db",
					Relocatable: false,
				})
				proj.Data.Spaces = append(proj.Data.Spaces, project.Space{
					Name:     "default",
					Segments: []string{"main"},
				})
				proj.Data.ActiveSpace = "default"
				if err := proj.Save(); err != nil {
					return err
				}
				fmt.Printf("Initialized module '%s' (work/%s/) for %s at base 0x%X\n", targetName, targetName, initBinary, baseVal)
				return nil
			}
			return fmt.Errorf("must provide either --hunk-file <path> or both --binary <path> and --base <hex>")
		},
	}
	initCmd.Flags().StringVar(&initBinary, "binary", "", "Path to flat binary file")
	initCmd.Flags().StringVar(&initBase, "base", "", "Base address in hex (for --binary)")
	initCmd.Flags().StringVar(&initOutput, "output", "", "Output assembly file path")
	initCmd.Flags().StringVar(&initHunkFile, "hunk-file", "", "Path to AmigaOS multi-hunk executable")
	initCmd.Flags().BoolVar(&initForce, "force", false, "Overwrite existing target workspace if already initialized")
	rootCmd.AddCommand(initCmd)

	// --- entry ---
	var entryName string
	entryCmd := &cobra.Command{
		Use:   "entry <addr>",
		Short: "Add or update an entry point",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			addrStr := args[0]
			proj, err := loadTargetProject(getWorkspaceRoot(), moduleName)
			if err != nil {
				return err
			}
			var segName string
			var addrU32 uint32
			resolved := false
			if segPart, rest, hasColon := strings.Cut(addrStr, ":"); hasColon {
				if seg := proj.SegmentByName(strings.TrimSpace(segPart)); seg != nil {
					clean := strings.TrimSpace(rest)
					if offStr, ok := strings.CutPrefix(clean, "+"); ok {
						off, err := parseHex(offStr)
						if err != nil {
							return err
						}
						addrU32 = seg.Base + off
					} else {
						a, err := parseHex(clean)
						if err != nil {
							return err
						}
						addrU32 = a
					}
					segName = seg.Name
					resolved = true
				}
			}
			if !resolved {
				a, err := parseHex(addrStr)
				if err != nil {
					return err
				}
				addrU32 = a
				if s := proj.SegmentAtAddr(a); s != nil {
					segName = s.Name
				}
			}

			found := false
			for i := range proj.Data.EntryPoints {
				ep := &proj.Data.EntryPoints[i]
				if (ep.Segment == "" || strings.EqualFold(ep.Segment, segName)) && ep.Addr == addrU32 {
					ep.Name = entryName
					if ep.Segment == "" && segName != "" {
						ep.Segment = segName
					}
					found = true
					break
				}
			}
			if !found {
				proj.Data.EntryPoints = append(proj.Data.EntryPoints, project.EntryPoint{
					Addr:    addrU32,
					Name:    entryName,
					Segment: segName,
				})
			}
			if err := proj.Save(); err != nil {
				return err
			}
			fmt.Printf("Added entry point %s at 0x%X\n", entryName, addrU32)
			return nil
		},
	}
	entryCmd.Flags().StringVar(&entryName, "name", "", "Entry point symbol name")
	_ = entryCmd.MarkFlagRequired("name")
	rootCmd.AddCommand(entryCmd)

	// --- analyze ---
	var analyzeAll, analyzeTrace bool
	var analyzeSegment string
	var analyzeBudget uint64
	analyzeCmd := &cobra.Command{
		Use:   "analyze",
		Short: "Run multi-stage static (or trace-seeded) analysis",
		RunE: func(_ *cobra.Command, _ []string) error {
			proj, err := loadTargetProject(getWorkspaceRoot(), moduleName)
			if err != nil {
				return err
			}
			seg, err := requireSegment(proj)
			if err != nil {
				return err
			}
			ctrl, err := db.New(seg.DB)
			if err != nil {
				return err
			}
			defer ctrl.Close()

			_ = analyzeAll
			if analyzeTrace {
				proj.SyncDBScope(ctrl)
				return runTraceAnalysis(proj, ctrl, analyzeBudget)
			}
			return runProjectAnalysis(proj, ctrl, analyzeSegment)
		},
	}
	analyzeCmd.Flags().BoolVar(&analyzeAll, "all", false, "Analyze all segments in the project")
	analyzeCmd.Flags().StringVarP(&analyzeSegment, "segment", "s", "", "Analyze only a single named segment (flat projects)")
	analyzeCmd.Flags().BoolVar(&analyzeTrace, "trace", false, "Trace-driven analysis: run binary in sandboxed M68000 interpreter")
	analyzeCmd.Flags().Uint64Var(&analyzeBudget, "budget", 0, "Instruction budget for --trace")
	rootCmd.AddCommand(analyzeCmd)

	// --- emit ---
	var emitRelocatable, emitAll, emitAmiga, emitForce bool
	emitCmd := &cobra.Command{
		Use:   "emit",
		Short: "Emit assembly files",
		RunE: func(_ *cobra.Command, _ []string) error {
			workspaceRoot := getWorkspaceRoot()
			proj, err := loadTargetProject(workspaceRoot, moduleName)
			if err != nil {
				return err
			}
			if emitAll || emitAmiga {
				fmt.Printf("Emitting modular Amiga assembly for module '%s'...\n", proj.Data.TargetName)
				return emitter.EmitAllAmiga(proj, workspaceRoot, emitForce)
			}
			fmt.Printf("Emitting assembly for module '%s'...\n", proj.Data.TargetName)
			seg, err := requireSegment(proj)
			if err != nil {
				return err
			}
			ctrl, err := db.New(seg.DB)
			if err != nil {
				return err
			}
			defer ctrl.Close()

			em, err := emitter.New(proj, ctrl)
			if err != nil {
				return err
			}
			outPath := em.TargetOutputPath()
			if err := em.Emit(emitRelocatable, emitForce); err != nil {
				return err
			}
			fmt.Printf("Wrote assembly to %s\n", outPath)
			return nil
		},
	}
	emitCmd.Flags().BoolVar(&emitRelocatable, "relocatable", false, "Emit relocatable assembly")
	emitCmd.Flags().BoolVar(&emitAll, "all", false, "Emit modular Amiga assembly")
	emitCmd.Flags().BoolVar(&emitAmiga, "amiga", false, "Emit modular Amiga assembly")
	emitCmd.Flags().BoolVar(&emitForce, "force", false, "Overwrite existing emitted assembly files")
	rootCmd.AddCommand(emitCmd)

	// --- hint ---
	var hintFollow, hintString bool
	var hintComment, hintSegment, hintFunction, hintBase, hintBatchFile string
	var hintCount, hintEntrySize int
	hintCmd := &cobra.Command{
		Use:   "hint [pointer|data|code|base-reg|jump-table] [addr...]",
		Short: "Provide one or more analysis hints (pointer, data, code, base-reg, or jump-table; supports --batch/-f)",
		Args:  cobra.ArbitraryArgs,
		RunE: func(_ *cobra.Command, args []string) error {
			type hintSpec struct {
				kind      string
				addrStr   string
				countStr  string
				baseStr   string
				entrySize int
				follow    bool
				isString  bool
				comment   string
			}
			var specs []hintSpec

			if hintBatchFile != "" {
				var r io.Reader
				if hintBatchFile == "-" {
					r = os.Stdin
				} else {
					fpath := resolveCallerPath(hintBatchFile)
					f, err := os.Open(fpath)
					if err != nil {
						return fmt.Errorf("failed to open hint batch file '%s': %w", fpath, err)
					}
					defer f.Close()
					r = f
				}
				scanner := bufio.NewScanner(r)
				lineIdx := 0
				for scanner.Scan() {
					lineIdx++
					line := scanner.Text()
					trimmed := line
					if idx := strings.IndexByte(trimmed, '#'); idx >= 0 {
						trimmed = trimmed[:idx]
					}
					if idx := strings.IndexByte(trimmed, ';'); idx >= 0 {
						trimmed = trimmed[:idx]
					}
					trimmed = strings.TrimSpace(trimmed)
					if trimmed == "" {
						continue
					}
					fields := strings.Fields(trimmed)
					if len(fields) == 1 {
						specs = append(specs, hintSpec{
							kind:      "code",
							addrStr:   fields[0],
							entrySize: hintEntrySize,
							follow:    hintFollow,
							isString:  hintString,
						})
						continue
					}
					k := strings.ToLower(fields[0])
					switch k {
					case "code":
						for _, a := range fields[1:] {
							specs = append(specs, hintSpec{kind: "code", addrStr: a})
						}
					case "pointer", "data", "base-reg", "jump-table":
						sp := hintSpec{
							kind:      k,
							addrStr:   fields[1],
							baseStr:   hintBase,
							entrySize: hintEntrySize,
							follow:    hintFollow,
							isString:  hintString,
						}
						for _, extra := range fields[2:] {
							switch {
							case extra == "--follow":
								sp.follow = true
							case extra == "--string":
								sp.isString = true
							case strings.HasPrefix(extra, "--base="):
								sp.baseStr = strings.TrimPrefix(extra, "--base=")
							case strings.HasPrefix(extra, "--count="):
								sp.countStr = strings.TrimPrefix(extra, "--count=")
							case sp.countStr == "":
								sp.countStr = extra
							case sp.baseStr == "":
								sp.baseStr = extra
							}
						}
						specs = append(specs, sp)
					default:
						return fmt.Errorf("invalid hint type %q on line %d (expected pointer, data, code, base-reg, or jump-table)", fields[0], lineIdx)
					}
				}
				if err := scanner.Err(); err != nil {
					return err
				}
			}

			if len(args) > 0 {
				typeStr := strings.ToLower(args[0])
				switch typeStr {
				case "code":
					if len(args) < 2 {
						return fmt.Errorf("usage: hunks hint code <addr1> [addr2...]")
					}
					for _, a := range args[1:] {
						specs = append(specs, hintSpec{
							kind:    "code",
							addrStr: a,
							comment: hintComment,
						})
					}
				case "pointer", "data", "base-reg", "jump-table":
					if len(args) < 2 {
						return fmt.Errorf("usage: hunks hint %s <addr> [count]", typeStr)
					}
					var countStr string
					if len(args) >= 3 {
						countStr = args[2]
					} else if hintCount > 0 {
						countStr = fmt.Sprintf("%d", hintCount)
					}
					specs = append(specs, hintSpec{
						kind:      typeStr,
						addrStr:   args[1],
						countStr:  countStr,
						baseStr:   hintBase,
						entrySize: hintEntrySize,
						follow:    hintFollow,
						isString:  hintString,
						comment:   hintComment,
					})
				default:
					return fmt.Errorf("invalid hint type %q (expected pointer, data, code, base-reg, or jump-table)", args[0])
				}
			}

			if len(specs) == 0 {
				return fmt.Errorf("expected `hunks hint <pointer|data|code|base-reg|jump-table> <addr>...` or `--batch <file>`")
			}

			proj, err := loadTargetProject(getWorkspaceRoot(), moduleName)
			if err != nil {
				return err
			}
			seg, err := requireSegment(proj)
			if err != nil {
				return err
			}
			ctrl, err := db.New(seg.DB)
			if err != nil {
				return err
			}
			defer ctrl.Close()
			proj.SyncDBScope(ctrl)

			var allCodeSeeds []uint32
			type jtEntry struct {
				entryAddr  uint32
				targetAddr uint32
				baseAddr   uint32
			}
			var jtEntries []jtEntry
			needFullAnalyze := false

			for _, sp := range specs {
				switch sp.kind {
				case "base-reg":
					reg := strings.ToLower(sp.addrStr)
					if reg != "a4" && reg != "a5" && reg != "a6" {
						return fmt.Errorf("base-reg: register must be a4, a5 or a6 (got '%s')", sp.addrStr)
					}
					if sp.countStr == "" {
						return fmt.Errorf("base-reg: missing base address (usage: hint base-reg a4 0x<addr>)")
					}
					baseAddr, err := parseHex(sp.countStr)
					if err != nil {
						return err
					}
					scopeKind := "global"
					scopeKey := ""
					if hintFunction != "" {
						scopeKind = "function"
						scopeKey = hintFunction
					} else if hintSegment != "" {
						scopeKind = "segment"
						scopeKey = hintSegment
					}
					if err := ctrl.SetBaseReg(scopeKind, scopeKey, reg, baseAddr, "hint"); err != nil {
						return err
					}
					needFullAnalyze = true
					fmt.Printf("Set base-reg %s = 0x%X (scope: %s %s)\n", reg, baseAddr, scopeKind, scopeKey)

				case "pointer":
					addrU32, err := resolveAddrOrLabel(proj, ctrl, sp.addrStr)
					if err != nil {
						return err
					}
					cnt := uint32(1)
					if sp.countStr != "" {
						cnt, err = parseHex(sp.countStr)
						if err != nil {
							return err
						}
					}
					an, err := analyzer.New(proj, ctrl)
					if err != nil {
						return err
					}
					var ptrSeeds []uint32
					if err := ctrl.WithTransaction(func() error {
						for i := uint32(0); i < cnt; i++ {
							slotAddr := addrU32 + (i * 4)
							if err := ctrl.MarkData(slotAddr, 4, db.CellPointer); err != nil {
								return err
							}
							var tgt uint32
							hasTgt := false
							if rTgt, ok := an.Relocs[slotAddr]; ok {
								tgt = rTgt
								hasTgt = true
							} else if u32Tgt, ok := an.ReadU32(slotAddr); ok {
								tgt = u32Tgt
								hasTgt = true
							}
							if hasTgt && (an.IsInAnySegment(tgt) || an.IsInMemoryRegion(tgt)) {
								an.AddLabel(&slotAddr, tgt)
								_ = ctrl.InsertXref(slotAddr, tgt, db.XrefDataAddr)
								lbl := an.GetOrDefaultLabel(tgt)
								_ = ctrl.SetCellOp(slotAddr, lbl)
								if sp.follow && tgt%2 == 0 && an.IsInCodeSegment(tgt) && !slices.Contains(allCodeSeeds, tgt) {
									allCodeSeeds = append(allCodeSeeds, tgt)
									ptrSeeds = append(ptrSeeds, tgt)
								}
							}
						}
						if sp.comment != "" {
							return ctrl.UpdateComment(addrU32, sp.comment)
						}
						return nil
					}); err != nil {
						return err
					}
					fmt.Printf("Added pointer hint at 0x%X with count %d (%d code target(s) queued)\n", addrU32, cnt, len(ptrSeeds))

				case "data":
					addrU32, err := resolveAddrOrLabel(proj, ctrl, sp.addrStr)
					if err != nil {
						return err
					}
					size := uint32(1)
					if sp.countStr != "" {
						size, err = parseHex(sp.countStr)
						if err != nil {
							return err
						}
					}
					regionType := db.CellDataB
					if sp.isString {
						regionType = db.CellStr
					}
					if err := ctrl.MarkData(addrU32, size, regionType); err != nil {
						return err
					}
					if sp.comment != "" {
						_ = ctrl.UpdateComment(addrU32, sp.comment)
					}
					fmt.Printf("Added data hint at 0x%X with size %d\n", addrU32, size)

				case "jump-table":
					tableAddr, err := resolveAddrOrLabel(proj, ctrl, sp.addrStr)
					if err != nil {
						return err
					}
					tableAddr &= ^uint32(1)
					baseAddr := tableAddr
					if sp.baseStr != "" {
						baseAddr, err = resolveAddrOrLabel(proj, ctrl, sp.baseStr)
						if err != nil {
							return fmt.Errorf("cannot resolve --base %q: %w", sp.baseStr, err)
						}
					}
					entSize := uint32(2)
					if sp.entrySize == 4 {
						entSize = 4
					} else if sp.entrySize != 0 && sp.entrySize != 2 {
						return fmt.Errorf("invalid --entry-size %d (expected 2 or 4)", sp.entrySize)
					}
					var explicitCnt uint32
					if sp.countStr != "" {
						explicitCnt, err = parseHex(sp.countStr)
						if err != nil {
							return err
						}
					}
					an, err := analyzer.New(proj, ctrl)
					if err != nil {
						return err
					}
					maxEntries := explicitCnt
					if maxEntries == 0 {
						maxEntries = 256
					}
					var minFwdTarget uint32 = 0xFFFFFFFF
					var tableEntries []jtEntry
					for i := uint32(0); i < maxEntries; i++ {
						entryAddr := tableAddr + i*entSize
						if explicitCnt == 0 && entryAddr >= minFwdTarget {
							break
						}
						if !an.IsSameSegment(tableAddr, entryAddr) {
							break
						}
						var off int64
						var okOff bool
						if entSize == 2 {
							if v, ok16 := an.ReadI16(entryAddr); ok16 {
								off = int64(v)
								okOff = true
							}
						} else {
							if v, ok32 := an.ReadU32(entryAddr); ok32 {
								off = int64(int32(v))
								okOff = true
							}
						}
						if !okOff {
							break
						}
						targetAddr := uint32(int64(baseAddr) + off)
						if explicitCnt == 0 {
							if off == 0 || targetAddr%2 != 0 || !an.IsSameSegment(tableAddr, targetAddr) {
								break
							}
							if targetAddr > tableAddr && targetAddr < entryAddr+entSize {
								break
							}
							if _, okInsn := an.DecodeValidInsn(targetAddr, false); !okInsn {
								break
							}
						}
						if targetAddr > tableAddr {
							minFwdTarget = min(minFwdTarget, targetAddr)
						}
						tableEntries = append(tableEntries, jtEntry{
							entryAddr:  entryAddr,
							targetAddr: targetAddr,
							baseAddr:   baseAddr,
						})
					}
					if len(tableEntries) == 0 {
						return fmt.Errorf("no valid jump-table entries found at 0x%X", tableAddr)
					}
					cellType := db.CellDataW
					if entSize == 4 {
						cellType = db.CellDataL
					}
					if err := ctrl.WithTransaction(func() error {
						an.AddLabel(nil, tableAddr)
						if baseAddr != tableAddr {
							an.AddLabel(nil, baseAddr)
						}
						baseLbl := an.GetOrDefaultLabel(baseAddr)
						for _, je := range tableEntries {
							if err := ctrl.MarkData(je.entryAddr, entSize, cellType); err != nil {
								return err
							}
							if je.targetAddr%2 == 0 && an.IsInAnySegment(je.targetAddr) {
								src := je.entryAddr
								an.AddLabel(&src, je.targetAddr)
								_ = ctrl.InsertXref(je.entryAddr, je.targetAddr, db.XrefDataAddr)
								tgtLbl := an.GetOrDefaultLabel(je.targetAddr)
								_ = ctrl.SetCellOp(je.entryAddr, fmt.Sprintf("%s-%s", tgtLbl, baseLbl))
								if an.IsInCodeSegment(je.targetAddr) && !slices.Contains(allCodeSeeds, je.targetAddr) {
									allCodeSeeds = append(allCodeSeeds, je.targetAddr)
								}
							}
							jtEntries = append(jtEntries, je)
						}
						if sp.comment != "" {
							return ctrl.UpdateComment(tableAddr, sp.comment)
						}
						return nil
					}); err != nil {
						return err
					}
					fmt.Printf("Marked jump-table at 0x%X (%d entries, base 0x%X, %d code target(s) queued)\n",
						tableAddr, len(tableEntries), baseAddr, len(allCodeSeeds))

				case "code":
					addrU32, err := resolveAddrOrLabel(proj, ctrl, sp.addrStr)
					if err != nil {
						return err
					}
					addrAligned := addrU32 &^ 1
					if !slices.Contains(allCodeSeeds, addrAligned) {
						allCodeSeeds = append(allCodeSeeds, addrAligned)
					}
					if sp.comment != "" {
						_ = ctrl.UpdateComment(addrAligned, sp.comment)
					}
				}
			}

			if needFullAnalyze {
				an, err := analyzer.New(proj, ctrl)
				if err != nil {
					return err
				}
				an.Analyze(nil)
			}
			if len(allCodeSeeds) > 0 {
				aligned, err := applyCodeHintsBatch(proj, ctrl, allCodeSeeds)
				if err != nil {
					return err
				}
				if len(jtEntries) > 0 {
					if an, err := analyzer.New(proj, ctrl); err == nil {
						an.RefreshCaches()
						_ = ctrl.WithTransaction(func() error {
							for _, je := range jtEntries {
								tgtLbl := an.GetOrDefaultLabel(je.targetAddr)
								baseLbl := an.GetOrDefaultLabel(je.baseAddr)
								_ = ctrl.SetCellOp(je.entryAddr, fmt.Sprintf("%s-%s", tgtLbl, baseLbl))
							}
							return nil
						})
					}
				}
				if len(aligned) == 1 && len(specs) == 1 && specs[0].kind == "code" {
					fmt.Printf("Marked code and incrementally analyzed at 0x%X\n", aligned[0])
				} else {
					fmt.Printf("Marked %d code seed(s) and incrementally analyzed (first: 0x%X)\n", len(aligned), aligned[0])
				}
			}
			return nil
		},
	}
	hintCmd.Flags().BoolVar(&hintFollow, "follow", false, "Follow pointer target")
	hintCmd.Flags().StringVar(&hintComment, "comment", "", "Optional comment")
	hintCmd.Flags().BoolVar(&hintString, "string", false, "Mark data as string")
	hintCmd.Flags().StringVar(&hintSegment, "segment", "", "For base-reg: limit the invariant to a specific segment")
	hintCmd.Flags().StringVar(&hintFunction, "function", "", "For base-reg: limit the invariant to a specific function label")
	hintCmd.Flags().StringVar(&hintBase, "base", "", "For jump-table: base address/label added to each relative offset (default: table_addr)")
	hintCmd.Flags().IntVar(&hintCount, "count", 0, "Number of entries or bytes (alternative to positional [count])")
	hintCmd.Flags().IntVar(&hintEntrySize, "entry-size", 2, "For jump-table: byte width of each signed offset entry (2 or 4)")
	hintCmd.Flags().StringVar(&hintBatchFile, "batch", "", "Batch file of hint directives per line (use '-' for stdin)")
	hintCmd.Flags().StringVarP(&hintBatchFile, "file", "f", "", "Alias for --batch")
	rootCmd.AddCommand(hintCmd)

	// --- rename ---
	var renameFile string
	var renameDelete bool
	renameCmd := &cobra.Command{
		Use:   "rename [args...]",
		Short: "Rename one or more symbols (or delete labels with --delete)",
		RunE: func(_ *cobra.Command, args []string) error {
			if renameDelete {
				if len(args) == 0 {
					return fmt.Errorf("expected `hunks rename --delete <addr_or_label>...`")
				}
				proj, err := loadTargetProject(getWorkspaceRoot(), moduleName)
				if err != nil {
					return err
				}
				seg, err := requireSegment(proj)
				if err != nil {
					return err
				}
				ctrl, err := db.New(seg.DB)
				if err != nil {
					return err
				}
				defer ctrl.Close()
				proj.SyncDBScope(ctrl)
				var deleted []uint32
				if err := ctrl.WithTransaction(func() error {
					for _, arg := range args {
						addr, err := resolveAddrOrLabel(proj, ctrl, arg)
						if err != nil {
							return fmt.Errorf("cannot resolve address or label %q: %w", arg, err)
						}
						if err := ctrl.DeleteLabelAndRename(addr); err != nil {
							return err
						}
						proj.Data.EntryPoints = slices.DeleteFunc(proj.Data.EntryPoints, func(ep project.EntryPoint) bool {
							return ep.Addr == addr
						})
						deleted = append(deleted, addr)
						fmt.Printf("Deleted label at 0x%X (%s)\n", addr, arg)
					}
					return nil
				}); err != nil {
					return err
				}
				_ = proj.Save()
				if an, err := analyzer.New(proj, ctrl); err == nil {
					an.ReanalyzeXrefsBatch(deleted)
				}
				return nil
			}
			type pair struct{ oldName, newName string }
			var pairs []pair

			if renameFile != "" {
				var r io.Reader
				if renameFile == "-" {
					r = os.Stdin
				} else {
					fpath := resolveCallerPath(renameFile)
					f, err := os.Open(fpath)
					if err != nil {
						return fmt.Errorf("Failed to open rename file '%s': %w", fpath, err)
					}
					defer f.Close()
					r = f
				}
				scanner := bufio.NewScanner(r)
				lineIdx := 0
				for scanner.Scan() {
					lineIdx++
					line := scanner.Text()
					trimmed := line
					if idx := strings.IndexByte(trimmed, '#'); idx >= 0 {
						trimmed = trimmed[:idx]
					}
					if idx := strings.IndexByte(trimmed, ';'); idx >= 0 {
						trimmed = trimmed[:idx]
					}
					trimmed = strings.TrimSpace(trimmed)
					if trimmed == "" {
						continue
					}
					if oldP, newP, ok := strings.Cut(trimmed, "="); ok {
						o := strings.TrimSpace(oldP)
						n := strings.TrimSpace(newP)
						if o != "" && n != "" {
							pairs = append(pairs, pair{o, n})
							continue
						}
					}
					cols := strings.FieldsFunc(trimmed, func(r rune) bool {
						return unicode.IsSpace(r) || r == ','
					})
					if len(cols) >= 2 {
						pairs = append(pairs, pair{cols[0], cols[1]})
					} else {
						return fmt.Errorf("Invalid rename entry on line %d: '%s'. Expected '<old> <new>' or '<old>=<new>'.", lineIdx, line)
					}
				}
				if err := scanner.Err(); err != nil {
					return err
				}
			}

			var posArgs []string
			for _, a := range args {
				if oldP, newP, ok := strings.Cut(a, "="); ok {
					o := strings.TrimSpace(oldP)
					n := strings.TrimSpace(newP)
					if o != "" && n != "" {
						pairs = append(pairs, pair{o, n})
						continue
					}
				}
				posArgs = append(posArgs, a)
			}
			if len(posArgs)%2 != 0 {
				return fmt.Errorf("Expected '<old_name> <new_name>', '<old>=<new>', or '--file <path>'.")
			}
			for i := 0; i < len(posArgs); i += 2 {
				pairs = append(pairs, pair{posArgs[i], posArgs[i+1]})
			}
			if len(pairs) == 0 {
				return fmt.Errorf("No rename pairs provided. Pass '<old_name> <new_name>', '<old>=<new>', or '--file <path>'.")
			}

			proj, err := loadTargetProject(getWorkspaceRoot(), moduleName)
			if err != nil {
				return err
			}
			seenDBs := make(map[string]bool)
			segs := slices.Clone(proj.Data.Segments)
			for _, seg := range segs {
				if seenDBs[seg.DB] {
					continue
				}
				seenDBs[seg.DB] = true
				if err := func(dbPath string) error {
					ctrl, err := db.New(dbPath)
					if err != nil {
						return err
					}
					defer ctrl.Close()
					proj.SyncDBScope(ctrl)
					return ctrl.WithTransaction(func() error {
						renamesMap, _ := ctrl.GetAllRenames()
						var affectedAddrs []uint32
						for _, p := range pairs {
							cleanOld := p.oldName
							if _, r, ok := strings.Cut(p.oldName, ":"); ok {
								cleanOld = strings.TrimSpace(r)
							}
							resolvedAddr, hasResolved := proj.ResolveTarget(ctrl, p.oldName)
							var targetSeg string
							if hasResolved {
								if s := proj.SegmentAtAddr(resolvedAddr); s != nil {
									targetSeg = s.Name
								}
							} else if sPart, _, ok := strings.Cut(p.oldName, ":"); ok {
								if s := proj.SegmentByName(strings.TrimSpace(sPart)); s != nil {
									targetSeg = s.Name
								}
							}
							prevSeg := ctrl.ActiveSeg()
							if targetSeg != "" {
								ctrl.SetActiveSeg(targetSeg)
							}
							effectiveOld := cleanOld
							if hasResolved {
								if lbl, ok, _ := ctrl.GetLabel(resolvedAddr); ok && lbl != "" {
									effectiveOld = lbl
								} else {
									auto := proj.AutoLabel(resolvedAddr)
									_ = ctrl.SetLabel(resolvedAddr, auto, db.LabelLab, true)
									effectiveOld = auto
								}
							}
							prevRenamed := renamesMap[effectiveOld]
							if err := ctrl.SetRename(effectiveOld, p.newName); err != nil {
								ctrl.SetActiveSeg(prevSeg)
								return err
							}
							renamesMap[effectiveOld] = p.newName
							proj.ReKeyFunctionABI(effectiveOld, p.newName)
							proj.ReKeyFunctionABI(cleanOld, p.newName)
							if prevRenamed != "" {
								proj.ReKeyFunctionABI(prevRenamed, p.newName)
							}
							if hasResolved {
								affectedAddrs = append(affectedAddrs, resolvedAddr)
							} else if targetAddr, ok := ctrl.LabelAddrByName(effectiveOld, false); ok {
								affectedAddrs = append(affectedAddrs, targetAddr)
							}
							ctrl.SetActiveSeg(prevSeg)
						}

						an, err := analyzer.New(proj, ctrl)
						if err != nil {
							return err
						}
						an.ReanalyzeXrefsBatch(affectedAddrs)
						return nil
					})
				}(seg.DB); err != nil {
					return err
				}
			}
			if err := proj.Save(); err != nil {
				return err
			}
			if len(pairs) == 1 {
				fmt.Printf("Renamed %s to %s\n", pairs[0].oldName, pairs[0].newName)
			} else {
				fmt.Printf("Renamed %d symbols in module '%s'\n", len(pairs), proj.Data.TargetName)
			}
			return nil
		},
	}
	renameCmd.Flags().StringVarP(&renameFile, "file", "f", "", "Batch file containing '<old_name> <new_name>' or '<old_name>=<new_name>' per line (use '-' for stdin)")
	renameCmd.Flags().StringVar(&renameFile, "batch", "", "Alias for --file")
	renameCmd.Flags().BoolVarP(&renameDelete, "delete", "d", false, "Delete the specified label(s) and any associated rename entry")
	rootCmd.AddCommand(renameCmd)

	// --- comment ---
	var commentBlock bool
	var commentBatchFile string
	commentCmd := &cobra.Command{
		Use:   "comment [addr] [text]",
		Short: "Set or remove an inline or block comment at an address (or batch via --batch/--file)",
		Args:  cobra.RangeArgs(0, 2),
		RunE: func(_ *cobra.Command, args []string) error {
			proj, err := loadTargetProject(getWorkspaceRoot(), moduleName)
			if err != nil {
				return err
			}
			seg, err := requireSegment(proj)
			if err != nil {
				return err
			}
			ctrl, err := db.New(seg.DB)
			if err != nil {
				return err
			}
			defer ctrl.Close()
			proj.SyncDBScope(ctrl)
			cg, err := callgraph.Build(proj)
			if err != nil {
				return err
			}

			updateAddrComment := func(addrU32 uint32, val string) error {
				targetCtrl := ctrl
				if tgtSeg := proj.SegmentAtAddr(addrU32); tgtSeg != nil && tgtSeg.DB != "" && tgtSeg.DB != seg.DB {
					c, err := db.New(tgtSeg.DB)
					if err != nil {
						return err
					}
					defer c.Close()
					proj.SyncDBScope(c)
					targetCtrl = c
				}
				if commentBlock {
					return targetCtrl.UpdateBlockComment(addrU32, val)
				}
				return targetCtrl.UpdateComment(addrU32, val)
			}

			applyOne := func(addrStr, val string) error {
				addrU32, note, err := resolveStrictCommentAddr(proj, ctrl, cg, addrStr)
				if err != nil {
					return err
				}
				if note != "" {
					fmt.Fprintln(os.Stderr, note)
				}
				return updateAddrComment(addrU32, val)
			}

			if commentBatchFile != "" {
				var r io.Reader
				if commentBatchFile == "-" {
					r = os.Stdin
				} else {
					f, err := os.Open(resolveCallerPath(commentBatchFile))
					if err != nil {
						return err
					}
					defer f.Close()
					r = f
				}
				scanner := bufio.NewScanner(r)
				count := 0
				if err := ctrl.WithTransaction(func() error {
					for scanner.Scan() {
						line := strings.TrimSpace(scanner.Text())
						if line == "" || strings.HasPrefix(line, "#") {
							continue
						}
						var targetPart, textPart string
						if b, a, ok := strings.Cut(line, "="); ok {
							targetPart = strings.TrimSpace(b)
							textPart = strings.TrimSpace(a)
						} else if fields := strings.Fields(line); len(fields) >= 2 {
							targetPart = fields[0]
							textPart = strings.TrimSpace(line[len(fields[0]):])
						} else {
							continue
						}
						if err := applyOne(targetPart, textPart); err != nil {
							return err
						}
						count++
					}
					return scanner.Err()
				}); err != nil {
					return err
				}
				fmt.Printf("Applied %d comment(s)\n", count)
				return nil
			}

			if len(args) == 0 {
				return fmt.Errorf("provide <addr> [text] or --batch <file>")
			}
			addrStr := args[0]
			var val string
			if len(args) >= 2 {
				val = args[1]
			}
			addrU32, note, err := resolveStrictCommentAddr(proj, ctrl, cg, addrStr)
			if err != nil {
				return err
			}
			if note != "" {
				fmt.Fprintln(os.Stderr, note)
			}
			if err := updateAddrComment(addrU32, val); err != nil {
				return err
			}
			if commentBlock {
				if val == "" {
					fmt.Printf("Removed block comment at 0x%X\n", addrU32)
				} else {
					fmt.Printf("Added block comment at 0x%X\n", addrU32)
				}
			} else {
				if val == "" {
					fmt.Printf("Removed comment at 0x%X\n", addrU32)
				} else {
					fmt.Printf("Added comment at 0x%X\n", addrU32)
				}
			}
			return nil
		},
	}
	commentCmd.Flags().BoolVarP(&commentBlock, "block", "b", false, "Set block comment (above function/instruction) instead of inline comment")
	commentCmd.Flags().StringVar(&commentBatchFile, "batch", "", "Batch file containing '<addr_or_label+off> = <comment>' per line (use '-' for stdin)")
	commentCmd.Flags().StringVarP(&commentBatchFile, "file", "f", "", "Alias for --batch")
	rootCmd.AddCommand(commentCmd)

	// --- operand ---
	var operandBatchFile string
	operandCmd := &cobra.Command{
		Use:   "operand [addr] [HEX|DEC|BIN]",
		Short: "Set immediate operand format at one or more addresses (supports --batch/-f)",
		Args:  cobra.ArbitraryArgs,
		RunE: func(_ *cobra.Command, args []string) error {
			type opEntry struct {
				addrStr string
				format  string
			}
			var entries []opEntry

			if operandBatchFile != "" {
				var r io.Reader
				if operandBatchFile == "-" {
					r = os.Stdin
				} else {
					fpath := resolveCallerPath(operandBatchFile)
					f, err := os.Open(fpath)
					if err != nil {
						return fmt.Errorf("failed to open operand batch file '%s': %w", fpath, err)
					}
					defer f.Close()
					r = f
				}
				scanner := bufio.NewScanner(r)
				lineIdx := 0
				for scanner.Scan() {
					lineIdx++
					line := scanner.Text()
					trimmed := line
					if idx := strings.IndexByte(trimmed, '#'); idx >= 0 {
						trimmed = trimmed[:idx]
					}
					if idx := strings.IndexByte(trimmed, ';'); idx >= 0 {
						trimmed = trimmed[:idx]
					}
					trimmed = strings.TrimSpace(trimmed)
					if trimmed == "" {
						continue
					}
					if aPart, fPart, ok := strings.Cut(trimmed, "="); ok {
						entries = append(entries, opEntry{
							addrStr: strings.TrimSpace(aPart),
							format:  strings.ToUpper(strings.TrimSpace(fPart)),
						})
						continue
					}
					fields := strings.Fields(trimmed)
					if len(fields) >= 2 {
						entries = append(entries, opEntry{
							addrStr: fields[0],
							format:  strings.ToUpper(fields[1]),
						})
					} else {
						return fmt.Errorf("invalid operand entry on line %d: %q (expected '<addr> <HEX|DEC|BIN>')", lineIdx, line)
					}
				}
				if err := scanner.Err(); err != nil {
					return err
				}
			}

			for i := 0; i < len(args); {
				if aPart, fPart, ok := strings.Cut(args[i], "="); ok {
					entries = append(entries, opEntry{
						addrStr: strings.TrimSpace(aPart),
						format:  strings.ToUpper(strings.TrimSpace(fPart)),
					})
					i++
					continue
				}
				if i+1 >= len(args) {
					return fmt.Errorf("expected '<addr> <HEX|DEC|BIN>', '<addr>=<HEX|DEC|BIN>', or '--batch <file>'")
				}
				entries = append(entries, opEntry{
					addrStr: args[i],
					format:  strings.ToUpper(args[i+1]),
				})
				i += 2
			}

			if len(entries) == 0 {
				return fmt.Errorf("no operand entries provided; pass '<addr> <HEX|DEC|BIN>' or '--batch <file>'")
			}
			for _, e := range entries {
				switch e.format {
				case "HEX", "DEC", "BIN":
				default:
					return fmt.Errorf("invalid operand format %q for %s (expected HEX, DEC, or BIN)", e.format, e.addrStr)
				}
			}

			proj, err := loadTargetProject(getWorkspaceRoot(), moduleName)
			if err != nil {
				return err
			}
			seg, err := requireSegment(proj)
			if err != nil {
				return err
			}
			ctrl, err := db.New(seg.DB)
			if err != nil {
				return err
			}
			defer ctrl.Close()
			proj.SyncDBScope(ctrl)

			var resolvedAddrs []uint32
			if err := ctrl.WithTransaction(func() error {
				for _, e := range entries {
					addrVal, err := resolveAddrOrLabel(proj, ctrl, e.addrStr)
					if err != nil {
						return err
					}
					if targetSeg := proj.SegmentAtAddr(addrVal); targetSeg != nil {
						ctrl.SetActiveSeg(targetSeg.Name)
					}
					if err := ctrl.SetOperandFormat(addrVal, e.format); err != nil {
						return err
					}
					resolvedAddrs = append(resolvedAddrs, addrVal)
				}
				return nil
			}); err != nil {
				return err
			}

			proj.SyncDBScope(ctrl)
			an, err := analyzer.New(proj, ctrl)
			if err != nil {
				return err
			}
			an.RefreshCaches()
			for _, addrVal := range resolvedAddrs {
				an.ReanalyzeInstruction(addrVal)
			}
			proj.SyncDBScope(ctrl)
			if len(resolvedAddrs) == 1 {
				fmt.Printf("Set operand format at $%X to %s\n", resolvedAddrs[0], entries[0].format)
			} else {
				fmt.Printf("Set operand format on %d instruction(s)\n", len(resolvedAddrs))
			}
			return nil
		},
	}
	operandCmd.Flags().StringVar(&operandBatchFile, "batch", "", "Batch file containing '<addr> <HEX|DEC|BIN>' per line (use '-' for stdin)")
	operandCmd.Flags().StringVarP(&operandBatchFile, "file", "f", "", "Alias for --batch")
	rootCmd.AddCommand(operandCmd)

	// --- callgraph / cg ---
	var cgSegment, cgFormat string
	var cgDepth, cgUpDepth, cgLimit int
	var cgCode, cgLeaves, cgAnchors, cgReady, cgSuspect, cgIndirect, cgUnrenamed bool
	cgCmd := &cobra.Command{
		Use:     "callgraph [target...]",
		Aliases: []string{"cg"},
		Short:   "Query the static call graph",
		Args:    cobra.ArbitraryArgs,
		RunE: func(_ *cobra.Command, args []string) error {
			proj, err := loadTargetProject(getWorkspaceRoot(), moduleName)
			if err != nil {
				return err
			}
			cg, err := callgraph.Build(proj)
			if err != nil {
				return err
			}
			renderOne := func(target string) (string, error) {
				opts := &callgraph.Options{
					Target:    target,
					Segment:   cgSegment,
					Depth:     cgDepth,
					UpDepth:   cgUpDepth,
					Code:      cgCode,
					Leaves:    cgLeaves,
					Anchors:   cgAnchors,
					Ready:     cgReady,
					Suspect:   cgSuspect,
					Indirect:  cgIndirect,
					Unrenamed: cgUnrenamed,
					Limit:     cgLimit,
					Format:    cgFormat,
				}
				out, err := cg.Render(proj, opts)
				if err != nil && target != "" {
					// Auto-fallback to non-code data + XREF inspection if target resolves to data/global.
					if seg, sErr := requireSegment(proj); sErr == nil {
						if ctrl, cErr := db.New(seg.DB); cErr == nil {
							defer ctrl.Close()
							proj.SyncDBScope(ctrl)
							if addr, aErr := resolveAddrOrLabel(proj, ctrl, target); aErr == nil {
								if proj.SegmentAtAddr(addr) != nil {
									return renderDataInspection(proj, ctrl, cg, addr, 64, false, "", 1, cgFormat)
								}
								return runXrefCommand(proj, ctrl, cg, fmt.Sprintf("0x%X", addr), cgFormat)
							}
						}
					}
				}
				return out, err
			}
			if len(args) <= 1 {
				var target string
				if len(args) == 1 {
					target = args[0]
				}
				output, err := renderOne(target)
				if err != nil {
					return err
				}
				fmt.Print(output)
				return nil
			}
			for i, t := range args {
				if i > 0 {
					fmt.Println()
				}
				output, err := renderOne(t)
				if err != nil {
					return err
				}
				fmt.Print(output)
			}
			return nil
		},
	}
	cgCmd.Flags().StringVarP(&cgSegment, "segment", "s", "", "Filter by segment/hunk name or number (e.g. hunk5 or --hunk 5)")
	cgCmd.Flags().StringVar(&cgSegment, "hunk", "", "Alias for --segment")
	cgCmd.Flags().IntVarP(&cgDepth, "depth", "d", 2, "Outgoing callee expansion depth when inspecting a target")
	cgCmd.Flags().IntVar(&cgUpDepth, "up-depth", 2, "Incoming caller expansion depth when inspecting a target")
	cgCmd.Flags().BoolVarP(&cgCode, "code", "c", false, "Include disassembly of target function and caller context snippets")
	cgCmd.Flags().BoolVar(&cgLeaves, "leaves", false, "List leaf functions (0 outgoing calls), sorted by caller count")
	cgCmd.Flags().BoolVar(&cgAnchors, "anchors", false, "List functions anchored by STRING references or Amiga hardware registers")
	cgCmd.Flags().BoolVar(&cgReady, "ready", false, "List unrenamed functions whose callees are all renamed (bottom-up frontier)")
	cgCmd.Flags().BoolVar(&cgSuspect, "suspect", false, "List functions with suspect fallthrough into DATA/STRING without rts/jmp/bra")
	cgCmd.Flags().BoolVar(&cgIndirect, "indirect", false, "List all indirect and trampoline call/jump dispatch sites (resolved and unresolved)")
	cgCmd.Flags().BoolVarP(&cgUnrenamed, "unrenamed", "u", false, "Only show unrenamed functions (LAB_*) in worklist modes")
	cgCmd.Flags().IntVarP(&cgLimit, "limit", "n", 50, "Maximum number of functions to list in worklist modes (0 = all)")
	cgCmd.Flags().StringVarP(&cgFormat, "format", "f", "text", "Output format: text, json, dot, mermaid")
	rootCmd.AddCommand(cgCmd)

	// --- status ---
	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Report code coverage statistics for the module",
		RunE: func(_ *cobra.Command, _ []string) error {
			proj, err := loadTargetProject(getWorkspaceRoot(), moduleName)
			if err != nil {
				return err
			}
			code := float64(proj.Data.Analysis.CodeBytes)
			total := float64(max(proj.Data.Analysis.TotalBytes, 1))
			percent := (code / total) * 100.0
			fmt.Printf("Module '%s': Coverage: %.2f%% (%.0f/%.0f bytes)\n", proj.Data.TargetName, percent, code, total)
			return nil
		},
	}
	rootCmd.AddCommand(statusCmd)

	// --- map ---
	mapCmd := &cobra.Command{
		Use:   "map",
		Short: "Load symbol maps or define memory regions",
	}
	mapLoadCmd := &cobra.Command{
		Use:   "load <file>",
		Short: "Load address-to-symbol mappings from a file",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			file := args[0]
			proj, err := loadTargetProject(getWorkspaceRoot(), moduleName)
			if err != nil {
				return err
			}
			seg, err := requireSegment(proj)
			if err != nil {
				return err
			}
			ctrl, err := db.New(seg.DB)
			if err != nil {
				return err
			}
			defer ctrl.Close()
			proj.SyncDBScope(ctrl)

			resolvedFile := resolveCallerPath(file)
			f, err := os.Open(resolvedFile)
			if err != nil {
				return fmt.Errorf("could not open file '%s': %w", file, err)
			}
			defer f.Close()
			scanner := bufio.NewScanner(f)
			count := 0
			if err := ctrl.WithTransaction(func() error {
				for scanner.Scan() {
					line := strings.TrimSpace(scanner.Text())
					if line == "" || strings.HasPrefix(line, ";") {
						continue
					}
					parts := strings.Fields(line)
					if len(parts) >= 2 {
						if addr, err := parseHex(parts[0]); err == nil {
							label := proj.AutoLabel(addr)
							targetSeg := ctrl.SegOf(addr)
							var renErr error
							ctrl.WithActiveSeg(targetSeg, func() {
								renErr = ctrl.SetRename(label, parts[1])
							})
							if renErr != nil {
								return renErr
							}
							count++
						}
					}
				}
				return scanner.Err()
			}); err != nil {
				return err
			}
			fmt.Printf("Loaded %d mappings from %s\n", count, file)
			return nil
		},
	}
	mapRegionCmd := &cobra.Command{
		Use:   "region <name> <start> <end>",
		Short: "Add or update a named memory region",
		Args:  cobra.ExactArgs(3),
		RunE: func(_ *cobra.Command, args []string) error {
			name, startStr, endStr := args[0], args[1], args[2]
			proj, err := loadTargetProject(getWorkspaceRoot(), moduleName)
			if err != nil {
				return err
			}
			s, err := parseHex(startStr)
			if err != nil {
				return err
			}
			e, err := parseHex(endStr)
			if err != nil {
				return err
			}
			found := false
			for i := range proj.Data.MemoryRegions {
				if proj.Data.MemoryRegions[i].Name == name {
					proj.Data.MemoryRegions[i].Start = s
					proj.Data.MemoryRegions[i].End = e
					found = true
					break
				}
			}
			if !found {
				proj.Data.MemoryRegions = append(proj.Data.MemoryRegions, project.MemoryRegion{
					Name:  name,
					Start: s,
					End:   e,
				})
			}
			if err := proj.Save(); err != nil {
				return err
			}
			fmt.Printf("Updated memory region %s\n", name)
			return nil
		},
	}
	mapCmd.AddCommand(mapLoadCmd, mapRegionCmd)
	rootCmd.AddCommand(mapCmd)

	// --- segment ---
	segmentCmd := &cobra.Command{
		Use:   "segment",
		Short: "Manage segments in the project",
	}
	var segAddFile, segAddBase, segAddName string
	segAddCmd := &cobra.Command{
		Use:   "add",
		Short: "Add a flat binary segment",
		RunE: func(_ *cobra.Command, _ []string) error {
			proj, err := loadTargetProject(getWorkspaceRoot(), moduleName)
			if err != nil {
				return err
			}
			for _, s := range proj.Data.Segments {
				if strings.EqualFold(s.Name, segAddName) {
					return fmt.Errorf("segment '%s' already exists", segAddName)
				}
			}
			baseVal, err := parseHex(segAddBase)
			if err != nil {
				return err
			}
			resolvedFile := resolveCallerPath(segAddFile)
			sharedDB := proj.SharedDB()
			var flatSize uint32
			if info, err := os.Stat(resolvedFile); err == nil {
				flatSize = uint32(info.Size())
			}
			proj.Data.Segments = append(proj.Data.Segments, project.Segment{
				Name:        segAddName,
				HunkIndex:   len(proj.Data.Segments),
				HunkType:    hunk.HunkTypeCode,
				MemoryType:  hunk.MemoryPublic,
				AllocSize:   flatSize,
				File:        &resolvedFile,
				Base:        baseVal,
				DB:          sharedDB,
				Relocatable: false,
			})
			if err := proj.Save(); err != nil {
				return err
			}
			fmt.Printf("Added segment '%s' (%s at $%X)\n", segAddName, segAddFile, baseVal)
			return nil
		},
	}
	segAddCmd.Flags().StringVar(&segAddFile, "file", "", "Binary file path")
	segAddCmd.Flags().StringVar(&segAddBase, "base", "", "Base address in hex")
	segAddCmd.Flags().StringVar(&segAddName, "name", "", "Segment name")
	_ = segAddCmd.MarkFlagRequired("file")
	_ = segAddCmd.MarkFlagRequired("base")
	_ = segAddCmd.MarkFlagRequired("name")

	var segSplitAt, segSplitLen, segSplitTo, segSplitBase, segSplitName string
	segSplitCmd := &cobra.Command{
		Use:   "split <parent>",
		Short: "Slice an extent out of an existing segment into a new static-base segment",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			parent := args[0]
			proj, err := loadTargetProject(getWorkspaceRoot(), moduleName)
			if err != nil {
				return err
			}
			atU32, err := parseHex(segSplitAt)
			if err != nil {
				return err
			}
			atVal := int(atU32)
			baseVal, err := parseHex(segSplitBase)
			if err != nil {
				return err
			}
			var sliceLen int
			switch {
			case segSplitLen != "" && segSplitTo == "":
				l, err := parseHex(segSplitLen)
				if err != nil {
					return err
				}
				sliceLen = int(l)
			case segSplitLen == "" && segSplitTo != "":
				t, err := parseHex(segSplitTo)
				if err != nil {
					return err
				}
				toVal := int(t)
				if toVal <= atVal {
					return fmt.Errorf("--to ($%X) must be greater than --at ($%X)", toVal, atVal)
				}
				sliceLen = toVal - atVal
			case segSplitLen != "" && segSplitTo != "":
				return fmt.Errorf("provide either --len or --to, not both")
			default:
				return fmt.Errorf("provide either --len or --to")
			}

			var parentSeg *project.Segment
			for i := range proj.Data.Segments {
				if strings.EqualFold(proj.Data.Segments[i].Name, parent) {
					parentSeg = &proj.Data.Segments[i]
					break
				}
			}
			if parentSeg == nil {
				return fmt.Errorf("parent segment '%s' not found", parent)
			}
			parentBytes := parentSeg.LoadBinaryData()
			end := atVal + sliceLen
			if end > len(parentBytes) {
				return fmt.Errorf("slice [%#X..%#X] exceeds parent '%s' size %#X", atVal, end, parent, len(parentBytes))
			}
			for _, s := range proj.Data.Segments {
				if strings.EqualFold(s.Name, segSplitName) {
					return fmt.Errorf("segment '%s' already exists", segSplitName)
				}
			}
			binFile := fmt.Sprintf("%s.bin", segSplitName)
			if err := os.WriteFile(binFile, parentBytes[atVal:end], 0o644); err != nil {
				return err
			}
			sharedDB := proj.SharedDB()
			proj.Data.Segments = append(proj.Data.Segments, project.Segment{
				Name:        segSplitName,
				HunkIndex:   len(proj.Data.Segments),
				HunkType:    hunk.HunkTypeCode,
				MemoryType:  hunk.MemoryPublic,
				AllocSize:   uint32(sliceLen),
				File:        &binFile,
				Base:        baseVal,
				DB:          sharedDB,
				Relocatable: false,
			})
			for i := range proj.Data.Spaces {
				if proj.Data.Spaces[i].Name == proj.Data.ActiveSpace {
					proj.Data.Spaces[i].Segments = append(proj.Data.Spaces[i].Segments, segSplitName)
					break
				}
			}
			if err := proj.Save(); err != nil {
				return err
			}
			fmt.Printf("Split '%s' [%#X..%#X] (%d bytes) -> segment '%s' @ $%X (%s)\n",
				parent, atVal, end, sliceLen, segSplitName, baseVal, binFile)
			return nil
		},
	}
	segSplitCmd.Flags().StringVar(&segSplitAt, "at", "", "Byte offset into parent payload where slice starts")
	segSplitCmd.Flags().StringVar(&segSplitLen, "len", "", "Length of slice in bytes")
	segSplitCmd.Flags().StringVar(&segSplitTo, "to", "", "End offset (exclusive) of slice")
	segSplitCmd.Flags().StringVar(&segSplitBase, "base", "", "Load/run base address of new segment")
	segSplitCmd.Flags().StringVar(&segSplitName, "name", "", "Name of new segment")
	_ = segSplitCmd.MarkFlagRequired("at")
	_ = segSplitCmd.MarkFlagRequired("base")
	_ = segSplitCmd.MarkFlagRequired("name")

	segRemoveCmd := &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove a segment from the project",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := args[0]
			proj, err := loadTargetProject(getWorkspaceRoot(), moduleName)
			if err != nil {
				return err
			}
			dbPath := proj.SharedDB()
			if s := proj.SegmentByName(name); s != nil {
				dbPath = s.DB
			}
			if ctrl, err := db.New(dbPath); err == nil {
				_ = ctrl.DeleteSegment(name)
				_ = ctrl.Close()
			}
			proj.Data.Segments = slices.DeleteFunc(proj.Data.Segments, func(s project.Segment) bool {
				return strings.EqualFold(s.Name, name)
			})
			for i := range proj.Data.Spaces {
				proj.Data.Spaces[i].Segments = slices.DeleteFunc(proj.Data.Spaces[i].Segments, func(s string) bool {
					return strings.EqualFold(s, name)
				})
			}
			proj.Data.EntryPoints = slices.DeleteFunc(proj.Data.EntryPoints, func(ep project.EntryPoint) bool {
				return strings.EqualFold(ep.Segment, name)
			})
			if err := proj.Save(); err != nil {
				return err
			}
			fmt.Printf("Removed segment '%s'\n", name)
			return nil
		},
	}

	segListCmd := &cobra.Command{
		Use:   "list",
		Short: "List all segments in the project",
		RunE: func(_ *cobra.Command, _ []string) error {
			proj, err := loadTargetProject(getWorkspaceRoot(), moduleName)
			if err != nil {
				return err
			}
			for _, s := range proj.Data.Segments {
				fileStr := "<bss>"
				if s.File != nil {
					fileStr = *s.File
				}
				fmt.Printf("  %s : %s @ $%X (db: %s)\n", s.Name, fileStr, s.Base, s.DB)
			}
			return nil
		},
	}
	segmentCmd.AddCommand(segAddCmd, segSplitCmd, segRemoveCmd, segListCmd)
	rootCmd.AddCommand(segmentCmd)

	// --- space ---
	spaceCmd := &cobra.Command{
		Use:   "space",
		Short: "Manage address spaces in the project",
	}
	var spaceCreateSegs []string
	spaceCreateCmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a named address space",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := args[0]
			proj, err := loadTargetProject(getWorkspaceRoot(), moduleName)
			if err != nil {
				return err
			}
			proj.Data.Spaces = append(proj.Data.Spaces, project.Space{
				Name:     name,
				Segments: slices.Clone(spaceCreateSegs),
			})
			if proj.Data.ActiveSpace == "" {
				proj.Data.ActiveSpace = name
			}
			if err := proj.Save(); err != nil {
				return err
			}
			fmt.Printf("Created space '%s' with segments: %v\n", name, spaceCreateSegs)
			return nil
		},
	}
	spaceCreateCmd.Flags().StringSliceVar(&spaceCreateSegs, "segments", nil, "Comma-separated segment names")

	spaceSwitchCmd := &cobra.Command{
		Use:   "switch <name>",
		Short: "Switch the active address space",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := args[0]
			proj, err := loadTargetProject(getWorkspaceRoot(), moduleName)
			if err != nil {
				return err
			}
			found := false
			for _, s := range proj.Data.Spaces {
				if s.Name == name {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("space '%s' not found", name)
			}
			proj.Data.ActiveSpace = name
			if err := proj.Save(); err != nil {
				return err
			}
			fmt.Printf("Switched to space '%s'\n", name)
			return nil
		},
	}

	spaceListCmd := &cobra.Command{
		Use:   "list",
		Short: "List all address spaces",
		RunE: func(_ *cobra.Command, _ []string) error {
			proj, err := loadTargetProject(getWorkspaceRoot(), moduleName)
			if err != nil {
				return err
			}
			for _, s := range proj.Data.Spaces {
				marker := " "
				if s.Name == proj.Data.ActiveSpace {
					marker = "▸"
				}
				fmt.Printf("%s %s : %v\n", marker, s.Name, s.Segments)
			}
			return nil
		},
	}
	spaceCmd.AddCommand(spaceCreateCmd, spaceSwitchCmd, spaceListCmd)
	rootCmd.AddCommand(spaceCmd)

	// --- carve ---
	var carveLen, carveEnd, carveFile, carveName string
	carveCmd := &cobra.Command{
		Use:   "carve <start>",
		Short: "Mark a range as an opaque incbin block",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			startStr := args[0]
			proj, err := loadTargetProject(getWorkspaceRoot(), moduleName)
			if err != nil {
				return err
			}
			startVal, err := parseHex(startStr)
			if err != nil {
				return err
			}
			var endVal uint32
			switch {
			case carveLen != "" && carveEnd == "":
				l, err := parseHex(carveLen)
				if err != nil {
					return err
				}
				endVal = startVal + l
			case carveLen == "" && carveEnd != "":
				e, err := parseHex(carveEnd)
				if err != nil {
					return err
				}
				if e <= startVal {
					return fmt.Errorf("--end ($%X) must be greater than start ($%X)", e, startVal)
				}
				endVal = e
			case carveLen != "" && carveEnd != "":
				return fmt.Errorf("provide either --len or --end, not both")
			default:
				return fmt.Errorf("provide either --len or --end")
			}

			seg := proj.SegmentAtAddr(startVal)
			if seg == nil {
				return fmt.Errorf("no segment owns address $%X in the active space", startVal)
			}
			if endVal > seg.EndAddr() {
				return fmt.Errorf("carve [%#X..%#X] exceeds segment '%s' end %#X", startVal, endVal, seg.Name, seg.EndAddr())
			}
			ctrl, err := db.New(seg.DB)
			if err != nil {
				return err
			}
			defer ctrl.Close()
			proj.ActiveSegmentName = seg.Name
			proj.SyncDBScope(ctrl)

			if seg.IsRelocatable() {
				interior := ctrl.RelocsInRange(startVal, endVal)
				if len(interior) > 0 {
					return fmt.Errorf("refusing to carve: range contains %d relocation site(s) (first $%X) in relocatable segment '%s'; freezing a relocatable pointer would break rebuild",
						len(interior), interior[0], seg.Name)
				}
				if startVal%2 != 0 || (endVal-startVal)%2 != 0 {
					return fmt.Errorf("refusing to carve: start/length must be even-aligned in relocatable segment '%s' (start $%X, len %d)",
						seg.Name, startVal, endVal-startVal)
				}
			}

			segBytes := seg.LoadBinaryData()
			off := int(startVal - seg.Base)
			endOff := int(endVal - seg.Base)
			if off < 0 || endOff > len(segBytes) {
				return fmt.Errorf("carve range exceeds segment payload")
			}

			label := carveName
			isAuto := false
			if label == "" {
				label = proj.AutoLabel(startVal)
				isAuto = true
			}
			sidecar := carveFile
			var opStr *string
			if sidecar != "" {
				opStr = &sidecar
			} else {
				sidecar = fmt.Sprintf("assets/%s.bin", label)
			}

			if err := ctrl.WithTransaction(func() error {
				if err := ctrl.ClearOverlaps(startVal, endVal-startVal); err != nil {
					return err
				}
				if err := ctrl.DeleteCellsInRange(startVal, endVal); err != nil {
					return err
				}
				if err := ctrl.InsertCell(&db.Cell{
					Seg:        seg.Name,
					Addr:       startVal,
					Size:       endVal - startVal,
					Type:       db.CellIncbin,
					Confidence: 255,
					OpStr:      opStr,
				}); err != nil {
					return err
				}
				return ctrl.SetLabel(startVal, label, db.LabelDat, isAuto)
			}); err != nil {
				return err
			}

			fmt.Printf("Carved [%#X..%#X] (%d bytes) in '%s' -> %s (label %s)\n",
				startVal, endVal, endVal-startVal, seg.Name, sidecar, label)
			return nil
		},
	}
	carveCmd.Flags().StringVar(&carveLen, "len", "", "Length in bytes (mutually exclusive with --end)")
	carveCmd.Flags().StringVar(&carveEnd, "end", "", "End address, exclusive (mutually exclusive with --len)")
	carveCmd.Flags().StringVar(&carveFile, "file", "", "Sidecar file path (default: assets/<name>.bin)")
	carveCmd.Flags().StringVar(&carveName, "name", "", "Label placed at the carve start (default: auto label)")
	rootCmd.AddCommand(carveCmd)

	// --- uncarve ---
	uncarveCmd := &cobra.Command{
		Use:   "uncarve <start>",
		Short: "Remove a carve, restoring the range for re-analysis",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			startStr := args[0]
			proj, err := loadTargetProject(getWorkspaceRoot(), moduleName)
			if err != nil {
				return err
			}
			startVal, err := parseHex(startStr)
			if err != nil {
				return err
			}
			seg := proj.SegmentAtAddr(startVal)
			if seg == nil {
				return fmt.Errorf("no segment owns address $%X", startVal)
			}
			ctrl, err := db.New(seg.DB)
			if err != nil {
				return err
			}
			defer ctrl.Close()
			proj.ActiveSegmentName = seg.Name
			proj.SyncDBScope(ctrl)
			cell, err := ctrl.GetCell(startVal)
			if err != nil || cell == nil || cell.Type != db.CellIncbin || cell.Size == 0 {
				return fmt.Errorf("no carve starts at $%X", startVal)
			}
			carveEnd := cell.Addr + cell.Size
			if err := ctrl.WithTransaction(func() error {
				if err := ctrl.DeleteCellsInRange(cell.Addr, carveEnd); err != nil {
					return err
				}
				if err := ctrl.DeleteLabelAt(cell.Addr); err != nil {
					return err
				}
				return ctrl.UpdateBlockComment(cell.Addr, "")
			}); err != nil {
				return err
			}
			fmt.Printf("Uncarved [%#X..%#X] in '%s'. Run `hunks analyze` to reclassify the range.\n",
				cell.Addr, carveEnd, seg.Name)
			return nil
		},
	}
	rootCmd.AddCommand(uncarveCmd)

	// --- tui ---
	tuiCmd := &cobra.Command{
		Use:   "tui",
		Short: "Launch the interactive terminal user interface",
		RunE: func(_ *cobra.Command, _ []string) error {
			proj, err := loadTargetProject(getWorkspaceRoot(), moduleName)
			if err != nil {
				return err
			}
			return tui.Run(proj)
		},
	}
	rootCmd.AddCommand(tuiCmd)
	registerAgentCommands(rootCmd, getWorkspaceRoot, &moduleName, resolveCallerPath)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
