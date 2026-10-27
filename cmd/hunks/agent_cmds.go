package main

import (
	"bufio"
	"cmp"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/mikolas/hunks/internal/amiga"
	"github.com/mikolas/hunks/internal/callgraph"
	"github.com/mikolas/hunks/internal/db"
	"github.com/mikolas/hunks/internal/project"
	"github.com/spf13/cobra"
)

func registerAgentCommands(
	rootCmd *cobra.Command,
	getWorkspaceRoot func() string,
	moduleName *string,
	resolveCallerPath func(string) string,
) {
	// --- 1. search ---
	var searchSegment, searchFormat string
	var searchLimit int
	var searchDense bool
	searchCmd := &cobra.Command{
		Use:   "search <query>",
		Short: "Search instructions, operands, strings, comments, labels, bytes, hardware clusters, or SMC writes",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			query := strings.TrimSpace(strings.Join(args, " "))
			proj, err := loadTargetProject(getWorkspaceRoot(), *moduleName)
			if err != nil {
				return err
			}
			cg, err := callgraph.Build(proj)
			if err != nil {
				return err
			}
			return runSearchCommand(proj, cg, query, searchSegment, searchLimit, searchDense, searchFormat)
		},
	}
	searchCmd.Flags().StringVarP(&searchSegment, "segment", "s", "", "Filter results to a specific segment/hunk")
	searchCmd.Flags().IntVarP(&searchLimit, "limit", "n", 100, "Maximum number of results to return (0 = unlimited)")
	searchCmd.Flags().BoolVar(&searchDense, "dense", false, "For cluster:<name>, only return dense pockets (>=3 hits in 24 bytes)")
	searchCmd.Flags().StringVarP(&searchFormat, "format", "f", "text", "Output format: text or json")
	rootCmd.AddCommand(searchCmd)

	// --- 2. data (alias: inspect) ---
	var dataLen, dataCount int
	var dataCopper bool
	var dataStruct, dataFormat string
	dataCmd := &cobra.Command{
		Use:     "data <addr_or_label>",
		Aliases: []string{"inspect"},
		Short:   "Inspect non-code data, pointer tables, copper lists, strings, or struct arrays",
		Args:    cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			proj, err := loadTargetProject(getWorkspaceRoot(), *moduleName)
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

			addr, err := resolveAddrOrLabel(proj, ctrl, args[0])
			if err != nil {
				return fmt.Errorf("cannot resolve address or label %q: %w", args[0], err)
			}
			cg, err := callgraph.Build(proj)
			if err != nil {
				return err
			}
			out, err := renderDataInspection(proj, ctrl, cg, addr, dataLen, dataCopper, dataStruct, dataCount, dataFormat)
			if err != nil {
				return err
			}
			fmt.Print(out)
			return nil
		},
	}
	dataCmd.Flags().IntVar(&dataLen, "len", 64, "Number of bytes to inspect when target is not a single bounded table/string")
	dataCmd.Flags().BoolVar(&dataCopper, "copper", false, "Decode words as Amiga Copper MOVE/WAIT/SKIP instructions")
	dataCmd.Flags().StringVar(&dataStruct, "struct", "", "Decode bytes as records of the named struct")
	dataCmd.Flags().IntVar(&dataCount, "count", 1, "Number of struct records to decode with --struct")
	dataCmd.Flags().StringVarP(&dataFormat, "format", "f", "text", "Output format: text or json")
	rootCmd.AddCommand(dataCmd)

	// --- 3. xref ---
	var xrefFormat string
	xrefCmd := &cobra.Command{
		Use:   "xref <addr_or_label_or_range>",
		Short: "Query cross-references to an address, label, hardware register, or address range (a..b)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			proj, err := loadTargetProject(getWorkspaceRoot(), *moduleName)
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
			out, err := runXrefCommand(proj, ctrl, cg, args[0], xrefFormat)
			if err != nil {
				return err
			}
			fmt.Print(out)
			return nil
		},
	}
	xrefCmd.Flags().StringVarP(&xrefFormat, "format", "f", "text", "Output format: text or json")
	rootCmd.AddCommand(xrefCmd)

	// --- 5a. struct ---
	var structFormat string
	structCmd := &cobra.Command{
		Use:   "struct",
		Short: "Define, list, or remove struct definitions for register-displacement symbolic substitution",
	}
	var structSize int
	structAddCmd := &cobra.Command{
		Use:   "add <StructName> [<offset>=<FieldName[.b|.w|.l|.p]>...]",
		Short: "Add or update fields on a named struct",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			structName := strings.TrimSpace(args[0])
			if structName == "" {
				return fmt.Errorf("struct name cannot be empty")
			}
			proj, err := loadTargetProject(getWorkspaceRoot(), *moduleName)
			if err != nil {
				return err
			}
			if proj.Data.Structs == nil {
				proj.Data.Structs = make(map[string]map[string]string)
			}
			sdef, ok := proj.Data.Structs[structName]
			if !ok || sdef == nil {
				sdef = make(map[string]string)
				proj.Data.Structs[structName] = sdef
			}
			for _, spec := range args[1:] {
				offPart, fieldPart, hasEq := strings.Cut(spec, "=")
				if !hasEq {
					return fmt.Errorf("invalid field spec %q (expected <offset>=<FieldName[.b|.w|.l|.p]>)", spec)
				}
				offVal, err := parseSignedOffset(offPart)
				if err != nil {
					rhsBase, rhsSuffix := project.StripFieldType(strings.TrimSpace(fieldPart))
					if altOff, altErr := parseSignedOffset(rhsBase); altErr == nil {
						offVal = altOff
						err = nil
						fName, fSuf := project.StripFieldType(strings.TrimSpace(offPart))
						if fSuf == "" && rhsSuffix != "" {
							fSuf = rhsSuffix
						}
						if fSuf != "" {
							fieldPart = fName + "." + fSuf
						} else {
							fieldPart = fName
						}
					}
				}
				if err != nil {
					return fmt.Errorf("invalid offset %q in %q: %w", offPart, spec, err)
				}
				fieldPart = strings.TrimSpace(fieldPart)
				if fieldPart == "" {
					delete(sdef, strconv.FormatInt(offVal, 10))
				} else {
					sdef[strconv.FormatInt(offVal, 10)] = fieldPart
				}
			}
			if structSize > 0 {
				sdef["_size"] = strconv.Itoa(structSize)
			}
			if err := proj.Save(); err != nil {
				return err
			}
			fmt.Printf("Updated struct '%s' (%d field entries)\n", structName, len(sdef))
			return nil
		},
	}
	structAddCmd.Flags().IntVar(&structSize, "size", 0, "Total byte stride/size of the struct (for array decoding and <Struct>_SIZEOF)")

	structListCmd := &cobra.Command{
		Use:   "list",
		Short: "List all defined structs and their fields",
		RunE: func(_ *cobra.Command, _ []string) error {
			proj, err := loadTargetProject(getWorkspaceRoot(), *moduleName)
			if err != nil {
				return err
			}
			return renderStructList(proj, structFormat)
		},
	}
	structListCmd.Flags().StringVarP(&structFormat, "format", "f", "text", "Output format: text or json")

	structRemoveCmd := &cobra.Command{
		Use:   "remove <StructName>",
		Short: "Remove a struct definition",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := strings.TrimSpace(args[0])
			proj, err := loadTargetProject(getWorkspaceRoot(), *moduleName)
			if err != nil {
				return err
			}
			delete(proj.Data.Structs, name)
			for k, v := range proj.Data.RegisterAliases {
				if v == name {
					delete(proj.Data.RegisterAliases, k)
				}
			}
			if err := proj.Save(); err != nil {
				return err
			}
			fmt.Printf("Removed struct '%s'\n", name)
			return nil
		},
	}
	structCmd.AddCommand(structAddCmd, structListCmd, structRemoveCmd)
	rootCmd.AddCommand(structCmd)

	// --- 5b. alias ---
	var aliasFunc, aliasFormat string
	aliasCmd := &cobra.Command{
		Use:   "alias [a0..a6] [StructName]",
		Short: "Bind an address register to a struct (globally or scoped with --fn <func>)",
		Args:  cobra.RangeArgs(0, 2),
		RunE: func(_ *cobra.Command, args []string) error {
			proj, err := loadTargetProject(getWorkspaceRoot(), *moduleName)
			if err != nil {
				return err
			}
			if len(args) == 0 {
				return renderAliasList(proj, aliasFormat)
			}
			if len(args) < 2 {
				return fmt.Errorf("expected `hunks alias <a0..a6> <StructName> [--fn <func>]` or `hunks alias list`")
			}
			reg := strings.ToLower(strings.TrimSpace(args[0]))
			if len(reg) != 2 || reg[0] != 'a' || reg[1] < '0' || reg[1] > '6' {
				return fmt.Errorf("register must be a0..a6 (got %q)", args[0])
			}
			structName := strings.TrimSpace(args[1])
			if _, exists := proj.Data.Structs[structName]; !exists {
				return fmt.Errorf("struct %q is not defined; define it first with `hunks struct add %s ...`", structName, structName)
			}
			key := reg
			if strings.TrimSpace(aliasFunc) != "" {
				key = strings.TrimSpace(aliasFunc) + ":" + reg
			}
			if proj.Data.RegisterAliases == nil {
				proj.Data.RegisterAliases = make(map[string]string)
			}
			proj.Data.RegisterAliases[key] = structName
			if err := proj.Save(); err != nil {
				return err
			}
			fmt.Printf("Bound alias %s -> %s\n", key, structName)
			return nil
		},
	}
	aliasCmd.Flags().StringVar(&aliasFunc, "fn", "", "Scope the register alias to a specific function name or label")
	aliasCmd.Flags().StringVarP(&aliasFormat, "format", "f", "text", "Output format when listing aliases: text or json")

	var aliasListFormat string
	aliasListCmd := &cobra.Command{
		Use:   "list",
		Short: "List all active register aliases",
		RunE: func(_ *cobra.Command, _ []string) error {
			proj, err := loadTargetProject(getWorkspaceRoot(), *moduleName)
			if err != nil {
				return err
			}
			return renderAliasList(proj, aliasListFormat)
		},
	}
	aliasListCmd.Flags().StringVarP(&aliasListFormat, "format", "f", "text", "Output format: text or json")

	var aliasRemoveFunc string
	aliasRemoveCmd := &cobra.Command{
		Use:   "remove <a0..a6>",
		Short: "Remove a register alias",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			reg := strings.ToLower(strings.TrimSpace(args[0]))
			key := reg
			if strings.TrimSpace(aliasRemoveFunc) != "" {
				key = strings.TrimSpace(aliasRemoveFunc) + ":" + reg
			}
			proj, err := loadTargetProject(getWorkspaceRoot(), *moduleName)
			if err != nil {
				return err
			}
			delete(proj.Data.RegisterAliases, key)
			if err := proj.Save(); err != nil {
				return err
			}
			fmt.Printf("Removed alias %s\n", key)
			return nil
		},
	}
	aliasRemoveCmd.Flags().StringVar(&aliasRemoveFunc, "fn", "", "Function scope of the alias to remove")
	aliasCmd.AddCommand(aliasListCmd, aliasRemoveCmd)
	rootCmd.AddCommand(aliasCmd)

	// --- 7. abi ---
	var abiBatchFile, abiFormat string
	var abiVerify bool
	abiCmd := &cobra.Command{
		Use:   "abi [func] [signature]",
		Short: "Set, inspect, or verify function register ABI / calling conventions",
		Args:  cobra.RangeArgs(0, 2),
		RunE: func(_ *cobra.Command, args []string) error {
			proj, err := loadTargetProject(getWorkspaceRoot(), *moduleName)
			if err != nil {
				return err
			}
			return runABICommand(proj, args, abiBatchFile, abiVerify, abiFormat, resolveCallerPath)
		},
	}
	abiCmd.Flags().StringVar(&abiBatchFile, "batch", "", "Batch file containing '<func> = <abi_signature>' per line (use '-' for stdin)")
	abiCmd.Flags().StringVar(&abiBatchFile, "file", "", "Alias for --batch")
	abiCmd.Flags().BoolVar(&abiVerify, "verify", false, "Verify user-defined ABI strings against statically inferred ReadRegs/WriteRegs")
	abiCmd.Flags().StringVarP(&abiFormat, "format", "f", "text", "Output format: text or json")
	rootCmd.AddCommand(abiCmd)

	// --- 8. dump ---
	var dumpFormat, dumpSection string
	dumpCmd := &cobra.Command{
		Use:   "dump",
		Short: "Export all durable reverse-engineering state (renames, comments, regions, structs, aliases, carves)",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			proj, err := loadTargetProject(getWorkspaceRoot(), *moduleName)
			if err != nil {
				return err
			}
			out, err := runDumpCommand(proj, dumpSection, dumpFormat)
			if err != nil {
				return err
			}
			fmt.Print(out)
			return nil
		},
	}
	dumpCmd.Flags().StringVar(&dumpSection, "section", "", "Export only one section: renames, comments, regions, structs, aliases, carves, entries")
	dumpCmd.Flags().StringVarP(&dumpFormat, "format", "f", "text", "Output format: text or json")
	rootCmd.AddCommand(dumpCmd)
}

func formatFnOffset(addr, entryAddr uint32) string {
	if addr >= entryAddr {
		return fmt.Sprintf("+%X", addr-entryAddr)
	}
	return fmt.Sprintf("-%X", entryAddr-addr)
}

func parseSignedOffset(s string) (int64, error) {
	clean := strings.TrimSpace(s)
	neg := false
	if after, ok := strings.CutPrefix(clean, "-"); ok {
		neg = true
		clean = strings.TrimSpace(after)
	} else if after, ok := strings.CutPrefix(clean, "+"); ok {
		clean = strings.TrimSpace(after)
	}
	u, err := project.ParseUint32(clean)
	if err != nil {
		return 0, err
	}
	val := int64(u)
	if neg {
		val = -val
	}
	return val, nil
}

// --- §1: hunks search ---

type searchHitJSON struct {
	Addr        string `json:"addr"`
	Segment     string `json:"segment"`
	Offset      string `json:"offset"`
	Func        string `json:"func,omitempty"`
	FnOffset    string `json:"fn_offset,omitempty"`
	Type        string `json:"type"`
	Instruction string `json:"instruction"`
	Comment     string `json:"comment,omitempty"`
}

func matchesClusterInstruction(clusterName string, mnem, opStr, comment string) bool {
	c := strings.ToLower(strings.TrimSpace(clusterName))
	mLower := strings.ToLower(mnem)
	baseMnem, _, _ := strings.Cut(mLower, ".")
	combined := strings.ToUpper(opStr + " " + comment)

	switch c {
	case "3dmath", "math":
		switch baseMnem {
		case "muls", "mulu", "divs", "divu":
			return true
		}
		return false
	case "mul":
		return baseMnem == "muls" || baseMnem == "mulu"
	case "div":
		return baseMnem == "divs" || baseMnem == "divu"
	case "trig", "sin", "cos":
		switch baseMnem {
		case "muls", "mulu", "asr", "lsr", "lsl", "asl":
			return strings.Contains(opStr, "(a") && strings.Contains(opStr, ",")
		}
		return false
	case "blitter":
		for _, tok := range []string{"BLT", "DMACON"} {
			if strings.Contains(combined, tok) {
				return true
			}
		}
		return false
	case "copper":
		for _, tok := range []string{"COP1LC", "COP2LC", "COPJMP", "COPCON", "COPINS"} {
			if strings.Contains(combined, tok) {
				return true
			}
		}
		return false
	case "paula", "audio":
		for _, tok := range []string{"AUD0", "AUD1", "AUD2", "AUD3", "ADKCON"} {
			if strings.Contains(combined, tok) {
				return true
			}
		}
		return false
	case "bitplane", "display", "video":
		for _, tok := range []string{"BPL", "DIWSTRT", "DIWSTOP", "DDFSTRT", "DDFSTOP", "COLOR"} {
			if strings.Contains(combined, tok) {
				return true
			}
		}
		return false
	case "sprite", "sprites":
		return strings.Contains(combined, "SPR")
	case "cia", "timer":
		return strings.Contains(combined, "CIA")
	case "dma":
		return strings.Contains(combined, "DMACON")
	case "irq", "interrupt":
		for _, tok := range []string{"INTENA", "INTREQ"} {
			if strings.Contains(combined, tok) {
				return true
			}
		}
		return false
	}
	return false
}

func dispatchControllerSearch(proj *project.Project, ctrl *db.Controller, cg *callgraph.CallGraph, query string) []uint32 {
	const maxDBLimit = 10000
	q := strings.TrimSpace(query)
	qLower := strings.ToLower(q)
	var out []uint32
	add := func(items []db.AddrText) {
		for _, it := range items {
			out = append(out, it.Addr)
		}
	}

	switch {
	case strings.HasPrefix(qLower, "m:"):
		add(ctrl.SearchCode("m", strings.TrimSpace(q[2:]), nil, maxDBLimit))
	case strings.HasPrefix(qLower, "o:"):
		needle := strings.TrimSpace(q[2:])
		add(ctrl.SearchCode("o", needle, nil, maxDBLimit))
		// Also match auto/inline comments (e.g. resolved hardware or base-reg targets).
		add(ctrl.SearchComments(needle, nil, maxDBLimit))
		if len(proj.Data.RegisterAliases) > 0 && len(proj.Data.Structs) > 0 {
			needleLower := strings.ToLower(needle)
			for addr, cell := range cg.Cells {
				if cell.Type != db.CellCode {
					continue
				}
				var fnName, fnRaw string
				if fAddr, ok := cg.InsnToFunc[addr]; ok {
					if f, ok := cg.Functions[fAddr]; ok {
						fnName = f.Name
						fnRaw = f.RawName
					}
				}
				aliased := proj.ApplyStructAliasesToOpStr(cell.OpStrVal(), fnName, fnRaw)
				if strings.Contains(strings.ToLower(aliased), needleLower) {
					out = append(out, addr)
				}
			}
		}
	case strings.HasPrefix(qLower, "s:"):
		add(ctrl.SearchStrings(strings.TrimSpace(q[2:]), nil, maxDBLimit))
	case strings.HasPrefix(qLower, "c:"):
		add(ctrl.SearchComments(strings.TrimSpace(q[2:]), nil, maxDBLimit))
	case strings.HasPrefix(qLower, "l:"):
		add(ctrl.SearchLabels(strings.TrimSpace(q[2:]), nil, maxDBLimit))
	case strings.HasPrefix(qLower, "b:"):
		hexClean := strings.ReplaceAll(strings.TrimSpace(q[2:]), " ", "")
		var pat []byte
		for i := 0; i+2 <= len(hexClean); i += 2 {
			b, err := strconv.ParseUint(hexClean[i:i+2], 16, 8)
			if err != nil {
				return nil
			}
			pat = append(pat, byte(b))
		}
		if len(pat) > 0 {
			for _, seg := range proj.ActiveSegments() {
				data := seg.LoadBinaryData()
				for i := 0; i+len(pat) <= len(data); i++ {
					if slices.Equal(data[i:i+len(pat)], pat) {
						rawAddr := seg.Base + uint32(i)
						snapped := rawAddr
						cg.CellsTree.DescendLessOrEqual(db.Cell{Addr: rawAddr}, func(c db.Cell) bool {
							if rawAddr >= c.Addr && rawAddr < c.Addr+c.Size {
								snapped = c.Addr
							}
							return false
						})
						out = append(out, snapped)
					}
				}
			}
		}
	default:
		add(ctrl.SearchLabels(q, nil, maxDBLimit))
		add(ctrl.SearchCode("m", q, nil, maxDBLimit))
		add(ctrl.SearchCode("o", q, nil, maxDBLimit))
		add(ctrl.SearchComments(q, nil, maxDBLimit))
		add(ctrl.SearchStrings(q, nil, maxDBLimit))
	}
	return out
}

func runSearchCommand(
	proj *project.Project,
	cg *callgraph.CallGraph,
	query string,
	segFilter string,
	limit int,
	denseOnly bool,
	format string,
) error {
	normSeg := callgraph.NormalizeSegmentFilter(segFilter)
	qLower := strings.ToLower(strings.TrimSpace(query))

	var matchedAddrs []uint32

	seenDBs := make(map[string]bool)
	for _, seg := range proj.ActiveSegments() {
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

			switch {
			case qLower == "smc":
				// Match all CODE cells with [SMC] comment or XrefDataWrite targeting a CODE cell.
				for _, addr := range slices.Sorted(maps.Keys(cg.Cells)) {
					cell := cg.Cells[addr]
					if cell.Type != db.CellCode {
						continue
					}
					if strings.Contains(cg.Comments[addr].EffectiveComment(), "[SMC]") {
						matchedAddrs = append(matchedAddrs, addr)
					}
				}
				for _, x := range ctrl.AllXrefs() {
					if x.Kind == db.XrefDataWrite {
						if srcCell, ok := cg.Cells[x.Source]; ok && srcCell.Type == db.CellCode {
							if tgtCell, ok := cg.Cells[x.Target]; ok && tgtCell.Type == db.CellCode {
								if !slices.Contains(matchedAddrs, x.Source) {
									matchedAddrs = append(matchedAddrs, x.Source)
								}
							}
						}
					}
				}

			case strings.HasPrefix(qLower, "cluster:"):
				clusterName := strings.TrimSpace(query[len("cluster:"):])
				var clusterAddrs []uint32
				for _, addr := range slices.Sorted(maps.Keys(cg.Cells)) {
					cell := cg.Cells[addr]
					if cell.Type != db.CellCode {
						continue
					}
					cmt := cg.Comments[addr].EffectiveComment()
					if matchesClusterInstruction(clusterName, cell.MnemonicStr(), cell.OpStrVal(), cmt) {
						clusterAddrs = append(clusterAddrs, addr)
					}
				}
				if denseOnly {
					for i := range clusterAddrs {
						j := i
						for j < len(clusterAddrs) && clusterAddrs[j]-clusterAddrs[i] <= 24 {
							j++
						}
						if j-i >= 3 {
							for k := i; k < j; k++ {
								matchedAddrs = append(matchedAddrs, clusterAddrs[k])
							}
						}
					}
				} else {
					matchedAddrs = append(matchedAddrs, clusterAddrs...)
				}

			default:
				matchedAddrs = append(matchedAddrs, dispatchControllerSearch(proj, ctrl, cg, query)...)
			}
			return nil
		}(seg.DB); err != nil {
			return err
		}
	}

	slices.Sort(matchedAddrs)
	matchedAddrs = slices.Compact(matchedAddrs)

	var hits []searchHitJSON
	for _, addr := range matchedAddrs {
		seg := proj.SegmentAtAddr(addr)
		segName := "?"
		var segOff uint32
		if seg != nil {
			segName = seg.Name
			if addr >= seg.Base {
				segOff = addr - seg.Base
			}
		}
		if normSeg != "" && !strings.EqualFold(segName, normSeg) {
			continue
		}
		var fnName, fnRaw, fnOffStr string
		if fAddr, ok := cg.InsnToFunc[addr]; ok {
			if f, ok := cg.Functions[fAddr]; ok {
				fnName = f.Name
				fnRaw = f.RawName
				fnOffStr = formatFnOffset(addr, f.EntryAddr)
			}
		}
		cell, ok := cg.Cells[addr]
		cellType := "DATA"
		var insnText string
		if ok {
			cellType = cell.Type.AsStr()
			mnem := cell.MnemonicStr()
			ops := cell.OpStrVal()
			if cell.Type == db.CellCode {
				ops = proj.ApplyStructAliasesToOpStr(ops, fnName, fnRaw)
			}
			if mnem != "" {
				insnText = strings.TrimSpace(fmt.Sprintf("%-8s %s", mnem, ops))
			} else if ops != "" {
				insnText = fmt.Sprintf("%-8s %s", cellType, ops)
			} else {
				insnText = cellType
			}
		} else if lbl := cg.Labels[addr]; lbl != "" {
			cellType = "LABEL"
			insnText = lbl
		}
		cmt := cg.Comments[addr].EffectiveComment()
		hits = append(hits, searchHitJSON{
			Addr:        fmt.Sprintf("0x%X", addr),
			Segment:     segName,
			Offset:      fmt.Sprintf("+%05X", segOff),
			Func:        fnName,
			FnOffset:    fnOffStr,
			Type:        cellType,
			Instruction: insnText,
			Comment:     cmt,
		})
		if limit > 0 && len(hits) >= limit {
			break
		}
	}

	if format == "json" {
		payload := map[string]any{
			"query": query,
			"count": len(hits),
			"hits":  hits,
		}
		b, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}

	fmt.Printf("=== Search %q (%d hits) ===\n", query, len(hits))
	for _, h := range hits {
		ctx := fmt.Sprintf("[%s]", h.Type)
		if h.Func != "" {
			ctx = fmt.Sprintf("[%s%s]", h.Func, h.FnOffset)
		}
		cmt := ""
		if h.Comment != "" {
			cmt = " ; " + h.Comment
		}
		fmt.Printf("  %s  %-26s %s%s\n", h.Offset, ctx, h.Instruction, cmt)
	}
	return nil
}

// --- §2: hunks data ---

func renderDataInspection(
	proj *project.Project,
	ctrl *db.Controller,
	cg *callgraph.CallGraph,
	addr uint32,
	byteLen int,
	copperMode bool,
	structName string,
	structCount int,
	format string,
) (string, error) {
	seg := proj.SegmentAtAddr(addr)
	if seg == nil {
		return "", fmt.Errorf("address $%X is not in any mapped binary segment (no file bytes to dump); use 'hunks xref $%X' to inspect references", addr, addr)
	}
	segBytes := seg.LoadBinaryData()
	if addr < seg.Base || int(addr-seg.Base) >= len(segBytes) {
		return "", fmt.Errorf("address $%X is outside segment '%s' file payload ($%X..$%X); use 'hunks xref $%X' to inspect references",
			addr, seg.Name, seg.Base, seg.Base+uint32(len(segBytes)), addr)
	}
	relOff := int(addr - seg.Base)
	if byteLen <= 0 {
		byteLen = 64
	}
	// If a single non-code cell at addr is larger than default 64 bytes (e.g. a string or pointer table), use its size.
	if c, ok := cg.Cells[addr]; ok && c.Type != db.CellCode && int(c.Size) > byteLen && byteLen == 64 {
		byteLen = int(c.Size)
	}
	endOff := min(relOff+byteLen, len(segBytes))
	rawSlice := segBytes[relOff:endOff]
	endAddr := seg.Base + uint32(endOff)

	lbl := cg.Labels[addr]
	if lbl == "" {
		lbl = proj.AutoLabel(addr)
	}
	cellType := "RAW"
	if c, ok := cg.Cells[addr]; ok {
		cellType = c.Type.AsStr()
	}
	allRelocs, _ := ctrl.GetAllRelocs()

	resolvePtrLabel := func(slotAddr, val uint32, isPointerCell bool) (string, bool) {
		if rTgt, ok := allRelocs[slotAddr]; ok {
			val = rTgt
			isPointerCell = true
		}
		if c, ok := cg.Cells[slotAddr]; ok && c.Type == db.CellPointer {
			isPointerCell = true
		}
		if !isPointerCell {
			return "", false
		}
		if l := cg.Labels[val]; l != "" {
			return l, true
		}
		if hw, ok := amiga.GetAmigaHWLabel(val); ok {
			return hw, true
		}
		if proj.SegmentAtAddr(val) != nil {
			return proj.AutoLabel(val), true
		}
		return "", false
	}

	if structName != "" {
		sdef, ok := proj.Data.Structs[structName]
		if !ok {
			return "", fmt.Errorf("struct %q is not defined", structName)
		}
		return renderStructRecords(proj, cg, seg, addr, lbl, structName, sdef, structCount, segBytes, resolvePtrLabel, format)
	}

	if copperMode {
		return renderCopperDecode(seg, addr, lbl, rawSlice, format)
	}

	type dataItemJSON struct {
		Offset  string `json:"offset"`
		Addr    string `json:"addr"`
		Type    string `json:"type"`
		Asm     string `json:"asm"`
		Target  string `json:"target,omitempty"`
		Comment string `json:"comment,omitempty"`
	}
	var items []dataItemJSON
	cur := addr
	for cur < endAddr {
		c, hasCell := cg.Cells[cur]
		off := cur - seg.Base
		bIdx := int(off)
		if hasCell && c.Addr == cur && c.Size > 0 && cur+c.Size <= endAddr {
			switch c.Type {
			case db.CellPointer, db.CellDataL:
				if bIdx+4 <= len(segBytes) {
					val := binary.BigEndian.Uint32(segBytes[bIdx : bIdx+4])
					isPtr := c.Type == db.CellPointer
					if _, hasR := allRelocs[cur]; hasR {
						isPtr = true
					}
					tLbl, resolved := resolvePtrLabel(cur, val, isPtr)
					asm := fmt.Sprintf("dc.l $%08X", val)
					var tgtStr string
					if resolved {
						asm = fmt.Sprintf("dc.l %s", tLbl)
						tgtStr = fmt.Sprintf("$%08X (%s)", val, tLbl)
					}
					items = append(items, dataItemJSON{
						Offset:  fmt.Sprintf("+%05X", off),
						Addr:    fmt.Sprintf("0x%X", cur),
						Type:    c.Type.AsStr(),
						Asm:     asm,
						Target:  tgtStr,
						Comment: cg.Comments[cur].EffectiveComment(),
					})
					cur += 4
					continue
				}
			case db.CellStr:
				endC := min(bIdx+int(c.Size), len(segBytes))
				strPreview := string(segBytes[bIdx:endC])
				strPreview = strings.TrimRight(strPreview, "\x00")
				items = append(items, dataItemJSON{
					Offset:  fmt.Sprintf("+%05X", off),
					Addr:    fmt.Sprintf("0x%X", cur),
					Type:    c.Type.AsStr(),
					Asm:     fmt.Sprintf("dc.b %q,0", strPreview),
					Comment: cg.Comments[cur].EffectiveComment(),
				})
				cur += c.Size
				continue
			case db.CellDataW:
				if bIdx+2 <= len(segBytes) {
					val := binary.BigEndian.Uint16(segBytes[bIdx : bIdx+2])
					items = append(items, dataItemJSON{
						Offset:  fmt.Sprintf("+%05X", off),
						Addr:    fmt.Sprintf("0x%X", cur),
						Type:    c.Type.AsStr(),
						Asm:     fmt.Sprintf("dc.w $%04X (%d)", val, int16(val)),
						Comment: cg.Comments[cur].EffectiveComment(),
					})
					cur += 2
					continue
				}
			}
		}

		// Fallback hex/word dump row (16 bytes per row)
		rowLen := min(16, int(endAddr-cur))
		rowBytes := segBytes[bIdx : bIdx+rowLen]
		var words []string
		for i := 0; i < len(rowBytes); i += 2 {
			if i+2 <= len(rowBytes) {
				words = append(words, fmt.Sprintf("$%04X", binary.BigEndian.Uint16(rowBytes[i:i+2])))
			} else {
				words = append(words, fmt.Sprintf("$%02X", rowBytes[i]))
			}
		}
		var ascii strings.Builder
		for _, b := range rowBytes {
			if b >= 0x20 && b <= 0x7E {
				ascii.WriteByte(b)
			} else {
				ascii.WriteByte('.')
			}
		}
		items = append(items, dataItemJSON{
			Offset:  fmt.Sprintf("+%05X", off),
			Addr:    fmt.Sprintf("0x%X", cur),
			Type:    cellType,
			Asm:     strings.Join(words, " "),
			Comment: ascii.String(),
		})
		cur += uint32(rowLen)
	}

	xrefOut, _ := runXrefCommand(proj, ctrl, cg, fmt.Sprintf("0x%X", addr), "text")

	if format == "json" {
		payload := map[string]any{
			"addr":    fmt.Sprintf("0x%X", addr),
			"segment": seg.Name,
			"offset":  fmt.Sprintf("+%05X", addr-seg.Base),
			"label":   lbl,
			"type":    cellType,
			"length":  len(rawSlice),
			"items":   items,
		}
		b, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return "", err
		}
		return string(b) + "\n", nil
	}

	var out strings.Builder
	fmt.Fprintf(&out, "=== Data @ %s [+%05X / $%X] (%s, %d bytes) ===\n", lbl, addr-seg.Base, addr, cellType, len(rawSlice))
	for _, it := range items {
		tgt := ""
		if it.Target != "" {
			tgt = " -> " + it.Target
		}
		cmt := ""
		if it.Comment != "" {
			cmt = "  ; " + it.Comment
		}
		fmt.Fprintf(&out, "  %s  %-38s%s%s\n", it.Offset, it.Asm, tgt, cmt)
	}
	out.WriteByte('\n')
	out.WriteString(xrefOut)
	return out.String(), nil
}

func renderCopperDecode(seg *project.Segment, addr uint32, lbl string, raw []byte, format string) (string, error) {
	type copEntry struct {
		Offset  string `json:"offset"`
		Word0   string `json:"word0"`
		Word1   string `json:"word1"`
		Kind    string `json:"kind"`
		Summary string `json:"summary"`
	}
	var entries []copEntry
	for i := 0; i+4 <= len(raw); i += 4 {
		w0 := binary.BigEndian.Uint16(raw[i : i+2])
		w1 := binary.BigEndian.Uint16(raw[i+2 : i+4])
		off := (addr - seg.Base) + uint32(i)
		if (w0 & 1) == 0 {
			regOff := uint32(w0 & 0x01FE)
			regName, ok := amiga.GetAmigaHWLabel(amiga.CustomBase + regOff)
			if !ok {
				regName = fmt.Sprintf("$DFF%03X", regOff)
			}
			bf := amiga.DecodeCustomRegWrite(regOff, w1)
			sum := fmt.Sprintf("MOVE $%04X -> %s", w1, regName)
			if bf != "" {
				sum += " (" + bf + ")"
			}
			entries = append(entries, copEntry{
				Offset:  fmt.Sprintf("+%05X", off),
				Word0:   fmt.Sprintf("$%04X", w0),
				Word1:   fmt.Sprintf("$%04X", w1),
				Kind:    "MOVE",
				Summary: sum,
			})
		} else if w0 == 0xFFFF && w1 == 0xFFFE {
			entries = append(entries, copEntry{
				Offset:  fmt.Sprintf("+%05X", off),
				Word0:   "$FFFF",
				Word1:   "$FFFE",
				Kind:    "END",
				Summary: "WAIT ($FFFF,$FFFE) — End of Copperlist",
			})
			break
		} else {
			vp := (w0 >> 8) & 0xFF
			hp := w0 & 0xFE
			kind := "WAIT"
			if (w1 & 1) != 0 {
				kind = "SKIP"
			}
			entries = append(entries, copEntry{
				Offset:  fmt.Sprintf("+%05X", off),
				Word0:   fmt.Sprintf("$%04X", w0),
				Word1:   fmt.Sprintf("$%04X", w1),
				Kind:    kind,
				Summary: fmt.Sprintf("%s vpos=%d ($%02X), hpos=%d ($%02X), mask=$%04X", kind, vp, vp, hp, hp, w1),
			})
		}
	}
	if format == "json" {
		b, err := json.MarshalIndent(map[string]any{
			"addr":    fmt.Sprintf("0x%X", addr),
			"label":   lbl,
			"entries": entries,
		}, "", "  ")
		if err != nil {
			return "", err
		}
		return string(b) + "\n", nil
	}
	var out strings.Builder
	fmt.Fprintf(&out, "=== Copperlist @ %s [+%05X / $%X] ===\n", lbl, addr-seg.Base, addr)
	for _, e := range entries {
		fmt.Fprintf(&out, "  %s  %s %s  %s\n", e.Offset, e.Word0, e.Word1, e.Summary)
	}
	return out.String(), nil
}

func renderStructRecords(
	proj *project.Project,
	cg *callgraph.CallGraph,
	seg *project.Segment,
	addr uint32,
	lbl string,
	structName string,
	sdef map[string]string,
	count int,
	segBytes []byte,
	resolvePtrLabel func(uint32, uint32, bool) (string, bool),
	format string,
) (string, error) {
	if count <= 0 {
		count = 1
	}
	type fSpec struct {
		off   int
		name  string
		fType string
		size  int
	}
	var fields []fSpec
	for k, rawF := range sdef {
		if k == "_size" {
			continue
		}
		off, err := strconv.Atoi(k)
		if err != nil || off < 0 {
			continue
		}
		fname, suf := project.StripFieldType(rawF)
		fields = append(fields, fSpec{off: off, name: fname, fType: suf})
	}
	slices.SortFunc(fields, func(a, b fSpec) int {
		return cmp.Compare(a.off, b.off)
	})
	stride := 0
	if szStr, ok := sdef["_size"]; ok {
		stride, _ = strconv.Atoi(szStr)
	}
	for i := range fields {
		switch fields[i].fType {
		case "b":
			fields[i].size = 1
		case "w":
			fields[i].size = 2
		case "l", "p":
			fields[i].size = 4
		default:
			if i+1 < len(fields) {
				diff := fields[i+1].off - fields[i].off
				if diff == 1 || diff == 2 || diff == 4 {
					fields[i].size = diff
				} else {
					fields[i].size = 2
				}
			} else if stride > fields[i].off {
				diff := stride - fields[i].off
				if diff == 1 || diff == 2 || diff == 4 {
					fields[i].size = diff
				} else {
					fields[i].size = 2
				}
			} else {
				fields[i].size = 2
			}
		}
		if fields[i].off+fields[i].size > stride {
			stride = fields[i].off + fields[i].size
		}
	}
	if stride <= 0 {
		stride = 2
	}

	type fieldValJSON struct {
		Offset int    `json:"offset"`
		Field  string `json:"field"`
		Size   int    `json:"size"`
		Hex    string `json:"hex"`
		Dec    int64  `json:"dec"`
		Target string `json:"target,omitempty"`
	}
	type recJSON struct {
		Index  int            `json:"index"`
		Addr   string         `json:"addr"`
		Offset string         `json:"offset"`
		Fields []fieldValJSON `json:"fields"`
	}
	var records []recJSON
	for idx := 0; idx < count; idx++ {
		recAddr := addr + uint32(idx*stride)
		if int(recAddr-seg.Base)+stride > len(segBytes) {
			break
		}
		var fvals []fieldValJSON
		for _, f := range fields {
			fAddr := recAddr + uint32(f.off)
			bOff := int(fAddr - seg.Base)
			if bOff+f.size > len(segBytes) {
				continue
			}
			var hexStr, tgtStr string
			var decVal int64
			switch f.size {
			case 1:
				v := segBytes[bOff]
				hexStr = fmt.Sprintf("$%02X", v)
				decVal = int64(int8(v))
			case 2:
				v := binary.BigEndian.Uint16(segBytes[bOff : bOff+2])
				hexStr = fmt.Sprintf("$%04X", v)
				decVal = int64(int16(v))
			default:
				v := binary.BigEndian.Uint32(segBytes[bOff : bOff+4])
				hexStr = fmt.Sprintf("$%08X", v)
				decVal = int64(int32(v))
				isPtr := f.fType == "p" || (proj.SegmentAtAddr(v) != nil && cg.Labels[v] != "")
				if tLbl, ok := resolvePtrLabel(fAddr, v, isPtr); ok {
					tgtStr = tLbl
				}
			}
			fvals = append(fvals, fieldValJSON{
				Offset: f.off,
				Field:  f.name,
				Size:   f.size,
				Hex:    hexStr,
				Dec:    decVal,
				Target: tgtStr,
			})
		}
		records = append(records, recJSON{
			Index:  idx,
			Addr:   fmt.Sprintf("0x%X", recAddr),
			Offset: fmt.Sprintf("+%05X", recAddr-seg.Base),
			Fields: fvals,
		})
	}

	if format == "json" {
		b, err := json.MarshalIndent(map[string]any{
			"struct":  structName,
			"stride":  stride,
			"count":   len(records),
			"records": records,
		}, "", "  ")
		if err != nil {
			return "", err
		}
		return string(b) + "\n", nil
	}

	var out strings.Builder
	fmt.Fprintf(&out, "=== Struct %s @ %s [+%05X / $%X] (stride %d bytes, %d record(s)) ===\n",
		structName, lbl, addr-seg.Base, addr, stride, len(records))
	for _, r := range records {
		fmt.Fprintf(&out, "  [%d] %s (%s):\n", r.Index, r.Offset, r.Addr)
		for _, fv := range r.Fields {
			tgt := ""
			if fv.Target != "" {
				tgt = " -> " + fv.Target
			}
			fmt.Fprintf(&out, "    +%-3d %-22s = %-10s (%d)%s\n", fv.Offset, fv.Field, fv.Hex, fv.Dec, tgt)
		}
	}
	return out.String(), nil
}

// --- §3: hunks xref ---

type xrefHitJSON struct {
	SourceAddr string `json:"source_addr"`
	Segment    string `json:"segment"`
	Offset     string `json:"offset"`
	Func       string `json:"func,omitempty"`
	FnOffset   string `json:"fn_offset,omitempty"`
	Kind       string `json:"kind"`
	Insn       string `json:"insn"`
	TargetAddr string `json:"target_addr"`
}

func collectXrefsToRange(proj *project.Project, fallbackCtrl *db.Controller, startAddr, endAddr uint32, externalOnly bool) []db.Xref {
	var rawXrefs []db.Xref
	seenDBs := make(map[string]bool)
	for _, seg := range proj.ActiveSegments() {
		if seenDBs[seg.DB] {
			continue
		}
		seenDBs[seg.DB] = true
		func(dbPath string) {
			ctrl, err := db.New(dbPath)
			if err != nil {
				return
			}
			defer ctrl.Close()
			proj.SyncDBScope(ctrl)
			rawXrefs = append(rawXrefs, ctrl.GetXrefsToRange(startAddr, endAddr, externalOnly)...)
		}(seg.DB)
	}
	if len(seenDBs) == 0 && fallbackCtrl != nil {
		rawXrefs = fallbackCtrl.GetXrefsToRange(startAddr, endAddr, externalOnly)
	}
	return rawXrefs
}

func runXrefCommand(
	proj *project.Project,
	ctrl *db.Controller,
	cg *callgraph.CallGraph,
	spec string,
	format string,
) (string, error) {
	trimmed := strings.TrimSpace(spec)
	if startPart, endPart, isRange := strings.Cut(trimmed, ".."); isRange {
		startAddr, err := resolveAddrOrLabel(proj, ctrl, strings.TrimSpace(startPart))
		if err != nil {
			return "", fmt.Errorf("invalid range start %q: %w", startPart, err)
		}
		endAddr, err := resolveAddrOrLabel(proj, ctrl, strings.TrimSpace(endPart))
		if err != nil {
			return "", fmt.Errorf("invalid range end %q: %w", endPart, err)
		}
		if endAddr < startAddr {
			startAddr, endAddr = endAddr, startAddr
		}
		return renderXrefRange(proj, ctrl, cg, startAddr, endAddr, format)
	}

	var targetAddr uint32
	if hwEqs := amiga.GetAllEquates(); len(hwEqs) > 0 {
		for k, v := range hwEqs {
			if strings.EqualFold(k, trimmed) {
				targetAddr = v
				break
			}
		}
	}
	if targetAddr == 0 {
		var err error
		targetAddr, err = resolveAddrOrLabel(proj, ctrl, trimmed)
		if err != nil {
			return "", fmt.Errorf("cannot resolve address or label %q: %w", trimmed, err)
		}
	}

	rawXrefs := collectXrefsToRange(proj, ctrl, targetAddr, targetAddr, false)
	hits := formatXrefHits(proj, cg, rawXrefs, 0, 0, false)

	lbl := cg.Labels[targetAddr]
	if lbl == "" {
		if hw, ok := amiga.GetAmigaHWLabel(targetAddr); ok {
			lbl = hw
		} else {
			lbl = fmt.Sprintf("$%X", targetAddr)
		}
	}

	if format == "json" {
		b, err := json.MarshalIndent(map[string]any{
			"target_addr":  fmt.Sprintf("0x%X", targetAddr),
			"target_label": lbl,
			"count":        len(hits),
			"xrefs":        hits,
		}, "", "  ")
		if err != nil {
			return "", err
		}
		return string(b) + "\n", nil
	}

	var out strings.Builder
	fmt.Fprintf(&out, "=== XREFs to %s ($%X) — %d reference(s) ===\n", lbl, targetAddr, len(hits))
	if len(hits) == 0 {
		out.WriteString("  (none)\n")
		return out.String(), nil
	}
	for _, h := range hits {
		ctx := "[DATA]"
		if h.Func != "" {
			ctx = fmt.Sprintf("[%s%s]", h.Func, h.FnOffset)
		}
		fmt.Fprintf(&out, "  %-10s %s  %-26s %s\n", h.Kind, h.Offset, ctx, h.Insn)
	}
	return out.String(), nil
}

func renderXrefRange(
	proj *project.Project,
	ctrl *db.Controller,
	cg *callgraph.CallGraph,
	startAddr, endAddr uint32,
	format string,
) (string, error) {
	rawXrefs := collectXrefsToRange(proj, ctrl, startAddr, endAddr, true)
	// Exclude internal references where source is also inside [startAddr, endAddr].
	hits := formatXrefHits(proj, cg, rawXrefs, startAddr, endAddr, true)

	type targetSummary struct {
		TargetAddr  string   `json:"target_addr"`
		TargetLabel string   `json:"target_label,omitempty"`
		Reads       int      `json:"reads"`
		Writes      int      `json:"writes"`
		Calls       int      `json:"calls"`
		Branches    int      `json:"branches"`
		Addrs       int      `json:"addrs"`
		Ptrs        int      `json:"ptrs"`
		Accessors   []string `json:"accessors"`
	}
	byTarget := make(map[uint32]*targetSummary)
	for _, h := range hits {
		tAddr, _ := project.ParseHex(h.TargetAddr)
		ts, ok := byTarget[tAddr]
		if !ok {
			lbl := cg.Labels[tAddr]
			if lbl == "" {
				if hw, ok := amiga.GetAmigaHWLabel(tAddr); ok {
					lbl = hw
				}
			}
			ts = &targetSummary{
				TargetAddr:  fmt.Sprintf("0x%X", tAddr),
				TargetLabel: lbl,
			}
			byTarget[tAddr] = ts
		}
		switch h.Kind {
		case "READ":
			ts.Reads++
		case "WRITE":
			ts.Writes++
		case "CALL":
			ts.Calls++
		case "BRANCH":
			ts.Branches++
		case "PTR":
			ts.Ptrs++
		default:
			ts.Addrs++
		}
		acc := h.Offset
		if h.Func != "" {
			acc = fmt.Sprintf("%s%s (%s)", h.Func, h.FnOffset, h.Kind)
		}
		if len(ts.Accessors) < 6 && !slices.Contains(ts.Accessors, acc) {
			ts.Accessors = append(ts.Accessors, acc)
		}
	}

	sortedTargets := slices.Sorted(maps.Keys(byTarget))
	summaries := make([]*targetSummary, len(sortedTargets))
	for i, k := range sortedTargets {
		summaries[i] = byTarget[k]
	}

	if format == "json" {
		b, err := json.MarshalIndent(map[string]any{
			"start":   fmt.Sprintf("0x%X", startAddr),
			"end":     fmt.Sprintf("0x%X", endAddr),
			"targets": summaries,
			"xrefs":   hits,
		}, "", "  ")
		if err != nil {
			return "", err
		}
		return string(b) + "\n", nil
	}

	var out strings.Builder
	fmt.Fprintf(&out, "=== External XREF Rollup for [$%X..$%X] (%d target(s), %d external ref(s)) ===\n",
		startAddr, endAddr, len(summaries), len(hits))
	for _, ts := range summaries {
		lbl := ""
		if ts.TargetLabel != "" {
			lbl = " (" + ts.TargetLabel + ")"
		}
		fmt.Fprintf(&out, "  %-10s%-20s R:%-2d W:%-2d C:%-2d B:%-2d P:%-2d | %s\n",
			ts.TargetAddr, lbl, ts.Reads, ts.Writes, ts.Calls, ts.Branches, ts.Ptrs,
			strings.Join(ts.Accessors, ", "))
	}
	return out.String(), nil
}

func formatXrefHits(
	proj *project.Project,
	cg *callgraph.CallGraph,
	rawXrefs []db.Xref,
	excludeStart, excludeEnd uint32,
	excludeInternal bool,
) []xrefHitJSON {
	var hits []xrefHitJSON
	for _, x := range rawXrefs {
		if excludeInternal && x.Source >= excludeStart && x.Source <= excludeEnd {
			continue
		}
		seg := proj.SegmentAtAddr(x.Source)
		segName := "?"
		var segOff uint32
		if seg != nil {
			segName = seg.Name
			if x.Source >= seg.Base {
				segOff = x.Source - seg.Base
			}
		}
		var fnName, fnOff string
		if fAddr, ok := cg.InsnToFunc[x.Source]; ok {
			if f, ok := cg.Functions[fAddr]; ok {
				fnName = f.Name
				fnOff = formatFnOffset(x.Source, f.EntryAddr)
			}
		}
		kindStr := "ADDR"
		switch x.Kind {
		case db.XrefDataRead:
			kindStr = "READ"
		case db.XrefDataWrite:
			kindStr = "WRITE"
		case db.XrefCodeCall:
			kindStr = "CALL"
		case db.XrefCodeBranch:
			kindStr = "BRANCH"
		}
		insnStr := ""
		if c, ok := cg.Cells[x.Source]; ok {
			if c.Type == db.CellPointer {
				kindStr = "PTR"
				insnStr = "dc.l " + c.OpStrVal()
			} else {
				mnem := c.MnemonicStr()
				ops := c.OpStrVal()
				insnStr = strings.TrimSpace(fmt.Sprintf("%-8s %s", mnem, ops))
			}
		}
		hits = append(hits, xrefHitJSON{
			SourceAddr: fmt.Sprintf("0x%X", x.Source),
			Segment:    segName,
			Offset:     fmt.Sprintf("+%05X", segOff),
			Func:       fnName,
			FnOffset:   fnOff,
			Kind:       kindStr,
			Insn:       insnStr,
			TargetAddr: fmt.Sprintf("0x%X", x.Target),
		})
	}
	return hits
}

// --- §5: struct / alias rendering ---

func renderStructList(proj *project.Project, format string) error {
	if format == "json" {
		b, err := json.MarshalIndent(proj.Data.Structs, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}
	if len(proj.Data.Structs) == 0 {
		fmt.Println("No structs defined.")
		return nil
	}
	for _, sname := range slices.Sorted(maps.Keys(proj.Data.Structs)) {
		sdef := proj.Data.Structs[sname]
		sz := sdef["_size"]
		if sz != "" {
			fmt.Printf("  %s (size %s bytes):\n", sname, sz)
		} else {
			fmt.Printf("  %s:\n", sname)
		}
		var offs []int
		for k := range sdef {
			if k == "_size" {
				continue
			}
			if v, err := strconv.Atoi(k); err == nil {
				offs = append(offs, v)
			}
		}
		slices.Sort(offs)
		for _, off := range offs {
			fmt.Printf("    +%-4d ($%02X)  %s\n", off, uint32(off), sdef[strconv.Itoa(off)])
		}
	}
	return nil
}

func renderAliasList(proj *project.Project, format string) error {
	if format == "json" {
		b, err := json.MarshalIndent(proj.Data.RegisterAliases, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}
	if len(proj.Data.RegisterAliases) == 0 {
		fmt.Println("No register aliases defined.")
		return nil
	}
	for _, k := range slices.Sorted(maps.Keys(proj.Data.RegisterAliases)) {
		fmt.Printf("  %-28s -> %s\n", k, proj.Data.RegisterAliases[k])
	}
	return nil
}

// --- §6: strict comment offset validation ---

func resolveStrictCommentAddr(proj *project.Project, ctrl *db.Controller, cg *callgraph.CallGraph, addrStr string) (uint32, string, error) {
	s := strings.TrimSpace(addrStr)
	if basePart, dispPart, hasPlus := strings.Cut(s, "+"); hasPlus && strings.TrimSpace(basePart) != "" {
		baseTrim := strings.TrimSpace(basePart)
		disp, err := project.ParseHex(strings.TrimSpace(dispPart))
		if err == nil {
			if fnEntry, ok := cg.ResolveTarget(proj, baseTrim, ""); ok {
				if f, isF := cg.Functions[fnEntry]; isF {
					cand := fnEntry + disp
					fnEnd := fnEntry + f.ByteSize
					if len(f.InsnAddrs) > 0 {
						lastIA := f.InsnAddrs[len(f.InsnAddrs)-1]
						if lastC, ok := cg.Cells[lastIA]; ok && lastIA+lastC.Size > fnEnd {
							fnEnd = lastIA + lastC.Size
						}
					}
					var note string
					if cand >= fnEnd {
						// Check if disp was actually a segment offset (+051CC instead of +1CC).
						segBase := f.EntryAddr - f.OffsetInSeg
						segCand := segBase + disp
						if segCand >= fnEntry && segCand < fnEnd {
							if c, ok := cg.Cells[segCand]; ok && c.Type == db.CellCode {
								fnRel := segCand - fnEntry
								note = fmt.Sprintf("Note: resolved %s as segment offset +%05X (function-relative: %s+%X)",
									s, disp, f.Name, fnRel)
								return segCand, note, nil
							}
						}
						return 0, "", fmt.Errorf("offset +%X lands at $%X, which is outside function %s ($%X..$%X, size $%X bytes)",
							disp, cand, f.Name, fnEntry, fnEnd, fnEnd-fnEntry)
					}
					if c, ok := cg.Cells[cand]; ok && c.Addr == cand {
						return cand, note, nil
					}
					// Misaligned inside an instruction! Find nearest valid instruction offsets.
					var prevOff, nextOff uint32
					for _, ia := range f.InsnAddrs {
						if ia < cand {
							prevOff = ia - fnEntry
						} else if ia > cand {
							nextOff = ia - fnEntry
							break
						}
					}
					return 0, "", fmt.Errorf("offset %s+%X ($%X) lands mid-instruction; nearest valid instruction offsets in %s are +%X and +%X",
						f.Name, disp, cand, f.Name, prevOff, nextOff)
				}
			}
		}
	}

	addr, err := resolveAddrOrLabel(proj, ctrl, s)
	if err != nil {
		return 0, "", err
	}
	// Check if addr lands mid-instruction in any CODE cell.
	var midCell *db.Cell
	cg.CellsTree.DescendLessOrEqual(db.Cell{Addr: addr}, func(c db.Cell) bool {
		if c.Type == db.CellCode && addr > c.Addr && addr < c.Addr+c.Size {
			cp := c
			midCell = &cp
		}
		return false
	})
	if midCell != nil {
		return 0, "", fmt.Errorf("address $%X lands mid-instruction inside %d-byte instruction %q at $%X (next instruction at $%X)",
			addr, midCell.Size, midCell.MnemonicStr()+" "+midCell.OpStrVal(), midCell.Addr, midCell.Addr+midCell.Size)
	}
	return addr, "", nil
}

// --- §7: hunks abi ---

func runABICommand(
	proj *project.Project,
	args []string,
	batchFile string,
	verify bool,
	format string,
	resolveCallerPath func(string) string,
) error {
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

	if batchFile != "" {
		var r io.Reader
		if batchFile == "-" {
			r = os.Stdin
		} else {
			f, err := os.Open(resolveCallerPath(batchFile))
			if err != nil {
				return err
			}
			defer f.Close()
			r = f
		}
		scanner := bufio.NewScanner(r)
		count := 0
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			fnPart, sigPart, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			fnAddr, ok := cg.ResolveTarget(proj, strings.TrimSpace(fnPart), "")
			if !ok {
				return fmt.Errorf("unknown function %q in ABI batch file", strings.TrimSpace(fnPart))
			}
			sig := strings.TrimSpace(sigPart)
			fnName := proj.AutoLabel(fnAddr)
			if f, ok := cg.Functions[fnAddr]; ok {
				fnName = f.Name
			}
			proj.SetFunctionABI(fnName, sig)
			if f, ok := cg.Functions[fnAddr]; ok {
				f.ABI = sig
				for _, w := range callgraph.VerifyABI(sig, f.InRegs, f.ModRegs, f.SavedRegs) {
					fmt.Fprintf(os.Stderr, "Warning (%s): %s\n", f.Name, w)
				}
			}
			count++
		}
		if err := scanner.Err(); err != nil {
			return err
		}
		if err := proj.Save(); err != nil {
			return err
		}
		fmt.Printf("Updated %d function ABI signature(s)\n", count)
		return nil
	}

	if len(args) == 2 {
		fnAddr, ok := cg.ResolveTarget(proj, args[0], "")
		if !ok {
			return fmt.Errorf("function %q not found", args[0])
		}
		sig := strings.TrimSpace(args[1])
		f := cg.Functions[fnAddr]
		proj.SetFunctionABI(f.Name, sig)
		if err := proj.Save(); err != nil {
			return err
		}
		f.ABI = sig
		warnings := callgraph.VerifyABI(sig, f.InRegs, f.ModRegs, f.SavedRegs)
		for _, w := range warnings {
			fmt.Fprintf(os.Stderr, "Warning (%s): %s\n", f.Name, w)
		}
		fmt.Printf("Set ABI for %s (+%05X): %s\n", f.Name, f.OffsetInSeg, sig)
		return nil
	}

	if len(args) == 1 {
		fnAddr, ok := cg.ResolveTarget(proj, args[0], "")
		if !ok {
			return fmt.Errorf("function %q not found", args[0])
		}
		f := cg.Functions[fnAddr]
		warnings := callgraph.VerifyABI(f.ABI, f.InRegs, f.ModRegs, f.SavedRegs)
		if format == "json" {
			b, err := json.MarshalIndent(map[string]any{
				"function":   f.Name,
				"addr":       fmt.Sprintf("0x%X", f.EntryAddr),
				"offset":     fmt.Sprintf("+%05X", f.OffsetInSeg),
				"abi":        f.ABI,
				"in_regs":    f.InRegs,
				"mod_regs":   f.ModRegs,
				"saved_regs": f.SavedRegs,
				"warnings":   warnings,
			}, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(b))
			return nil
		}
		fmt.Printf("  %s [+%05X]:\n", f.Name, f.OffsetInSeg)
		if f.ABI != "" {
			fmt.Printf("    ABI:           %s\n", f.ABI)
		}
		fmt.Printf("    Regs (static): %s\n", f.StaticABISummary())
		for _, w := range warnings {
			fmt.Printf("    [!] %s\n", w)
		}
		return nil
	}

	// List all functions with user-defined ABI (or all functions if --verify).
	type abiRow struct {
		Func      string   `json:"func"`
		Addr      string   `json:"addr"`
		Offset    string   `json:"offset"`
		ABI       string   `json:"abi"`
		InRegs    []string `json:"in_regs"`
		ModRegs   []string `json:"mod_regs"`
		SavedRegs []string `json:"saved_regs,omitempty"`
		Warnings  []string `json:"warnings,omitempty"`
	}
	var rows []abiRow
	for _, addr := range cg.FuncAddrs {
		f := cg.Functions[addr]
		if f.ABI == "" && !verify {
			continue
		}
		var warnings []string
		if f.ABI != "" {
			warnings = callgraph.VerifyABI(f.ABI, f.InRegs, f.ModRegs, f.SavedRegs)
		}
		if verify && f.ABI != "" && len(warnings) == 0 {
			continue
		}
		if verify && f.ABI == "" {
			continue
		}
		rows = append(rows, abiRow{
			Func:      f.Name,
			Addr:      fmt.Sprintf("0x%X", f.EntryAddr),
			Offset:    fmt.Sprintf("+%05X", f.OffsetInSeg),
			ABI:       f.ABI,
			InRegs:    f.InRegs,
			ModRegs:   f.ModRegs,
			SavedRegs: f.SavedRegs,
			Warnings:  warnings,
		})
	}
	if format == "json" {
		b, err := json.MarshalIndent(rows, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}
	if len(rows) == 0 {
		if verify {
			fmt.Println("All user-defined function ABI signatures are consistent with static register usage.")
		} else {
			fmt.Println("No user-defined ABI signatures set.")
		}
		return nil
	}
	for _, r := range rows {
		fmt.Printf("  %-28s [%s] ABI: %s\n", r.Func, r.Offset, r.ABI)
		for _, w := range r.Warnings {
			fmt.Printf("    [!] %s\n", w)
		}
	}
	return nil
}

// --- §8: hunks dump ---

func runDumpCommand(proj *project.Project, section string, format string) (string, error) {
	cg, err := callgraph.Build(proj)
	if err != nil {
		return "", err
	}

	type renameEntry struct {
		Addr    string `json:"addr"`
		Segment string `json:"segment"`
		Offset  string `json:"offset"`
		OldName string `json:"old_name"`
		NewName string `json:"new_name"`
		ABI     string `json:"abi,omitempty"`
	}
	type commentEntry struct {
		Addr         string `json:"addr"`
		Segment      string `json:"segment"`
		Offset       string `json:"offset"`
		Func         string `json:"func,omitempty"`
		FnOffset     string `json:"fn_offset,omitempty"`
		Comment      string `json:"comment,omitempty"`
		BlockComment string `json:"block_comment,omitempty"`
	}
	type carveEntry struct {
		Addr    string `json:"addr"`
		Segment string `json:"segment"`
		Size    uint32 `json:"size"`
		File    string `json:"file"`
	}

	renames := []renameEntry{}
	for _, addr := range slices.Sorted(maps.Keys(cg.Labels)) {
		newName := cg.Labels[addr]
		rawName := cg.RawLabels[addr]
		if rawName == "" {
			rawName = proj.AutoLabel(addr)
		}
		if newName == rawName && strings.HasPrefix(newName, "LAB_") {
			continue
		}
		seg := proj.SegmentAtAddr(addr)
		segName := ""
		var off uint32
		if seg != nil {
			segName = seg.Name
			if addr >= seg.Base {
				off = addr - seg.Base
			}
		}
		var abi string
		if f, ok := cg.Functions[addr]; ok {
			abi = f.ABI
		}
		renames = append(renames, renameEntry{
			Addr:    fmt.Sprintf("0x%X", addr),
			Segment: segName,
			Offset:  fmt.Sprintf("+%05X", off),
			OldName: rawName,
			NewName: newName,
			ABI:     abi,
		})
	}

	userComments := []commentEntry{}
	carves := []carveEntry{}
	seenDBs := make(map[string]bool)
	for _, seg := range proj.ActiveSegments() {
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
			for _, ac := range ctrl.GetUserComments() {
				addr := ac.Addr
				s := proj.SegmentAtAddr(addr)
				segName := ""
				var off uint32
				if s != nil {
					segName = s.Name
					if addr >= s.Base {
						off = addr - s.Base
					}
				}
				var fnName, fnOff string
				if fAddr, ok := cg.InsnToFunc[addr]; ok {
					if f, ok := cg.Functions[fAddr]; ok {
						fnName = f.Name
						fnOff = formatFnOffset(addr, f.EntryAddr)
					}
				}
				userComments = append(userComments, commentEntry{
					Addr:         fmt.Sprintf("0x%X", addr),
					Segment:      segName,
					Offset:       fmt.Sprintf("+%05X", off),
					Func:         fnName,
					FnOffset:     fnOff,
					Comment:      ac.Comment,
					BlockComment: ac.BlockComment,
				})
			}
			return nil
		}(seg.DB); err != nil {
			return "", err
		}
	}

	for _, addr := range slices.Sorted(maps.Keys(cg.Cells)) {
		c := cg.Cells[addr]
		if c.Type == db.CellIncbin {
			carves = append(carves, carveEntry{
				Addr:    fmt.Sprintf("0x%X", c.Addr),
				Segment: c.Seg,
				Size:    c.Size,
				File:    c.OpStrVal(),
			})
		}
	}

	payload := map[string]any{
		"target_name":      proj.Data.TargetName,
		"entry_points":     proj.Data.EntryPoints,
		"memory_regions":   proj.Data.MemoryRegions,
		"renames":          renames,
		"comments":         userComments,
		"structs":          proj.Data.Structs,
		"register_aliases": proj.Data.RegisterAliases,
		"function_abis":    proj.Data.FunctionABIs,
		"carves":           carves,
	}
	if section != "" {
		secKey := strings.ToLower(strings.TrimSpace(section))
		switch secKey {
		case "entries", "entry_points":
			payload = map[string]any{"entry_points": proj.Data.EntryPoints}
		case "regions", "memory_regions":
			payload = map[string]any{"memory_regions": proj.Data.MemoryRegions}
		case "renames":
			payload = map[string]any{"renames": renames}
		case "comments":
			payload = map[string]any{"comments": userComments}
		case "structs":
			payload = map[string]any{"structs": proj.Data.Structs}
		case "aliases", "register_aliases":
			payload = map[string]any{"register_aliases": proj.Data.RegisterAliases}
		case "abis", "function_abis":
			payload = map[string]any{"function_abis": proj.Data.FunctionABIs}
		case "carves":
			payload = map[string]any{"carves": carves}
		default:
			return "", fmt.Errorf("unknown dump section %q", section)
		}
	}

	if format == "json" {
		b, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return "", err
		}
		return string(b) + "\n", nil
	}

	var out strings.Builder
	fmt.Fprintf(&out, "=== Project Dump (%s) ===\n", proj.Data.TargetName)
	fmt.Fprintf(&out, "  Renames: %d | User Comments: %d | Regions: %d | Structs: %d | Aliases: %d | Carves: %d\n\n",
		len(renames), len(userComments), len(proj.Data.MemoryRegions), len(proj.Data.Structs), len(proj.Data.RegisterAliases), len(carves))
	if len(renames) > 0 && (section == "" || section == "renames") {
		out.WriteString("=== Renames ===\n")
		for _, r := range renames {
			abi := ""
			if r.ABI != "" {
				abi = " [ABI: " + r.ABI + "]"
			}
			fmt.Fprintf(&out, "  %s (%s)  %s -> %s%s\n", r.Offset, r.Addr, r.OldName, r.NewName, abi)
		}
		out.WriteByte('\n')
	}
	if len(userComments) > 0 && (section == "" || section == "comments") {
		out.WriteString("=== User Comments ===\n")
		for _, c := range userComments {
			ctx := c.Offset
			if c.Func != "" {
				ctx = fmt.Sprintf("%s (%s%s)", c.Offset, c.Func, c.FnOffset)
			}
			if c.BlockComment != "" {
				fmt.Fprintf(&out, "  %s [block]: %s\n", ctx, strings.ReplaceAll(c.BlockComment, "\n", " // "))
			}
			if c.Comment != "" {
				fmt.Fprintf(&out, "  %s: %s\n", ctx, c.Comment)
			}
		}
		out.WriteByte('\n')
	}
	return out.String(), nil
}
