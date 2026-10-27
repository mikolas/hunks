package tui

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/mikolas/hunks/internal/amiga"
	"github.com/mikolas/hunks/internal/db"
	"github.com/mikolas/hunks/internal/hunk"
	"github.com/mikolas/hunks/internal/m68k"
	"github.com/mikolas/hunks/internal/project"
)

func isExplicitCell(c *db.Cell) bool {
	if c == nil {
		return false
	}
	switch c.Type {
	case db.CellCode, db.CellStr, db.CellPointer, db.CellIncbin:
		return true
	case db.CellDataB, db.CellDataZero:
		return false
	default:
		return c.Confidence >= 100
	}
}

func isPrintableASCII(b byte) bool {
	return b >= 0x20 && b <= 0x7E
}

// buildASCIIBoxAndMask formats raw (1..16 bytes) into a 16-char │...│ ASCII box and computes
// a 16-bit bitmask of bytes belonging to a >= 4-byte printable ASCII run.
func buildASCIIBoxAndMask(raw []byte) (string, uint16) {
	n := min(len(raw), 16)
	var sb strings.Builder
	sb.Grow(22)
	sb.WriteString("│")
	for i := range n {
		if isPrintableASCII(raw[i]) {
			sb.WriteByte(raw[i])
		} else {
			sb.WriteByte('.')
		}
	}
	for i := n; i < 16; i++ {
		sb.WriteByte(' ')
	}
	sb.WriteString("│")

	var mask uint16
	i := 0
	for i < n {
		if !isPrintableASCII(raw[i]) {
			i++
			continue
		}
		j := i + 1
		for j < n && isPrintableASCII(raw[j]) {
			j++
		}
		if j-i >= 4 {
			for k := i; k < j; k++ {
				mask |= 1 << uint(k)
			}
		}
		i = j
	}
	return sb.String(), mask
}

func findContainingCellInSlice(cells []db.Cell, addr uint32) *db.Cell {
	lo, hi := 0, len(cells)
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if cells[mid].Addr <= addr {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo > 0 && addr < cells[lo-1].Addr+cells[lo-1].Size {
		return &cells[lo-1]
	}
	return nil
}

func findContainingSpanInSlice(spans []db.CellSpan, addr uint32) (db.CellSpan, bool) {
	lo, hi := 0, len(spans)
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if spans[mid].Addr <= addr {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo > 0 && addr < spans[lo-1].Addr+spans[lo-1].Size {
		return spans[lo-1], true
	}
	return db.CellSpan{}, false
}

func isCellAlignedInSpace(spans []db.CellSpan, addr uint32) bool {
	span, ok := findContainingSpanInSlice(spans, addr)
	return !ok || span.Addr == addr
}

func isAllHex(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func resolveFlatCrossSegOperandsTUI(
	proj *project.Project,
	mnem string,
	opStr string,
	baseAddr, endAddr uint32,
	allLabels map[uint32]string,
	cellSpans []db.CellSpan,
	curSeg string,
) (rewrittenOp string, hint string, firstTarget *uint32) {
	if opStr == "" || !strings.Contains(opStr, "$") {
		return opStr, "", nil
	}

	var tokBuf [4]string
	tokens := tokBuf[:0]
	depth := 0
	last := 0
	for i := range len(opStr) {
		switch opStr[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				tokens = append(tokens, opStr[last:i])
				last = i + 1
			}
		}
	}
	tokens = append(tokens, opStr[last:])

	op, sz := m68k.ParseMnemonic(mnem)
	isLong := op.HasLongEA(sz)

	var outBuf [4]string
	outTokens := outBuf[:0]
	rewritten := false

	for _, rawTok := range tokens {
		tok := strings.TrimSpace(rawTok)
		var matchedTarget uint32
		var isAbsLong bool
		var matched bool

		if afterDollar, ok := strings.CutPrefix(tok, "$"); ok {
			if inner, ok := strings.CutSuffix(afterDollar, ".l"); ok && isAllHex(inner) {
				if val, err := strconv.ParseUint(inner, 16, 32); err == nil {
					matchedTarget = uint32(val)
					isAbsLong = true
					matched = true
				}
			}
		} else if isLong {
			if inner, ok := strings.CutPrefix(tok, "#$"); ok && isAllHex(inner) {
				if val, err := strconv.ParseUint(inner, 16, 32); err == nil && val >= 0x100 {
					matchedTarget = uint32(val)
					isAbsLong = false
					matched = true
				}
			}
		}

		if matched && (matchedTarget < baseAddr || matchedTarget >= endAddr) {
			if _, isHW := amiga.GetAmigaHWLabel(matchedTarget); !isHW {
				if lbl, ok := allLabels[matchedTarget]; ok && lbl != "" &&
					!strings.HasPrefix(lbl, "CUSTOM_") &&
					!strings.HasPrefix(lbl, "CIAA_") &&
					!strings.HasPrefix(lbl, "CIAB_") {
					if isCellAlignedInSpace(cellSpans, matchedTarget) {
						rewritten = true
						if isAbsLong {
							outTokens = append(outTokens, lbl+".l")
						} else {
							outTokens = append(outTokens, "#"+lbl)
						}
						if firstTarget == nil {
							tCopy := matchedTarget
							firstTarget = &tCopy
						}
						if hint == "" {
							if tseg := proj.SegmentAtAddr(matchedTarget); tseg != nil && !strings.EqualFold(tseg.Name, curSeg) {
								hint = "→ " + tseg.Name + ":" + lbl
							}
						}
						continue
					}
				}
			}
		}

		outTokens = append(outTokens, rawTok)
	}

	if !rewritten {
		return opStr, "", nil
	}
	return strings.Join(outTokens, ","), hint, firstTarget
}

func wrapCommentLines(text string, maxCols int) []string {
	if maxCols < 20 {
		maxCols = 20
	}
	var out []string
	for _, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSuffix(rawLine, "\r")
		if len(line) <= maxCols {
			out = append(out, line)
			continue
		}
		words := strings.Fields(line)
		if len(words) == 0 {
			out = append(out, "")
			continue
		}
		cur := words[0]
		for _, w := range words[1:] {
			if len(cur)+1+len(w) <= maxCols {
				cur += " " + w
			} else {
				out = append(out, cur)
				cur = w
			}
		}
		out = append(out, cur)
	}
	return out
}

func packXrefBadges(badges []XrefBadge, maxCols int) [][]XrefBadge {
	if len(badges) == 0 {
		return nil
	}
	if maxCols < 30 {
		maxCols = 30
	}
	const prefixLen = 8 // len("; XREF: ")
	var lines [][]XrefBadge
	var cur []XrefBadge
	curLen := prefixLen
	for _, b := range badges {
		addLen := len(b.Text)
		if len(cur) > 0 {
			addLen += 2 // ", "
		}
		if len(cur) > 0 && curLen+addLen > maxCols {
			lines = append(lines, cur)
			cur = []XrefBadge{b}
			curLen = prefixLen + len(b.Text)
		} else {
			cur = append(cur, b)
			curLen += addLen
		}
	}
	if len(cur) > 0 {
		lines = append(lines, cur)
	}
	return lines
}

func formatStringChunks(raw []byte, maxCols int) []string {
	if maxCols < 24 {
		maxCols = 24
	}
	var chunks []string
	var sb strings.Builder
	inStr := false

	flush := func() {
		if inStr {
			sb.WriteByte('"')
			inStr = false
		}
		if sb.Len() > 0 {
			chunks = append(chunks, sb.String())
			sb.Reset()
		}
	}

	for _, b := range raw {
		isASCII := b >= 32 && b <= 126 && b != '"'
		if isASCII {
			need := 1
			if !inStr {
				need = 3 // ,"c" or "c"
			}
			if sb.Len()+need > maxCols && sb.Len() > 0 {
				flush()
			}
			if !inStr {
				if sb.Len() > 0 {
					sb.WriteByte(',')
				}
				sb.WriteByte('"')
				inStr = true
			}
			sb.WriteByte(b)
		} else {
			var hexTok string
			if b == 0 {
				hexTok = "0"
			} else {
				hexTok = fmt.Sprintf("$%02X", b)
			}
			need := len(hexTok) + 1
			if inStr {
				need++ // closing quote
			}
			if sb.Len()+need > maxCols && sb.Len() > 0 {
				flush()
			}
			if inStr {
				sb.WriteByte('"')
				inStr = false
			}
			if sb.Len() > 0 {
				sb.WriteByte(',')
			}
			sb.WriteString(hexTok)
		}
	}
	flush()
	if len(chunks) == 0 {
		chunks = append(chunks, "0")
	}
	return chunks
}

func combineWithHint(cmt, hint string) string {
	switch {
	case cmt == "" && hint == "":
		return ""
	case cmt == "":
		return hint
	case hint == "":
		return cmt
	default:
		if strings.Contains(cmt, "->") || strings.Contains(cmt, "→") {
			return cmt
		}
		return fmt.Sprintf("%s (%s)", cmt, hint)
	}
}

func resolveEOLComment(
	ac db.AddressComment,
	refTarget *uint32,
	targetHint string,
	allTargetComments map[uint32]db.AddressComment,
) (string, CommentStyle) {
	// Priority 1: User EOL Comment on this address
	if ac.Comment != "" {
		return combineWithHint(ac.Comment, targetHint), CommentStyleUser
	}
	// Priority 2: Referenced Target's Comment (when this row has no user comment)
	if refTarget != nil {
		if tac, ok := allTargetComments[*refTarget]; ok {
			var refText string
			if tac.BlockComment != "" {
				firstLine, _, _ := strings.Cut(tac.BlockComment, "\n")
				refText = strings.TrimSpace(strings.TrimSuffix(firstLine, "\r"))
			} else if tac.Comment != "" {
				firstLine, _, _ := strings.Cut(tac.Comment, "\n")
				refText = strings.TrimSpace(strings.TrimSuffix(firstLine, "\r"))
			}
			if refText != "" {
				return combineWithHint(refText, targetHint), CommentStyleRef
			}
		}
	}
	// Priority 3: Analyzer/Trace Auto-Comment or targetHint
	if ac.AutoComment != "" || targetHint != "" {
		return combineWithHint(ac.AutoComment, targetHint), CommentStyleAuto
	}
	return "", CommentStyleNone
}

func badgeTypePriority(typ string) int {
	switch typ {
	case "CALL", "CODE_CALL":
		return 1
	case "UNCOND", "COND_TRUE", "CODE_BRANCH":
		return 2
	case "DATA_WRITE":
		return 3
	case "DATA_READ":
		return 4
	case "DATA_ADDR":
		return 5
	default:
		return 6
	}
}

func buildXrefBadgesMap(
	proj *project.Project,
	startAddr, endAddr uint32,
	incoming []db.XrefRecord,
	vecXrefs map[uint32][]db.AddrText,
	localCells []db.Cell,
	cellSpans []db.CellSpan,
	allLabels map[uint32]string,
	sortedLabelAddrs []uint32,
) map[uint32][]XrefBadge {
	type rawCaller struct {
		srcAddr      uint32
		recType      string
		overrideMnem string
	}

	byTarget := make(map[uint32][]rawCaller)
	for _, r := range incoming {
		byTarget[r.TargetAddr] = append(byTarget[r.TargetAddr], rawCaller{
			srcAddr: r.SourceAddr,
			recType: r.Type,
		})
	}
	for targetAddr, vcs := range vecXrefs {
		if targetAddr < startAddr || targetAddr >= endAddr {
			continue
		}
		for _, vc := range vcs {
			mnem, _, _ := strings.Cut(vc.Text, " ")
			byTarget[targetAddr] = append(byTarget[targetAddr], rawCaller{
				srcAddr:      vc.Addr,
				recType:      "CALL",
				overrideMnem: mnem,
			})
		}
	}

	out := make(map[uint32][]XrefBadge, len(byTarget))
	for targetAddr, callers := range byTarget {
		slices.SortFunc(callers, func(a, b rawCaller) int {
			if c := cmp.Compare(a.srcAddr, b.srcAddr); c != 0 {
				return c
			}
			return cmp.Compare(badgeTypePriority(a.recType), badgeTypePriority(b.recType))
		})

		seenCaller := make(map[uint32]struct{}, len(callers))
		badges := make([]XrefBadge, 0, len(callers))
		for _, caller := range callers {
			rawSrc := caller.srcAddr
			var snappedAddr uint32
			var mnem string
			var isPtrCell bool

			if caller.overrideMnem != "" {
				snappedAddr = rawSrc
				mnem = caller.overrideMnem
			} else if rawSrc >= startAddr && rawSrc < endAddr && len(localCells) > 0 {
				if c := findContainingCellInSlice(localCells, rawSrc); c != nil {
					if allLabels[targetAddr] == "" && c.Type == db.CellCode &&
						(strings.HasSuffix(c.OpStrVal(), ".w") || strings.Contains(c.OpStrVal(), ".w,")) {
						continue
					}
					snappedAddr = c.Addr
					mnem = c.MnemonicStr()
					if c.Type == db.CellPointer || c.Type == db.CellDataL {
						isPtrCell = true
						if mnem == "" {
							mnem = "dc.l"
						}
					}
				} else {
					snappedAddr = rawSrc
				}
			} else if span, ok := findContainingSpanInSlice(cellSpans, rawSrc); ok {
				snappedAddr = span.Addr
				mnem = span.Mnemonic
				if mnem == "dc.l" {
					isPtrCell = true
				}
			} else {
				snappedAddr = rawSrc
			}

			if _, dup := seenCaller[snappedAddr]; dup {
				continue
			}
			seenCaller[snappedAddr] = struct{}{}

			callerSeg := proj.SegmentAtAddr(snappedAddr)
			var callerSegBase uint32
			if callerSeg != nil {
				callerSegBase = callerSeg.Base
			}
			idx, found := slices.BinarySearch(sortedLabelAddrs, snappedAddr)
			if found {
				idx++
			}
			var enclosingLabel string
			if idx > 0 && sortedLabelAddrs[idx-1] >= callerSegBase {
				enclosingLabel = allLabels[sortedLabelAddrs[idx-1]]
			} else {
				enclosingLabel = proj.AutoLabel(snappedAddr)
			}

			callerRef := enclosingLabel
			if callerSeg != nil && callerSeg.Base != startAddr {
				callerRef = fmt.Sprintf("%s:%s", callerSeg.Name, enclosingLabel)
			}

			var suffix string
			switch caller.recType {
			case "DATA_WRITE":
				suffix = "W"
			case "DATA_READ":
				suffix = "R"
			case "DATA_ADDR":
				if isPtrCell {
					suffix = "*"
				} else if mnem != "" {
					suffix = mnem
				} else {
					suffix = "*"
				}
			default:
				if mnem != "" {
					suffix = mnem
				} else {
					suffix = caller.recType
				}
			}

			badges = append(badges, XrefBadge{
				CallerAddr: snappedAddr,
				Text:       fmt.Sprintf("%s:%X(%s)", callerRef, snappedAddr, suffix),
			})
		}
		if len(badges) > 0 {
			out[targetAddr] = badges
		}
	}
	return out
}

// BuildListingRows constructs the width-aware Sub-Row listing view model for seg.
// It is completely decoupled from internal/emitter and never mutates database state.
func BuildListingRows(
	proj *project.Project,
	ctrl *db.Controller,
	seg *project.Segment,
	width int,
) ([]ListingRow, uint32, error) {
	if seg == nil {
		return nil, 0, fmt.Errorf("no active segment")
	}
	return buildListingRowsWithData(proj, ctrl, seg, seg.LoadBinaryData(), width)
}

func buildListingRowsWithData(
	proj *project.Project,
	ctrl *db.Controller,
	seg *project.Segment,
	binData []byte,
	width int,
) ([]ListingRow, uint32, error) {
	if seg == nil {
		return nil, 0, fmt.Errorf("no active segment")
	}
	proj.SyncDBScope(ctrl)

	innerWidth := max(width-2, 60)
	commentWrapWidth := max(innerWidth-14, 30)
	xrefWrapWidth := max(innerWidth-60, 30)
	stringWrapWidth := max(innerWidth-24, 24)

	baseAddr := seg.Base
	dataEnd := baseAddr + uint32(len(binData))
	allocEnd := max(seg.EndAddr(), dataEnd)
	queryEnd := max(allocEnd, baseAddr+1)

	allLabels, err := ctrl.GetAllLabelsResolved()
	if err != nil {
		return nil, 0, err
	}
	sortedAllLabelAddrs := slices.Sorted(maps.Keys(allLabels))
	allRelocs, err := ctrl.GetAllRelocs()
	if err != nil || allRelocs == nil {
		allRelocs = make(map[uint32]uint32)
	}
	jmpBases := ctrl.DetectJumpVectorBases()
	vecXrefs := ctrl.GetVectoredCallXrefs(baseAddr, queryEnd, jmpBases, allRelocs)
	cellSpans, _ := ctrl.GetSpaceCellSpans()
	allCells, err := ctrl.CellsInRange(baseAddr, queryEnd)
	if err != nil {
		return nil, 0, err
	}
	commentsMap, _ := ctrl.GetCommentsInRange(baseAddr, queryEnd)
	allTargetComments, _ := ctrl.GetAllTargetComments()
	incomingXrefs, _ := ctrl.IncomingXrefsInRange(baseAddr, queryEnd)
	outgoingTargets, _ := ctrl.OutgoingTargetsInRange(baseAddr, queryEnd)

	crossSegSources := make(map[uint32]bool)
	for _, src := range ctrl.CrossRegionControlSources(baseAddr, queryEnd) {
		crossSegSources[src] = true
	}

	xrefsByTarget := buildXrefBadgesMap(
		proj,
		baseAddr,
		queryEnd,
		incomingXrefs,
		vecXrefs,
		allCells,
		cellSpans,
		allLabels,
		sortedAllLabelAddrs,
	)

	getLabelStr := func(a uint32) string {
		if l, ok := allLabels[a]; ok {
			if strings.HasPrefix(l, "CUSTOM_") || strings.HasPrefix(l, "CIAA_") || strings.HasPrefix(l, "CIAB_") {
				return ""
			}
			return l
		}
		if hw, ok := amiga.GetAmigaHWLabel(a); ok {
			return hw
		}
		return ""
	}

	curSeg := ctrl.ActiveSeg()
	segIsRelocatable := seg.IsRelocatable()
	entryAddrs := make(map[uint32]bool, len(proj.Data.EntryPoints))
	for _, ep := range proj.Data.EntryPoints {
		if ep.Segment == "" || strings.EqualFold(ep.Segment, curSeg) {
			entryAddrs[ep.Addr] = true
		}
	}
	fnEntrySet := make(map[uint32]bool, len(entryAddrs)+16)
	for _, fnAddr := range ctrl.FunctionEntries() {
		fnEntrySet[fnAddr] = true
	}
	for a := range entryAddrs {
		fnEntrySet[a] = true
	}

	var rows []ListingRow
	appendSpacerIfNeeded := func() {
		if len(rows) > 0 && rows[len(rows)-1].Kind != SubRowSpacer {
			rows = append(rows, ListingRow{Kind: SubRowSpacer})
		}
	}

	emitPreSubRows := func(addr uint32, cellSize uint32, cellType string, includeEffInBlock bool, labelIsPrimary bool) {
		ac := commentsMap[addr]
		blockText := ac.BlockComment
		if includeEffInBlock {
			if eff := ac.EffectiveComment(); eff != "" && eff != blockText {
				if blockText != "" {
					blockText = blockText + "\n" + eff
				} else {
					blockText = eff
				}
			}
		}
		badges := xrefsByTarget[addr]
		lbl := getLabelStr(addr)
		if fnEntrySet[addr] {
			if abiStr := proj.GetFunctionABI(lbl, proj.AutoLabel(addr)); abiStr != "" && !strings.Contains(blockText, "ABI:") {
				abiLine := "ABI: " + abiStr
				if blockText != "" {
					blockText = abiLine + "\n" + blockText
				} else {
					blockText = abiLine
				}
			}
		}

		if blockText != "" || len(badges) > 0 || lbl != "" {
			appendSpacerIfNeeded()
		}

		addrCopy := addr
		if blockText != "" {
			for _, line := range wrapCommentLines(blockText, commentWrapWidth) {
				trimmed := strings.TrimSpace(line)
				isBanner := strings.HasPrefix(trimmed, "===") || strings.HasPrefix(trimmed, "---")
				rows = append(rows, ListingRow{
					Addr:         &addrCopy,
					Kind:         SubRowBlockComment,
					Comment:      line,
					IsBannerRule: isBanner,
					CellType:     cellType,
					Size:         cellSize,
				})
			}
		}
		if len(badges) > 0 && lbl == "" {
			lbl = proj.AutoLabel(addr)
		}
		var badgeLines [][]XrefBadge
		if len(badges) > 0 {
			badgeLines = packXrefBadges(badges, xrefWrapWidth)
		}
		if lbl != "" {
			if segIsRelocatable && entryAddrs[addr] {
				rows = append(rows, ListingRow{
					Addr:     &addrCopy,
					Kind:     SubRowDirective,
					Mnem:     "xdef",
					Operands: lbl,
					CellType: cellType,
					Size:     cellSize,
				})
			}
			var firstBadges []XrefBadge
			if len(badgeLines) > 0 {
				firstBadges = badgeLines[0]
			}
			rows = append(rows, ListingRow{
				Addr:      &addrCopy,
				Kind:      SubRowLabel,
				IsPrimary: labelIsPrimary,
				Label:     lbl + ":",
				XrefTotal: len(badges),
				Xrefs:     firstBadges,
				CellType:  cellType,
				Size:      cellSize,
			})
			if len(badgeLines) > 1 {
				for _, contLine := range badgeLines[1:] {
					rows = append(rows, ListingRow{
						Addr:      &addrCopy,
						Kind:      SubRowXref,
						XrefTotal: len(badges),
						Xrefs:     contLine,
						CellType:  cellType,
						Size:      cellSize,
					})
				}
			}
		}
	}

	// 1. Header directives (SECTION / XDEF or ORG)
	if segIsRelocatable {
		secName := fmt.Sprintf("S_%d", seg.HunkIndex)
		secType := "code"
		switch seg.HunkType {
		case hunk.HunkTypeData:
			secType = "data"
		case hunk.HunkTypeBss:
			secType = "bss"
		}
		secMem := ""
		switch seg.MemoryType {
		case hunk.MemoryChip:
			secMem = ",chip"
		case hunk.MemoryFast:
			secMem = ",fast"
		}
		rows = append(rows, ListingRow{
			Kind:     SubRowDirective,
			Mnem:     "SECTION",
			Operands: fmt.Sprintf("%s,%s%s", secName, secType, secMem),
		})
		if exported, err := ctrl.GetExportedLabelsInRange(baseAddr, queryEnd); err == nil && len(exported) > 0 {
			appendSpacerIfNeeded()
			for _, name := range exported {
				rows = append(rows, ListingRow{
					Kind:     SubRowDirective,
					Mnem:     "XDEF",
					Operands: name,
				})
			}
		}
		appendSpacerIfNeeded()
	} else {
		rows = append(rows, ListingRow{
			Kind:     SubRowDirective,
			Mnem:     "org",
			Operands: fmt.Sprintf("$%X", baseAddr),
		})
		appendSpacerIfNeeded()
	}

	emitUninitRange := func(startAddr, totalEnd, qEnd uint32, useDx bool) {
		labels := ctrl.LabelsNamedInRange(startAddr, qEnd)
		curAddr := startAddr
		emitSpan := func(a, diff uint32) {
			aCopy := a
			var mnem, op string
			if useDx {
				if a%4 == 0 && diff%4 == 0 {
					mnem, op = "dx.l", strconv.FormatUint(uint64(diff/4), 10)
				} else if a%2 == 0 && diff%2 == 0 {
					mnem, op = "dx.w", strconv.FormatUint(uint64(diff/2), 10)
				} else {
					mnem, op = "dx.b", strconv.FormatUint(uint64(diff), 10)
				}
			} else {
				if diff%4 == 0 {
					mnem, op = "ds.l", strconv.FormatUint(uint64(diff/4), 10)
				} else {
					mnem, op = "ds.b", strconv.FormatUint(uint64(diff), 10)
				}
			}
			ac := commentsMap[a]
			eolText, eolStyle := resolveEOLComment(ac, nil, "", allTargetComments)
			rows = append(rows, ListingRow{
				Addr:         &aCopy,
				Kind:         SubRowDirective,
				IsPrimary:    true,
				Mnem:         mnem,
				Operands:     op,
				Comment:      eolText,
				CommentStyle: eolStyle,
				CellType:     "BSS",
				Size:         diff,
			})
		}

		for _, lbl := range labels {
			if lbl.Addr > curAddr {
				emitSpan(curAddr, lbl.Addr-curAddr)
				curAddr = lbl.Addr
			}
			emitPreSubRows(lbl.Addr, 0, "BSS", false, true)
		}
		if curAddr < totalEnd {
			emitSpan(curAddr, totalEnd-curAddr)
		}
	}

	if seg.HunkType == hunk.HunkTypeBss {
		totalEnd := baseAddr + seg.AllocSize
		emitUninitRange(baseAddr, totalEnd, max(totalEnd, baseAddr+1), false)
		return rows, 0, nil
	}

	// Filter explicit cells and accumulate codeBytes; also record which addresses had any Stage 3 cell.
	var explicitCells []db.Cell
	stage3CellAt := make(map[uint32]string, len(allCells))
	var codeBytes uint32
	for _, c := range allCells {
		if c.Type == db.CellCode {
			codeBytes += c.Size
		}
		stage3CellAt[c.Addr] = c.Type.AsStr()
		if isExplicitCell(&c) {
			explicitCells = append(explicitCells, c)
		}
	}

	// Build sorted split points inside [baseAddr, dataEnd) for coalesced dc.b spans:
	// Any address with a Label, Comment/BlockComment/AutoComment, or incoming Xref splits a 16-byte dc.b row.
	splitSet := make(map[uint32]struct{})
	for _, la := range sortedAllLabelAddrs {
		if la >= baseAddr && la < dataEnd && getLabelStr(la) != "" {
			splitSet[la] = struct{}{}
		}
	}
	for ca, ac := range commentsMap {
		if ca >= baseAddr && ca < dataEnd && (ac.Comment != "" || ac.BlockComment != "" || ac.AutoComment != "") {
			splitSet[ca] = struct{}{}
		}
	}
	for ta := range xrefsByTarget {
		if ta >= baseAddr && ta < dataEnd {
			splitSet[ta] = struct{}{}
		}
	}
	sortedSplitAddrs := slices.Sorted(maps.Keys(splitSet))

	emitCoalescedDataRange := func(start, end uint32) {
		cur := start
		for cur < end {
			limit := min(cur+16, end)
			// Check if any split address lies strictly inside (cur, limit)
			idx, _ := slices.BinarySearch(sortedSplitAddrs, cur+1)
			if idx < len(sortedSplitAddrs) && sortedSplitAddrs[idx] < limit {
				limit = sortedSplitAddrs[idx]
			}
			chunkSize := limit - cur
			off := int(cur - baseAddr)
			var raw []byte
			if off >= 0 && off < len(binData) {
				endOff := min(off+int(chunkSize), len(binData))
				raw = binData[off:endOff]
			}

			cellType := "DATA_B"
			if _, ok := stage3CellAt[cur]; !ok {
				cellType = "GAP"
			}

			emitPreSubRows(cur, chunkSize, cellType, false, false)

			hexParts := make([]string, len(raw))
			for i, b := range raw {
				hexParts[i] = fmt.Sprintf("$%02X", b)
			}
			asciiBox, runMask := buildASCIIBoxAndMask(raw)

			var refTgt *uint32
			if tgt, ok := outgoingTargets[cur]; ok {
				tCopy := tgt
				refTgt = &tCopy
			}
			ac := commentsMap[cur]
			eolText, eolStyle := resolveEOLComment(ac, refTgt, "", allTargetComments)

			curCopy := cur
			rows = append(rows, ListingRow{
				Addr:             &curCopy,
				Kind:             SubRowData,
				IsPrimary:        true,
				RawBytes:         raw,
				Mnem:             "dc.b",
				Operands:         strings.Join(hexParts, ","),
				ASCIIBox:         asciiBox,
				PrintableRunMask: runMask,
				Comment:          eolText,
				CommentStyle:     eolStyle,
				RefTarget:        refTgt,
				CellType:         cellType,
				Size:             chunkSize,
			})
			cur = limit
		}
	}

	addr := baseAddr
	expIdx := 0
	var curFuncLabel, curFuncAutoLabel string
	for addr < dataEnd {
		nextExpAddr := dataEnd
		if expIdx < len(explicitCells) {
			nextExpAddr = explicitCells[expIdx].Addr
		}
		if nextExpAddr < addr {
			expIdx++
			continue
		}
		if addr < nextExpAddr {
			emitCoalescedDataRange(addr, nextExpAddr)
			addr = nextExpAddr
			continue
		}

		cell := &explicitCells[expIdx]
		expIdx++

		var raw []byte
		if len(cell.RawBytes) > 0 {
			raw = cell.RawBytes
		} else {
			off := int(addr - baseAddr)
			if off >= 0 && off < len(binData) {
				endOff := min(off+int(cell.Size), len(binData))
				raw = binData[off:endOff]
			}
		}

		isStringCell := cell.Type == db.CellStr
		emitPreSubRows(addr, cell.Size, cell.Type.AsStr(), isStringCell, false)
		if fnEntrySet[addr] {
			if l := getLabelStr(addr); l != "" {
				curFuncLabel = l
			} else {
				curFuncLabel = proj.AutoLabel(addr)
			}
			curFuncAutoLabel = proj.AutoLabel(addr)
		}

		addrCopy := addr
		switch cell.Type {
		case db.CellCode:
			mnem := cell.MnemonicStr()
			opStr := proj.ApplyStructAliasesToOpStr(cell.OpStrVal(), curFuncLabel, curFuncAutoLabel)
			var timing m68k.Timing
			var isTerm bool
			if insn, ok := m68k.Decode(raw, addr); ok {
				timing = insn.Timing()
				isTerm = insn.IsTerminator()
			}

			var targetHint string
			var refTgt *uint32
			if tgt, ok := outgoingTargets[addr]; ok {
				tCopy := tgt
				refTgt = &tCopy
			}

			if !segIsRelocatable {
				var flatTgt *uint32
				opStr, targetHint, flatTgt = resolveFlatCrossSegOperandsTUI(
					proj, mnem, opStr, baseAddr, dataEnd, allLabels, cellSpans, curSeg,
				)
				if refTgt == nil && flatTgt != nil {
					refTgt = flatTgt
				}
			}

			op, _ := m68k.ParseMnemonic(mnem)
			if (op == m68k.OpJSR || op == m68k.OpJMP || op == m68k.OpBSR) && strings.Contains(opStr, "(") && !strings.Contains(opStr, "pc") {
				if _, realTgt, ok := ctrl.ResolveVectoredTarget(opStr, jmpBases, allRelocs); ok {
					tgtLbl := getLabelStr(realTgt)
					if tgtLbl == "" {
						tgtLbl = proj.AutoLabel(realTgt)
					}
					qual := proj.QualifiedLabel(realTgt, tgtLbl)
					targetHint = fmt.Sprintf("→ %s", qual)
					tCopy := realTgt
					refTgt = &tCopy
				}
			}
			if targetHint == "" {
				for off := addr; off < addr+cell.Size; off++ {
					if relocTgt, ok := allRelocs[off]; ok {
						if refTgt == nil {
							tCopy := relocTgt
							refTgt = &tCopy
						}
						if tseg := proj.SegmentAtAddr(relocTgt); tseg != nil && tseg.Base != baseAddr {
							targetHint = fmt.Sprintf("→ %s", tseg.Name)
							break
						}
					}
				}
			}

			if (op == m68k.OpJSR || op == m68k.OpBSR) && refTgt != nil {
				if calleeABI := proj.GetFunctionABI(getLabelStr(*refTgt), proj.AutoLabel(*refTgt)); calleeABI != "" {
					abiTag := fmt.Sprintf("[ABI: %s]", calleeABI)
					if targetHint == "" {
						targetHint = abiTag
					} else if !strings.Contains(targetHint, "ABI:") {
						targetHint = targetHint + " " + abiTag
					}
				}
			}

			ac := commentsMap[addr]
			eolText, eolStyle := resolveEOLComment(ac, refTgt, targetHint, allTargetComments)

			rows = append(rows, ListingRow{
				Addr:         &addrCopy,
				Kind:         SubRowCode,
				IsPrimary:    true,
				RawBytes:     raw,
				Timing:       timing,
				Mnem:         mnem,
				Operands:     opStr,
				Comment:      eolText,
				CommentStyle: eolStyle,
				RefTarget:    refTgt,
				CellType:     "CODE",
				Size:         cell.Size,
				CrossSegment: crossSegSources[addr],
			})
			if isTerm {
				appendSpacerIfNeeded()
			}

		case db.CellStr:
			chunks := formatStringChunks(raw, stringWrapWidth)
			for i, chunk := range chunks {
				rows = append(rows, ListingRow{
					Addr:      &addrCopy,
					Kind:      SubRowString,
					IsPrimary: i == 0,
					Mnem:      "dc.b",
					Operands:  chunk,
					CellType:  "STRING",
					Size:      cell.Size,
				})
			}

		case db.CellIncbin:
			file := cell.OpStrVal()
			if file == "" {
				if lbl := getLabelStr(addr); lbl != "" {
					file = fmt.Sprintf("assets/%s.bin", lbl)
				} else {
					file = fmt.Sprintf("assets/incbin_%08X.bin", addr)
				}
			}
			ac := commentsMap[addr]
			eolText, eolStyle := resolveEOLComment(ac, nil, "", allTargetComments)
			rows = append(rows, ListingRow{
				Addr:         &addrCopy,
				Kind:         SubRowDirective,
				IsPrimary:    true,
				Mnem:         "incbin",
				Operands:     fmt.Sprintf("%q", file),
				Comment:      eolText,
				CommentStyle: eolStyle,
				CellType:     "INCBIN",
				Size:         cell.Size,
			})

		default:
			// Explicit CellPointer or Confidence >= 100 CellDataB / CellDataW / CellDataL / CellDataZero
			var mnem, opStr, targetHint string
			var refTgt *uint32
			if tgt, ok := outgoingTargets[addr]; ok {
				tCopy := tgt
				refTgt = &tCopy
			}

			switch cell.Type {
			case db.CellDataB:
				var val byte
				if len(raw) > 0 {
					val = raw[0]
				}
				mnem = "dc.b"
				opStr = fmt.Sprintf("$%02X", val)
			case db.CellDataW:
				var val uint16
				if len(raw) >= 2 {
					val = uint16(raw[0])<<8 | uint16(raw[1])
				}
				mnem = "dc.w"
				opStr = fmt.Sprintf("$%04X", val)
			case db.CellDataL, db.CellPointer:
				var val uint32
				if len(raw) >= 4 {
					val = uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])
				}
				mnem = "dc.l"
				if cell.Type == db.CellPointer {
					if relocTgt, ok := allRelocs[addr]; ok {
						val = relocTgt
						if tseg := proj.SegmentAtAddr(relocTgt); tseg != nil && tseg.Base != baseAddr {
							targetHint = fmt.Sprintf("→ %s", tseg.Name)
						}
					}
					if refTgt == nil && val != 0 {
						vCopy := val
						refTgt = &vCopy
					}
					lbl := getLabelStr(val)
					var defined bool
					if lbl != "" {
						if val >= baseAddr && val < dataEnd {
							c := findContainingCellInSlice(allCells, val)
							defined = c == nil || c.Addr == val
						} else {
							defined = isCellAlignedInSpace(cellSpans, val)
						}
					}
					if defined {
						opStr = lbl
					} else {
						opStr = fmt.Sprintf("$%08X", val)
					}
				} else {
					opStr = fmt.Sprintf("$%08X", val)
				}
			default:
				// Explicit CellDataZero: emit in <=16-byte dc.b chunks
				emitCoalescedDataRange(addr, addr+cell.Size)
				addr += cell.Size
				continue
			}

			asciiBox, runMask := buildASCIIBoxAndMask(raw)
			ac := commentsMap[addr]
			eolText, eolStyle := resolveEOLComment(ac, refTgt, targetHint, allTargetComments)

			rows = append(rows, ListingRow{
				Addr:             &addrCopy,
				Kind:             SubRowData,
				IsPrimary:        true,
				RawBytes:         raw,
				Mnem:             mnem,
				Operands:         opStr,
				ASCIIBox:         asciiBox,
				PrintableRunMask: runMask,
				Comment:          eolText,
				CommentStyle:     eolStyle,
				RefTarget:        refTgt,
				CellType:         cell.Type.AsStr(),
				Size:             cell.Size,
			})
		}

		addr += cell.Size
	}

	if len(binData) == 0 {
		emitPreSubRows(baseAddr, 0, "", false, true)
	}

	onDiskLen := uint32(len(binData))
	if seg.FileDataLen != nil {
		onDiskLen = *seg.FileDataLen
	}
	if seg.AllocSize > onDiskLen {
		tailStart := baseAddr + onDiskLen
		tailEnd := baseAddr + seg.AllocSize
		emitUninitRange(tailStart, tailEnd, tailEnd, true)
	}

	return rows, codeBytes, nil
}
