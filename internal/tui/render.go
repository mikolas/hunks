package tui

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/mattn/go-runewidth"
	"github.com/mikolas/hunks/internal/hunk"
	"github.com/mikolas/hunks/internal/modules"
	"github.com/mikolas/hunks/internal/project"
)

// ANSI SGR color codes matching ratatui's Color palette.
const (
	fgDefault    = ""
	fgBlack      = "30"
	fgGreen      = "32"
	fgYellow     = "33"
	fgBlue       = "34"
	fgMagenta    = "35"
	fgCyan       = "36"
	fgGray       = "37"
	fgDarkGray   = "90"
	fgLightGreen = "92"
	fgWhite      = "97"

	bgDefault  = ""
	bgBlack    = "40"
	bgBlue     = "44"
	bgGray     = "47"
	bgDarkGray = "100"

	bgPointer = "48;2;20;20;40"
	bgData    = "48;2;25;25;25"
	bgString  = "48;2;30;28;15"
	bgGap     = "48;2;15;15;15"
	bgSelect  = "48;2;45;45;20"
)

type cellStyle struct {
	fg      string
	bg      string
	bold    bool
	italic  bool
	reverse bool
}

type styledSpan struct {
	text  string
	style cellStyle
}

type screenCell struct {
	ch    rune
	width int // 1 = normal, 2 = wide head, 0 = wide continuation
	style cellStyle
}

type rect struct {
	x int
	y int
	w int
	h int
}

func centeredRect(width, height int, r rect) rect {
	w := min(width, r.w)
	h := min(height, r.h)
	x := r.x + max(r.w-w, 0)/2
	y := r.y + max(r.h-h, 0)/2
	return rect{x: x, y: y, w: w, h: h}
}

type screenBuffer struct {
	w     int
	h     int
	cells []screenCell
}

func newScreenBuffer(w, h int) *screenBuffer {
	cells := make([]screenCell, w*h)
	for i := range cells {
		cells[i] = screenCell{ch: ' ', width: 1}
	}
	return &screenBuffer{w: w, h: h, cells: cells}
}

func (b *screenBuffer) setCell(x, y int, ch rune, rw int, st cellStyle) {
	if x < 0 || x >= b.w || y < 0 || y >= b.h {
		return
	}
	idx := y*b.w + x
	// If overwriting the second half of a wide rune, clear the first half.
	if b.cells[idx].width == 0 && x > 0 {
		b.cells[idx-1] = screenCell{ch: ' ', width: 1, style: st}
	}
	// If overwriting the first half of a wide rune, clear its continuation cell.
	if b.cells[idx].width == 2 && x+1 < b.w {
		b.cells[idx+1] = screenCell{ch: ' ', width: 1, style: st}
	}
	if rw == 2 {
		if x+1 >= b.w {
			b.cells[idx] = screenCell{ch: ' ', width: 1, style: st}
			return
		}
		b.cells[idx] = screenCell{ch: ch, width: 2, style: st}
		b.cells[idx+1] = screenCell{ch: 0, width: 0, style: st}
		return
	}
	b.cells[idx] = screenCell{ch: ch, width: 1, style: st}
}

func (b *screenBuffer) clearRect(r rect, st cellStyle) {
	xEnd := min(r.x+r.w, b.w)
	yEnd := min(r.y+r.h, b.h)
	for y := max(r.y, 0); y < yEnd; y++ {
		for x := max(r.x, 0); x < xEnd; x++ {
			b.setCell(x, y, ' ', 1, st)
		}
	}
}

func (b *screenBuffer) putString(x, y, maxW int, s string, st cellStyle) int {
	if y < 0 || y >= b.h || maxW <= 0 {
		return 0
	}
	col := 0
	for _, r := range s {
		if r == '\n' || r == '\r' {
			break
		}
		if r == '\t' {
			r = ' '
		}
		rw := runewidth.RuneWidth(r)
		if rw <= 0 {
			continue
		}
		if col+rw > maxW || x+col+rw > b.w {
			break
		}
		b.setCell(x+col, y, r, rw, st)
		col += rw
	}
	return col
}

func (b *screenBuffer) putSpans(x, y, maxW int, spans []styledSpan, fillBG string, reverseAll bool) {
	var rowOverride *cellStyle
	if reverseAll {
		rowOverride = &cellStyle{bg: fillBG, reverse: true}
	}
	b.putSpansRow(x, y, maxW, spans, fillBG, rowOverride)
}

func (b *screenBuffer) putSpansRow(x, y, maxW int, spans []styledSpan, fillBG string, rowOverride *cellStyle) {
	if y < 0 || y >= b.h || maxW <= 0 {
		return
	}
	baseStyle := cellStyle{bg: fillBG}
	if rowOverride != nil {
		baseStyle = *rowOverride
	}
	for col := 0; col < maxW && x+col < b.w; col++ {
		b.setCell(x+col, y, ' ', 1, baseStyle)
	}
	col := 0
	for _, sp := range spans {
		st := sp.style
		if rowOverride != nil {
			if rowOverride.reverse {
				if st.bg == "" && fillBG != "" {
					st.bg = fillBG
				}
				st.reverse = true
			} else {
				st = *rowOverride
			}
		} else if st.bg == "" && fillBG != "" {
			st.bg = fillBG
		}
		n := b.putString(x+col, y, maxW-col, sp.text, st)
		col += n
		if col >= maxW {
			break
		}
	}
}

func (b *screenBuffer) drawBox(r rect, title string, borderStyle, bgStyle cellStyle) rect {
	if r.w < 2 || r.h < 2 {
		return rect{x: r.x, y: r.y, w: 0, h: 0}
	}
	b.clearRect(r, bgStyle)

	// Corners
	b.setCell(r.x, r.y, '┌', 1, borderStyle)
	b.setCell(r.x+r.w-1, r.y, '┐', 1, borderStyle)
	b.setCell(r.x, r.y+r.h-1, '└', 1, borderStyle)
	b.setCell(r.x+r.w-1, r.y+r.h-1, '┘', 1, borderStyle)

	// Top and bottom horizontal edges
	for x := r.x + 1; x < r.x+r.w-1; x++ {
		b.setCell(x, r.y, '─', 1, borderStyle)
		b.setCell(x, r.y+r.h-1, '─', 1, borderStyle)
	}

	// Left and right vertical edges
	for y := r.y + 1; y < r.y+r.h-1; y++ {
		b.setCell(r.x, y, '│', 1, borderStyle)
		b.setCell(r.x+r.w-1, y, '│', 1, borderStyle)
	}

	// Title in top border
	if title != "" && r.w > 4 {
		b.putString(r.x+1, r.y, r.w-2, title, borderStyle)
	}

	return rect{
		x: r.x + 1,
		y: r.y + 1,
		w: r.w - 2,
		h: r.h - 2,
	}
}

func writeSGR(sb *strings.Builder, st cellStyle) {
	sb.WriteString("\x1b[0")
	if st.bold {
		sb.WriteString(";1")
	}
	if st.italic {
		sb.WriteString(";3")
	}
	if st.reverse {
		sb.WriteString(";7")
	}
	if st.fg != "" {
		sb.WriteByte(';')
		sb.WriteString(st.fg)
	}
	if st.bg != "" {
		sb.WriteByte(';')
		sb.WriteString(st.bg)
	}
	sb.WriteByte('m')
}

func (b *screenBuffer) render() string {
	var sb strings.Builder
	sb.Grow(b.w * b.h * 2)
	for y := 0; y < b.h; y++ {
		if y > 0 {
			sb.WriteByte('\n')
		}
		var curStyle cellStyle
		hasStyle := false
		rowOff := y * b.w
		for x := 0; x < b.w; x++ {
			c := b.cells[rowOff+x]
			if c.width == 0 {
				continue
			}
			if !hasStyle || c.style != curStyle {
				writeSGR(&sb, c.style)
				curStyle = c.style
				hasStyle = true
			}
			if c.ch == 0 {
				sb.WriteByte(' ')
			} else {
				sb.WriteRune(c.ch)
			}
		}
		sb.WriteString("\x1b[0m")
	}
	return sb.String()
}

// RenderInline renders the TextInput value with cursor for plain-text tests.
func (ti *TextInput) RenderInline() string {
	spans := ti.inlineSpans()
	var sb strings.Builder
	for _, sp := range spans {
		sb.WriteString(sp.text)
	}
	return sb.String()
}

func (ti *TextInput) inlineSpans() []styledSpan {
	cur := min(max(ti.Cursor, 0), len(ti.Value))
	before := ti.Value[:cur]
	cursorChar := " "
	var after string
	if cur < len(ti.Value) {
		_, sz := utf8.DecodeRuneInString(ti.Value[cur:])
		cursorChar = ti.Value[cur : cur+sz]
		after = ti.Value[cur+sz:]
	}
	return []styledSpan{
		{text: before, style: cellStyle{fg: fgWhite}},
		{text: cursorChar, style: cellStyle{fg: fgWhite, reverse: true}},
		{text: after, style: cellStyle{fg: fgWhite}},
	}
}

// RenderUI renders the complete TUI screen into a fixed-size 2D cell buffer.
func RenderUI(a *App) string {
	if a.Theme.Op.fg == "" {
		a.Theme = DefaultTheme()
	}
	width := max(a.Width, 80)
	height := max(a.Height, 24)
	if width != a.LastWidth && a.DB != nil && a.Proj != nil {
		anchorAddr, ok := a.CursorAddr()
		_ = a.LoadData()
		if ok {
			a.GotoAddress(anchorAddr)
		}
	}

	buf := newScreenBuffer(width, height)

	menuArea := rect{x: 0, y: 0, w: width, h: 1}
	mainArea := rect{x: 0, y: 1, w: width, h: max(height-2, 1)}
	statusArea := rect{x: 0, y: height - 1, w: width, h: 1}

	renderMenuBar(buf, a, menuArea)
	renderDisasm(buf, a, mainArea)
	renderStatusBar(buf, a, statusArea)
	renderModal(buf, a, rect{x: 0, y: 0, w: width, h: height})

	rendered := buf.render()
	if a.PendingEscapeSeq != "" {
		rendered += a.PendingEscapeSeq
		a.PendingEscapeSeq = ""
	}
	if a.Modal.Kind == ModalBitplane && a.Modal.Bitplane != nil {
		st := a.Modal.Bitplane
		if st.CachedEscapeSeq != "" {
			rendered += st.CachedEscapeSeq
		}
	}
	return rendered
}

func renderMenuBar(buf *screenBuffer, a *App, area rect) {
	t := &a.Theme
	btnStyle := t.MenuBtn
	gapStyle := t.Bar

	var spans []styledSpan
	if a.Modal.Kind == ModalBitplane {
		protoName := a.Modal.PixelProtocol.String()
		spans = []styledSpan{
			{text: " [?]Help ", style: btnStyle},
			{text: " ", style: gapStyle},
			{text: " [w]Save PNG ", style: btnStyle},
			{text: " ", style: gapStyle},
			{text: " [W]Save IFF ", style: btnStyle},
			{text: " ", style: gapStyle},
			{text: " [K]Carve ", style: btnStyle},
			{text: " ", style: gapStyle},
			{text: " [g]Geometry ", style: btnStyle},
			{text: " ", style: gapStyle},
			{text: " [p]Palette ", style: btnStyle},
			{text: " ", style: gapStyle},
			{text: fmt.Sprintf(" [v]Proto:%s ", protoName), style: btnStyle},
			{text: " ", style: gapStyle},
			{text: " [Esc]Close ", style: btnStyle},
		}
		buf.putSpansRow(area.x, area.y, area.w, spans, t.Bar.bg, nil)
		return
	}

	spans = []styledSpan{
		{text: " [?]Help ", style: btnStyle},
		{text: " ", style: gapStyle},
		{text: " [S]Segments ", style: btnStyle},
		{text: " ", style: gapStyle},
		{text: " [f]Funcs ", style: btnStyle},
		{text: " ", style: gapStyle},
		{text: " [x]XRefs ", style: btnStyle},
		{text: " ", style: gapStyle},
		{text: " [/]Search ", style: btnStyle},
		{text: " ", style: gapStyle},
		{text: " [m]MemMap ", style: btnStyle},
		{text: " ", style: gapStyle},
		{text: " [e]Export ", style: btnStyle},
		{text: " ", style: gapStyle},
		{text: " [r]Analyze ", style: btnStyle},
	}
	buf.putSpansRow(area.x, area.y, area.w, spans, t.Bar.bg, nil)
}

func renderStatusBar(buf *screenBuffer, a *App, area rect) {
	t := &a.Theme
	buf.clearRect(area, t.Bar)
	if a.StatusMsg != "" {
		buf.putString(area.x, area.y, area.w, a.StatusMsg, t.BarAccent)
		return
	}
	if a.Modal.Kind == ModalBitplane {
		buf.putString(area.x, area.y, area.w,
			" [←/→]Width [,/.;↑/↓]Move [s/h]Height [+/-]BPU [1-7]Sync [Space]All [c]Pal [i]Inv [o/O]Zoom [Tab]Layout [w]PNG [Esc]Exit",
			t.Bar)
		return
	}
	status := a.GetStatusLine()
	if sep := strings.Index(status, " │ "); sep > 0 {
		n := buf.putString(area.x, area.y, area.w, status[:sep], t.BarAccent)
		buf.putString(area.x+n, area.y, area.w-n, status[sep:], t.Bar)
		return
	}
	buf.putString(area.x, area.y, area.w, status, t.Bar)
}

func rowBGColor(cellType string, t *Theme) string {
	switch cellType {
	case "POINTER":
		return t.RowPointer.bg
	case "DATA_B", "DATA_W", "DATA_L":
		return t.RowData.bg
	case "STRING":
		return t.RowString.bg
	case "GAP":
		return t.RowGap.bg
	default:
		return t.BG.bg
	}
}

func appendXrefBadgeSpans(spans []styledSpan, badges []XrefBadge, isSelected bool, dataByteOff int, t *Theme) []styledSpan {
	selBadge := min(max(dataByteOff, 0), max(len(badges)-1, 0))
	for bi, b := range badges {
		if bi > 0 {
			spans = append(spans, styledSpan{text: ", ", style: t.XSym})
		}
		if isSelected && bi == selBadge {
			spans = append(spans, styledSpan{text: b.Text, style: t.XActive})
			continue
		}
		openIdx := strings.LastIndexByte(b.Text, '(')
		if openIdx >= 0 && strings.HasSuffix(b.Text, ")") {
			prefix := b.Text[:openIdx+1]
			kind := b.Text[openIdx+1 : len(b.Text)-1]
			var kindSt cellStyle
			switch kind {
			case "c":
				kindSt = t.XC
			case "j":
				kindSt = t.XJ
			default:
				kindSt = t.XPtr
			}
			spans = append(spans,
				styledSpan{text: prefix, style: t.XSym},
				styledSpan{text: kind, style: kindSt},
				styledSpan{text: ")", style: t.XSym},
			)
		} else {
			spans = append(spans, styledSpan{text: b.Text, style: t.XSym})
		}
	}
	return spans
}

func listingRowSpans(
	row *ListingRow,
	baseAddr uint32,
	isRelocatable bool,
	isSelected bool,
	dataByteOff int,
	t *Theme,
) []styledSpan {
	if row.Kind == SubRowSpacer {
		return nil
	}

	// Col 01..10 (width 10): Address (printed only on primary rows)
	// Col 11..12 (width 2):  Margin ("  " or "⇢ ")
	// Total prefix before Col 13 Unified Alignment Stop = 12 chars.
	addrStr := "          "
	if row.Addr != nil && row.IsPrimary && row.Kind != SubRowLabel {
		a := *row.Addr
		if isRelocatable {
			var off uint32
			if a >= baseAddr {
				off = a - baseAddr
			}
			addrStr = fmt.Sprintf("+%05X    ", off)
		} else {
			addrStr = fmt.Sprintf("$%05X    ", a)
		}
	}
	marginStr := "  "
	if row.CrossSegment && row.IsPrimary {
		marginStr = "⇢ "
	}
	addrSt := t.Addr
	if row.CrossSegment {
		addrSt = t.AddrCross
	}
	addrPrefix := styledSpan{
		text:  padOrTruncate(addrStr, 10) + marginStr,
		style: addrSt,
	}

	switch row.Kind {
	case SubRowBlockComment:
		return []styledSpan{
			{text: strings.Repeat(" ", 12)},
			{text: "; " + row.Comment, style: t.Rep},
		}

	case SubRowLabel:
		lblSt := t.Sub
		switch {
		case strings.HasPrefix(row.Label, "LAB") || strings.HasPrefix(row.Label, "DAT") ||
			strings.HasPrefix(row.Label, "PTR") || strings.HasPrefix(row.Label, "STR") ||
			strings.HasPrefix(row.Label, "EQU") || strings.HasPrefix(row.Label, "."):
			lblSt = t.Loc
		case isHardwareSymbol(row.Label):
			lblSt = t.HW
		}
		if len(row.Xrefs) == 0 {
			return []styledSpan{
				{text: strings.Repeat(" ", 12)},
				{text: row.Label, style: lblSt},
			}
		}
		// Pad label from Col 13 out to Col 61 (48 chars) so "; XREF[n]: " aligns at Col 61
		lblWidth := max(48, len(row.Label)+2)
		xrefTotal := max(row.XrefTotal, len(row.Xrefs))
		spans := []styledSpan{
			{text: strings.Repeat(" ", 12)},
			{text: padOrTruncate(row.Label, lblWidth), style: lblSt},
			{text: fmt.Sprintf("; XREF[%d]: ", xrefTotal), style: t.XHdr},
		}
		return appendXrefBadgeSpans(spans, row.Xrefs, isSelected, dataByteOff, t)

	case SubRowXref:
		// Continuation XREF line aligned at Col 61 (0-based x = 60)
		xrefTotal := max(row.XrefTotal, len(row.Xrefs))
		hdrLen := len(fmt.Sprintf("; XREF[%d]: ", xrefTotal))
		padAfterSemi := max(hdrLen-1, 2)
		spans := []styledSpan{
			{text: strings.Repeat(" ", 60)},
			{text: ";" + strings.Repeat(" ", padAfterSemi), style: t.XHdr},
		}
		return appendXrefBadgeSpans(spans, row.Xrefs, isSelected, dataByteOff, t)

	case SubRowDirective:
		mSt := t.Directive
		if row.Mnem == "incbin" {
			mSt = t.XJ
		} else if strings.HasPrefix(row.Mnem, "ds.") || strings.HasPrefix(row.Mnem, "dx.") {
			mSt = t.XHdr
		}
		opWidth := max(36, len(row.Operands)+2)
		spans := []styledSpan{
			addrPrefix,
			{text: padOrTruncate(row.Mnem, 12), style: mSt},
			{text: padOrTruncate(row.Operands, opWidth), style: t.Imm},
		}
		if row.Comment != "" {
			spans = append(spans, commentSpans("; ", row.Comment, row.CommentStyle, t)...)
		}
		return spans

	case SubRowString:
		return []styledSpan{
			addrPrefix,
			{text: padOrTruncate(row.Mnem, 12), style: t.Op},
			{text: row.Operands, style: t.Str},
		}

	case SubRowCode:
		// Col 13..24 (width 12): Mnemonic
		// Col 25..60 (width 36 min): Operands (never truncated)
		// Col 61..W: "; " + Comment
		mnemSt := t.Op
		if isFlowMnemonic(row.Mnem) {
			mnemSt = t.Flow
		}
		opWidth := max(36, len(row.Operands)+2)
		spans := []styledSpan{
			addrPrefix,
			{text: padOrTruncate(row.Mnem, 12), style: mnemSt},
		}
		spans = append(spans, tokenizeOperands(row.Operands, opWidth, t)...)
		if row.Comment != "" {
			spans = append(spans, commentSpans("; ", row.Comment, row.CommentStyle, t)...)
		}
		return spans

	case SubRowData:
		// Col 13..24 (width 12): Mnemonic ("dc.b", "dc.w", "dc.l")
		// Col 25..74 (width 50): 16-byte hex grid (48..49 chars + padding) or $XXXX/$XXXXXXXX
		// Col 75..94 (width 20): "; │<16 ASCII chars>│"
		// Col 96..W: Optional trailing comment
		spans := []styledSpan{
			addrPrefix,
			{text: padOrTruncate(row.Mnem, 12), style: t.Op},
		}
		activeByte := min(max(dataByteOff, 0), max(int(row.Size)-1, 0))
		const dataOpSlotWidth = 50 // Col 25..74 so "; │" starts at Col 75
		opColsUsed := 0

		if row.Mnem == "dc.b" && len(row.RawBytes) > 0 {
			for bi, b := range row.RawBytes {
				if bi > 0 {
					sepWidth := 1
					if bi == 8 {
						sepWidth = 2
					}
					if isSelected && (bi == activeByte || bi-1 == activeByte) {
						sepWidth--
					}
					if sepWidth > 0 {
						spans = append(spans, styledSpan{text: strings.Repeat(" ", sepWidth), style: t.XSym})
						opColsUsed += sepWidth
					}
				}
				if isSelected && bi == activeByte {
					spans = append(spans, styledSpan{
						text:  fmt.Sprintf("[%02X]", b),
						style: t.XActive,
					})
					opColsUsed += 4
				} else {
					spans = append(spans, styledSpan{
						text:  fmt.Sprintf("%02X", b),
						style: t.XSym,
					})
					opColsUsed += 2
				}
			}
		} else if isSelected && strings.HasPrefix(row.Operands, "$") && len(row.RawBytes) >= 2 && (row.Mnem == "dc.w" || row.Mnem == "dc.l") {
			spans = append(spans, styledSpan{text: "$", style: t.XSym})
			opColsUsed++
			for bi, b := range row.RawBytes {
				st := t.XSym
				if bi == activeByte {
					st = t.XActive
				}
				spans = append(spans, styledSpan{text: fmt.Sprintf("%02X", b), style: st})
				opColsUsed += 2
			}
		} else {
			opSt := t.XSym
			if row.CellType == "POINTER" {
				opSt = t.XPtr
			}
			spans = append(spans, styledSpan{text: row.Operands, style: opSt})
			opColsUsed += len(row.Operands)
		}

		if opColsUsed < dataOpSlotWidth {
			spans = append(spans, styledSpan{text: strings.Repeat(" ", dataOpSlotWidth-opColsUsed)})
		} else {
			spans = append(spans, styledSpan{text: "  "})
		}

		// Render │ASCII│ box (16 slots, padded with spaces when len(RawBytes) < 16)
		if len(row.RawBytes) > 0 {
			spans = append(spans, styledSpan{text: "; │", style: t.XHdr})
			n := min(len(row.RawBytes), 16)
			for bi := range 16 {
				if bi >= n {
					spans = append(spans, styledSpan{text: " ", style: t.XHdr})
					continue
				}
				b := row.RawBytes[bi]
				ch := "."
				if isPrintableASCII(b) {
					ch = string(rune(b))
				}
				if isSelected && bi == activeByte {
					spans = append(spans, styledSpan{
						text:  "[" + ch + "]",
						style: t.XActive,
					})
				} else if (row.PrintableRunMask & (1 << uint(bi))) != 0 {
					spans = append(spans, styledSpan{
						text:  ch,
						style: t.Str,
					})
				} else {
					spans = append(spans, styledSpan{
						text:  ch,
						style: t.XHdr,
					})
				}
			}
			spans = append(spans, styledSpan{text: "│", style: t.XHdr})
		}

		if row.Comment != "" {
			spans = append(spans, commentSpans(" ", row.Comment, row.CommentStyle, t)...)
		}
		return spans
	}
	return nil
}

func buildTopBorderTitle(a *App) string {
	spaceName := a.Proj.Data.ActiveSpace
	if spaceName == "" {
		spaceName = "default"
	}
	segCount := len(a.Proj.ActiveSegments())
	seg := a.Proj.CurrentSegment()
	if seg == nil {
		return fmt.Sprintf(" Disassembly ── Space: %s [%d segs] ", spaceName, segCount)
	}
	htype := "CODE"
	switch seg.HunkType {
	case hunk.HunkTypeData:
		htype = "DATA"
	case hunk.HunkTypeBss:
		htype = "BSS"
	}
	var rangeStr string
	if seg.IsRelocatable() {
		rangeStr = fmt.Sprintf("+%05X..+%05X", 0, seg.AllocSize)
	} else {
		rangeStr = fmt.Sprintf("$%05X..$%05X", seg.Base, seg.EndAddr())
	}
	return fmt.Sprintf(" Disassembly ── Space: %s [%d segs] │ Segment: %s (%s, %s) ",
		spaceName, segCount, seg.Name, htype, rangeStr)
}

func renderDisasm(buf *screenBuffer, a *App, area rect) {
	t := &a.Theme
	borderStyle := t.Border
	title := buildTopBorderTitle(a)
	inner := buf.drawBox(area, title, borderStyle, t.BG)
	if inner.w <= 0 || inner.h <= 0 {
		return
	}

	visibleRows := inner.h
	half := visibleRows / 2
	totalRows := len(a.DisasmRows)
	sel := 0
	if totalRows > 0 {
		sel = min(max(a.SelectedIdx, 0), totalRows-1)
	}
	var offset int
	switch {
	case sel <= half:
		offset = 0
	case sel+half >= totalRows:
		offset = max(totalRows-visibleRows, 0)
	default:
		offset = sel - half
	}
	a.ScrollOffset = offset
	endRow := min(offset+visibleRows, totalRows)

	selStart, selEnd, hasSel := a.GetSelectionRange()

	for i := offset; i < endRow; i++ {
		y := inner.y + (i - offset)
		row := &a.DisasmRows[i]
		isSelected := i == sel
		spans := listingRowSpans(row, a.BaseAddr, a.IsRelocatable, isSelected, a.DataByteOff, t)
		fillBG := rowBGColor(row.CellType, t)
		if hasSel && row.Addr != nil {
			rStart := *row.Addr
			rEnd := rStart + max(row.Size, 1) - 1
			if rStart <= selEnd && rEnd >= selStart {
				fillBG = t.Selection.bg
			}
		}
		var rowOverride *cellStyle
		if isSelected {
			if row.Kind == SubRowData || row.Kind == SubRowXref {
				fillBG = t.Bar.bg
			} else {
				rowOverride = &t.Cursor
			}
		}
		buf.putSpansRow(inner.x, y, inner.w, spans, fillBG, rowOverride)
	}

	renderScrollbar(buf, area, totalRows, sel, borderStyle, t)
}

func renderScrollbar(buf *screenBuffer, area rect, totalRows, sel int, borderStyle cellStyle, t *Theme) {
	if area.h < 3 || area.w < 2 {
		return
	}
	sx := area.x + area.w - 1
	buf.setCell(sx, area.y, '↑', 1, borderStyle)
	buf.setCell(sx, area.y+area.h-1, '↓', 1, borderStyle)
	trackH := area.h - 2
	if trackH <= 0 {
		return
	}
	thumbPos := 0
	if totalRows > 1 {
		thumbPos = (sel * (trackH - 1)) / (totalRows - 1)
	}
	thumbPos = min(max(thumbPos, 0), trackH-1)
	for i := 0; i < trackH; i++ {
		ch := '║'
		st := cellStyle{fg: t.XHdr.fg, bg: t.BG.bg}
		if i == thumbPos {
			ch = '█'
			st = cellStyle{fg: t.Flow.fg, bg: t.BG.bg, bold: true}
		}
		buf.setCell(sx, area.y+1+i, ch, 1, st)
	}
}

func formatModalAddr(addr uint32, isRelocatable bool, proj *project.Project) string {
	if seg := proj.SegmentAtAddr(addr); seg != nil {
		if isRelocatable {
			var off uint32
			if addr >= seg.Base {
				off = addr - seg.Base
			}
			return fmt.Sprintf("%s +%05X", seg.Name, off)
		}
		if len(proj.Data.Segments) > 1 {
			return fmt.Sprintf("%s:$%05X", seg.Name, addr)
		}
	}
	return fmt.Sprintf("$%05X", addr)
}

func renderInputModal(buf *screenBuffer, screen rect, title string, input *TextInput, borderFG string) {
	area := centeredRect(50, 3, screen)
	inner := buf.drawBox(area, title, cellStyle{fg: borderFG}, cellStyle{})
	buf.putSpans(inner.x, inner.y, inner.w, input.inlineSpans(), bgDefault, false)
}

func renderListModal(buf *screenBuffer, area rect, title string, borderFG string, rows [][]styledSpan, selected int) {
	inner := buf.drawBox(area, title, cellStyle{fg: borderFG}, cellStyle{})
	if inner.h <= 0 || inner.w <= 0 || len(rows) == 0 {
		return
	}
	sel := min(max(selected, 0), len(rows)-1)
	offset := 0
	if sel >= inner.h {
		offset = sel - inner.h + 1
	}
	end := min(offset+inner.h, len(rows))
	for i := offset; i < end; i++ {
		y := inner.y + (i - offset)
		buf.putSpans(inner.x, y, inner.w, rows[i], bgDefault, i == sel)
	}
}

func renderModal(buf *screenBuffer, a *App, screen rect) {
	m := &a.Modal
	switch m.Kind {
	case ModalNone:
		return
	case ModalRename:
		renderInputModal(buf, screen, " Rename Label ", &m.Input, fgYellow)
	case ModalComment:
		renderInputModal(buf, screen, " Comment ", &m.Input, fgYellow)
	case ModalBlockComment:
		renderInputModal(buf, screen, " Block Comment ", &m.Input, fgYellow)
	case ModalGoto:
		title := " Goto (hex or label) "
		if a.IsRelocatable {
			title = " Goto (+offset, label, or seg:label) "
		}
		renderInputModal(buf, screen, title, &m.Input, fgCyan)
	case ModalSearch:
		guidanceH := 0
		if len(m.SearchHits) == 0 {
			if strings.HasPrefix(strings.TrimLeft(m.Input.Value, " "), "cluster:") {
				guidanceH = 8
			} else {
				guidanceH = 1
			}
		}
		h := max(min(len(m.SearchHits)+guidanceH+3, 16), guidanceH+3)
		area := centeredRect(66, h, screen)
		inner := buf.drawBox(area, " Search  (go: [seg:]addr/label · m:/o:/s:/c:/b:/l: · cluster:) ", cellStyle{fg: fgCyan}, cellStyle{})
		if inner.h <= 0 {
			return
		}
		buf.putSpans(inner.x, inner.y, inner.w, m.Input.inlineSpans(), bgDefault, false)
		y := inner.y + 1
		if len(m.SearchHits) == 0 {
			if strings.HasPrefix(strings.TrimLeft(m.Input.Value, " "), "cluster:") {
				if y < inner.y+inner.h {
					buf.putString(inner.x, y, inner.w, "cluster presets (dense-region finder):", cellStyle{fg: fgYellow})
					y++
				}
				presets := [][2]string{
					{"3dmath", "mul/div arithmetic (3D / fixed-point math)"},
					{"blitter", "BLTCON/BLTxPT/BLTxMOD/BLTxDAT/BLTSIZE ($040-074)"},
					{"copper", "COP1LC/COP2LC/COPJMP ($080-08A)"},
					{"bitplane", "DIWSTRT/STOP, DDF, BPLxPT/MOD, BPLCON ($08E-10A)"},
					{"audio", "AUDxLC/LEN/PER/VOL/DAT ($0A0-0DF)"},
				}
				for _, p := range presets {
					if y >= inner.y+inner.h {
						break
					}
					buf.putSpans(inner.x, y, inner.w, []styledSpan{
						{text: fmt.Sprintf("  cluster:%-9s", p[0]), style: cellStyle{fg: fgGreen}},
						{text: p[1], style: cellStyle{fg: fgDarkGray}},
					}, bgDefault, false)
					y++
				}
				if y < inner.y+inner.h {
					buf.putString(inner.x, y, inner.w, "  scope to a segment: cluster:hunk3/blitter", cellStyle{fg: fgDarkGray})
				}
			} else if y < inner.y+inner.h {
				buf.putString(inner.x, y, inner.w, "m:mnem o:operand s:string c:comment b:bytes l:label  cluster:{3dmath,blitter,copper,bitplane,audio}  scope: prefix:seg/…", cellStyle{fg: fgDarkGray})
			}
		} else {
			limit := min(len(m.SearchHits), 10, inner.h-1)
			for i := 0; i < limit; i++ {
				hit := m.SearchHits[i]
				buf.putSpans(inner.x, y+i, inner.w, []styledSpan{
					{text: formatModalAddr(hit.Addr, a.IsRelocatable, a.Proj) + " ", style: cellStyle{fg: fgBlue}},
					{text: hit.Text, style: cellStyle{fg: fgGreen}},
				}, bgDefault, i == 0)
			}
		}
	case ModalXrefs:
		h := min(len(m.Xrefs)+2, 20)
		area := centeredRect(72, max(h, 3), screen)
		rows := make([][]styledSpan, len(m.Xrefs))
		for i, xr := range m.Xrefs {
			rows[i] = []styledSpan{
				{text: formatModalAddr(xr.Addr, a.IsRelocatable, a.Proj) + " ", style: cellStyle{fg: fgBlue}},
				{text: fmt.Sprintf("%-12s", xr.Type), style: cellStyle{fg: fgYellow}},
				{text: xr.Insn, style: cellStyle{fg: fgWhite}},
			}
		}
		renderListModal(buf, area, " XREFs (Enter=go, Esc=close) ", fgGreen, rows, m.ListSelect)
	case ModalFunctions:
		filtered := filterFuncs(m.AllFuncs, m.Filter)
		h := min(len(filtered)+3, 25)
		area := centeredRect(72, max(h, 3), screen)
		title := " Functions (type to filter) "
		if m.Filter != "" {
			title = fmt.Sprintf(" Functions [%s] ", m.Filter)
		}
		rows := make([][]styledSpan, len(filtered))
		for i, fn := range filtered {
			spans := []styledSpan{
				{text: formatModalAddr(fn.Addr, a.IsRelocatable, a.Proj) + " ", style: cellStyle{fg: fgBlue}},
				{text: padOrTruncate(fn.Name, max(22, len(fn.Name)+2)), style: cellStyle{fg: fgGreen}},
			}
			if fn.Cycles != "" {
				spans = append(spans, styledSpan{text: fn.Cycles, style: cellStyle{fg: fgYellow}})
			}
			rows[i] = spans
		}
		renderListModal(buf, area, title, fgGreen, rows, m.ListSelect)
	case ModalContextMenu:
		items := ContextMenuItems()
		area := centeredRect(30, len(items)+2, screen)
		rows := make([][]styledSpan, len(items))
		for i, item := range items {
			rows[i] = []styledSpan{{text: item, style: cellStyle{fg: fgWhite}}}
		}
		renderListModal(buf, area, " Actions ", fgWhite, rows, m.ListSelect)
	case ModalMemoryMap:
		regions := a.Proj.Data.MemoryRegions
		h := min(len(regions)+3, 15)
		area := centeredRect(50, max(h, 3), screen)
		rows := make([][]styledSpan, len(regions))
		for i, r := range regions {
			rows[i] = []styledSpan{{
				text:  fmt.Sprintf("%s: $%X - $%X", r.Name, r.Start, r.End),
				style: cellStyle{fg: fgWhite},
			}}
		}
		renderListModal(buf, area, " Memory Regions (d=delete, Esc=close) ", fgMagenta, rows, m.ListSelect)
	case ModalHelp:
		area := centeredRect(64, 22, screen)
		inner := buf.drawBox(area, " Help (? to close) ", cellStyle{fg: fgWhite}, cellStyle{})
		helpLines := []string{
			"Navigation:",
			"  j/k ↑/↓  Move       ←/→  Byte/XREF cursor",
			"  Enter    Follow ref  -/Bksp   Go back",
			"  g  Goto   /  Search  f  Functions  x  XREFs",
			"  S  Segments  I  Add seg  Ctrl-s  Spaces",
			"  Ctrl-d/u Half page   Home/End  Top/Bottom",
			"",
			"Annotation:",
			"  n  Rename   ;  Comment   :  Block comment",
			"  #  Cycle format (HEX/DEC/BIN)",
			"",
			"Type Marking:",
			"  c Code  b Byte  w Word  l Long  v/V Select/Sub",
			"  s String  p Pointer  P Ptr table  u Undefine",
			"  K Carve selection->incbin (on carve: uncarve)",
			"",
			"Other:",
			"  e Export  r Re-analyze  m Memory map  Ctrl-z Undo",
			"  B Bitplanes  M Music  t Structs  a Aliases  ? Help  q Quit",
			"",
			"Mouse: Scroll=navigate, Right-click=context menu",
		}
		for i := 0; i < len(helpLines) && i < inner.h; i++ {
			buf.putString(inner.x, inner.y+i, inner.w, helpLines[i], cellStyle{fg: fgWhite})
		}
	case ModalStructEditor:
		st := &m.StructState
		area := centeredRect(55, 18, screen)
		var title string
		var rows [][]styledSpan
		if st.SelectedStruct >= 0 && st.SelectedStruct < len(st.Structs) {
			name := st.Structs[st.SelectedStruct]
			title = fmt.Sprintf(" Struct: %s (a=add field, d=del, Esc=back) ", name)
			for _, f := range st.Fields {
				rows = append(rows, []styledSpan{{
					text:  fmt.Sprintf("  %4s: %s", f.Offset, f.Name),
					style: cellStyle{fg: fgWhite},
				}})
			}
		} else {
			title = " Structs (Enter=edit, n=new, d=del, Esc=close) "
			for _, s := range st.Structs {
				rows = append(rows, []styledSpan{{
					text:  "  " + s,
					style: cellStyle{fg: fgWhite},
				}})
			}
		}
		var inputLine string
		switch st.InputMode {
		case StructInputNewStruct:
			inputLine = "New struct name: " + st.Input
		case StructInputNewFieldOffset:
			inputLine = "Field offset: " + st.Input
		case StructInputNewFieldName:
			inputLine = fmt.Sprintf("Field name (offset %s): %s", st.PendingOffset, st.Input)
		}
		if inputLine != "" {
			rows = append(rows, []styledSpan{{text: inputLine, style: cellStyle{fg: fgCyan}}})
		}
		renderListModal(buf, area, title, fgYellow, rows, st.Selected)
	case ModalAliasEditor:
		keys := sortedMapKeys(a.Proj.Data.RegisterAliases)
		h := min(len(keys)+3, 15)
		area := centeredRect(45, max(h, 3), screen)
		rows := make([][]styledSpan, len(keys))
		for i, k := range keys {
			rows[i] = []styledSpan{{
				text:  fmt.Sprintf("  %s → %s", k, a.Proj.Data.RegisterAliases[k]),
				style: cellStyle{fg: fgWhite},
			}}
		}
		renderListModal(buf, area, " Register Aliases (d=del, Esc=close) ", fgYellow, rows, m.ListSelect)
	case ModalCarveName:
		area := centeredRect(56, 3, screen)
		title := fmt.Sprintf(" Carve $%X..$%X -> incbin (name, Enter) ", m.CarveStart, m.CarveEnd+1)
		inner := buf.drawBox(area, title, cellStyle{fg: fgGreen}, cellStyle{})
		buf.putSpans(inner.x, inner.y, inner.w, m.Input.inlineSpans(), bgDefault, false)
	case ModalPointerCount:
		area := centeredRect(30, 3, screen)
		inner := buf.drawBox(area, " Pointer count ", cellStyle{fg: fgCyan}, cellStyle{})
		buf.putSpans(inner.x, inner.y, inner.w, m.Input.inlineSpans(), bgDefault, false)
	case ModalSpaceSwitcher:
		spaces := a.Proj.Data.Spaces
		h := min(len(spaces)+3, 15)
		area := centeredRect(50, max(h, 3), screen)
		rows := make([][]styledSpan, len(spaces))
		for i, s := range spaces {
			marker := "  "
			if s.Name == a.Proj.Data.ActiveSpace {
				marker = "▸ "
			}
			rows[i] = []styledSpan{{
				text:  fmt.Sprintf("%s%s [%s]", marker, s.Name, strings.Join(s.Segments, ", ")),
				style: cellStyle{fg: fgWhite},
			}}
		}
		renderListModal(buf, area, " Spaces (Enter=switch, d=del, Esc=close) ", fgMagenta, rows, m.ListSelect)
	case ModalSegmentManager:
		segs := a.Proj.ActiveSegments()
		spaceName := "(all)"
		if sp := a.Proj.ActiveSpace(); sp != nil {
			spaceName = sp.Name
		}
		h := min(len(segs)+3, 18)
		area := centeredRect(65, max(h, 3), screen)
		title := fmt.Sprintf(" Segments [%s] (Enter=jump, I=add, d=del, Esc=close) ", spaceName)
		rows := make([][]styledSpan, len(segs))
		for i, s := range segs {
			fileStr := "<bss>"
			if s.File != nil {
				fileStr = *s.File
			}
			sizeKB := s.FileSize() / 1024
			var text string
			if s.IsRelocatable() {
				htype := "CODE"
				switch s.HunkType {
				case hunk.HunkTypeData:
					htype = "DATA"
				case hunk.HunkTypeBss:
					htype = "BSS"
				}
				text = fmt.Sprintf("  %-12s %-20s %-6s  %dKB", s.Name, fileStr, htype, sizeKB)
			} else {
				text = fmt.Sprintf("  %-12s %-20s $%05X  %dKB", s.Name, fileStr, s.Base, sizeKB)
			}
			rows[i] = []styledSpan{{text: text, style: cellStyle{fg: fgWhite}}}
		}
		renderListModal(buf, area, title, fgGreen, rows, m.ListSelect)
	case ModalFileBrowser:
		fb := &m.FileBrowser
		filtered := fb.FilteredEntries()
		h := min(len(filtered)+4, 20)
		area := centeredRect(55, max(h, 4), screen)
		title := fmt.Sprintf(" %s ", fb.Path)
		if fb.Filtering {
			title = fmt.Sprintf(" %s [filter: %s] ", fb.Path, fb.Filter)
		}
		rows := make([][]styledSpan, len(filtered))
		for i, e := range filtered {
			var text string
			if e.IsDir {
				text = fmt.Sprintf("  📁 %s/", e.Name)
			} else {
				text = fmt.Sprintf("  📄 %-30s %6dKB", e.Name, e.Size/1024)
			}
			rows[i] = []styledSpan{{text: text, style: cellStyle{fg: fgWhite}}}
		}
		renderListModal(buf, area, title, fgCyan, rows, fb.Selected)
	case ModalSegmentForm:
		sf := &m.SegmentForm
		area := centeredRect(50, 10, screen)
		inner := buf.drawBox(area, " New Segment ", cellStyle{fg: fgYellow}, cellStyle{})
		mark := func(field uint8, suffix string) string {
			if sf.ActiveField == field {
				return " ◄" + suffix
			}
			return ""
		}
		fields := []string{
			fmt.Sprintf(" File: %s (%dKB)", sf.File, sf.FileSize/1024),
			fmt.Sprintf(" Name:  [%s]%s", sf.Name, mark(0, "")),
			fmt.Sprintf(" Base:  [%s]%s", sf.Base, mark(1, "")),
			fmt.Sprintf(" Entry: [%s]%s", sf.Entry, mark(2, " (optional)")),
			fmt.Sprintf(" Space: [%s]%s", sf.Space, mark(3, "")),
			" ",
			" [Tab]next  [Enter]confirm  [Esc]cancel",
		}
		for i := 0; i < len(fields) && i < inner.h; i++ {
			buf.putString(inner.x, inner.y+i, inner.w, fields[i], cellStyle{fg: fgWhite})
		}
	case ModalBitplane:
		renderBitplaneModal(buf, a, screen)
	case ModalBitplaneGeometry:
		renderInputModal(buf, screen, " Bitmap Geometry (WxH or WxHxD) ", &m.Input, fgCyan)
	case ModalBitplanePalette:
		renderInputModal(buf, screen, " Set Palette Address / Offset ", &m.Input, fgCyan)
	case ModalMusicRipper:
		st := &m.MusicRipper
		h := min(len(st.Items)+4, 18)
		area := centeredRect(70, max(h, 6), screen)
		rows := make([][]styledSpan, len(st.Items))
		for i, it := range st.Items {
			marker := "  "
			if i == st.Selected {
				marker = "▸ "
			}
			addr := a.BaseAddr + uint32(it.Start)
			roleTag := ""
			if it.Role != modules.RegionPrimary {
				roleTag = fmt.Sprintf(" [%s]", it.Role)
			}
			rows[i] = []styledSpan{
				{text: marker, style: cellStyle{fg: fgCyan, bold: true}},
				{text: fmt.Sprintf("%-18s", it.Name), style: cellStyle{fg: fgWhite, bold: true}},
				{text: fmt.Sprintf(" (%-8s)", it.Variant), style: cellStyle{fg: fgDarkGray}},
				{text: fmt.Sprintf(" +$%05X ($%05X)", it.Start, addr), style: cellStyle{fg: fgCyan}},
				{text: fmt.Sprintf(" %6d B%s", it.Len, roleTag), style: cellStyle{fg: fgYellow}},
			}
		}
		title := " Music Ripper (Enter=Jump, w=Rip, K=Carve, Esc=Close) "
		renderListModal(buf, area, title, fgCyan, rows, st.Selected)
	}
}

var (
	bitplaneLabelBase      = mustParseStyle("#C0CAF5 bold")
	bitplaneActiveSyncBase = mustParseStyle("#E0AF68 bold")
	bitplaneActiveBPUBase  = mustParseStyle("#7AA2F7 bold")
	bitplaneDimNumBase     = mustParseStyle("#65728A")
)

func renderBitplaneModal(buf *screenBuffer, a *App, screen rect) {
	st := a.Modal.Bitplane
	if st == nil {
		return
	}
	t := &a.Theme
	area := rect{x: 0, y: 1, w: screen.w, h: max(screen.h-2, 1)}

	protoName := a.Modal.PixelProtocol.String()
	startAddr := a.BaseAddr + st.BPL[0]
	diwStr := fmt.Sprintf("DIW: %d×%d", st.VisibleWidth(), st.Height)
	ddfStr := fmt.Sprintf("DDF: %d px (%d B)", st.WidthPx(), st.RowBytes)

	inner := buf.drawBox(area, "", t.Border, t.BG)
	if inner.w <= 0 || inner.h <= 0 {
		return
	}

	accentStyle := t.BarAccent
	labelStyle := bitplaneLabelBase
	labelStyle.bg = t.BG.bg
	activeSyncStyle := bitplaneActiveSyncBase
	activeSyncStyle.bg = t.BG.bg
	activeBPUStyle := bitplaneActiveBPUBase
	activeBPUStyle.bg = t.BG.bg
	dimNumStyle := bitplaneDimNumBase
	dimNumStyle.bg = t.BG.bg

	var titleSpans []styledSpan
	titleSpans = append(titleSpans, styledSpan{text: " Bitplanes ", style: accentStyle})
	titleSpans = append(titleSpans, styledSpan{text: "── ", style: t.Border})
	titleSpans = append(titleSpans, styledSpan{text: fmt.Sprintf("%s ", a.FormatAddr(startAddr)), style: accentStyle})
	titleSpans = append(titleSpans, styledSpan{text: "│ ", style: t.Border})
	titleSpans = append(titleSpans, styledSpan{text: fmt.Sprintf("%s ", diwStr), style: accentStyle})
	titleSpans = append(titleSpans, styledSpan{text: "│ ", style: t.Border})
	titleSpans = append(titleSpans, styledSpan{text: fmt.Sprintf("%s ", ddfStr), style: accentStyle})
	titleSpans = append(titleSpans, styledSpan{text: "│ ", style: t.Border})
	titleSpans = append(titleSpans, styledSpan{text: fmt.Sprintf("Scale: %dx ", st.Scale), style: accentStyle})
	titleSpans = append(titleSpans, styledSpan{text: "│ ", style: t.Border})
	titleSpans = append(titleSpans, styledSpan{text: fmt.Sprintf("%s ", protoName), style: accentStyle})

	curX := area.x + 1
	for _, sp := range titleSpans {
		if curX >= area.x+area.w-1 {
			break
		}
		rem := (area.x + area.w - 1) - curX
		n := buf.putString(curX, area.y, rem, sp.text, sp.style)
		curX += n
	}

	// Line 0 of inner: Custom Chipset Registers
	bpl1mod, bpl2mod := st.HardwareModulos()
	bplcon0Hex := fmt.Sprintf("$%04X", st.BPLCON0Hex())

	var regSpans []styledSpan
	regSpans = append(regSpans, styledSpan{text: " BPLCON0: ", style: labelStyle})
	regSpans = append(regSpans, styledSpan{text: fmt.Sprintf("%s ", bplcon0Hex), style: accentStyle})
	regSpans = append(regSpans, styledSpan{text: "│ BPL1MOD: ", style: labelStyle})
	regSpans = append(regSpans, styledSpan{text: fmt.Sprintf("%d ", bpl1mod), style: accentStyle})
	regSpans = append(regSpans, styledSpan{text: "BPL2MOD: ", style: labelStyle})
	regSpans = append(regSpans, styledSpan{text: fmt.Sprintf("%d ", bpl2mod), style: accentStyle})
	regSpans = append(regSpans, styledSpan{text: "│ BPLxPT: ", style: labelStyle})

	maxPlanesToShow := max(st.BPU(), 6)
	for p := 0; p < maxPlanesToShow; p++ {
		pNum := p + 1
		pText := fmt.Sprintf("%d:$%05X ", pNum, st.BPL[p])
		if (st.ControlMask & (1 << p)) != 0 {
			regSpans = append(regSpans, styledSpan{text: pText, style: accentStyle})
		} else {
			regSpans = append(regSpans, styledSpan{text: pText, style: dimNumStyle})
		}
	}
	buf.putSpansRow(inner.x, inner.y, inner.w, regSpans, t.BG.bg, nil)

	// Line 1 of inner: Indicators and Palette
	bpu := st.BPU()
	var indSpans []styledSpan
	indSpans = append(indSpans, styledSpan{text: " BPU:     ", style: labelStyle})
	for p := 1; p <= 7; p++ {
		pStr := fmt.Sprintf(" %d ", p)
		if p <= bpu {
			indSpans = append(indSpans, styledSpan{text: pStr, style: activeBPUStyle})
		} else {
			indSpans = append(indSpans, styledSpan{text: pStr, style: dimNumStyle})
		}
	}
	indSpans = append(indSpans, styledSpan{text: "│ Synced: ", style: labelStyle})
	for p := 1; p <= 7; p++ {
		pStr := fmt.Sprintf(" %d ", p)
		if (st.ControlMask & (1 << (p - 1))) != 0 {
			indSpans = append(indSpans, styledSpan{text: pStr, style: activeSyncStyle})
		} else {
			indSpans = append(indSpans, styledSpan{text: pStr, style: dimNumStyle})
		}
	}

	palName := "Grayscale"
	switch st.PaletteMode {
	case PaletteHighContrast:
		palName = "High-Contrast"
	case PaletteCustom:
		if st.CustomPalName != "" {
			palName = st.CustomPalName
		} else {
			palName = "Custom"
		}
	}
	indSpans = append(indSpans, styledSpan{text: fmt.Sprintf("│ Pal: %s ", palName), style: labelStyle})
	pal := st.BuildDefaultPalette()
	swatchCount := min(1<<bpu, 8)
	for i := 0; i < swatchCount; i++ {
		c := pal[i]
		stFG := fmt.Sprintf("38;2;%d;%d;%d", c.R, c.G, c.B)
		stBG := t.BG.bg
		indSpans = append(indSpans, styledSpan{
			text:  "█",
			style: cellStyle{fg: stFG, bg: stBG},
		})
	}
	buf.putSpansRow(inner.x, inner.y+1, inner.w, indSpans, t.BG.bg, nil)

	// Line 2 of inner: Divider
	if inner.h > 2 {
		sepStyle := cellStyle{fg: t.Border.fg, bg: t.BG.bg}
		for x := inner.x; x < inner.x+inner.w; x++ {
			buf.setCell(x, inner.y+2, '─', 1, sepStyle)
		}
	}

	// Canvas rows: inner.y+3 .. inner.y+inner.h-1
	canvasH := inner.h - 3
	if canvasH <= 0 {
		return
	}

	if a.Modal.PixelProtocol == ProtocolHalfBlock {
		// Half-block ▀ fallback rendering into screenBuffer
		halfBlockPxH := canvasH * 2
		img := st.DecodeImage(a.BinaryData, inner.w, halfBlockPxH)
		for cy := 0; cy < canvasH; cy++ {
			screenY := inner.y + 3 + cy
			for cx := 0; cx < inner.w; cx++ {
				topC := img.RGBAAt(cx, cy*2)
				botC := img.RGBAAt(cx, cy*2+1)
				topSGR := fmt.Sprintf("38;2;%d;%d;%d", topC.R, topC.G, topC.B)
				botSGR := fmt.Sprintf("48;2;%d;%d;%d", botC.R, botC.G, botC.B)
				buf.setCell(inner.x+cx, screenY, '▀', 1, cellStyle{
					fg: topSGR,
					bg: botSGR,
				})
			}
		}
	} else {
		// In true pixel graphics mode (Kitty, Sixel, iTerm2), keep the canvas area
		// completely clear (empty spaces with background) so that the terminal graphics
		// overlay is never overwritten by character cells.
		for cy := 0; cy < canvasH; cy++ {
			screenY := inner.y + 3 + cy
			for cx := 0; cx < inner.w; cx++ {
				buf.setCell(inner.x+cx, screenY, ' ', 1, t.BG)
			}
		}
	}
}

func padOrTruncate(s string, width int) string {
	sw := runewidth.StringWidth(s)
	if sw == width {
		return s
	}
	if sw < width {
		return s + strings.Repeat(" ", width-sw)
	}
	return runewidth.Truncate(s, width, "")
}
