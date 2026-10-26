package tui

import (
	"fmt"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/term"
	"github.com/mikolas/hunks/internal/db"
	"github.com/mikolas/hunks/internal/m68k"
	"github.com/mikolas/hunks/internal/project"
)

// App holds the full interactive TUI state and implements tea.Model.
type App struct {
	Proj             *project.Project
	DB               *db.Controller
	Theme            Theme
	SelectedIdx      int
	ScrollOffset     int
	DisasmRows       []ListingRow
	ShouldQuit       bool
	Modal            Modal
	NavHistory       []uint32
	StatusMsg        string
	BinaryData       []byte
	BaseAddr         uint32
	IsRelocatable    bool
	CachedCodeBytes  uint32
	DataByteOff      int
	UndoStack        []UndoEntry
	SelectionStart   *uint32
	Width            int
	Height           int
	LastWidth        int
	PixelWidth       int
	PixelHeight      int
	CellWidth        int
	CellHeight       int
	PendingEscapeSeq string
	activeDBPath     string
	ownsDB           bool
}

// NewApp initializes the TUI state from proj and ctrl.
func NewApp(proj *project.Project, ctrl *db.Controller) (*App, error) {
	seg := proj.CurrentSegment()
	if seg == nil {
		return nil, fmt.Errorf("no active segment; run `hunks init` first")
	}
	binData := seg.LoadBinaryData()
	app := &App{
		Proj:          proj,
		DB:            ctrl,
		Theme:         LoadTheme(),
		BinaryData:    binData,
		BaseAddr:      seg.Base,
		IsRelocatable: seg.IsRelocatable(),
		Width:         120,
		Height:        40,
		activeDBPath:  seg.DB,
	}
	if err := app.LoadData(); err != nil {
		return nil, err
	}
	found := false
	for i, r := range app.DisasmRows {
		if r.Addr != nil && r.IsPrimary {
			app.SelectedIdx = i
			found = true
			break
		}
	}
	if !found {
		for i, r := range app.DisasmRows {
			if r.Addr != nil {
				app.SelectedIdx = i
				break
			}
		}
	}
	return app, nil
}

// Run launches the interactive Bubble Tea TUI for proj.
func Run(proj *project.Project) error {
	seg := proj.CurrentSegment()
	if seg == nil {
		return fmt.Errorf("no active segment; run `hunks init` first")
	}
	ctrl, err := db.New(seg.DB)
	if err != nil {
		return err
	}
	defer ctrl.Close()

	app, err := NewApp(proj, ctrl)
	if err != nil {
		return err
	}
	defer func() {
		if app.ownsDB && app.DB != nil {
			_ = app.DB.Close()
		}
	}()

	app.QueryTermPixelSize()

	p := tea.NewProgram(app, tea.WithAltScreen(), tea.WithMouseCellMotion())
	_, err = p.Run()
	return err
}

// Init implements tea.Model.
func (a *App) Init() tea.Cmd {
	return nil
}

// Update implements tea.Model.
func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m := msg.(type) {
	case tea.WindowSizeMsg:
		a.Width = m.Width
		a.Height = m.Height
		a.UpdateTermPixelSize()
		if a.Modal.Kind == ModalBitplane && a.Modal.Bitplane != nil {
			a.refreshBitplaneCache()
		}
		if max(a.Width, 80) != a.LastWidth {
			anchorAddr, ok := a.CursorAddr()
			_ = a.LoadData()
			if ok {
				a.GotoAddress(anchorAddr)
			}
		}
	case tea.KeyMsg:
		a.HandleKeyMsg(m)
		if a.ShouldQuit {
			return a, tea.Quit
		}
	case tea.MouseMsg:
		a.HandleMouseMsg(m)
	}
	return a, nil
}

// View implements tea.Model.
func (a *App) View() string {
	return RenderUI(a)
}

// FormatAddr formats addr according to relocatable vs flat segment display rules.
func (a *App) FormatAddr(addr uint32) string {
	if a.IsRelocatable {
		segEnd := a.BaseAddr + uint32(len(a.BinaryData))
		if addr >= a.BaseAddr && addr < segEnd {
			return fmt.Sprintf("+%05X", addr-a.BaseAddr)
		}
		if seg := a.Proj.SegmentAtAddr(addr); seg != nil {
			var off uint32
			if addr >= seg.Base {
				off = addr - seg.Base
			}
			return fmt.Sprintf("%s+%05X", seg.Name, off)
		}
	}
	return fmt.Sprintf("$%05X", addr)
}

// LoadData regenerates DisasmRows for the active segment using BuildListingRows.
func (a *App) LoadData() error {
	a.Proj.SyncDBScope(a.DB)
	segPtr := a.Proj.CurrentSegment()
	if segPtr == nil {
		return fmt.Errorf("no active segment")
	}
	binData := a.BinaryData
	if len(binData) == 0 {
		binData = segPtr.LoadBinaryData()
	}
	effW := max(a.Width, 80)
	rows, codeBytes, err := buildListingRowsWithData(a.Proj, a.DB, segPtr, binData, effW)
	if err != nil {
		return err
	}
	a.DisasmRows = rows
	a.CachedCodeBytes = codeBytes
	a.LastWidth = effW
	return nil
}

// SwitchSegment switches the active segment to segName and reloads disassembly rows.
func (a *App) SwitchSegment(segName string) {
	segPtr := a.Proj.SegmentByName(segName)
	if segPtr == nil {
		return
	}
	seg := *segPtr
	if seg.DB != "" && seg.DB != ":memory:" && seg.DB != a.activeDBPath {
		newDB, err := db.New(seg.DB)
		if err != nil {
			a.StatusMsg = fmt.Sprintf("Failed to open DB for segment '%s'", segName)
			return
		}
		if a.ownsDB && a.DB != nil {
			_ = a.DB.Close()
		}
		a.DB = newDB
		a.ownsDB = true
		a.activeDBPath = seg.DB
	}
	a.BinaryData = seg.LoadBinaryData()
	a.BaseAddr = seg.Base
	a.IsRelocatable = seg.IsRelocatable()
	a.Proj.ActiveSegmentName = seg.Name
	_ = a.LoadData()
	firstIdx := 0
	found := false
	for i, r := range a.DisasmRows {
		if r.Addr != nil && r.IsPrimary {
			firstIdx = i
			found = true
			break
		}
	}
	if !found {
		for i, r := range a.DisasmRows {
			if r.Addr != nil {
				firstIdx = i
				break
			}
		}
	}
	a.SelectedIdx = firstIdx
	a.DataByteOff = 0
	a.StatusMsg = fmt.Sprintf("Switched to segment '%s'", seg.Name)
}

// ToggleSelection starts or cancels a byte range selection.
func (a *App) ToggleSelection() {
	if a.SelectionStart != nil {
		a.SelectionStart = nil
		a.StatusMsg = "Selection cancelled"
	} else if cur, ok := a.CursorAddr(); ok {
		a.SelectionStart = &cur
		a.StatusMsg = fmt.Sprintf("Selection started at %s (move cursor, then type to apply)", a.FormatAddr(cur))
	}
}

// SelectSubroutine selects (or cancels selection of) the subroutine enclosing the cursor.
func (a *App) SelectSubroutine() {
	funcStart, lastInsnAddr, ok := a.subroutineBoundsAtCursor()
	if !ok {
		a.StatusMsg = "No subroutine at cursor"
		return
	}
	if selStart, selEnd, hasSel := a.GetSelectionRange(); hasSel && selStart == funcStart && selEnd == lastInsnAddr {
		a.SelectionStart = nil
		a.StatusMsg = "Selection cancelled"
		return
	}
	a.SelectionStart = &funcStart
	a.GotoAddress(lastInsnAddr)
}

func isSubroutineTerminator(mnem string) bool {
	op, _ := m68k.ParseMnemonic(mnem)
	switch op {
	case m68k.OpRTS, m68k.OpRTE, m68k.OpRTR, m68k.OpJMP, m68k.OpBRA, m68k.OpILLEGAL:
		return true
	}
	return false
}

func branchTargetAddr(row *ListingRow, curAddr uint32) (uint32, bool) {
	if len(row.RawBytes) >= 2 {
		if insn, ok := m68k.Decode(row.RawBytes, curAddr); ok {
			if insn.IsBranch() && !insn.IsCall() {
				for _, op := range insn.Operands() {
					if op.Mode == m68k.EABranch || op.Mode == m68k.EAPCDisp16 {
						return op.UVal, true
					}
				}
				if row.RefTarget != nil {
					return *row.RefTarget, true
				}
			}
			return 0, false
		}
	}
	op, _ := m68k.ParseMnemonic(row.Mnem)
	if (op == m68k.OpBcc || op == m68k.OpDBcc || op == m68k.OpBRA) && row.RefTarget != nil {
		return *row.RefTarget, true
	}
	return 0, false
}

func (a *App) subroutineBoundsAtCursor() (uint32, uint32, bool) {
	cur, ok := a.CursorAddr()
	if !ok {
		return 0, 0, false
	}

	var codeIdxs []int
	curCodePos := -1
	for i := range a.DisasmRows {
		r := &a.DisasmRows[i]
		if r.Kind == SubRowCode && r.Addr != nil {
			if *r.Addr == cur && curCodePos < 0 {
				curCodePos = len(codeIdxs)
			}
			codeIdxs = append(codeIdxs, i)
		}
	}
	if len(codeIdxs) == 0 || curCodePos < 0 {
		return 0, 0, false
	}

	funcSet := make(map[uint32]struct{})
	if a.DB != nil {
		for _, fa := range a.DB.FunctionLabelAddrs() {
			funcSet[fa] = struct{}{}
		}
	}
	if a.Proj != nil {
		for _, ep := range a.Proj.Data.EntryPoints {
			if ep.Segment == "" || strings.EqualFold(ep.Segment, a.Proj.ActiveSegmentName) {
				funcSet[ep.Addr] = struct{}{}
			}
		}
	}
	funcAddrs := slices.Sorted(maps.Keys(funcSet))

	subStartPos := 0
	var maxBranchTarget uint32
	for pos := 0; pos < len(codeIdxs); pos++ {
		curRow := &a.DisasmRows[codeIdxs[pos]]
		curAddr := *curRow.Addr
		curSize := max(curRow.Size, 2)
		nextAddr := curAddr + curSize

		if brTgt, isBr := branchTargetAddr(curRow, curAddr); isBr && brTgt > curAddr {
			idx, _ := slices.BinarySearch(funcAddrs, curAddr+1)
			crossesFunc := idx < len(funcAddrs) && funcAddrs[idx] <= brTgt
			if !crossesFunc && brTgt > maxBranchTarget {
				maxBranchTarget = brTgt
			}
		}

		isEnd := false
		if pos+1 >= len(codeIdxs) {
			isEnd = true
		} else {
			nextRow := &a.DisasmRows[codeIdxs[pos+1]]
			if *nextRow.Addr != nextAddr {
				isEnd = true
			} else if _, isFunc := funcSet[*nextRow.Addr]; isFunc {
				isEnd = true
			} else if isSubroutineTerminator(curRow.Mnem) && maxBranchTarget < nextAddr {
				isEnd = true
			}
		}

		if isEnd {
			if pos >= curCodePos {
				startAddr := *a.DisasmRows[codeIdxs[subStartPos]].Addr
				endAddr := *a.DisasmRows[codeIdxs[pos]].Addr
				return startAddr, endAddr, true
			}
			subStartPos = pos + 1
			maxBranchTarget = 0
		}
	}

	return 0, 0, false
}

func formatRangeUint32(lo, hi uint32) string {
	if lo == hi {
		return strconv.FormatUint(uint64(lo), 10)
	}
	return strconv.FormatUint(uint64(lo), 10) + "-" + strconv.FormatUint(uint64(hi), 10)
}

func formatBlockTiming(minCyc, maxCyc, minR, maxR, minW, maxW uint32) string {
	if maxCyc == 0 {
		return "-- cyc"
	}
	return fmt.Sprintf("%s (%s/%s) cyc",
		formatRangeUint32(minCyc, maxCyc),
		formatRangeUint32(minR, maxR),
		formatRangeUint32(minW, maxW),
	)
}

func (a *App) selectionBlockStats(start, end uint32) (size uint32, insns int, timingStr string) {
	maxEndByte := end
	var minCyc, maxCyc uint32
	var minR, maxR uint32
	var minW, maxW uint32

	for i := range a.DisasmRows {
		row := &a.DisasmRows[i]
		if row.Kind != SubRowCode || row.Addr == nil {
			continue
		}
		rStart := *row.Addr
		rEnd := rStart + max(row.Size, 1) - 1
		if rStart > end || rEnd < start {
			continue
		}
		if rEnd > maxEndByte {
			maxEndByte = rEnd
		}
		insns++
		t := row.Timing
		switch t.Kind {
		case m68k.TimingBranch, m68k.TimingRange:
			minCyc += uint32(min(t.Primary.Cycles, t.Secondary.Cycles))
			maxCyc += uint32(max(t.Primary.Cycles, t.Secondary.Cycles))
			minR += uint32(min(t.Primary.Reads, t.Secondary.Reads))
			maxR += uint32(max(t.Primary.Reads, t.Secondary.Reads))
			minW += uint32(min(t.Primary.Writes, t.Secondary.Writes))
			maxW += uint32(max(t.Primary.Writes, t.Secondary.Writes))
		default:
			minCyc += uint32(t.Primary.Cycles)
			maxCyc += uint32(t.Primary.Cycles)
			minR += uint32(t.Primary.Reads)
			maxR += uint32(t.Primary.Reads)
			minW += uint32(t.Primary.Writes)
			maxW += uint32(t.Primary.Writes)
		}
	}
	size = maxEndByte - start + 1
	if insns > 0 {
		timingStr = formatBlockTiming(minCyc, maxCyc, minR, maxR, minW, maxW)
	}
	return size, insns, timingStr
}

// GetSelectionRange returns the ordered inclusive (start, end) selection range if active.
func (a *App) GetSelectionRange() (uint32, uint32, bool) {
	if a.SelectionStart == nil {
		return 0, 0, false
	}
	cur, ok := a.CursorAddr()
	if !ok {
		return 0, 0, false
	}
	start := min(*a.SelectionStart, cur)
	end := max(*a.SelectionStart, cur)
	return start, end, true
}

// MarkSelection marks the active selection range as cellType with unitSize.
func (a *App) MarkSelection(cellType db.CellType, unitSize uint32) {
	start, end, ok := a.GetSelectionRange()
	if !ok || unitSize == 0 {
		return
	}
	count := (end-start)/unitSize + 1
	size := count * unitSize
	if a.rangeOverlapsIncbin(start, size) {
		a.StatusMsg = "Folded incbin — press 'b' or 'K' to unfold first"
		return
	}
	a.pushUndoForRegion(start, size)
	_ = a.DB.WithTransaction(func() error {
		if cellType == db.CellStr {
			return a.DB.MarkData(start, size, db.CellStr)
		}
		for i := range count {
			if err := a.DB.MarkData(start+i*unitSize, unitSize, cellType); err != nil {
				return err
			}
		}
		return nil
	})
	a.SelectionStart = nil
	a.ReloadAtCursor()
	a.StatusMsg = fmt.Sprintf("Marked %d bytes as %s at %s", size, cellType.AsStr(), a.FormatAddr(start))
}

// GetStatusLine returns the formatted bottom status bar line.
func (a *App) GetStatusLine() string {
	addr, ok := a.CursorAddr()
	if !ok {
		return " No selection"
	}
	if start, end, selOk := a.GetSelectionRange(); selOk {
		size, insns, timingStr := a.selectionBlockStats(start, end)
		if insns > 0 {
			return fmt.Sprintf(" SELECT: %s–%s (%dB, %d insns) │ %s │ c/b/w/l/s/p/K to apply, Esc cancel",
				a.FormatAddr(start), a.FormatAddr(end), size, insns, timingStr)
		}
		return fmt.Sprintf(" SELECT: %s–%s (%dB) │ c/b/w/l/s/p/K to apply, Esc cancel",
			a.FormatAddr(start), a.FormatAddr(end), size)
	}

	var off uint32
	if addr >= a.BaseAddr {
		off = addr - a.BaseAddr
	}

	displayLabel := "-"
	if name, ok := a.DB.NearestLabelAtOrBefore(a.BaseAddr, addr); ok {
		if ren, hasRen, _ := a.DB.GetRename(name); hasRen && ren != "" {
			displayLabel = ren
		} else {
			displayLabel = name
		}
	}

	cellInfo := "undefined"
	var rowSize uint32
	var byteSuffix string
	var timing m68k.Timing
	if a.SelectedIdx >= 0 && a.SelectedIdx < len(a.DisasmRows) {
		r := &a.DisasmRows[a.SelectedIdx]
		if r.CellType != "" {
			cellInfo = r.CellType
		}
		rowSize = r.Size
		timing = r.Timing
		if r.Kind == SubRowData && r.Size > 1 {
			byteSuffix = fmt.Sprintf(" +%d", a.DataByteOff)
		}
	}
	if timing.Primary.Cycles == 0 {
		for i := range a.DisasmRows {
			if a.DisasmRows[i].Addr != nil && *a.DisasmRows[i].Addr == addr && a.DisasmRows[i].IsPrimary {
				timing = a.DisasmRows[i].Timing
				break
			}
		}
	}
	if cellInfo == "undefined" {
		if c, err := a.DB.GetCellContaining(addr); err == nil && c != nil {
			cellInfo = c.Type.AsStr()
			rowSize = c.Size
		}
	}

	total := uint32(len(a.BinaryData))
	var pct float64
	if total > 0 {
		pct = (float64(a.CachedCodeBytes) / float64(total)) * 100.0
	}

	var sizePart string
	if rowSize > 0 {
		sizePart = fmt.Sprintf("%s (%dB)%s", cellInfo, rowSize, byteSuffix)
	} else {
		sizePart = cellInfo
	}

	return fmt.Sprintf(" %s (off +%05X) │ %s │ %s │ %s │ Code %5.1f%% │ ←/→:byte ;:cmt ?:help",
		a.FormatAddr(addr),
		off,
		padOrTruncate(displayLabel, 16),
		padOrTruncate(sizePart, 16),
		padOrTruncate(timing.String(), 19),
		pct)
}

// QueryTermPixelSize queries the terminal text area pixel size via \x1b[14t
// in raw mode at startup (before Bubble Tea takes ownership of stdin).
func (a *App) QueryTermPixelSize() {
	if cols, rows, err := term.GetSize(os.Stdout.Fd()); err == nil && cols > 0 && rows > 0 {
		a.Width = cols
		a.Height = rows
	}
	if pxW, pxH := QueryTextAreaPixels(); pxW > 0 && pxH > 0 {
		a.PixelWidth = pxW
		a.PixelHeight = pxH
		if a.Width > 0 {
			a.CellWidth = a.PixelWidth / a.Width
		}
		if a.Height > 0 {
			a.CellHeight = a.PixelHeight / a.Height
		}
	}
}

// UpdateTermPixelSize updates the terminal window pixel dimensions when the
// character grid (Width x Height) is resized during an active TUI session.
func (a *App) UpdateTermPixelSize() {
	if a.CellWidth <= 0 && a.PixelWidth > 0 && a.Width > 0 {
		a.CellWidth = a.PixelWidth / a.Width
	}
	if a.CellHeight <= 0 && a.PixelHeight > 0 && a.Height > 0 {
		a.CellHeight = a.PixelHeight / a.Height
	}
	if a.CellWidth > 0 && a.CellHeight > 0 && a.Width > 0 && a.Height > 0 {
		a.PixelWidth = a.Width * a.CellWidth
		a.PixelHeight = a.Height * a.CellHeight
	}
}
