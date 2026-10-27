package tui

import (
	"fmt"
	"image/png"
	"os"
	"path/filepath"
	"strings"

	"github.com/mikolas/hunks/internal/analyzer"
	"github.com/mikolas/hunks/internal/db"
	"github.com/mikolas/hunks/internal/modules"
)

func (a *App) pushUndo(entry UndoEntry) {
	a.UndoStack = append(a.UndoStack, entry)
	if len(a.UndoStack) > 50 {
		a.UndoStack = a.UndoStack[1:]
	}
}

func (a *App) pushUndoForRegion(addr, size uint32) {
	cells, _ := a.DB.CellsOverlapping(addr, size)
	comments, _ := a.DB.GetCommentsInRange(addr, addr+size)
	var oldLabels []db.Label
	if lbl, _ := a.DB.GetLabelFull(addr); lbl != nil {
		oldLabels = append(oldLabels, *lbl)
	}
	a.pushUndo(UndoEntry{
		Kind:         UndoCellDelete,
		ClearedStart: addr,
		ClearedLen:   size,
		Cells:        cells,
		Comments:     comments,
		OldLabels:    oldLabels,
	})
}

// incbinCellAtCursor returns the INCBIN cell if and only if the cursor is currently
// positioned on an INCBIN row in DisasmRows (and backed by a CellIncbin in the DB).
// It never matches dc.x (SubRowData), CODE, or other non-incbin rows.
func (a *App) incbinCellAtCursor() *db.Cell {
	if len(a.DisasmRows) > 0 {
		idx := min(max(a.SelectedIdx, 0), len(a.DisasmRows)-1)
		row := a.DisasmRows[idx]
		if row.Kind == SubRowData || row.CellType != "INCBIN" {
			return nil
		}
		if row.Addr != nil {
			if cell, err := a.DB.GetCell(*row.Addr); err == nil && cell != nil && cell.Type == db.CellIncbin && cell.Size > 0 {
				return cell
			}
		}
		return nil
	}
	addr, ok := a.CursorAddr()
	if !ok {
		return nil
	}
	if cell, err := a.DB.GetCell(addr); err == nil && cell != nil && cell.Type == db.CellIncbin && cell.Size > 0 {
		return cell
	}
	return nil
}

// rangeOverlapsIncbin returns true if [start, start+size) overlaps any CellIncbin in the DB.
func (a *App) rangeOverlapsIncbin(start, size uint32) bool {
	cells, err := a.DB.CellsOverlapping(start, size)
	if err != nil {
		return false
	}
	for i := range cells {
		if cells[i].Type == db.CellIncbin {
			return true
		}
	}
	return false
}

// Undo reverts the most recent user edit from UndoStack.
func (a *App) Undo() {
	if len(a.UndoStack) == 0 {
		a.StatusMsg = "Nothing to undo"
		return
	}
	entry := a.UndoStack[len(a.UndoStack)-1]
	a.UndoStack = a.UndoStack[:len(a.UndoStack)-1]
	switch entry.Kind {
	case UndoCellDelete:
		if err := a.DB.WithTransaction(func() error {
			if err := a.DB.ClearOverlaps(entry.ClearedStart, entry.ClearedLen); err != nil {
				return err
			}
			clearMin := entry.ClearedStart
			clearMax := entry.ClearedStart + entry.ClearedLen
			for i := range entry.Cells {
				if entry.Cells[i].Addr < clearMin {
					clearMin = entry.Cells[i].Addr
				}
				if end := entry.Cells[i].Addr + entry.Cells[i].Size; end > clearMax {
					clearMax = end
				}
			}
			if err := a.DB.DeleteCellsInRange(clearMin, clearMax); err != nil {
				return err
			}
			for i := range entry.Cells {
				if err := a.DB.InsertCell(&entry.Cells[i]); err != nil {
					return err
				}
			}
			currentComments, _ := a.DB.GetCommentsInRange(entry.ClearedStart, entry.ClearedStart+entry.ClearedLen)
			for cAddr := range currentComments {
				if _, existed := entry.Comments[cAddr]; !existed {
					if err := a.DB.UpdateComment(cAddr, ""); err != nil {
						return err
					}
					if err := a.DB.UpdateBlockComment(cAddr, ""); err != nil {
						return err
					}
					if err := a.DB.SetAutoComment(cAddr, ""); err != nil {
						return err
					}
				}
			}
			for cAddr, ac := range entry.Comments {
				if err := a.DB.UpdateComment(cAddr, ac.Comment); err != nil {
					return err
				}
				if err := a.DB.UpdateBlockComment(cAddr, ac.BlockComment); err != nil {
					return err
				}
				if err := a.DB.SetAutoComment(cAddr, ac.AutoComment); err != nil {
					return err
				}
			}
			if entry.DeletedLabel {
				if err := a.DB.DeleteLabelAt(entry.ClearedStart); err != nil {
					return err
				}
			}
			for _, lbl := range entry.OldLabels {
				if err := a.DB.SetLabel(lbl.Addr, lbl.Name, lbl.Type, lbl.IsAuto); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			a.StatusMsg = fmt.Sprintf("Undo failed: %v", err)
			return
		}
	case UndoLabelChange:
		if entry.OldStr != nil {
			_ = a.DB.RenameLabelAt(entry.Addr, *entry.OldStr)
		} else {
			_ = a.DB.DeleteLabelAt(entry.Addr)
		}
	case UndoCommentChange:
		cmt := ""
		if entry.OldStr != nil {
			cmt = *entry.OldStr
		}
		_ = a.DB.UpdateComment(entry.Addr, cmt)
	case UndoBlockCommentChange:
		cmt := ""
		if entry.OldStr != nil {
			cmt = *entry.OldStr
		}
		_ = a.DB.UpdateBlockComment(entry.Addr, cmt)
	case UndoRename:
		curRen, hasCur, _ := a.DB.GetRename(entry.Key)
		if entry.OldStr != nil {
			_ = a.DB.SetRename(entry.Key, *entry.OldStr)
			if hasCur && curRen != "" {
				a.Proj.ReKeyFunctionABI(curRen, *entry.OldStr)
			}
		} else {
			_ = a.DB.DeleteRename(entry.Key)
			if hasCur && curRen != "" {
				a.Proj.ReKeyFunctionABI(curRen, entry.Key)
			}
		}
		_ = a.Proj.Save()
	}
	a.ReloadAtCursor()
	a.StatusMsg = "Undone"
}

// MarkString marks a NUL-terminated or printable ASCII string starting at the cursor.
func (a *App) MarkString() {
	if a.incbinCellAtCursor() != nil {
		a.StatusMsg = "Folded incbin — press 'b' or 'K' to unfold first"
		return
	}
	addr, ok := a.CursorAddr()
	if !ok {
		return
	}
	off := int(addr - a.BaseAddr)
	if off < 0 || off >= len(a.BinaryData) {
		return
	}
	isPrintable := func(b byte) bool {
		return (b >= 0x20 && b <= 0x7E) || b == '\t' || b == '\r' || b == '\n'
	}
	end := off
	for end < len(a.BinaryData) && isPrintable(a.BinaryData[end]) {
		end++
	}
	if end < len(a.BinaryData) && a.BinaryData[end] == 0 {
		end++
	}
	if end == off {
		for end < len(a.BinaryData) && end-off < 256 && a.BinaryData[end] != 0 {
			end++
		}
		if end < len(a.BinaryData) && a.BinaryData[end] == 0 {
			end++
		}
	}
	size := uint32(end - off)
	if size == 0 {
		return
	}
	if a.rangeOverlapsIncbin(addr, size) {
		a.StatusMsg = "Folded incbin — press 'b' or 'K' to unfold first"
		return
	}
	a.pushUndoForRegion(addr, size)
	_ = a.DB.WithTransaction(func() error {
		return a.DB.MarkData(addr, size, db.CellStr)
	})
	a.ReloadAtCursor()
	a.StatusMsg = fmt.Sprintf("Marked %d byte string at %s", size, a.FormatAddr(addr))
}

// MarkType marks size bytes at the cursor as cellType (or unfolds an incbin when pressing 'b').
func (a *App) MarkType(cellType db.CellType, size uint32) {
	if a.incbinCellAtCursor() != nil {
		if cellType == db.CellDataB {
			a.UncarveAtCursor()
		} else {
			a.StatusMsg = "Folded incbin — press 'b' or 'K' to unfold first"
		}
		return
	}
	addr, ok := a.CursorAddr()
	if !ok {
		return
	}
	if a.rangeOverlapsIncbin(addr, size) {
		a.StatusMsg = "Folded incbin — press 'b' or 'K' to unfold first"
		return
	}
	a.pushUndoForRegion(addr, size)
	_ = a.DB.WithTransaction(func() error {
		return a.DB.MarkData(addr, size, cellType)
	})
	a.ReloadAtCursor()
	a.StatusMsg = fmt.Sprintf("Marked %s at %s", cellType.AsStr(), a.FormatAddr(addr))
}

// MarkCode marks the word-aligned cursor address as a code entry point and runs incremental analysis.
func (a *App) MarkCode() {
	if a.incbinCellAtCursor() != nil {
		a.StatusMsg = "Folded incbin — press 'b' or 'K' to unfold first"
		return
	}
	rawAddr, ok := a.CursorAddr()
	if !ok {
		return
	}
	addr := rawAddr &^ 1
	if a.rangeOverlapsIncbin(addr, 2) {
		a.StatusMsg = "Folded incbin — press 'b' or 'K' to unfold first"
		return
	}
	a.pushUndoForRegion(addr, 2)
	if _, err := analyzer.ApplyCodeHint(a.Proj, a.DB, addr); err != nil {
		a.StatusMsg = fmt.Sprintf("Analyze failed: %v", err)
		return
	}
	a.ReloadAtCursor()
	a.StatusMsg = fmt.Sprintf("Marked code at %s", a.FormatAddr(addr))
}

// CarveRange carves [start, endIncl] in the current segment into an INCBIN cell.
func (a *App) CarveRange(start, endIncl uint32, name, blockComment string) {
	if endIncl < start || endIncl == 0xFFFFFFFF || start < a.BaseAddr {
		a.StatusMsg = "Invalid carve range"
		return
	}
	end := endIncl + 1
	seg := a.Proj.SegmentAtAddr(start)
	if seg == nil {
		a.StatusMsg = "No segment owns the selection start"
		return
	}
	if end > seg.EndAddr() {
		a.StatusMsg = "Selection exceeds segment end"
		return
	}
	if seg.IsRelocatable() {
		interior := a.DB.RelocsInRange(start, end)
		if len(interior) > 0 {
			a.StatusMsg = fmt.Sprintf("Refused: %d relocation site(s) in range (first %s); would break rebuild",
				len(interior), a.FormatAddr(interior[0]))
			return
		}
		if start%2 != 0 || (end-start)%2 != 0 {
			a.StatusMsg = "Refused: start/length must be even-aligned in a relocatable segment"
			return
		}
	}

	off := int(start - a.BaseAddr)
	endOff := int(end - a.BaseAddr)
	if off < 0 || endOff > len(a.BinaryData) {
		a.StatusMsg = "Selection exceeds segment payload"
		return
	}

	cells, _ := a.DB.CellsOverlapping(start, end-start)
	comments, _ := a.DB.GetCommentsInRange(start, end)
	var oldLabels []db.Label
	hadStartLabel := false
	if lbl, _ := a.DB.GetLabelFull(start); lbl != nil {
		oldLabels = append(oldLabels, *lbl)
		hadStartLabel = true
	}
	var interiorOverlappedStarts []uint32
	for _, c := range cells {
		if c.Type == db.CellIncbin && c.Addr > start && c.Addr < end {
			interiorOverlappedStarts = append(interiorOverlappedStarts, c.Addr)
			if lbl, _ := a.DB.GetLabelFull(c.Addr); lbl != nil {
				oldLabels = append(oldLabels, *lbl)
			}
		}
	}

	label := strings.TrimSpace(name)
	isAuto := false
	if label == "" {
		label = a.Proj.AutoLabel(start)
		isAuto = true
	}
	sidecar := fmt.Sprintf("assets/%s.bin", label)

	if err := a.DB.WithTransaction(func() error {
		if err := a.DB.ClearOverlaps(start, end-start); err != nil {
			return err
		}
		if err := a.DB.DeleteCellsInRange(start, end); err != nil {
			return err
		}
		for _, cStart := range interiorOverlappedStarts {
			if err := a.DB.DeleteLabelAt(cStart); err != nil {
				return err
			}
			if err := a.DB.UpdateBlockComment(cStart, ""); err != nil {
				return err
			}
		}
		if err := a.DB.InsertCell(&db.Cell{
			Seg:        a.DB.SegOf(start),
			Addr:       start,
			Size:       end - start,
			Type:       db.CellIncbin,
			Confidence: 255,
		}); err != nil {
			return err
		}
		if err := a.DB.SetLabel(start, label, db.LabelDat, isAuto); err != nil {
			return err
		}
		if blockComment != "" {
			if err := a.DB.UpdateBlockComment(start, blockComment); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		a.StatusMsg = fmt.Sprintf("Carve failed: %v", err)
		return
	}

	a.pushUndo(UndoEntry{
		Kind:         UndoCellDelete,
		ClearedStart: start,
		ClearedLen:   end - start,
		Cells:        cells,
		Comments:     comments,
		OldLabels:    oldLabels,
		DeletedLabel: !hadStartLabel,
	})

	a.SelectionStart = nil
	a.ReloadAtCursor()
	// Move the disassembly cursor to the carved incbin's start address (intentional TUI UX
	// when carving from ModalBitplane, ModalMusicRipper, or a downward/upward range selection).
	a.GotoAddress(start)
	a.StatusMsg = fmt.Sprintf("Carved %d bytes at %s -> %s", end-start, a.FormatAddr(start), sidecar)
}

// UncarveAtCursor unfolds the INCBIN cell at the cursor row back into bytes.
// It refuses to act if the cursor is on a dc.x data row or any non-INCBIN row.
func (a *App) UncarveAtCursor() {
	cell := a.incbinCellAtCursor()
	if cell == nil {
		a.StatusMsg = "No carve at cursor"
		return
	}
	carveStart := cell.Addr
	carveEnd := cell.Addr + cell.Size
	cells, _ := a.DB.CellsOverlapping(carveStart, cell.Size)
	comments, _ := a.DB.GetCommentsInRange(carveStart, carveEnd)
	var oldLabels []db.Label
	if lbl, _ := a.DB.GetLabelFull(carveStart); lbl != nil {
		oldLabels = append(oldLabels, *lbl)
	}
	if err := a.DB.WithTransaction(func() error {
		if err := a.DB.DeleteCellsInRange(carveStart, carveEnd); err != nil {
			return err
		}
		if err := a.DB.DeleteLabelAt(carveStart); err != nil {
			return err
		}
		if err := a.DB.UpdateBlockComment(carveStart, ""); err != nil {
			return err
		}
		return nil
	}); err != nil {
		a.StatusMsg = fmt.Sprintf("Uncarve failed: %v", err)
		return
	}
	a.pushUndo(UndoEntry{
		Kind:         UndoCellDelete,
		ClearedStart: carveStart,
		ClearedLen:   cell.Size,
		Cells:        cells,
		Comments:     comments,
		OldLabels:    oldLabels,
	})
	a.ReloadAtCursor()
	a.StatusMsg = fmt.Sprintf("Uncarved %s — press 'r' to reclassify", a.FormatAddr(carveStart))
}

// Undefine deletes the cell and control edges at the cursor address (or unfolds an INCBIN).
func (a *App) Undefine() {
	if a.incbinCellAtCursor() != nil {
		a.UncarveAtCursor()
		return
	}
	addr, ok := a.CursorAddr()
	if !ok {
		return
	}
	targetAddr := addr
	if cell, err := a.DB.GetCellContaining(addr); err == nil && cell != nil {
		if cell.Type == db.CellIncbin {
			return
		}
		targetAddr = cell.Addr
		a.pushUndoForRegion(targetAddr, max(cell.Size, 1))
	}
	_ = a.DB.DeleteCellAndEdges(targetAddr)
	a.ReloadAtCursor()
	a.StatusMsg = fmt.Sprintf("Undefined at %s", a.FormatAddr(targetAddr))
}

// CycleOperandFormat cycles the operand format (HEX -> DEC -> BIN -> HEX) at the cursor.
func (a *App) CycleOperandFormat() {
	addr, ok := a.CursorAddr()
	if !ok {
		return
	}
	current, _, _ := a.DB.GetOperandFormat(addr)
	var next string
	switch current {
	case "", "HEX":
		next = "DEC"
	case "DEC":
		next = "BIN"
	default:
		next = "HEX"
	}
	_ = a.DB.SetOperandFormat(addr, next)
	var an *analyzer.Analyzer
	var err error
	if targetSeg := a.Proj.SegmentAtAddr(addr); targetSeg != nil && !targetSeg.IsRelocatable() {
		an, err = analyzer.NewForSegment(a.Proj, a.DB, targetSeg.Name)
	} else {
		an, err = analyzer.New(a.Proj, a.DB)
	}
	if err == nil && an != nil {
		an.ReanalyzeInstruction(addr)
	}
	a.Proj.SyncDBScope(a.DB)
	a.ReloadAtCursor()
}

// CalculateBitplaneScale calculates the optimal integer scale factor (1x..8x)
// to fit the native Amiga bitmap inside the terminal canvas using exact pixel resolution.
func (a *App) CalculateBitplaneScale(srcW, srcH int) int {
	if srcW <= 0 {
		srcW = 320
	}
	if srcH <= 0 {
		srcH = 200
	}

	if a.PixelWidth > 0 && a.PixelHeight > 0 && a.Width > 0 && a.Height > 0 {
		cellW := a.CellWidth
		if cellW <= 0 {
			cellW = a.PixelWidth / a.Width
		}
		cellH := a.CellHeight
		if cellH <= 0 {
			cellH = a.PixelHeight / a.Height
		}

		canvasCols := max(a.Width-2, 10)
		canvasRows := max(a.Height-6, 5)

		canvasPxW := canvasCols * cellW
		canvasPxH := canvasRows * cellH

		scaleW := canvasPxW / srcW
		scaleH := canvasPxH / srcH
		scale := min(scaleW, scaleH)
		if scale < 1 {
			scale = 1
		}
		if scale > 8 {
			scale = 8
		}
		return scale
	}

	return DetectOptimalScale(srcW, srcH)
}

// OpenBitplaneViewer initializes and launches the bitplane image viewer modal
// at the current cursor address.
func (a *App) OpenBitplaneViewer() {
	a.UpdateTermPixelSize()

	addr := a.BaseAddr
	if cur, ok := a.CursorAddr(); ok {
		addr = cur
	}
	var baseOff uint32
	if addr >= a.BaseAddr {
		baseOff = addr - a.BaseAddr
	}

	var st *BitplaneState
	if a.DB != nil {
		ac := a.DB.GetAddressComment(addr)
		lbl, _, _ := a.DB.GetLabel(addr)
		if restored, ok := ParseBitplaneBlockComment(ac.BlockComment, lbl, a.BaseAddr, baseOff, a.BinaryData); ok {
			st = restored
		}
	}
	if st == nil {
		st = NewBitplaneState(baseOff)
	}
	proto := DetectProtocol()

	// Scale to fit the terminal window canvas using exact pixel measurements
	st.Scale = a.CalculateBitplaneScale(st.VisibleWidth(), st.Height)

	a.Modal = Modal{
		Kind:          ModalBitplane,
		Bitplane:      st,
		PixelProtocol: proto,
	}
	a.StatusMsg = ""
	a.refreshBitplaneCache()
}

func (a *App) refreshBitplaneCache() {
	if a.Modal.Kind != ModalBitplane || a.Modal.Bitplane == nil {
		return
	}
	st := a.Modal.Bitplane

	var maxOutPxW, maxOutPxH int
	if a.CellWidth > 0 && a.CellHeight > 0 && a.Width > 0 && a.Height > 0 {
		canvasCols := max(a.Width-2, 10)
		canvasRows := max(a.Height-7, 5)
		maxOutPxW = canvasCols * a.CellWidth
		maxOutPxH = canvasRows * a.CellHeight
	}

	// Row 6: Line 1 (bar) + Area top border (Line 2) + Line 0 (Line 3) + Line 1 (Line 4) + Divider (Line 5) -> Canvas starts at Line 6
	st.UpdateCacheClipped(a.BinaryData, 2, 6, a.Modal.PixelProtocol, maxOutPxW, maxOutPxH)
}

func (a *App) assetsDir() string {
	if a.Proj != nil && a.Proj.WorkspaceRoot != "" {
		return filepath.Join(a.Proj.WorkspaceRoot, "assets")
	}
	return "assets"
}

// SaveBitplanePNG saves the full bitmap to assets/<seg>_<addr>_<W>x<H>x<D>.png.
func (a *App) SaveBitplanePNG() {
	st := a.Modal.Bitplane
	if st == nil {
		return
	}
	oldScale := st.Scale
	st.Scale = 1
	img := st.DecodeImage(a.BinaryData, 0, 0)
	st.Scale = oldScale

	dir := a.assetsDir()
	_ = os.MkdirAll(dir, 0755)

	segName := "seg"
	if a.Proj != nil && a.Proj.CurrentSegment() != nil {
		segName = a.Proj.CurrentSegment().Name
	}
	filename := fmt.Sprintf("%s_%05X_%dx%dx%d.png", segName, st.BPL[0], img.Bounds().Dx(), img.Bounds().Dy(), st.BPU())
	outPath := filepath.Join(dir, filename)

	f, err := os.Create(outPath)
	if err != nil {
		a.StatusMsg = fmt.Sprintf("PNG write error: %v", err)
		return
	}
	defer f.Close()

	if err := png.Encode(f, img); err != nil {
		a.StatusMsg = fmt.Sprintf("PNG encode error: %v", err)
		return
	}
	a.StatusMsg = fmt.Sprintf("Saved PNG: %s", outPath)
}

// SaveBitplaneIFF saves the bitmap to assets/<seg>_<addr>_<W>x<H>x<D>.ilbm.
func (a *App) SaveBitplaneIFF() {
	st := a.Modal.Bitplane
	if st == nil {
		return
	}
	iffBytes, err := EncodeIFFILBM(st, a.BinaryData)
	if err != nil {
		a.StatusMsg = fmt.Sprintf("IFF encode error: %v", err)
		return
	}

	dir := a.assetsDir()
	_ = os.MkdirAll(dir, 0755)

	segName := "seg"
	if a.Proj != nil && a.Proj.CurrentSegment() != nil {
		segName = a.Proj.CurrentSegment().Name
	}
	filename := fmt.Sprintf("%s_%05X_%dx%dx%d.ilbm", segName, st.BPL[0], st.VisibleWidth(), st.Height, st.BPU())
	outPath := filepath.Join(dir, filename)

	if err := os.WriteFile(outPath, iffBytes, 0644); err != nil {
		a.StatusMsg = fmt.Sprintf("IFF write error: %v", err)
		return
	}
	a.StatusMsg = fmt.Sprintf("Saved IFF ILBM: %s", outPath)
}

// CarveBitplaneRange initiates carving of the memory region spanned by the current bitplanes.
func (a *App) CarveBitplaneRange() {
	st := a.Modal.Bitplane
	if st == nil || a.DB == nil {
		return
	}
	startOff, endOff := st.ByteSpan()
	if len(a.BinaryData) > 0 && endOff > uint32(len(a.BinaryData)) {
		endOff = uint32(len(a.BinaryData))
	}
	if endOff <= startOff {
		return
	}
	startAddr := a.BaseAddr + startOff
	endAddr := a.BaseAddr + endOff

	seg := a.Proj.SegmentAtAddr(startAddr)
	if seg == nil || seg.IsRelocatable() {
		a.StatusMsg = "Refused: bitplane carving only supported in flat binaries"
		return
	}

	iSuf := ""
	if st.Interleaved {
		iSuf = "i"
	}
	hSuf := ""
	if st.Hires || st.RowBytes >= 80 {
		hSuf = "h"
	}
	hamSuf := ""
	if st.HAM && st.BPU() == 6 {
		hamSuf = "ham"
	}
	defaultLabel := fmt.Sprintf("gfx_%dx%dx%d%s%s%s", st.WidthPx(), st.Height, st.BPU(), iSuf, hSuf, hamSuf)
	blockComment := st.FormatBlockComment(a.BaseAddr)

	if a.Modal.PixelProtocol == ProtocolKitty {
		a.PendingEscapeSeq = ClearKittyPlacements()
	}

	a.Modal = Modal{
		Kind:              ModalCarveName,
		Input:             NewTextInput(defaultLabel),
		CarveStart:        startAddr,
		CarveEnd:          endAddr - 1,
		CarveBlockComment: blockComment,
		Bitplane:          st,
		PixelProtocol:     a.Modal.PixelProtocol,
	}
}

// OpenMusicRipper scans the active segment for embedded music modules and opens the ripper modal.
func (a *App) OpenMusicRipper() {
	if len(a.BinaryData) == 0 {
		a.StatusMsg = "No binary data in active segment"
		return
	}
	matches := modules.Scan(a.BinaryData)
	if len(matches) == 0 {
		a.StatusMsg = "No music modules found in segment"
		return
	}
	var items []MusicRipperItem
	for _, m := range matches {
		for _, r := range m.Regions {
			items = append(items, MusicRipperItem{
				FormatID: m.FormatID,
				Name:     m.Name,
				Variant:  m.Variant,
				Role:     r.Role,
				Start:    r.Start,
				Len:      r.Len,
			})
		}
	}
	cursorOff := 0
	if cur, ok := a.CursorAddr(); ok && cur >= a.BaseAddr {
		cursorOff = int(cur - a.BaseAddr)
	}
	bestIdx := 0
	for i, it := range items {
		if cursorOff >= it.Start && cursorOff < it.Start+it.Len {
			bestIdx = i
			break
		}
	}
	a.Modal = Modal{
		Kind: ModalMusicRipper,
		MusicRipper: MusicRipperState{
			Items:    items,
			Selected: bestIdx,
		},
	}
	a.StatusMsg = ""
}

func musicFormatSlug(name string) string {
	var sb strings.Builder
	prevUnderscore := false
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			sb.WriteRune(r)
			prevUnderscore = false
		} else if !prevUnderscore && sb.Len() > 0 {
			sb.WriteByte('_')
			prevUnderscore = true
		}
	}
	res := strings.TrimSuffix(sb.String(), "_")
	if res == "" {
		return "mod"
	}
	return res
}

// SaveMusicModule writes the selected module region to assets/<slug>_<offset>.bin (or .mod).
func (a *App) SaveMusicModule() {
	st := a.Modal.MusicRipper
	if len(st.Items) == 0 || st.Selected < 0 || st.Selected >= len(st.Items) {
		return
	}
	it := st.Items[st.Selected]
	endOff := it.Start + it.Len
	if it.Start < 0 || endOff > len(a.BinaryData) {
		a.StatusMsg = "Selected module exceeds binary payload"
		return
	}
	raw := a.BinaryData[it.Start:endOff]

	dir := a.assetsDir()
	_ = os.MkdirAll(dir, 0755)

	slug := musicFormatSlug(it.Name)
	ext := modules.FileExtForFormatID(it.FormatID, it.Role)
	filename := fmt.Sprintf("%s_%05X.%s", slug, it.Start, ext)
	outPath := filepath.Join(dir, filename)

	if err := os.WriteFile(outPath, raw, 0644); err != nil {
		a.StatusMsg = fmt.Sprintf("Module write error: %v", err)
		return
	}
	a.StatusMsg = fmt.Sprintf("Saved music module: %s (%d bytes)", outPath, len(raw))
}

// CarveMusicModule initiates carving of the selected music module region into an INCBIN cell.
func (a *App) CarveMusicModule() {
	st := a.Modal.MusicRipper
	if len(st.Items) == 0 || st.Selected < 0 || st.Selected >= len(st.Items) {
		return
	}
	it := st.Items[st.Selected]
	startAddr := a.BaseAddr + uint32(it.Start)
	endAddr := a.BaseAddr + uint32(it.Start+it.Len)

	seg := a.Proj.SegmentAtAddr(startAddr)
	if seg == nil || seg.IsRelocatable() {
		a.StatusMsg = "Refused: asset carving only supported in flat binaries"
		return
	}

	slug := musicFormatSlug(it.Name)
	defaultLabel := fmt.Sprintf("mod_%s_%05X", slug, it.Start)

	var sb strings.Builder
	fmt.Fprintf(&sb, "Music:  %s (%s) — %s\n", it.Name, it.Variant, it.Role)
	fmt.Fprintf(&sb, "Span:   $%06X..$%06X (%d bytes)", startAddr, endAddr, it.Len)
	blockComment := sb.String()

	a.Modal = Modal{
		Kind:              ModalCarveName,
		Input:             NewTextInput(defaultLabel),
		CarveStart:        startAddr,
		CarveEnd:          endAddr - 1,
		CarveBlockComment: blockComment,
		MusicRipper:       st,
	}
}
