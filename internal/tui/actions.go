package tui

import (
	"fmt"
	"image/png"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/mikolas/hunks/internal/analyzer"
	"github.com/mikolas/hunks/internal/db"
	"github.com/mikolas/hunks/internal/project"
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
	a.pushUndo(UndoEntry{
		Kind:         UndoCellDelete,
		ClearedStart: addr,
		ClearedLen:   size,
		Cells:        cells,
		Comments:     comments,
	})
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
		_ = a.DB.ClearOverlaps(entry.ClearedStart, entry.ClearedLen)
		for i := range entry.Cells {
			_ = a.DB.InsertCell(&entry.Cells[i])
		}
		for cAddr, ac := range entry.Comments {
			_ = a.DB.SetAutoComment(cAddr, ac.AutoComment)
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
		if entry.OldStr != nil {
			_ = a.DB.SetRename(entry.Key, *entry.OldStr)
		} else {
			_ = a.DB.DeleteRename(entry.Key)
		}
	}
	a.ReloadAtCursor()
	a.StatusMsg = "Undone"
}

// MarkString marks a NUL-terminated or printable ASCII string starting at the cursor.
func (a *App) MarkString() {
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
	a.pushUndoForRegion(addr, size)
	_ = a.DB.MarkData(addr, size, db.CellStr)
	a.ReloadAtCursor()
	a.StatusMsg = fmt.Sprintf("Marked %d byte string at %s", size, a.FormatAddr(addr))
}

// MarkType marks size bytes at the cursor as cellType.
func (a *App) MarkType(cellType db.CellType, size uint32) {
	addr, ok := a.CursorAddr()
	if !ok {
		return
	}
	a.pushUndoForRegion(addr, size)
	_ = a.DB.MarkData(addr, size, cellType)
	a.ReloadAtCursor()
	a.StatusMsg = fmt.Sprintf("Marked %s at %s", cellType.AsStr(), a.FormatAddr(addr))
}

// MarkCode marks the word-aligned cursor address as a code entry point and runs incremental analysis.
func (a *App) MarkCode() {
	rawAddr, ok := a.CursorAddr()
	if !ok {
		return
	}
	addr := rawAddr &^ 1
	a.pushUndoForRegion(addr, 2)
	if _, err := analyzer.ApplyCodeHint(a.Proj, a.DB, addr); err != nil {
		a.StatusMsg = fmt.Sprintf("Analyze failed: %v", err)
		return
	}
	a.ReloadAtCursor()
	a.StatusMsg = fmt.Sprintf("Marked code at %s", a.FormatAddr(addr))
}

// CarveRange carves [start, endIncl] in the current segment into an INCBIN cell.
func (a *App) CarveRange(start, endIncl uint32, name string) {
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
	raw := make([]byte, endOff-off)
	copy(raw, a.BinaryData[off:endOff])

	label := strings.TrimSpace(name)
	if label == "" {
		label = a.Proj.AutoLabel(start)
	}
	sidecar := fmt.Sprintf("assets/%s.bin", label)

	if err := a.DB.WithTransaction(func() error {
		if err := a.DB.ClearOverlaps(start, end-start); err != nil {
			return err
		}
		if err := a.DB.DeleteCellsInRange(start, end); err != nil {
			return err
		}
		if err := a.DB.InsertCell(&db.Cell{
			Seg:        a.DB.SegOf(start),
			Addr:       start,
			Size:       end - start,
			Type:       db.CellIncbin,
			Confidence: 255,
			RawBytes:   raw,
		}); err != nil {
			return err
		}
		return a.DB.SetLabel(start, label, db.LabelDat, false)
	}); err != nil {
		a.StatusMsg = fmt.Sprintf("Carve failed: %v", err)
		return
	}

	a.Proj.Data.Carves = slices.DeleteFunc(a.Proj.Data.Carves, func(c project.Carve) bool {
		return c.Start == start
	})
	a.Proj.Data.Carves = append(a.Proj.Data.Carves, project.Carve{
		Start: start,
		End:   end,
		File:  sidecar,
		Name:  label,
	})
	_ = a.Proj.Save()
	a.SelectionStart = nil
	a.ReloadAtCursor()
	a.StatusMsg = fmt.Sprintf("Carved %d bytes at %s -> %s", end-start, a.FormatAddr(start), sidecar)
}

// UncarveAtCursor removes the carve whose range contains the cursor address.
func (a *App) UncarveAtCursor() {
	addr, ok := a.CursorAddr()
	if !ok {
		return
	}
	idx := -1
	var carve project.Carve
	for i, c := range a.Proj.Data.Carves {
		if addr >= c.Start && addr < c.End {
			idx = i
			carve = c
			break
		}
	}
	if idx < 0 {
		a.StatusMsg = "No carve at cursor"
		return
	}
	_ = a.DB.DeleteCellsInRange(carve.Start, carve.End)
	a.Proj.Data.Carves = append(a.Proj.Data.Carves[:idx], a.Proj.Data.Carves[idx+1:]...)
	_ = a.Proj.Save()
	a.ReloadAtCursor()
	a.StatusMsg = fmt.Sprintf("Uncarved %s — press 'r' to reclassify", a.FormatAddr(carve.Start))
}

// Undefine deletes the cell and control edges at the cursor address.
func (a *App) Undefine() {
	addr, ok := a.CursorAddr()
	if !ok {
		return
	}
	targetAddr := addr
	if cell, err := a.DB.GetCellContaining(addr); err == nil && cell != nil {
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
	st := NewBitplaneState(baseOff)
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

	dir := "assets"
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

	dir := "assets"
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

// CarveBitplaneRange carves the memory region spanned by the current bitplanes.
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
	length := endOff - startOff

	label := fmt.Sprintf("gfx_%dx%dx%d", st.VisibleWidth(), st.Height, st.BPU())
	a.pushUndoForRegion(startAddr, length)
	if err := a.DB.WithTransaction(func() error {
		if err := a.DB.ClearOverlaps(startAddr, length); err != nil {
			return err
		}
		if err := a.DB.MarkData(startAddr, length, db.CellDataB); err != nil {
			return err
		}
		return a.DB.SetLabel(startAddr, label, db.LabelDat, true)
	}); err != nil {
		a.StatusMsg = fmt.Sprintf("Carve failed: %v", err)
		return
	}
	a.ReloadAtCursor()
	a.StatusMsg = fmt.Sprintf("Carved bitplane range +$%05X..+$%05X (%s)", startOff, endOff, label)
}
