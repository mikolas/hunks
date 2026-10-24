package tui

import "strings"

// CursorAddr returns the current byte address at the cursor (incorporating DataByteOff on SubRowData rows).
func (a *App) CursorAddr() (uint32, bool) {
	if len(a.DisasmRows) == 0 {
		return 0, false
	}
	idx := min(max(a.SelectedIdx, 0), len(a.DisasmRows)-1)
	row := a.DisasmRows[idx]
	if row.Addr != nil {
		if row.Kind == SubRowData && row.Size > 0 {
			off := min(max(a.DataByteOff, 0), int(row.Size)-1)
			return *row.Addr + uint32(off), true
		}
		return *row.Addr, true
	}
	for i := idx - 1; i >= 0; i-- {
		if a.DisasmRows[i].Addr != nil {
			return *a.DisasmRows[i].Addr, true
		}
	}
	for i := idx + 1; i < len(a.DisasmRows); i++ {
		if a.DisasmRows[i].Addr != nil {
			return *a.DisasmRows[i].Addr, true
		}
	}
	return 0, false
}

// GotoAddress moves the cursor to addr, switching segments if addr lies in another segment of the active space.
func (a *App) GotoAddress(addr uint32) {
	segEnd := a.BaseAddr + uint32(len(a.BinaryData))
	if addr < a.BaseAddr || addr >= segEnd {
		if tgtSeg := a.Proj.SegmentAtAddr(addr); tgtSeg != nil {
			segName := tgtSeg.Name
			if a.Proj.ActiveSegmentName != segName {
				a.SwitchSegment(segName)
			}
		}
	}
	idx := -1
	byteOff := 0
	// 1. Exact primary row match
	for i, r := range a.DisasmRows {
		if r.Addr != nil && r.IsPrimary && *r.Addr == addr {
			idx = i
			break
		}
	}
	// 2. Interior byte match inside a SubRowData row
	if idx < 0 {
		for i, r := range a.DisasmRows {
			if r.Addr != nil && r.Kind == SubRowData && *r.Addr <= addr && addr < *r.Addr+r.Size {
				idx = i
				byteOff = int(addr - *r.Addr)
				break
			}
		}
	}
	// 3. Any row at addr
	if idx < 0 {
		for i, r := range a.DisasmRows {
			if r.Addr != nil && *r.Addr == addr {
				idx = i
				break
			}
		}
	}
	// 4. First addressed row >= addr
	if idx < 0 {
		for i, r := range a.DisasmRows {
			if r.Addr != nil && *r.Addr >= addr && r.Mnem != "equ" {
				idx = i
				break
			}
		}
	}
	if idx < 0 {
		if len(a.DisasmRows) > 0 {
			idx = len(a.DisasmRows) - 1
		} else {
			idx = 0
		}
	}
	a.SelectedIdx = idx
	a.DataByteOff = byteOff
}

// NavigateTo pushes the current address onto NavHistory and jumps to addr.
func (a *App) NavigateTo(addr uint32) {
	if cur, ok := a.CursorAddr(); ok {
		a.NavHistory = append(a.NavHistory, cur)
		if len(a.NavHistory) > 100 {
			a.NavHistory = a.NavHistory[1:]
		}
	}
	a.GotoAddress(addr)
}

// NavigateBack pops the most recent address from NavHistory and jumps to it.
func (a *App) NavigateBack() {
	if len(a.NavHistory) == 0 {
		return
	}
	addr := a.NavHistory[len(a.NavHistory)-1]
	a.NavHistory = a.NavHistory[:len(a.NavHistory)-1]
	a.GotoAddress(addr)
}

// ReloadAtCursor reloads DisasmRows and restores the cursor address.
func (a *App) ReloadAtCursor() {
	addr, ok := a.CursorAddr()
	_ = a.LoadData()
	if ok {
		a.GotoAddress(addr)
	}
}

// FollowReference navigates to the control-flow, data, or XREF badge target at the cursor.
func (a *App) FollowReference() {
	if a.SelectedIdx >= 0 && a.SelectedIdx < len(a.DisasmRows) {
		row := &a.DisasmRows[a.SelectedIdx]
		if (row.Kind == SubRowXref || row.Kind == SubRowLabel) && len(row.Xrefs) > 0 {
			idx := min(max(a.DataByteOff, 0), len(row.Xrefs)-1)
			a.NavigateTo(row.Xrefs[idx].CallerAddr)
			return
		}
		if row.RefTarget != nil {
			a.NavigateTo(*row.RefTarget)
			return
		}
	}

	addr, ok := a.CursorAddr()
	if !ok {
		return
	}
	rowSize := uint32(2)
	if a.SelectedIdx >= 0 && a.SelectedIdx < len(a.DisasmRows) {
		rowSize = max(a.DisasmRows[a.SelectedIdx].Size, 2)
	}
	target, found := a.DB.FirstControlEdgeTarget(addr)
	if !found {
		target, found = a.DB.FirstXrefTargetIn(addr, addr+rowSize)
	}
	if !found && a.SelectedIdx >= 0 && a.SelectedIdx < len(a.DisasmRows) {
		cmt := a.DisasmRows[a.SelectedIdx].Comment
		arrowIdx := strings.Index(cmt, "→ ")
		prefix := "→ "
		if arrowIdx < 0 {
			arrowIdx = strings.Index(cmt, "-> ")
			prefix = "-> "
		}
		if arrowIdx >= 0 {
			after := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(cmt[arrowIdx:], prefix), ")"))
			if after != "" && strings.Contains(after, ":") {
				target, found = a.Proj.ResolveTarget(a.DB, after)
			}
		}
	}
	if found {
		a.NavigateTo(target)
	}
}

// MoveCursor moves the row cursor by delta.
func (a *App) MoveCursor(delta int) {
	if len(a.DisasmRows) == 0 {
		return
	}
	next := a.SelectedIdx + delta
	if next < 0 {
		next = 0
	} else if next >= len(a.DisasmRows) {
		next = len(a.DisasmRows) - 1
	}
	a.SelectedIdx = next
	dst := &a.DisasmRows[next]
	if dst.Kind == SubRowData && dst.Size > 0 {
		maxCol := min(int(dst.Size), 16) - 1
		a.DataByteOff = min(max(a.DataByteOff, 0), maxCol)
	} else {
		a.DataByteOff = 0
	}
}

// MoveDataByte moves the horizontal byte cursor on SubRowData rows (or badge cursor on SubRowLabel/SubRowXref rows) by delta.
func (a *App) MoveDataByte(delta int) {
	if a.SelectedIdx < 0 || a.SelectedIdx >= len(a.DisasmRows) {
		return
	}
	row := &a.DisasmRows[a.SelectedIdx]
	if (row.Kind == SubRowXref || row.Kind == SubRowLabel) && len(row.Xrefs) > 0 {
		maxIdx := len(row.Xrefs) - 1
		a.DataByteOff = min(max(a.DataByteOff+delta, 0), maxIdx)
		return
	}
	if row.Kind != SubRowData || row.Size == 0 {
		return
	}
	maxCol := min(int(row.Size), 16) - 1
	next := a.DataByteOff + delta
	if next < 0 {
		if a.SelectedIdx > 0 && a.DisasmRows[a.SelectedIdx-1].Kind == SubRowData && a.DisasmRows[a.SelectedIdx-1].Size > 0 {
			a.SelectedIdx--
			prevSize := min(int(a.DisasmRows[a.SelectedIdx].Size), 16)
			a.DataByteOff = prevSize - 1
			return
		}
		next = 0
	} else if next > maxCol {
		if a.SelectedIdx+1 < len(a.DisasmRows) && a.DisasmRows[a.SelectedIdx+1].Kind == SubRowData && a.DisasmRows[a.SelectedIdx+1].Size > 0 {
			a.SelectedIdx++
			a.DataByteOff = 0
			return
		}
		next = maxCol
	}
	a.DataByteOff = next
}
