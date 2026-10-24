package tui

import (
	"cmp"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mikolas/hunks/internal/analyzer"
	"github.com/mikolas/hunks/internal/db"
	"github.com/mikolas/hunks/internal/project"
)

// ContextMenuItems returns the labels displayed in the context menu modal.
func ContextMenuItems() []string {
	return []string{
		"Follow Reference  (Enter)",
		"Show XREFs        (x)",
		"───────────────────────",
		"Mark as Code      (c)",
		"Mark Byte         (b)",
		"Mark Word         (w)",
		"Mark Long         (l)",
		"Mark String       (s)",
		"Mark Pointer      (p)",
		"Undefine          (u)",
		"───────────────────────",
		"Rename            (n)",
		"Comment           (;)",
		"Block Comment     (:)",
		"Cycle Format      (#)",
		"───────────────────────",
		"Export ASM        (e)",
	}
}

func (a *App) executeContextAction(idx int) {
	switch idx {
	case 0:
		a.FollowReference()
	case 1:
		a.OpenXrefs()
	case 3:
		a.MarkCode()
	case 4:
		a.MarkType(db.CellDataB, 1)
	case 5:
		a.MarkType(db.CellDataW, 2)
	case 6:
		a.MarkType(db.CellDataL, 4)
	case 7:
		a.MarkString()
	case 8:
		a.MarkType(db.CellPointer, 4)
	case 9:
		a.Undefine()
	case 11:
		if addr, ok := a.CursorAddr(); ok {
			orig, hasLbl, _ := a.DB.GetLabel(addr)
			if !hasLbl || orig == "" {
				orig = a.Proj.AutoLabel(addr)
			}
			current := orig
			if ren, hasRen, _ := a.DB.GetRename(orig); hasRen && ren != "" {
				current = ren
			}
			a.Modal = Modal{Kind: ModalRename, Input: NewTextInput(current)}
		}
	case 12:
		a.openCommentModal(false)
	case 13:
		a.openCommentModal(true)
	case 14:
		a.CycleOperandFormat()
	case 16:
		a.ExportASM()
	}
}

func (a *App) openCommentModal(block bool) {
	if !block && a.SelectedIdx >= 0 && a.SelectedIdx < len(a.DisasmRows) {
		if a.DisasmRows[a.SelectedIdx].Kind == SubRowString {
			block = true
		}
	}
	var existing string
	if addr, ok := a.CursorAddr(); ok {
		if !block {
			if c, err := a.DB.GetCell(addr); err == nil && c != nil && c.Type == db.CellStr {
				block = true
			}
		}
		ac := a.DB.GetAddressComment(addr)
		if block {
			existing = ac.BlockComment
		} else {
			existing = ac.Comment
		}
	}
	if block {
		a.Modal = Modal{Kind: ModalBlockComment, Input: NewTextInput(existing)}
	} else {
		a.Modal = Modal{Kind: ModalComment, Input: NewTextInput(existing)}
	}
}

// HandleKeyMsg delegates a Bubble Tea KeyMsg to HandleKey.
func (a *App) HandleKeyMsg(m tea.KeyMsg) bool {
	return a.HandleKey(m.String())
}

// HandleKey processes a normalized key string (e.g. "j", "down", "right", "ctrl+z").
func (a *App) HandleKey(key string) bool {
	a.StatusMsg = ""
	if a.Modal.Kind != ModalNone {
		modal := a.Modal
		a.Modal = Modal{Kind: ModalNone}
		return a.handleModalKey(modal, key)
	}

	switch key {
	case "q":
		a.ShouldQuit = true
	case "j", "down":
		a.MoveCursor(1)
	case "k", "up":
		a.MoveCursor(-1)
	case "left":
		a.MoveDataByte(-1)
	case "right":
		a.MoveDataByte(1)
	case "ctrl+d":
		a.MoveCursor(15)
	case "ctrl+u":
		a.MoveCursor(-15)
	case "ctrl+z":
		a.Undo()
	case "ctrl+s":
		a.OpenSpaceSwitcher()
	case "pgdown":
		a.MoveCursor(30)
	case "pgup":
		a.MoveCursor(-30)
	case "home":
		a.MoveCursor(-len(a.DisasmRows))
	case "end":
		a.MoveCursor(len(a.DisasmRows))
	case "enter":
		a.FollowReference()
	case "backspace", "-":
		a.NavigateBack()
	case "g":
		a.Modal = Modal{Kind: ModalGoto, Input: EmptyTextInput()}
	case "/":
		a.OpenSearch()
	case "x":
		a.OpenXrefs()
	case "f":
		a.OpenFunctions()
	case "n":
		if addr, ok := a.CursorAddr(); ok {
			orig, hasLbl, _ := a.DB.GetLabel(addr)
			if !hasLbl || orig == "" {
				orig = a.Proj.AutoLabel(addr)
			}
			current := orig
			if ren, hasRen, _ := a.DB.GetRename(orig); hasRen && ren != "" {
				current = ren
			}
			a.Modal = Modal{Kind: ModalRename, Input: NewTextInput(current)}
		}
	case ";":
		a.openCommentModal(false)
	case ":":
		a.openCommentModal(true)
	case "#":
		a.CycleOperandFormat()
	case "c":
		if a.SelectionStart != nil {
			a.MarkSelection(db.CellCode, 1)
		} else {
			a.MarkCode()
		}
	case "b":
		if a.SelectionStart != nil {
			a.MarkSelection(db.CellDataB, 1)
		} else {
			a.MarkType(db.CellDataB, 1)
		}
	case "w":
		if a.SelectionStart != nil {
			a.MarkSelection(db.CellDataW, 2)
		} else {
			a.MarkType(db.CellDataW, 2)
		}
	case "l":
		if a.SelectionStart != nil {
			a.MarkSelection(db.CellDataL, 4)
		} else {
			a.MarkType(db.CellDataL, 4)
		}
	case "s":
		if a.SelectionStart != nil {
			a.MarkSelection(db.CellStr, 1)
		} else {
			a.MarkString()
		}
	case "p":
		if a.SelectionStart != nil {
			a.MarkSelection(db.CellPointer, 4)
		} else {
			a.MarkType(db.CellPointer, 4)
		}
	case "u":
		a.Undefine()
	case "K":
		if start, end, ok := a.GetSelectionRange(); ok {
			a.Modal = Modal{
				Kind:       ModalCarveName,
				Input:      EmptyTextInput(),
				CarveStart: start,
				CarveEnd:   end,
			}
		} else {
			a.UncarveAtCursor()
		}
	case "v":
		a.ToggleSelection()
	case "esc":
		if a.SelectionStart != nil {
			a.SelectionStart = nil
			a.StatusMsg = "Selection cancelled"
		}
	case "e":
		a.ExportASM()
	case "m":
		a.OpenMemoryMap()
	case "S":
		a.OpenSegmentManager()
	case "I":
		a.OpenFileBrowser()
	case "t":
		a.OpenStructEditor()
	case "a":
		a.OpenAliasEditor()
	case "P":
		a.Modal = Modal{Kind: ModalPointerCount, Input: EmptyTextInput()}
	case "r":
		if an, err := analyzer.New(a.Proj, a.DB); err == nil {
			an.Analyze(nil)
			a.ReloadAtCursor()
			a.StatusMsg = "Analysis complete"
		} else {
			a.StatusMsg = fmt.Sprintf("Analyze failed: %v", err)
		}
	case "?":
		a.Modal = Modal{Kind: ModalHelp}
	}
	return true
}

func (a *App) handleModalKey(modal Modal, key string) bool {
	switch modal.Kind {
	case ModalRename:
		status, val := modal.Input.HandleKey(key)
		switch status {
		case ComponentDone:
			if addr, ok := a.CursorAddr(); ok {
				orig, hasLbl, _ := a.DB.GetLabel(addr)
				if !hasLbl || orig == "" {
					orig = a.Proj.AutoLabel(addr)
					_ = a.DB.SetLabel(addr, orig, db.LabelLab, true)
				}
				_ = a.DB.SetRename(orig, val)
				_ = a.Proj.Save()
				if an, err := analyzer.New(a.Proj, a.DB); err == nil {
					an.ReanalyzeXrefs(addr)
				}
				a.ReloadAtCursor()
			}
		case ComponentContinue:
			a.Modal = modal
		}
	case ModalComment:
		status, val := modal.Input.HandleKey(key)
		switch status {
		case ComponentDone:
			if addr, ok := a.CursorAddr(); ok {
				old := a.DB.GetAddressComment(addr).Comment
				a.pushUndo(UndoEntry{Kind: UndoCommentChange, Addr: addr, OldStr: &old})
				_ = a.DB.UpdateComment(addr, val)
			}
			a.ReloadAtCursor()
		case ComponentContinue:
			a.Modal = modal
		}
	case ModalBlockComment:
		status, val := modal.Input.HandleKey(key)
		switch status {
		case ComponentDone:
			if addr, ok := a.CursorAddr(); ok {
				old := a.DB.GetAddressComment(addr).BlockComment
				a.pushUndo(UndoEntry{Kind: UndoBlockCommentChange, Addr: addr, OldStr: &old})
				_ = a.DB.UpdateBlockComment(addr, val)
			}
			a.ReloadAtCursor()
		case ComponentContinue:
			a.Modal = modal
		}
	case ModalGoto:
		status, val := modal.Input.HandleKey(key)
		switch status {
		case ComponentDone:
			trimmed := strings.TrimSpace(val)
			explicitOffset := strings.HasPrefix(trimmed, "+")
			clean := strings.TrimPrefix(trimmed, "+")
			if v, err := project.ParseHex(clean); err == nil {
				target := v
				if a.IsRelocatable && (explicitOffset || (v < uint32(len(a.BinaryData)) && (a.BaseAddr == 0 || v < a.BaseAddr))) {
					target = a.BaseAddr + v
				}
				a.NavigateTo(target)
			} else if target, ok := a.Proj.ResolveTarget(a.DB, trimmed); ok {
				if segPart, _, hasColon := strings.Cut(trimmed, ":"); hasColon {
					if seg := a.Proj.SegmentByName(strings.TrimSpace(segPart)); seg != nil && a.Proj.ActiveSegmentName != seg.Name {
						a.SwitchSegment(seg.Name)
					}
				}
				a.NavigateTo(target)
			}
		case ComponentContinue:
			a.Modal = modal
		}
	case ModalSearch:
		switch key {
		case "down":
			if len(modal.SearchHits) > 1 {
				first := modal.SearchHits[0]
				modal.SearchHits = append(modal.SearchHits[1:], first)
			}
			a.Modal = modal
		case "up":
			if len(modal.SearchHits) > 1 {
				last := modal.SearchHits[len(modal.SearchHits)-1]
				modal.SearchHits = append([]SearchHit{last}, modal.SearchHits[:len(modal.SearchHits)-1]...)
			}
			a.Modal = modal
		default:
			status, _ := modal.Input.HandleKey(key)
			switch status {
			case ComponentDone:
				if len(modal.SearchHits) > 0 {
					q := strings.TrimSpace(modal.Input.Value)
					var segHint string
					if p, r, hasColon := strings.Cut(q, ":"); hasColon {
						known := []string{"m", "o", "s", "c", "b", "l", "cluster"}
						if slices.Contains(known, p) {
							if s, _, hasSlash := strings.Cut(r, "/"); hasSlash {
								segHint = strings.TrimSpace(s)
							}
						} else {
							segHint = strings.TrimSpace(p)
						}
					}
					if segHint != "" {
						if seg := a.Proj.SegmentByName(segHint); seg != nil && a.Proj.ActiveSegmentName != seg.Name {
							a.SwitchSegment(seg.Name)
						}
					}
					a.NavigateTo(modal.SearchHits[0].Addr)
				}
			case ComponentContinue:
				modal.SearchHits = a.DoSearch(modal.Input.Value)
				a.Modal = modal
			}
		}
	case ModalXrefs:
		switch key {
		case "enter":
			if modal.ListSelect >= 0 && modal.ListSelect < len(modal.Xrefs) {
				a.NavigateTo(modal.Xrefs[modal.ListSelect].Addr)
				return true
			}
			a.Modal = modal
		case "esc", "x":
		case "down", "j":
			if modal.ListSelect+1 < len(modal.Xrefs) {
				modal.ListSelect++
			}
			a.Modal = modal
		case "up", "k":
			if modal.ListSelect > 0 {
				modal.ListSelect--
			}
			a.Modal = modal
		default:
			a.Modal = modal
		}
	case ModalFunctions:
		filtered := filterFuncs(modal.AllFuncs, modal.Filter)
		switch key {
		case "enter":
			if modal.ListSelect >= 0 && modal.ListSelect < len(filtered) {
				a.NavigateTo(filtered[modal.ListSelect].Addr)
				return true
			}
			a.Modal = modal
		case "esc":
		case "down":
			if modal.ListSelect+1 < len(filtered) {
				modal.ListSelect++
			}
			a.Modal = modal
		case "up":
			if modal.ListSelect > 0 {
				modal.ListSelect--
			}
			a.Modal = modal
		case "backspace":
			if len(modal.Filter) > 0 {
				modal.Filter = modal.Filter[:len(modal.Filter)-1]
			}
			modal.ListSelect = 0
			a.Modal = modal
		default:
			if len(key) == 1 && key[0] >= 0x20 && key[0] <= 0x7E {
				modal.Filter += key
				modal.ListSelect = 0
			}
			a.Modal = modal
		}
	case ModalContextMenu:
		items := ContextMenuItems()
		switch key {
		case "esc":
		case "down", "j":
			if modal.ListSelect+1 < len(items) {
				modal.ListSelect++
			}
			a.Modal = modal
		case "up", "k":
			if modal.ListSelect > 0 {
				modal.ListSelect--
			}
			a.Modal = modal
		case "enter":
			a.executeContextAction(modal.ListSelect)
		default:
			a.Modal = modal
		}
	case ModalMemoryMap:
		switch key {
		case "esc":
		case "down", "j":
			if modal.ListSelect+1 < len(a.Proj.Data.MemoryRegions) {
				modal.ListSelect++
			}
			a.Modal = modal
		case "up", "k":
			if modal.ListSelect > 0 {
				modal.ListSelect--
			}
			a.Modal = modal
		case "d":
			if modal.ListSelect >= 0 && modal.ListSelect < len(a.Proj.Data.MemoryRegions) {
				a.Proj.Data.MemoryRegions = append(a.Proj.Data.MemoryRegions[:modal.ListSelect], a.Proj.Data.MemoryRegions[modal.ListSelect+1:]...)
				_ = a.Proj.Save()
			}
			a.Modal = modal
		default:
			a.Modal = modal
		}
	case ModalHelp:
		if key != "esc" && key != "?" && key != "q" {
			a.Modal = modal
		}
	case ModalSpaceSwitcher:
		switch key {
		case "esc":
		case "down", "j":
			if modal.ListSelect+1 < len(a.Proj.Data.Spaces) {
				modal.ListSelect++
			}
			a.Modal = modal
		case "up", "k":
			if modal.ListSelect > 0 {
				modal.ListSelect--
			}
			a.Modal = modal
		case "enter":
			if modal.ListSelect >= 0 && modal.ListSelect < len(a.Proj.Data.Spaces) {
				sp := a.Proj.Data.Spaces[modal.ListSelect]
				a.Proj.Data.ActiveSpace = sp.Name
				_ = a.Proj.Save()
				a.Proj.SyncDBScope(a.DB)
				if len(sp.Segments) > 0 {
					a.SwitchSegment(sp.Segments[0])
				}
				a.StatusMsg = fmt.Sprintf("Switched to space '%s'", a.Proj.Data.ActiveSpace)
			}
		case "d":
			if modal.ListSelect >= 0 && modal.ListSelect < len(a.Proj.Data.Spaces) {
				if a.Proj.Data.Spaces[modal.ListSelect].Name != a.Proj.Data.ActiveSpace {
					a.Proj.Data.Spaces = append(a.Proj.Data.Spaces[:modal.ListSelect], a.Proj.Data.Spaces[modal.ListSelect+1:]...)
					_ = a.Proj.Save()
				} else {
					a.StatusMsg = "Cannot delete active space"
				}
			}
			a.Modal = modal
		default:
			a.Modal = modal
		}
	case ModalSegmentManager:
		activeSegs := a.Proj.ActiveSegments()
		switch key {
		case "esc":
		case "down", "j":
			if modal.ListSelect+1 < len(activeSegs) {
				modal.ListSelect++
			}
			a.Modal = modal
		case "up", "k":
			if modal.ListSelect > 0 {
				modal.ListSelect--
			}
			a.Modal = modal
		case "enter":
			if modal.ListSelect >= 0 && modal.ListSelect < len(activeSegs) {
				a.SwitchSegment(activeSegs[modal.ListSelect].Name)
				return true
			}
			a.Modal = modal
		case "I":
			a.OpenFileBrowser()
		case "d":
			if modal.ListSelect >= 0 && modal.ListSelect < len(activeSegs) {
				name := activeSegs[modal.ListSelect].Name
				_ = a.DB.DeleteSegment(name)
				a.Proj.Data.Segments = slices.DeleteFunc(a.Proj.Data.Segments, func(s project.Segment) bool {
					return strings.EqualFold(s.Name, name)
				})
				for i := range a.Proj.Data.Spaces {
					a.Proj.Data.Spaces[i].Segments = slices.DeleteFunc(a.Proj.Data.Spaces[i].Segments, func(s string) bool {
						return strings.EqualFold(s, name)
					})
				}
				a.Proj.Data.EntryPoints = slices.DeleteFunc(a.Proj.Data.EntryPoints, func(ep project.EntryPoint) bool {
					return strings.EqualFold(ep.Segment, name)
				})
				_ = a.Proj.Save()
				a.Proj.SyncDBScope(a.DB)
				a.StatusMsg = fmt.Sprintf("Removed segment '%s'", name)
				newLen := len(a.Proj.ActiveSegments())
				if modal.ListSelect >= newLen && newLen > 0 {
					modal.ListSelect = newLen - 1
				}
			}
			a.Modal = modal
		default:
			a.Modal = modal
		}
	case ModalFileBrowser:
		fb := &modal.FileBrowser
		filtered := fb.FilteredEntries()
		switch {
		case key == "esc":
		case key == "down" || (key == "j" && !fb.Filtering):
			if fb.Selected+1 < len(filtered) {
				fb.Selected++
			}
			a.Modal = modal
		case key == "up" || (key == "k" && !fb.Filtering):
			if fb.Selected > 0 {
				fb.Selected--
			}
			a.Modal = modal
		case key == "enter":
			if fb.Selected >= 0 && fb.Selected < len(filtered) {
				entry := filtered[fb.Selected]
				if entry.IsDir {
					if entry.Name == ".." {
						fb.Path = filepath.Dir(fb.Path)
					} else {
						fb.Path = filepath.Join(fb.Path, entry.Name)
					}
					fb.Entries = ReadDirEntries(fb.Path)
					fb.Selected = 0
					fb.Filter = ""
					a.Modal = modal
				} else {
					fullPath := filepath.Join(fb.Path, entry.Name)
					a.OpenSegmentForm(fullPath, entry.Size)
				}
			} else {
				a.Modal = modal
			}
		case key == "/":
			fb.Filtering = !fb.Filtering
			if !fb.Filtering {
				fb.Filter = ""
			}
			a.Modal = modal
		case key == "backspace" && fb.Filtering:
			if len(fb.Filter) > 0 {
				fb.Filter = fb.Filter[:len(fb.Filter)-1]
			}
			fb.Selected = 0
			a.Modal = modal
		case fb.Filtering && len(key) == 1 && key[0] >= 0x20 && key[0] <= 0x7E:
			fb.Filter += key
			fb.Selected = 0
			a.Modal = modal
		default:
			a.Modal = modal
		}
	case ModalSegmentForm:
		sf := &modal.SegmentForm
		switch key {
		case "esc":
		case "tab":
			sf.ActiveField = (sf.ActiveField + 1) % 4
			a.Modal = modal
		case "enter":
			base, _ := project.ParseHex(sf.Base)
			if sf.Name != "" && base > 0 {
				if !a.CreateSegment(sf.Name, sf.File, base, sf.Space) {
					a.Modal = modal
					return true
				}
				if sf.Entry != "" {
					if entryVal, err := project.ParseHex(sf.Entry); err == nil && entryVal > 0 {
						a.Proj.Data.EntryPoints = append(a.Proj.Data.EntryPoints, project.EntryPoint{
							Addr:    entryVal,
							Name:    "main",
							Segment: sf.Name,
						})
						_ = a.Proj.Save()
					}
				}
				segName := sf.Name
				a.SwitchSegment(segName)
				if an, err := analyzer.New(a.Proj, a.DB); err == nil {
					an.Analyze(nil)
				}
				a.ReloadAtCursor()
				a.StatusMsg = fmt.Sprintf("Segment '%s' ready", segName)
			} else {
				a.StatusMsg = "Name and base address required"
				a.Modal = modal
			}
		case "backspace":
			popChar := func(s *string) {
				if len(*s) > 0 {
					*s = (*s)[:len(*s)-1]
				}
			}
			switch sf.ActiveField {
			case 0:
				popChar(&sf.Name)
			case 1:
				popChar(&sf.Base)
			case 2:
				popChar(&sf.Entry)
			case 3:
				popChar(&sf.Space)
			}
			a.Modal = modal
		default:
			if len(key) == 1 && key[0] >= 0x20 && key[0] <= 0x7E {
				switch sf.ActiveField {
				case 0:
					sf.Name += key
				case 1:
					sf.Base += key
				case 2:
					sf.Entry += key
				case 3:
					sf.Space += key
				}
			}
			a.Modal = modal
		}
	case ModalStructEditor:
		st := &modal.StructState
		switch st.InputMode {
		case StructInputNone:
			switch key {
			case "esc":
				if st.SelectedStruct >= 0 {
					st.SelectedStruct = -1
					st.Fields = nil
					st.Selected = 0
					a.Modal = modal
				}
			case "n":
				st.InputMode = StructInputNewStruct
				st.Input = ""
				a.Modal = modal
			case "a":
				if st.SelectedStruct >= 0 {
					st.InputMode = StructInputNewFieldOffset
					st.Input = ""
				}
				a.Modal = modal
			case "d":
				if st.SelectedStruct >= 0 {
					if st.Selected >= 0 && st.Selected < len(st.Fields) {
						structName := st.Structs[st.SelectedStruct]
						offset := st.Fields[st.Selected].Offset
						if sMap, ok := a.Proj.Data.Structs[structName]; ok {
							delete(sMap, offset)
						}
						st.Fields = append(st.Fields[:st.Selected], st.Fields[st.Selected+1:]...)
						_ = a.Proj.Save()
					}
				} else if st.Selected >= 0 && st.Selected < len(st.Structs) {
					name := st.Structs[st.Selected]
					st.Structs = append(st.Structs[:st.Selected], st.Structs[st.Selected+1:]...)
					delete(a.Proj.Data.Structs, name)
					_ = a.Proj.Save()
				}
				a.Modal = modal
			case "enter":
				if st.SelectedStruct < 0 && st.Selected >= 0 && st.Selected < len(st.Structs) {
					st.SelectedStruct = st.Selected
					name := st.Structs[st.Selected]
					st.Fields = nil
					if sMap, ok := a.Proj.Data.Structs[name]; ok {
						for k, v := range sMap {
							st.Fields = append(st.Fields, StructField{Offset: k, Name: v})
						}
						slices.SortFunc(st.Fields, func(x, y StructField) int {
							xi, _ := strconv.Atoi(x.Offset)
							yi, _ := strconv.Atoi(y.Offset)
							return cmp.Compare(xi, yi)
						})
					}
					st.Selected = 0
				}
				a.Modal = modal
			case "down", "j":
				listLen := len(st.Structs)
				if st.SelectedStruct >= 0 {
					listLen = len(st.Fields)
				}
				if st.Selected+1 < listLen {
					st.Selected++
				}
				a.Modal = modal
			case "up", "k":
				if st.Selected > 0 {
					st.Selected--
				}
				a.Modal = modal
			default:
				a.Modal = modal
			}
		case StructInputNewStruct:
			switch key {
			case "enter":
				if st.Input != "" {
					if a.Proj.Data.Structs == nil {
						a.Proj.Data.Structs = make(map[string]map[string]string)
					}
					if _, exists := a.Proj.Data.Structs[st.Input]; !exists {
						a.Proj.Data.Structs[st.Input] = make(map[string]string)
						st.Structs = append(st.Structs, st.Input)
					}
					_ = a.Proj.Save()
				}
				st.InputMode = StructInputNone
				st.Input = ""
				a.Modal = modal
			case "esc":
				st.InputMode = StructInputNone
				a.Modal = modal
			case "backspace":
				if len(st.Input) > 0 {
					st.Input = st.Input[:len(st.Input)-1]
				}
				a.Modal = modal
			default:
				if len(key) == 1 && key[0] >= 0x20 && key[0] <= 0x7E {
					st.Input += key
				}
				a.Modal = modal
			}
		case StructInputNewFieldOffset:
			switch key {
			case "enter":
				st.PendingOffset = st.Input
				st.InputMode = StructInputNewFieldName
				st.Input = ""
				a.Modal = modal
			case "esc":
				st.InputMode = StructInputNone
				a.Modal = modal
			case "backspace":
				if len(st.Input) > 0 {
					st.Input = st.Input[:len(st.Input)-1]
				}
				a.Modal = modal
			default:
				if len(key) == 1 && key[0] >= 0x20 && key[0] <= 0x7E {
					st.Input += key
				}
				a.Modal = modal
			}
		case StructInputNewFieldName:
			switch key {
			case "enter":
				if st.SelectedStruct >= 0 && st.SelectedStruct < len(st.Structs) {
					structName := st.Structs[st.SelectedStruct]
					if a.Proj.Data.Structs[structName] == nil {
						a.Proj.Data.Structs[structName] = make(map[string]string)
					}
					a.Proj.Data.Structs[structName][st.PendingOffset] = st.Input
					st.Fields = append(st.Fields, StructField{Offset: st.PendingOffset, Name: st.Input})
					slices.SortFunc(st.Fields, func(x, y StructField) int {
						xi, _ := strconv.Atoi(x.Offset)
						yi, _ := strconv.Atoi(y.Offset)
						return cmp.Compare(xi, yi)
					})
					_ = a.Proj.Save()
				}
				st.InputMode = StructInputNone
				st.Input = ""
				a.Modal = modal
			case "esc":
				st.InputMode = StructInputNone
				a.Modal = modal
			case "backspace":
				if len(st.Input) > 0 {
					st.Input = st.Input[:len(st.Input)-1]
				}
				a.Modal = modal
			default:
				if len(key) == 1 && key[0] >= 0x20 && key[0] <= 0x7E {
					st.Input += key
				}
				a.Modal = modal
			}
		}
	case ModalAliasEditor:
		keys := sortedMapKeys(a.Proj.Data.RegisterAliases)
		switch key {
		case "esc":
		case "down", "j":
			if modal.ListSelect+1 < len(keys) {
				modal.ListSelect++
			}
			a.Modal = modal
		case "up", "k":
			if modal.ListSelect > 0 {
				modal.ListSelect--
			}
			a.Modal = modal
		case "d":
			if modal.ListSelect >= 0 && modal.ListSelect < len(keys) {
				delete(a.Proj.Data.RegisterAliases, keys[modal.ListSelect])
				_ = a.Proj.Save()
			}
			a.Modal = modal
		default:
			a.Modal = modal
		}
	case ModalPointerCount:
		status, val := modal.Input.HandleKey(key)
		switch status {
		case ComponentDone:
			if count, err := strconv.ParseUint(strings.TrimSpace(val), 10, 32); err == nil && count > 0 {
				a.MarkPointerTable(uint32(count))
			}
		case ComponentContinue:
			a.Modal = modal
		}
	case ModalCarveName:
		status, val := modal.Input.HandleKey(key)
		switch status {
		case ComponentDone:
			a.CarveRange(modal.CarveStart, modal.CarveEnd, val)
		case ComponentContinue:
			a.Modal = modal
		}
	}
	return true
}

// HandleMouseMsg processes mouse scroll and clicks in Bubble Tea.
func (a *App) HandleMouseMsg(m tea.MouseMsg) {
	if a.Modal.Kind != ModalNone {
		switch m.Button {
		case tea.MouseButtonWheelDown:
			a.HandleKey("down")
		case tea.MouseButtonWheelUp:
			a.HandleKey("up")
		}
		return
	}
	switch m.Button {
	case tea.MouseButtonWheelDown:
		a.MoveCursor(3)
	case tea.MouseButtonWheelUp:
		a.MoveCursor(-3)
	case tea.MouseButtonRight:
		if m.Action == tea.MouseActionPress {
			a.OpenContextMenu()
		}
	case tea.MouseButtonLeft:
		if m.Action == tea.MouseActionPress && m.Y == 0 {
			switch {
			case m.X >= 0 && m.X < 9:
				a.HandleKey("?")
			case m.X >= 10 && m.X < 23:
				a.HandleKey("S")
			case m.X >= 24 && m.X < 34:
				a.HandleKey("f")
			case m.X >= 35 && m.X < 45:
				a.HandleKey("x")
			case m.X >= 46 && m.X < 57:
				a.HandleKey("/")
			case m.X >= 58 && m.X < 69:
				a.HandleKey("m")
			case m.X >= 70 && m.X < 81:
				a.HandleKey("e")
			case m.X >= 82 && m.X < 94:
				a.HandleKey("r")
			}
			return
		}
		if (m.Action == tea.MouseActionPress || m.Action == tea.MouseActionMotion) && m.Y >= 2 && m.Y < a.Height-2 {
			contentHeight := max(a.Height-4, 1)
			rowY := max(m.Y-2, 0)
			if m.X >= max(a.Width-2, 0) {
				if len(a.DisasmRows) > 0 {
					ratio := min(max(float64(rowY)/float64(contentHeight), 0.0), 1.0)
					idx := int(ratio * float64(len(a.DisasmRows)))
					a.SelectedIdx = min(idx, len(a.DisasmRows)-1)
					a.DataByteOff = 0
				}
			} else {
				target := a.ScrollOffset + rowY
				if target < len(a.DisasmRows) {
					a.SelectedIdx = target
					a.DataByteOff = 0
				}
			}
		}
	}
}

func filterFuncs(all []FuncItem, filter string) []FuncItem {
	if filter == "" {
		return all
	}
	q := strings.ToLower(filter)
	var out []FuncItem
	for _, f := range all {
		if strings.Contains(strings.ToLower(f.Name), q) {
			out = append(out, f)
		}
	}
	return out
}

func sortedMapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
