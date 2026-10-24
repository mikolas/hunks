package tui

import (
	"strings"
	"unicode/utf8"

	"github.com/mikolas/hunks/internal/db"
	"github.com/mikolas/hunks/internal/m68k"
)

// SubRowKind identifies the visual sub-row category in the TUI listing engine.
type SubRowKind uint8

const (
	SubRowSpacer       SubRowKind = iota // Blank visual separator line
	SubRowBlockComment                   // ; <wrapped block comment line>
	SubRowXref                           // ; XREF: <wrapped caller badges>
	SubRowLabel                          // LAB_00100: (always with trailing ':')
	SubRowCode                           // Primary instruction row (with hex bytes + EOL comment)
	SubRowData                           // Primary data row (16-byte dc.b Hex/ASCII grid or explicit dc.w/dc.l)
	SubRowString                         // Primary string row (dc.b "...",0 — no hex bytes, no ASCII box, no EOL comment)
	SubRowDirective                      // SECTION / ORG / XDEF / EQU / INCBIN / DS.B / DX.B
)

// CommentStyle identifies the visual tier of a trailing EOL comment.
type CommentStyle uint8

const (
	CommentStyleNone CommentStyle = iota
	CommentStyleUser              // Priority 1: User-authored EOL comment (bright green)
	CommentStyleRef               // Priority 2: Echoed comment from referenced target (italic/dim green)
	CommentStyleAuto              // Priority 3: Analyzer/trace auto-comment (muted/dark green)
)

// XrefBadge represents a single navigable incoming cross-reference badge on a SubRowXref line.
type XrefBadge struct {
	CallerAddr uint32
	Text       string // e.g. "InitSprites:65656(bsr.w)" or "MainLoop:65420(W)"
}

// ListingRow represents a single visual sub-row in the full-width TUI listing view.
type ListingRow struct {
	Addr             *uint32
	Kind             SubRowKind
	IsPrimary        bool
	RawBytes         []byte
	Timing           m68k.Timing
	Label            string
	Mnem             string
	Operands         string
	ASCIIBox         string
	PrintableRunMask uint16
	Comment          string
	CommentStyle     CommentStyle
	IsBannerRule     bool
	XrefTotal        int
	Xrefs            []XrefBadge
	RefTarget        *uint32
	CellType         string
	Size             uint32
	CrossSegment     bool
}

// ComponentStatus indicates the result of a TextInput key event.
type ComponentStatus int

const (
	ComponentContinue ComponentStatus = iota
	ComponentDone
	ComponentCancel
)

// TextInput is a simple single-line text input widget with cursor.
type TextInput struct {
	Value  string
	Cursor int
}

// NewTextInput creates a TextInput initialized with initial and cursor at end.
func NewTextInput(initial string) TextInput {
	return TextInput{Value: initial, Cursor: len(initial)}
}

// EmptyTextInput creates an empty TextInput.
func EmptyTextInput() TextInput {
	return TextInput{}
}

// HandleKey processes a key string for TextInput.
func (ti *TextInput) HandleKey(key string) (ComponentStatus, string) {
	if key == "space" {
		key = " "
	}
	cur := min(max(ti.Cursor, 0), len(ti.Value))
	ti.Cursor = cur
	switch key {
	case "enter":
		return ComponentDone, ti.Value
	case "esc":
		return ComponentCancel, ""
	case "backspace":
		if ti.Cursor > 0 {
			_, sz := utf8.DecodeLastRuneInString(ti.Value[:ti.Cursor])
			ti.Value = ti.Value[:ti.Cursor-sz] + ti.Value[ti.Cursor:]
			ti.Cursor -= sz
		}
		return ComponentContinue, ""
	case "delete":
		if ti.Cursor < len(ti.Value) {
			_, sz := utf8.DecodeRuneInString(ti.Value[ti.Cursor:])
			ti.Value = ti.Value[:ti.Cursor] + ti.Value[ti.Cursor+sz:]
		}
		return ComponentContinue, ""
	case "left":
		if ti.Cursor > 0 {
			_, sz := utf8.DecodeLastRuneInString(ti.Value[:ti.Cursor])
			ti.Cursor -= sz
		}
		return ComponentContinue, ""
	case "right":
		if ti.Cursor < len(ti.Value) {
			_, sz := utf8.DecodeRuneInString(ti.Value[ti.Cursor:])
			ti.Cursor += sz
		}
		return ComponentContinue, ""
	case "home":
		ti.Cursor = 0
		return ComponentContinue, ""
	case "end":
		ti.Cursor = len(ti.Value)
		return ComponentContinue, ""
	default:
		if utf8.RuneCountInString(key) == 1 {
			r, _ := utf8.DecodeRuneInString(key)
			if r >= 0x20 && r != 0x7F {
				ti.Value = ti.Value[:ti.Cursor] + key + ti.Value[ti.Cursor:]
				ti.Cursor += len(key)
			}
		}
		return ComponentContinue, ""
	}
}

// ModalKind identifies the active modal dialog.
type ModalKind int

const (
	ModalNone ModalKind = iota
	ModalRename
	ModalComment
	ModalBlockComment
	ModalGoto
	ModalSearch
	ModalXrefs
	ModalFunctions
	ModalContextMenu
	ModalMemoryMap
	ModalHelp
	ModalStructEditor
	ModalAliasEditor
	ModalPointerCount
	ModalCarveName
	ModalSpaceSwitcher
	ModalSegmentManager
	ModalFileBrowser
	ModalSegmentForm
	ModalBitplane
	ModalBitplaneGeometry
	ModalBitplanePalette
)

// SearchHit represents a single search result row.
type SearchHit struct {
	Addr uint32
	Text string
}

// XrefItem represents a single cross-reference entry in the XREFs modal.
type XrefItem struct {
	Addr uint32
	Type string
	Insn string
}

// FuncItem represents a single function entry in the Functions modal.
type FuncItem struct {
	Addr uint32
	Name string
}

// DirEntryItem represents a file or directory in the FileBrowser modal.
type DirEntryItem struct {
	Name  string
	IsDir bool
	Size  uint64
}

// FileBrowserState holds state for the file browser modal.
type FileBrowserState struct {
	Path      string
	Entries   []DirEntryItem
	Selected  int
	Filter    string
	Filtering bool
}

// FilteredEntries returns entries matching the current filter.
func (fb *FileBrowserState) FilteredEntries() []DirEntryItem {
	if fb.Filter == "" {
		return fb.Entries
	}
	q := strings.ToLower(fb.Filter)
	var out []DirEntryItem
	for _, e := range fb.Entries {
		if e.Name == ".." || strings.Contains(strings.ToLower(e.Name), q) {
			out = append(out, e)
		}
	}
	return out
}

// SegmentFormState holds state for creating a new segment.
type SegmentFormState struct {
	File        string
	FileSize    uint64
	Name        string
	Base        string
	Entry       string
	Space       string
	ActiveField uint8 // 0=name, 1=base, 2=entry, 3=space
}

// StructInputKind identifies the sub-mode inside the struct editor modal.
type StructInputKind int

const (
	StructInputNone StructInputKind = iota
	StructInputNewStruct
	StructInputNewFieldOffset
	StructInputNewFieldName
)

// StructField represents an (offset, name) pair in the struct editor.
type StructField struct {
	Offset string
	Name   string
}

// StructEditorState holds state for the struct editor modal.
type StructEditorState struct {
	Structs        []string
	SelectedStruct int // -1 if none
	Fields         []StructField
	Selected       int
	InputMode      StructInputKind
	PendingOffset  string
	Input          string
}

// Modal holds the state of the currently active modal dialog.
type Modal struct {
	Kind        ModalKind
	Input       TextInput
	SearchHits  []SearchHit
	Xrefs       []XrefItem
	Filter      string
	AllFuncs    []FuncItem
	ListSelect  int
	StructState StructEditorState
	CarveStart  uint32
	CarveEnd    uint32
	FileBrowser   FileBrowserState
	SegmentForm   SegmentFormState
	Bitplane      *BitplaneState
	PixelProtocol PixelProtocol
}

// UndoKind identifies the kind of undo entry.
type UndoKind int

const (
	UndoCellDelete UndoKind = iota
	UndoLabelChange
	UndoCommentChange
	UndoBlockCommentChange
	UndoRename
)

// UndoEntry stores a reversible state change.
type UndoEntry struct {
	Kind         UndoKind
	ClearedStart uint32
	ClearedLen   uint32
	Cells        []db.Cell
	Comments     map[uint32]db.AddressComment
	Addr         uint32
	OldStr       *string
	Key          string
}
