package tui

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Theme holds pre-compiled SGR cellStyles for all TUI visual roles.
// Any subset of fields can be overridden via JSON in:
//  1. $HUNKS_THEME
//  2. <project-dir>/theme.json
//  3. ~/.config/hunks/theme.json
type Theme struct {
	BG        cellStyle `json:"bg"`
	Cursor    cellStyle `json:"cursor"`
	Selection cellStyle `json:"selection"`
	Bar       cellStyle `json:"bar"`
	BarAccent cellStyle `json:"bar_accent"`
	MenuBtn   cellStyle `json:"menu_btn"`
	Border    cellStyle `json:"border"`

	Addr      cellStyle `json:"addr"`
	AddrCross cellStyle `json:"addr_cross"`
	Op        cellStyle `json:"op"`
	Flow      cellStyle `json:"flow"`
	Directive cellStyle `json:"directive"`

	DReg cellStyle `json:"dreg"`
	AReg cellStyle `json:"areg"`
	Imm  cellStyle `json:"imm"`
	Sub  cellStyle `json:"sub"`
	Loc  cellStyle `json:"loc"`
	HW   cellStyle `json:"hw"`

	Usr cellStyle `json:"usr"`
	Rep cellStyle `json:"rep"`
	Ref cellStyle `json:"ref"`
	Aut cellStyle `json:"aut"`
	Str cellStyle `json:"str"`

	XHdr    cellStyle `json:"xhdr"`
	XSym    cellStyle `json:"xsym"`
	XC      cellStyle `json:"xc"`
	XJ      cellStyle `json:"xj"`
	XPtr    cellStyle `json:"xptr"`
	XActive cellStyle `json:"xactive"`

	RowPointer cellStyle `json:"row_pointer"`
	RowData    cellStyle `json:"row_data"`
	RowString  cellStyle `json:"row_string"`
	RowGap     cellStyle `json:"row_gap"`
}

// DefaultTheme returns the built-in dark truecolor palette.
func DefaultTheme() Theme {
	return Theme{
		BG:        mustParseStyle("bg:#16191B"),
		Cursor:    mustParseStyle("#111314 bg:#C8B58A bold"),
		Selection: mustParseStyle("bg:#2D2B1A"),
		Bar:       mustParseStyle("#A3B8CC bg:#202428"),
		BarAccent: mustParseStyle("#E0AF68 bg:#202428 bold"),
		MenuBtn:   mustParseStyle("#111314 bg:#88C0D0 bold"),
		Border:    mustParseStyle("#506660 bg:#16191B"),

		Addr:      mustParseStyle("#506660"),
		AddrCross: mustParseStyle("#BB9AF7"),
		Op:        mustParseStyle("#D8DEE9 bold"),
		Flow:      mustParseStyle("#E0AF68 bold"),
		Directive: mustParseStyle("#BB9AF7"),

		DReg: mustParseStyle("#A3B8CC"),
		AReg: mustParseStyle("#88C0D0"),
		Imm:  mustParseStyle("#D19A66"),
		Sub:  mustParseStyle("#7FB4CA bold"),
		Loc:  mustParseStyle("#6A9E7E bold"),
		HW:   mustParseStyle("#F7768E bold"),

		Usr: mustParseStyle("#A6E3A1"),
		Rep: mustParseStyle("#89DCEB"),
		Ref: mustParseStyle("#568C96 italic"),
		Aut: mustParseStyle("#6E738D italic"),
		Str: mustParseStyle("#F9E2AF"),

		XHdr:    mustParseStyle("#585B70"),
		XSym:    mustParseStyle("#7F849C"),
		XC:      mustParseStyle("#89DCEB bold"),
		XJ:      mustParseStyle("#A6E3A1 bold"),
		XPtr:    mustParseStyle("#BB9AF7 bold"),
		XActive: mustParseStyle("#111314 bg:#89DCEB bold"),

		RowPointer: mustParseStyle("bg:#1A1D28"),
		RowData:    mustParseStyle("bg:#1A1D20"),
		RowString:  mustParseStyle("bg:#201F18"),
		RowGap:     mustParseStyle("bg:#131618"),
	}
}

// LoadTheme returns DefaultTheme() overlaid with ~/.config/hunks/theme.json
// (or $HUNKS_THEME if set). If no config file exists, DefaultTheme() is returned.
func LoadTheme() Theme {
	t := DefaultTheme()
	var candidates []string
	if envPath := strings.TrimSpace(os.Getenv("HUNKS_THEME")); envPath != "" {
		candidates = append(candidates, envPath)
	}
	if cfgDir, err := os.UserConfigDir(); err == nil && cfgDir != "" {
		candidates = append(candidates, filepath.Join(cfgDir, "hunks", "theme.json"))
	}
	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		_ = json.Unmarshal(data, &t)
		break
	}
	return t
}

// UnmarshalJSON parses a compact style specification like "#E0AF68 bg:#202428 bold italic".
func (st *cellStyle) UnmarshalJSON(data []byte) error {
	var spec string
	if err := json.Unmarshal(data, &spec); err != nil {
		return err
	}
	parsed, err := parseStyleSpec(spec)
	if err != nil {
		return err
	}
	*st = parsed
	return nil
}

func mustParseStyle(spec string) cellStyle {
	st, err := parseStyleSpec(spec)
	if err != nil {
		panic(err)
	}
	return st
}

func parseStyleSpec(spec string) (cellStyle, error) {
	var st cellStyle
	for _, tok := range strings.Fields(spec) {
		lower := strings.ToLower(tok)
		switch {
		case lower == "bold":
			st.bold = true
		case lower == "italic":
			st.italic = true
		case lower == "reverse":
			st.reverse = true
		case strings.HasPrefix(lower, "bg:"):
			code, err := parseColorToken(tok[3:], true)
			if err != nil {
				return st, err
			}
			st.bg = code
		case strings.HasPrefix(lower, "fg:"):
			code, err := parseColorToken(tok[3:], false)
			if err != nil {
				return st, err
			}
			st.fg = code
		default:
			code, err := parseColorToken(tok, false)
			if err != nil {
				return st, err
			}
			st.fg = code
		}
	}
	return st, nil
}

func parseColorToken(tok string, isBG bool) (string, error) {
	if tok == "" || strings.EqualFold(tok, "default") || strings.EqualFold(tok, "none") {
		return "", nil
	}
	if strings.HasPrefix(tok, "#") && len(tok) == 7 {
		rgb, err := strconv.ParseUint(tok[1:], 16, 32)
		if err != nil {
			return "", fmt.Errorf("invalid hex color %q: %w", tok, err)
		}
		r := (rgb >> 16) & 0xFF
		g := (rgb >> 8) & 0xFF
		b := rgb & 0xFF
		if isBG {
			return fmt.Sprintf("48;2;%d;%d;%d", r, g, b), nil
		}
		return fmt.Sprintf("38;2;%d;%d;%d", r, g, b), nil
	}
	switch strings.ToLower(tok) {
	case "black":
		if isBG {
			return bgBlack, nil
		}
		return fgBlack, nil
	case "green":
		return fgGreen, nil
	case "lightgreen":
		return fgLightGreen, nil
	case "yellow":
		return fgYellow, nil
	case "blue":
		if isBG {
			return bgBlue, nil
		}
		return fgBlue, nil
	case "magenta":
		return fgMagenta, nil
	case "cyan":
		return fgCyan, nil
	case "gray", "grey":
		if isBG {
			return bgGray, nil
		}
		return fgGray, nil
	case "darkgray", "darkgrey":
		if isBG {
			return bgDarkGray, nil
		}
		return fgDarkGray, nil
	case "white":
		return fgWhite, nil
	}
	return "", fmt.Errorf("unrecognized color token %q", tok)
}

// isFlowMnemonic returns true for control-flow instructions (branches, jumps,
// calls, returns, and traps) so they render in Theme.Flow (#E0AF68).
func isFlowMnemonic(mnem string) bool {
	base := mnem
	if dot := strings.IndexByte(mnem, '.'); dot >= 0 {
		base = mnem[:dot]
	}
	switch strings.ToLower(base) {
	case "bra", "bsr", "bhi", "bls", "bcc", "bhs", "bcs", "blo", "bne", "beq",
		"bvc", "bvs", "bpl", "bmi", "bge", "blt", "bgt", "ble",
		"dbt", "dbf", "dbra", "dbhi", "dbls", "dbcc", "dbhs", "dbcs", "dblo",
		"dbne", "dbeq", "dbvc", "dbvs", "dbpl", "dbmi", "dbge", "dblt", "dbgt", "dble",
		"jmp", "jsr", "rts", "rte", "rtr", "trap", "trapv", "chk", "illegal", "stop", "reset":
		return true
	}
	return false
}

// tokenizeOperands splits an M68000 operand string into semantic spans
// (.imm, .areg, .dreg, .loc, .hw, .sub) and pads out to padWidth.
func tokenizeOperands(opStr string, padWidth int, t *Theme) []styledSpan {
	var spans []styledSpan
	push := func(text string, st cellStyle) {
		if text == "" {
			return
		}
		if n := len(spans); n > 0 && spans[n-1].style == st {
			spans[n-1].text += text
			return
		}
		spans = append(spans, styledSpan{text: text, style: st})
	}

	i := 0
	n := len(opStr)
	for i < n {
		ch := opStr[i]

		// 1. Immediate (#...)
		if ch == '#' {
			start := i
			i++
			for i < n && opStr[i] != ',' {
				i++
			}
			push(opStr[start:i], t.Imm)
			continue
		}

		// 2. Quoted string literal
		if ch == '"' || ch == '\'' {
			quote := ch
			start := i
			i++
			for i < n && opStr[i] != quote {
				if opStr[i] == '\\' && i+1 < n {
					i++
				}
				i++
			}
			if i < n {
				i++
			}
			push(opStr[start:i], t.Str)
			continue
		}

		// 3. Size suffix (.b, .w, .l, .s)
		if ch == '.' && i+1 < n && isSizeSuffixChar(opStr[i+1]) && (i+2 == n || !isIdentChar(opStr[i+2])) {
			push(opStr[i:i+2], t.DReg)
			i += 2
			continue
		}

		// 4. Hex literal ($...) or numeric literal / displacement
		if ch == '$' || (ch >= '0' && ch <= '9') || (ch == '-' && i+1 < n && (opStr[i+1] == '$' || (opStr[i+1] >= '0' && opStr[i+1] <= '9')) && (i == 0 || opStr[i-1] == ',' || opStr[i-1] == '(' || opStr[i-1] == '+')) {
			start := i
			if opStr[i] == '-' {
				i++
			}
			isHex := false
			if i < n && opStr[i] == '$' {
				isHex = true
				i++
				for i < n && isHexDigit(opStr[i]) {
					i++
				}
			} else {
				for i < n && opStr[i] >= '0' && opStr[i] <= '9' {
					i++
				}
			}
			lit := opStr[start:i]
			if isHex && isHardwareHexLiteral(lit) {
				push(lit, t.HW)
			} else {
				push(lit, t.Imm)
			}
			continue
		}

		// 5. Identifier (register, label, hardware symbol)
		if isIdentStart(ch) {
			start := i
			i++
			for i < n && isIdentChar(opStr[i]) {
				// Stop before a trailing .b/.w/.l/.s suffix on the identifier
				if opStr[i] == '.' && i+1 < n && isSizeSuffixChar(opStr[i+1]) && (i+2 == n || !isIdentChar(opStr[i+2])) {
					break
				}
				i++
			}
			ident := opStr[start:i]
			push(ident, classifyOperandIdent(ident, t))
			continue
		}

		// 6. Punctuation / operators ((, ), ,, -, +, /)
		push(opStr[i:i+1], t.DReg)
		i++
	}

	if len(opStr) < padWidth {
		push(strings.Repeat(" ", padWidth-len(opStr)), t.DReg)
	}
	return spans
}

func classifyOperandIdent(ident string, t *Theme) cellStyle {
	switch strings.ToLower(ident) {
	case "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "sp", "pc", "usp":
		return t.AReg
	case "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "sr", "ccr":
		return t.DReg
	}
	if isHardwareSymbol(ident) {
		return t.HW
	}
	if strings.HasPrefix(ident, "LAB_") || strings.HasPrefix(ident, ".") ||
		strings.HasPrefix(ident, "DAT_") || strings.HasPrefix(ident, "PTR_") ||
		strings.HasPrefix(ident, "STR_") || strings.HasPrefix(ident, "EQU_") {
		return t.Loc
	}
	return t.Sub
}

func isHardwareHexLiteral(lit string) bool {
	s := strings.TrimPrefix(strings.TrimPrefix(lit, "-"), "$")
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return false
	}
	return (v >= 0xDFF000 && v <= 0xDFFFFF) || (v >= 0xBFD000 && v <= 0xBFEFFF)
}

func isHardwareSymbol(ident string) bool {
	u := strings.ToUpper(ident)
	if u == "_CUSTOM" || strings.HasPrefix(u, "_CUSTOM+") {
		return true
	}
	prefixes := []string{
		"CUSTOM", "CIAA", "CIAB", "DMACON", "INTENA", "INTREQ", "ADKCON",
		"BPL", "COP", "BLT", "AUD", "SPR", "COLOR", "DIW", "DDF",
		"VPOS", "VHPOS", "JOY", "POT", "SER", "DSK", "CLX", "BEAM",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(u, p) {
			return true
		}
	}
	return false
}

func isSizeSuffixChar(c byte) bool {
	switch c {
	case 'b', 'B', 'w', 'W', 'l', 'L', 's', 'S':
		return true
	}
	return false
}

func isIdentStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '.'
}

func isIdentChar(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// commentSpans formats "; " + comment according to CommentStyle, highlighting
// embedded quoted strings ("...") in Theme.Str when rendering auto-comments.
func commentSpans(prefix, comment string, style CommentStyle, t *Theme) []styledSpan {
	switch style {
	case CommentStyleUser:
		return []styledSpan{{text: prefix + comment, style: t.Usr}}
	case CommentStyleRef:
		return []styledSpan{{text: prefix + comment, style: t.Ref}}
	default:
		full := prefix + comment
		if strings.IndexByte(full, '"') < 0 {
			return []styledSpan{{text: full, style: t.Aut}}
		}
		var spans []styledSpan
		i := 0
		for i < len(full) {
			q := strings.IndexByte(full[i:], '"')
			if q < 0 {
				spans = append(spans, styledSpan{text: full[i:], style: t.Aut})
				break
			}
			if q > 0 {
				spans = append(spans, styledSpan{text: full[i : i+q], style: t.Aut})
			}
			start := i + q
			end := start + 1
			for end < len(full) && full[end] != '"' {
				if full[end] == '\\' && end+1 < len(full) {
					end++
				}
				end++
			}
			if end < len(full) {
				end++
			}
			spans = append(spans, styledSpan{text: full[start:end], style: t.Str})
			i = end
		}
		return spans
	}
}
