package tui

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"strings"
)

// PixelProtocol selects the terminal pixel graphics protocol.
type PixelProtocol int

const (
	ProtocolAuto PixelProtocol = iota
	ProtocolKitty
	ProtocolIterm
	ProtocolSixel
	ProtocolHalfBlock
)

// String returns the human-readable display name of the protocol.
func (p PixelProtocol) String() string {
	switch p {
	case ProtocolKitty:
		return "Kitty"
	case ProtocolIterm:
		return "iTerm2"
	case ProtocolSixel:
		return "Sixel"
	case ProtocolHalfBlock:
		return "Half-Block"
	default:
		return "Auto"
	}
}

// DetectProtocol detects the best available graphics protocol for the current terminal.
func DetectProtocol() PixelProtocol {
	// 1. Kitty Graphics Protocol
	if os.Getenv("KITTY_WINDOW_ID") != "" ||
		os.Getenv("TERMINAL") == "kitty" ||
		os.Getenv("TERM_PROGRAM") == "ghostty" ||
		os.Getenv("TERM_PROGRAM") == "wezterm" {
		return ProtocolKitty
	}

	// 2. iTerm2 Inline Images Protocol
	if os.Getenv("TERM_PROGRAM") == "iTerm.app" {
		return ProtocolIterm
	}

	// 3. Sixel check via TERM
	term := strings.ToLower(os.Getenv("TERM"))
	if strings.Contains(term, "sixel") || strings.Contains(term, "foot") || strings.Contains(term, "mlterm") {
		return ProtocolSixel
	}

	// Default fallback to universal Unicode Half-Blocks
	return ProtocolHalfBlock
}

// EncodeKittyPNG encodes img into a Kitty Graphics Protocol sequence.
// It wraps the sequence in DEC cursor save (\x1b7), cursor positioning (\x1b[<row>;<col>H),
// and DEC cursor restore (\x1b8).
// Uses quiet mode (q=2) so Kitty does not emit ACK bytes into stdin,
// C=1 so the cursor does not move, and z=1 so the image displays cleanly above cells.
func EncodeKittyPNG(img *image.RGBA, col, row int) string {
	if img == nil || img.Bounds().Empty() {
		return ""
	}

	var pngBuf bytes.Buffer
	if err := png.Encode(&pngBuf, img); err != nil {
		return ""
	}

	b64Str := base64.StdEncoding.EncodeToString(pngBuf.Bytes())
	var sb strings.Builder

	// DEC cursor save, clear old images, position cursor to (col, row)
	sb.WriteString(fmt.Sprintf("\x1b7\x1b_Ga=d,d=a,q=2\x1b\\\x1b[%d;%dH", row, col))

	const chunkSize = 4096
	totalLen := len(b64Str)

	for off := 0; off < totalLen; off += chunkSize {
		end := off + chunkSize
		more := 1
		if end >= totalLen {
			end = totalLen
			more = 0
		}
		chunk := b64Str[off:end]

		if off == 0 {
			// First chunk specifies transmission parameters:
			// a=T: transmit and display immediately
			// f=100: PNG format
			// t=d: direct payload
			// q=2: completely quiet (no ACK response)
			// C=1: do not move cursor
			// z=1: draw on top of text layer
			sb.WriteString(fmt.Sprintf("\x1b_Ga=T,f=100,t=d,q=2,C=1,z=1,m=%d;%s\x1b\\", more, chunk))
		} else {
			// Subsequent chunks only specify m=<more>
			sb.WriteString(fmt.Sprintf("\x1b_Gm=%d;%s\x1b\\", more, chunk))
		}
	}

	// DEC cursor restore
	sb.WriteString("\x1b8")
	return sb.String()
}

// ClearKittyPlacements returns the escape sequence to purge all Kitty images from the screen.
func ClearKittyPlacements() string {
	return "\x1b_Ga=d,d=a,q=2\x1b\\"
}

// EncodeItermPNG encodes img into an iTerm2 / WezTerm inline image sequence.
// Wrapped in DEC cursor save (\x1b7) and restore (\x1b8).
func EncodeItermPNG(img *image.RGBA, col, row int) string {
	if img == nil || img.Bounds().Empty() {
		return ""
	}

	var pngBuf bytes.Buffer
	if err := png.Encode(&pngBuf, img); err != nil {
		return ""
	}

	b64Str := base64.StdEncoding.EncodeToString(pngBuf.Bytes())
	return fmt.Sprintf("\x1b7\x1b[%d;%dH\x1b]1337;File=inline=1;width=auto;height=auto:%s\a\x1b8", row, col, b64Str)
}

// EncodeSixel encodes img into a compressed Sixel escape sequence.
// Wrapped in DEC cursor save (\x1b7) and restore (\x1b8).
func EncodeSixel(img *image.RGBA, col, row int) string {
	if img == nil || img.Bounds().Empty() {
		return ""
	}

	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()
	if width <= 0 || height <= 0 {
		return ""
	}

	// Extract unique colors (up to 64)
	palette := make([]color.RGBA, 0, 64)
	colorMap := make(map[color.RGBA]int)

	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			c := img.RGBAAt(x, y)
			if _, exists := colorMap[c]; !exists {
				if len(palette) < 64 {
					colorMap[c] = len(palette)
					palette = append(palette, c)
				}
			}
		}
	}

	var sb strings.Builder
	// DEC cursor save and position
	sb.WriteString(fmt.Sprintf("\x1b7\x1b[%d;%dH", row, col))
	// DCS Sixel introducer: \x1bPq; aspect ratio 1:1, grid 0;0
	sb.WriteString("\x1bPq\"1;1")

	// Emit color palette definitions
	for idx, c := range palette {
		rPct := int(c.R) * 100 / 255
		gPct := int(c.G) * 100 / 255
		bPct := int(c.B) * 100 / 255
		sb.WriteString(fmt.Sprintf("#%d;2;%d;%d;%d", idx, rPct, gPct, bPct))
	}

	// Emit sixel scanbands (6 vertical pixel rows per band)
	for bandY := bounds.Min.Y; bandY < bounds.Max.Y; bandY += 6 {
		for colorIdx := range palette {
			var sixelRow []byte
			hasPixels := false

			for x := bounds.Min.X; x < bounds.Max.X; x++ {
				var sixelVal byte
				for bit := 0; bit < 6; bit++ {
					py := bandY + bit
					if py < bounds.Max.Y {
						c := img.RGBAAt(x, py)
						if cIdx, ok := colorMap[c]; ok && cIdx == colorIdx {
							sixelVal |= 1 << bit
						}
					}
				}
				if sixelVal != 0 {
					hasPixels = true
				}
				sixelRow = append(sixelRow, sixelVal+63)
			}

			if hasPixels {
				sb.WriteString(fmt.Sprintf("#%d", colorIdx))
				// RLE compression for the sixel row
				runChar := byte(0)
				runLen := 0
				for _, ch := range sixelRow {
					if ch == runChar {
						runLen++
					} else {
						if runLen > 0 {
							emitSixelRun(&sb, runChar, runLen)
						}
						runChar = ch
						runLen = 1
					}
				}
				if runLen > 0 {
					emitSixelRun(&sb, runChar, runLen)
				}
				sb.WriteByte('$') // Carriage return to start of sixel band
			}
		}
		sb.WriteByte('-') // Line feed to next 6-row band
	}

	// Sixel terminator ST + DEC cursor restore
	sb.WriteString("\x1b\\\x1b8")
	return sb.String()
}

func emitSixelRun(sb *strings.Builder, ch byte, length int) {
	if length > 3 {
		sb.WriteString(fmt.Sprintf("!%d%c", length, ch))
	} else {
		for i := 0; i < length; i++ {
			sb.WriteByte(ch)
		}
	}
}

// EncodeEscapeSeq builds the complete escape sequence for img positioned at (col, row).
func EncodeEscapeSeq(img *image.RGBA, proto PixelProtocol, col, row int) string {
	if img == nil || img.Bounds().Empty() {
		return ""
	}
	switch proto {
	case ProtocolKitty:
		return EncodeKittyPNG(img, col, row)
	case ProtocolIterm:
		return EncodeItermPNG(img, col, row)
	case ProtocolSixel:
		return EncodeSixel(img, col, row)
	default:
		return ""
	}
}
