package tui

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/x/term"
	"github.com/muesli/cancelreader"
)

// PaletteMode represents the palette coloring mode.
type PaletteMode int

const (
	PaletteGrayscale PaletteMode = iota
	PaletteHighContrast
	PaletteCustom
)

// BitplaneState tracks the geometry, plane pointers, palette, and cache for the bitplane viewer.
type BitplaneState struct {
	RowBytes        int            // Bytes per row per plane (e.g. 40 = 320 px)
	Height          int            // Scanline height (e.g. 200, 256)
	Planes          int            // Number of bitplanes (1..7, matching BPU)
	Interleaved     bool           // True if scanlines of planes are interleaved
	Modulo          int            // Modulo added to row stride in bytes
	Scale           int            // Nearest-neighbor integer zoom (1..8, default 1)
	Hires           bool           // True if 640 hires visible window mode
	BPL             [8]uint32      // Starting byte offset for each bitplane (1..7)
	ControlMask     uint8          // Bitmask of active planes in control selection (bit p = 1 means plane p+1 affected)
	VisibleMask     uint8          // Bitmask of active visible planes forming the image (bit p = 1 means plane p+1 decoded)
	PaletteMode     PaletteMode    // Grayscale, High-Contrast, Custom
	Invert          bool           // Invert colors
	Brightness      int            // Brightness bias (-4..+4)
	CustomPalette   [32]color.RGBA // Custom 32-color palette extracted or loaded
	CustomPalName   string         // e.g. "Copper@+$12340"
	HAM             bool           // Hold-And-Modify 6 mode
	CachedEscapeSeq string         // Cached terminal pixel escape sequence
	CachedProtocol  PixelProtocol  // Protocol used to generate CachedEscapeSeq
}

// NewBitplaneState initializes a BitplaneState starting at byte offset base.
func NewBitplaneState(base uint32) *BitplaneState {
	s := &BitplaneState{
		RowBytes:       40, // 320 px buffer
		Height:         200,
		Planes:         1,
		Interleaved:    false,
		Modulo:         0,
		Scale:          DetectOptimalScale(320, 200),
		ControlMask:    0x01,
		VisibleMask:    0x01,
		PaletteMode:    PaletteGrayscale,
		CachedProtocol: DetectProtocol(),
	}
	s.BPL[0] = base
	// Pre-calculate all 7 bitplane pointers so they are immediately valid when enabled
	planeSize := uint32(40 * 200)
	for p := 0; p < 8; p++ {
		s.BPL[p] = base + uint32(p)*planeSize
	}
	return s
}

// DetectOptimalScale calculates the optimal integer scaling factor (1x..8x)
// to display a native Amiga bitmap scaled against the terminal text area resolution.
func DetectOptimalScale(srcW, srcH int) int {
	if srcW <= 0 {
		srcW = 320
	}
	if srcH <= 0 {
		srcH = 200
	}

	screenW, screenH := detectScreenResolution()
	if screenW <= 0 || screenH <= 0 {
		// Fallback for modern high-DPI displays:
		// Target ~1200-1400px width for standard 320px Amiga bitmap (4x).
		scale := 1280 / srcW
		if scale < 1 {
			scale = 1
		}
		if scale > 6 {
			scale = 6
		}
		return scale
	}

	scaleW := screenW / srcW
	scaleH := (screenH * 4 / 5) / srcH
	scale := min(scaleW, scaleH)
	if scale < 1 {
		scale = 1
	}
	if scale > 8 {
		scale = 8
	}
	return scale
}

var (
	cachedScreenW int
	cachedScreenH int
)

func detectScreenResolution() (int, int) {
	return cachedScreenW, cachedScreenH
}

// ParseTextAreaPixelsResponse parses an XTWINOPS \x1b[4;<height>;<width>t terminal reply.
func ParseTextAreaPixelsResponse(data []byte) (width, height int, ok bool) {
	const prefix = "\x1b[4;"
	start := bytes.Index(data, []byte(prefix))
	if start < 0 {
		return 0, 0, false
	}
	rest := data[start+len(prefix):]
	end := bytes.IndexByte(rest, 't')
	if end < 0 {
		return 0, 0, false
	}
	parts := strings.Split(string(rest[:end]), ";")
	if len(parts) < 2 {
		return 0, 0, false
	}
	h, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	w, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil || w <= 0 || h <= 0 {
		return 0, 0, false
	}
	return w, h, true
}

// QueryTextAreaPixels queries the terminal text area size in pixels by sending
// \x1b[14t to stdout in raw mode and parsing the \x1b[4;<height>;<width>t reply
// from stdin. Must be called at startup before Bubble Tea takes ownership of stdin.
func QueryTextAreaPixels() (width, height int) {
	if !term.IsTerminal(os.Stdin.Fd()) || !term.IsTerminal(os.Stdout.Fd()) {
		return 0, 0
	}

	oldState, err := term.MakeRaw(os.Stdin.Fd())
	if err != nil {
		return 0, 0
	}
	defer func() {
		_ = term.Restore(os.Stdin.Fd(), oldState)
	}()

	cr, err := cancelreader.NewReader(os.Stdin)
	if err != nil {
		return 0, 0
	}
	defer func() {
		_ = cr.Close()
	}()

	if _, err := os.Stdout.WriteString("\x1b[14t"); err != nil {
		return 0, 0
	}

	timer := time.AfterFunc(100*time.Millisecond, func() {
		cr.Cancel()
	})
	defer timer.Stop()

	var resp []byte
	var buf [64]byte
	for len(resp) < 128 {
		n, readErr := cr.Read(buf[:])
		if n > 0 {
			resp = append(resp, buf[:n]...)
			if w, h, ok := ParseTextAreaPixelsResponse(resp); ok {
				cachedScreenW, cachedScreenH = w, h
				return w, h
			}
			if bytes.IndexByte(resp, 't') >= 0 {
				break
			}
		}
		if readErr != nil {
			break
		}
	}
	return 0, 0
}

// WidthPx returns the total bitmap width in pixels (RowBytes * 8).
func (s *BitplaneState) WidthPx() int {
	return s.RowBytes * 8
}

// BPU returns the number of active bitplanes in BPLCON0 (1..7, default 1).
func (s *BitplaneState) BPU() int {
	maxP := 1
	for p := 0; p < 8; p++ {
		if (s.VisibleMask & (1 << p)) != 0 {
			maxP = p + 1
		}
	}
	if s.Planes > maxP {
		maxP = s.Planes
	}
	if maxP < 1 {
		return 1
	}
	if maxP > 7 {
		return 7
	}
	return maxP
}

// SetBPU updates the number of active bitplanes (1..7) and synchronizes VisibleMask.
func (s *BitplaneState) SetBPU(n int) {
	if n < 1 {
		n = 1
	}
	if n > 7 {
		n = 7
	}
	s.Planes = n
	s.VisibleMask = uint8((1 << n) - 1)
}

// EffectivePlanes returns the active bitplane count (1..7), matching BPU.
func (s *BitplaneState) EffectivePlanes() int {
	return s.BPU()
}

// VisibleWidth returns the human-readable visible display window width in pixels.
// Standard Amiga display window is 320 px in Lowres or 640 px in Hires.
func (s *BitplaneState) VisibleWidth() int {
	maxW := 320
	if s.Hires || s.RowBytes >= 80 {
		maxW = 640
	}
	bufW := s.RowBytes * 8
	if bufW < maxW && bufW > 0 {
		return bufW
	}
	return maxW
}

// VisibleRowBytes returns the visible scanline width in bytes.
func (s *BitplaneState) VisibleRowBytes() int {
	return max(s.VisibleWidth()/8, 1)
}

// HardwareModulos returns the BPL1MOD and BPL2MOD register values.
// If the buffer in RAM is wider than the visible window (320 or 640 px),
// the extra bytes are cut and reflected in the modulo so scanlines advance cleanly.
func (s *BitplaneState) HardwareModulos() (int, int) {
	rowBytes := max(s.RowBytes, 1)
	visBytes := s.VisibleRowBytes()
	cutBytes := max(rowBytes-visBytes, 0)

	if s.Interleaved {
		bpu := max(s.BPU(), 1)
		mod := (bpu-1)*rowBytes + cutBytes + s.Modulo
		return mod, mod
	}
	mod := cutBytes + s.Modulo
	return mod, mod
}

// BPLCON0Hex returns the raw 16-bit register value for BPLCON0 ($DFF100).
func (s *BitplaneState) BPLCON0Hex() uint16 {
	bpu := s.BPU()
	val := uint16(bpu&7) << 12
	val |= 0x0200 // COLOR burst enable
	if s.Hires || s.RowBytes >= 80 {
		val |= 0x8000 // HIRES
	}
	if s.HAM && bpu == 6 {
		val |= 0x0800 // HAM
	}
	return val
}

// RowStrideBytes returns the byte stride between successive scanlines of a plane.
func (s *BitplaneState) RowStrideBytes() int {
	rowBytes := max(s.RowBytes, 1)
	if s.Interleaved {
		return rowBytes*max(s.BPU(), 1) + s.Modulo
	}
	return rowBytes + s.Modulo
}

// AutoSnapPlanes recalibrates starting pointers for all planes armed in ControlMask
// relative to the lowest armed plane, keeping unarmed planes and soloed offsets intact.
func (s *BitplaneState) AutoSnapPlanes() {
	anchorP := -1
	for p := 0; p < 8; p++ {
		if (s.ControlMask & (1 << p)) != 0 {
			anchorP = p
			break
		}
	}
	if anchorP < 0 {
		return
	}

	base := s.BPL[anchorP]
	step := uint32(s.RowStrideBytes() * max(s.Height, 1))
	if s.Interleaved {
		step = uint32(max(s.RowBytes, 1))
	}
	for p := anchorP + 1; p < 8; p++ {
		if (s.ControlMask & (1 << p)) != 0 {
			s.BPL[p] = base + uint32(p-anchorP)*step
		}
	}
}

// ChangeBPU updates BPU to newBPU (1..7), arms any newly enabled planes in ControlMask,
// and snaps newly added planes consecutively after the preceding plane.
func (s *BitplaneState) ChangeBPU(newBPU int) {
	if newBPU < 1 {
		newBPU = 1
	}
	if newBPU > 7 {
		newBPU = 7
	}
	oldBPU := s.BPU()
	s.SetBPU(newBPU)
	if newBPU > oldBPU {
		step := uint32(s.RowStrideBytes() * max(s.Height, 1))
		if s.Interleaved {
			step = uint32(max(s.RowBytes, 1))
		}
		for p := oldBPU; p < newBPU; p++ {
			s.ControlMask |= (1 << p)
			if p > 0 {
				s.BPL[p] = s.BPL[p-1] + step
			}
		}
		s.AutoSnapPlanes()
	} else if s.Interleaved {
		s.AutoSnapPlanes()
	}
}

// StepControlPlanes shifts starting pointers of all planes active in ControlMask by delta bytes.
// Inactive planes stay fixed, enabling precise inter-plane registration and color calibration.
func (s *BitplaneState) StepControlPlanes(delta int) {
	for p := 0; p < 8; p++ {
		if (s.ControlMask & (1 << p)) != 0 {
			newOff := int(s.BPL[p]) + delta
			if newOff < 0 {
				newOff = 0
			}
			s.BPL[p] = uint32(newOff)
		}
	}
}

// RotatePlanes shifts plane pointers cyclically (e.g., plane 1 becomes plane 2).
func (s *BitplaneState) RotatePlanes(forward bool) {
	bpu := s.BPU()
	if bpu <= 1 {
		return
	}
	if forward {
		last := s.BPL[bpu-1]
		for p := bpu - 1; p > 0; p-- {
			s.BPL[p] = s.BPL[p-1]
		}
		s.BPL[0] = last
	} else {
		first := s.BPL[0]
		for p := 0; p < bpu-1; p++ {
			s.BPL[p] = s.BPL[p+1]
		}
		s.BPL[bpu-1] = first
	}
}

// ByteSpan returns the byte range covered by all planes in the current geometry.
func (s *BitplaneState) ByteSpan() (uint32, uint32) {
	minOff := s.BPL[0]
	maxOff := s.BPL[0]
	rowBytes := uint32(max(s.RowBytes, 1))
	stride := uint32(max(s.RowStrideBytes(), 1))
	height := uint32(max(s.Height, 1))
	bpu := s.BPU()

	for p := 0; p < bpu; p++ {
		start := s.BPL[p]
		if start < minOff {
			minOff = start
		}
		var end uint32
		if s.Interleaved {
			end = start + (height-1)*stride + rowBytes
		} else {
			end = start + height*stride
		}
		if end > maxOff {
			maxOff = end
		}
	}
	return minOff, maxOff
}

// Convert0RGBToRGBA converts a 12-bit Amiga $0RGB word into 32-bit color.RGBA.
func Convert0RGBToRGBA(val uint16) color.RGBA {
	r4 := uint8((val >> 8) & 0x0F)
	g4 := uint8((val >> 4) & 0x0F)
	b4 := uint8(val & 0x0F)
	return color.RGBA{
		R: (r4 << 4) | r4,
		G: (g4 << 4) | g4,
		B: (b4 << 4) | b4,
		A: 255,
	}
}

// ParseAmigaPalette attempts to parse a 32-color palette at offset in data.
// Checks for Copper MOVE streams ($0180..$01BE) or contiguous $0RGB tables.
func ParseAmigaPalette(data []byte, offset uint32) ([32]color.RGBA, string, bool) {
	var pal [32]color.RGBA
	if int(offset)+4 > len(data) {
		return pal, "", false
	}

	// 1. Check for Copper list palette stream ($0180, $0182, ...)
	reg0 := binary.BigEndian.Uint16(data[offset : offset+2])
	if reg0 >= 0x0180 && reg0 <= 0x01BE && (reg0&1) == 0 {
		count := 0
		curr := int(offset)
		for curr+4 <= len(data) && count < 32 {
			reg := binary.BigEndian.Uint16(data[curr : curr+2])
			if reg < 0x0180 || reg > 0x01BE || (reg&1) != 0 {
				break
			}
			colIdx := int((reg - 0x0180) / 2)
			val := binary.BigEndian.Uint16(data[curr+2 : curr+4])
			pal[colIdx] = Convert0RGBToRGBA(val)
			count++
			curr += 4
		}
		if count >= 2 {
			return pal, "Copper", true
		}
	}

	// 2. Check for contiguous raw $0RGB table (requiring at least 4 contiguous valid colors)
	count := 0
	curr := int(offset)
	for curr+2 <= len(data) && count < 32 {
		val := binary.BigEndian.Uint16(data[curr : curr+2])
		if (val & 0xF000) != 0 {
			break
		}
		pal[count] = Convert0RGBToRGBA(val)
		count++
		curr += 2
	}
	if count >= 4 {
		return pal, "0RGB", true
	}

	return pal, "", false
}

// BuildDefaultPalette creates a 128-color palette based on mode, depth, invert, and brightness.
func (s *BitplaneState) BuildDefaultPalette() [128]color.RGBA {
	var pal [128]color.RGBA
	bpu := s.BPU()

	switch s.PaletteMode {
	case PaletteCustom:
		copy(pal[:32], s.CustomPalette[:32])
		// Extra Half-Brite (EHB) for planes 6 and 7 if custom palette
		for i := 0; i < 32; i++ {
			pal[i+32] = color.RGBA{
				R: pal[i].R >> 1,
				G: pal[i].G >> 1,
				B: pal[i].B >> 1,
				A: 255,
			}
		}
		for i := 0; i < 64; i++ {
			pal[i+64] = color.RGBA{
				R: pal[i].R >> 1,
				G: pal[i].G >> 1,
				B: pal[i].B >> 1,
				A: 255,
			}
		}
	case PaletteHighContrast:
		if bpu == 1 {
			pal[0] = color.RGBA{0, 0, 0, 255}
			pal[1] = color.RGBA{255, 255, 255, 255}
		} else {
			baseHues := [32]color.RGBA{
				{0x00, 0x00, 0x00, 0xFF}, {0xFF, 0xFF, 0xFF, 0xFF},
				{0x00, 0x55, 0xAA, 0xFF}, {0xEE, 0x44, 0x44, 0xFF},
				{0x55, 0xAA, 0x00, 0xFF}, {0xDD, 0x88, 0x00, 0xFF},
				{0x99, 0x33, 0xCC, 0xFF}, {0x00, 0xBB, 0xCC, 0xFF},
				{0xAA, 0xAA, 0xAA, 0xFF}, {0x55, 0x55, 0x55, 0xFF},
				{0x88, 0x00, 0x00, 0xFF}, {0x00, 0x88, 0x00, 0xFF},
				{0x00, 0x00, 0x88, 0xFF}, {0xCC, 0xAA, 0x00, 0xFF},
				{0xAA, 0x00, 0xAA, 0xFF}, {0x00, 0xAA, 0xAA, 0xFF},
				{0x77, 0x44, 0x00, 0xFF}, {0xFF, 0x77, 0x77, 0xFF},
				{0x77, 0xFF, 0x77, 0xFF}, {0x77, 0x77, 0xFF, 0xFF},
				{0xFF, 0xFF, 0x77, 0xFF}, {0xFF, 0x77, 0xFF, 0xFF},
				{0x77, 0xFF, 0xFF, 0xFF}, {0xDD, 0xDD, 0xDD, 0xFF},
				{0x33, 0x33, 0x33, 0xFF}, {0xCC, 0x44, 0x00, 0xFF},
				{0x00, 0xCC, 0x44, 0xFF}, {0x44, 0x00, 0xCC, 0xFF},
				{0x88, 0x88, 0x22, 0xFF}, {0x88, 0x22, 0x88, 0xFF},
				{0x22, 0x88, 0x88, 0xFF}, {0xFF, 0xCC, 0x99, 0xFF},
			}
			copy(pal[:32], baseHues[:32])
			for i := 32; i < 128; i++ {
				base := pal[i%32]
				factor := uint8(200 - (i/32)*40)
				pal[i] = color.RGBA{
					R: uint8((uint16(base.R) * uint16(factor)) / 255),
					G: uint8((uint16(base.G) * uint16(factor)) / 255),
					B: uint8((uint16(base.B) * uint16(factor)) / 255),
					A: 255,
				}
			}
		}
	default: // PaletteGrayscale
		numCols := 1 << bpu
		if numCols <= 2 {
			pal[0] = color.RGBA{0x00, 0x00, 0x00, 0xFF}
			pal[1] = color.RGBA{0xFF, 0xFF, 0xFF, 0xFF}
		} else {
			steps := min(numCols, 128)
			for i := 0; i < steps; i++ {
				v := uint8((i * 255) / (steps - 1))
				pal[i] = color.RGBA{R: v, G: v, B: v, A: 255}
			}
		}
	}

	// Extra Half-Brite (EHB): 6 planes, colors 32..63 are half brightness of 0..31
	if bpu == 6 && s.PaletteMode != PaletteGrayscale {
		for i := 0; i < 32; i++ {
			pal[i+32] = color.RGBA{
				R: pal[i].R >> 1,
				G: pal[i].G >> 1,
				B: pal[i].B >> 1,
				A: 255,
			}
		}
	}

	// Apply Invert
	if s.Invert {
		numCols := min(1<<bpu, 128)
		for i := 0; i < numCols; i++ {
			pal[i].R = 255 - pal[i].R
			pal[i].G = 255 - pal[i].G
			pal[i].B = 255 - pal[i].B
		}
	}

	// Apply Brightness bias
	if s.Brightness != 0 {
		bias := int16(s.Brightness) * 20
		numCols := min(1<<bpu, 128)
		for i := 0; i < numCols; i++ {
			clamp := func(val uint8) uint8 {
				res := int16(val) + bias
				if res < 0 {
					return 0
				}
				if res > 255 {
					return 255
				}
				return uint8(res)
			}
			pal[i].R = clamp(pal[i].R)
			pal[i].G = clamp(pal[i].G)
			pal[i].B = clamp(pal[i].B)
		}
	}

	return pal
}

// DecodeImage decodes planar Amiga graphics from data into an RGBA image.
// If maxPxW or maxPxH are <= 0, the full native bitmap width/height is decoded.
// Returns an *image.RGBA scaled by s.Scale via nearest-neighbor replication.
func (s *BitplaneState) DecodeImage(data []byte, maxPxW, maxPxH int) *image.RGBA {
	height := max(s.Height, 1)
	stride := s.RowStrideBytes()
	scale := max(min(s.Scale, 8), 1)

	visW := s.VisibleWidth()
	if maxPxW > 0 && maxPxW < visW {
		visW = maxPxW
	}
	visH := height
	if maxPxH > 0 && maxPxH < visH {
		visH = maxPxH
	}
	if visW <= 0 || visH <= 0 {
		return image.NewRGBA(image.Rect(0, 0, 1, 1))
	}

	palette := s.BuildDefaultPalette()
	dataLen := len(data)
	bpu := s.BPU()

	// Decode 1:1 pixels into flat slice
	rawPixels := make([]color.RGBA, visW*visH)

	for y := 0; y < visH; y++ {
		rowOffset := y * stride
		var lastHAM color.RGBA = palette[0]

		for x := 0; x < visW; x++ {
			byteIdx := x >> 3
			bitShift := 7 - (x & 7)

			var colorIdx int
			for p := 0; p < bpu; p++ {
				if (s.VisibleMask & (1 << p)) != 0 {
					offset := int(s.BPL[p]) + rowOffset + byteIdx
					if offset >= 0 && offset < dataLen {
						bit := (data[offset] >> bitShift) & 1
						colorIdx |= int(bit) << p
					}
				}
			}

			var pxColor color.RGBA
			if s.HAM && bpu == 6 {
				control := (colorIdx >> 4) & 3
				val := colorIdx & 0x0F
				val8 := uint8((val << 4) | val)
				switch control {
				case 0:
					pxColor = palette[val]
					lastHAM = pxColor
				case 1: // Modify Blue
					pxColor = color.RGBA{R: lastHAM.R, G: lastHAM.G, B: val8, A: 255}
					lastHAM = pxColor
				case 2: // Modify Red
					pxColor = color.RGBA{R: val8, G: lastHAM.G, B: lastHAM.B, A: 255}
					lastHAM = pxColor
				case 3: // Modify Green
					pxColor = color.RGBA{R: lastHAM.R, G: val8, B: lastHAM.B, A: 255}
					lastHAM = pxColor
				}
			} else {
				pxColor = palette[colorIdx&127]
			}

			rawPixels[y*visW+x] = pxColor
		}
	}

	// Nearest-neighbor integer scaling (Scale * Scale replication)
	outW := visW * scale
	outH := visH * scale
	img := image.NewRGBA(image.Rect(0, 0, outW, outH))

	for y := 0; y < visH; y++ {
		srcRowStart := y * visW
		for x := 0; x < visW; x++ {
			c := rawPixels[srcRowStart+x]
			for sy := 0; sy < scale; sy++ {
				destY := y*scale + sy
				destRowStart := destY * img.Stride
				for sx := 0; sx < scale; sx++ {
					destX := x*scale + sx
					off := destRowStart + destX*4
					img.Pix[off+0] = c.R
					img.Pix[off+1] = c.G
					img.Pix[off+2] = c.B
					img.Pix[off+3] = c.A
				}
			}
		}
	}

	return img
}

// UpdateCache pre-decodes the image and builds the terminal escape sequence.
// Called in Init() or Update() when parameters mutate—never inside View().
func (s *BitplaneState) UpdateCache(data []byte, col, row int, proto PixelProtocol) {
	s.UpdateCacheClipped(data, col, row, proto, 0, 0)
}

// UpdateCacheClipped pre-decodes the image clipped to maxOutPxW x maxOutPxH
// and builds the terminal escape sequence.
func (s *BitplaneState) UpdateCacheClipped(data []byte, col, row int, proto PixelProtocol, maxOutPxW, maxOutPxH int) {
	s.CachedProtocol = proto
	if proto == ProtocolHalfBlock {
		s.CachedEscapeSeq = ""
		return
	}

	scale := max(min(s.Scale, 8), 1)
	var maxSrcW, maxSrcH int
	if maxOutPxW > 0 {
		maxSrcW = max(maxOutPxW/scale, 1)
	}
	if maxOutPxH > 0 {
		maxSrcH = max(maxOutPxH/scale, 1)
	}

	img := s.DecodeImage(data, maxSrcW, maxSrcH)
	s.CachedEscapeSeq = EncodeEscapeSeq(img, proto, col, row)
}

// EncodeIFFILBM encodes the bitplane data into a standard Amiga IFF ILBM binary file.
func EncodeIFFILBM(st *BitplaneState, data []byte) ([]byte, error) {
	width := st.VisibleWidth()
	height := st.Height
	planes := max(min(st.BPU(), 7), 1)
	rowBytes := st.VisibleRowBytes()
	stride := st.RowStrideBytes()
	dataLen := len(data)

	// 1. BMHD chunk (20 bytes)
	bmhd := make([]byte, 20)
	binary.BigEndian.PutUint16(bmhd[0:2], uint16(width))
	binary.BigEndian.PutUint16(bmhd[2:4], uint16(height))
	binary.BigEndian.PutUint16(bmhd[4:6], 0) // x
	binary.BigEndian.PutUint16(bmhd[6:8], 0) // y
	bmhd[8] = uint8(planes)
	bmhd[9] = 0                                // masking: mskNone
	bmhd[10] = 0                               // compression: cmpNone
	bmhd[11] = 0                               // pad
	binary.BigEndian.PutUint16(bmhd[12:14], 0) // transparentColor
	bmhd[14] = 10                              // xAspect
	bmhd[15] = 11                              // yAspect (PAL standard)
	binary.BigEndian.PutUint16(bmhd[16:18], uint16(width))
	binary.BigEndian.PutUint16(bmhd[18:20], uint16(height))

	// 2. CMAP chunk
	numColors := 1 << planes
	if numColors > 32 && !st.HAM && planes <= 6 {
		numColors = 32 // EHB stores base 32 colors in CMAP
	}
	if numColors > 128 {
		numColors = 128
	}
	pal := st.BuildDefaultPalette()
	cmap := make([]byte, numColors*3)
	for i := 0; i < numColors; i++ {
		cmap[i*3+0] = pal[i].R
		cmap[i*3+1] = pal[i].G
		cmap[i*3+2] = pal[i].B
	}

	// 3. CAMG chunk (4 bytes)
	camg := make([]byte, 4)
	var viewModes uint32
	if st.HAM && planes == 6 {
		viewModes |= 0x0800 // HAM
	} else if planes == 6 {
		viewModes |= 0x0080 // EHB
	}
	if width >= 640 {
		viewModes |= 0x8000 // HIRES
	}
	binary.BigEndian.PutUint32(camg, viewModes)

	// 4. BODY chunk (interleaved scanlines of each plane)
	body := make([]byte, 0, height*planes*rowBytes)
	for y := 0; y < height; y++ {
		rowOff := y * stride
		for p := 0; p < planes; p++ {
			planeStart := int(st.BPL[p]) + rowOff
			for b := 0; b < rowBytes; b++ {
				idx := planeStart + b
				if idx >= 0 && idx < dataLen {
					body = append(body, data[idx])
				} else {
					body = append(body, 0)
				}
			}
		}
	}

	// Assemble FORM ILBM
	var out []byte
	out = append(out, []byte("FORM")...)
	formLenOffset := len(out)
	out = append(out, 0, 0, 0, 0) // placeholder for total length
	out = append(out, []byte("ILBM")...)

	writeChunk := func(tag string, chunkData []byte) {
		out = append(out, []byte(tag)...)
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(chunkData)))
		out = append(out, lenBuf[:]...)
		out = append(out, chunkData...)
		if len(chunkData)%2 != 0 {
			out = append(out, 0) // pad byte for word alignment
		}
	}

	writeChunk("BMHD", bmhd)
	writeChunk("CMAP", cmap)
	writeChunk("CAMG", camg)
	writeChunk("BODY", body)

	// Patch FORM length (total length minus 8)
	totalLen := uint32(len(out) - 8)
	binary.BigEndian.PutUint32(out[formLenOffset:formLenOffset+4], totalLen)

	return out, nil
}
