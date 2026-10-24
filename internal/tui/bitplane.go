package tui

import (
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"os"
	"path/filepath"
	"strings"
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
	RowBytes       int             // Bytes per row per plane (e.g. 40 = 320 px)
	Height         int             // Scanline height (e.g. 200, 256)
	Planes         int             // Number of bitplanes (1..6)
	Interleaved    bool            // True if scanlines of planes are interleaved
	Modulo         int             // Modulo added to row stride in bytes
	Scale          int             // Nearest-neighbor integer zoom (1..8, default 1)
	BPL             [6]uint32       // Starting byte offset for each bitplane
	ControlMask     uint8           // Bitmask of active planes in control selection (bit p = 1 means plane p affected)
	VisibleMask     uint8           // Bitmask of active visible planes forming the image (bit p = 1 means plane p decoded)
	PaletteMode     PaletteMode     // Grayscale, High-Contrast, Custom
	Invert          bool            // Invert colors
	Brightness      int             // Brightness bias (-4..+4)
	CustomPalette   [32]color.RGBA  // Custom 32-color palette extracted or loaded
	CustomPalName   string          // e.g. "Copper@+$12340"
	HAM             bool            // Hold-And-Modify 6 mode
	CachedEscapeSeq string          // Cached terminal pixel escape sequence
	CachedProtocol  PixelProtocol   // Protocol used to generate CachedEscapeSeq
}

// NewBitplaneState initializes a BitplaneState starting at byte offset base.
func NewBitplaneState(base uint32) *BitplaneState {
	s := &BitplaneState{
		RowBytes:       40, // 320 px
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
	s.AutoSnapPlanes()
	return s
}

// DetectOptimalScale calculates the optimal integer scaling factor (1x..8x)
// to display a native Amiga bitmap scaled against the physical screen resolution.
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

	// Target the bitmap to comfortably occupy roughly half the physical screen
	targetW := screenW / 2
	targetH := screenH / 2

	scaleW := targetW / srcW
	scaleH := targetH / srcH
	scale := min(scaleW, scaleH)
	if scale < 1 {
		scale = 1
	}
	if scale > 8 {
		scale = 8
	}
	return scale
}

func detectScreenResolution() (int, int) {
	matches, _ := filepath.Glob("/sys/class/drm/*/modes")
	for _, m := range matches {
		data, err := os.ReadFile(m)
		if err == nil && len(data) > 0 {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				var w, h int
				if n, _ := fmt.Sscanf(line, "%dx%d", &w, &h); n == 2 && w > 0 && h > 0 {
					return w, h
				}
			}
		}
	}
	return 0, 0
}

// WidthPx returns the total bitmap width in pixels (RowBytes * 8).
func (s *BitplaneState) WidthPx() int {
	return s.RowBytes * 8
}

// RowStrideBytes returns the byte stride between successive scanlines of a plane.
func (s *BitplaneState) RowStrideBytes() int {
	rowBytes := max(s.RowBytes, 1)
	if s.Interleaved {
		return rowBytes*max(s.Planes, 1) + s.Modulo
	}
	return rowBytes + s.Modulo
}

// AutoSnapPlanes recalibrates starting pointers for all planes armed in ControlMask.
// Unarmed planes stay fixed, preserving manual alignment offsets.
func (s *BitplaneState) AutoSnapPlanes() {
	base := s.BPL[0]
	rowBytes := max(s.RowBytes, 1)
	planes := max(min(s.Planes, 6), 1)

	if s.Interleaved {
		for p := range planes {
			if (s.ControlMask & (1 << p)) != 0 {
				s.BPL[p] = base + uint32(p*rowBytes)
			}
		}
	} else {
		planeSize := uint32(s.RowStrideBytes() * max(s.Height, 1))
		for p := range planes {
			if (s.ControlMask & (1 << p)) != 0 {
				s.BPL[p] = base + uint32(p)*planeSize
			}
		}
	}
}

// StepControlPlanes shifts starting pointers of all planes active in ControlMask by delta bytes.
// Inactive planes stay fixed, enabling precise inter-plane registration and color calibration.
func (s *BitplaneState) StepControlPlanes(delta int) {
	for p := 0; p < s.Planes; p++ {
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
	if s.Planes <= 1 {
		return
	}
	if forward {
		last := s.BPL[s.Planes-1]
		for p := s.Planes - 1; p > 0; p-- {
			s.BPL[p] = s.BPL[p-1]
		}
		s.BPL[0] = last
	} else {
		first := s.BPL[0]
		for p := 0; p < s.Planes-1; p++ {
			s.BPL[p] = s.BPL[p+1]
		}
		s.BPL[s.Planes-1] = first
	}
}

// ByteSpan returns the byte range covered by all planes in the current geometry.
func (s *BitplaneState) ByteSpan() (uint32, uint32) {
	minOff := s.BPL[0]
	maxOff := s.BPL[0]
	stride := uint32(max(s.RowStrideBytes(), 1))
	height := uint32(max(s.Height, 1))
	spanPerPlane := stride * height

	for p := 0; p < s.Planes; p++ {
		start := s.BPL[p]
		if start < minOff {
			minOff = start
		}
		end := start + spanPerPlane
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

// BuildDefaultPalette creates a 64-color palette based on mode, depth, invert, and brightness.
func (s *BitplaneState) BuildDefaultPalette() [64]color.RGBA {
	var pal [64]color.RGBA

	switch s.PaletteMode {
	case PaletteCustom:
		copy(pal[:32], s.CustomPalette[:32])
	case PaletteHighContrast:
		if s.Planes == 1 {
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
		}
	default: // PaletteGrayscale
		numCols := 1 << s.Planes
		if numCols <= 2 {
			pal[0] = color.RGBA{0x00, 0x00, 0x00, 0xFF}
			pal[1] = color.RGBA{0xFF, 0xFF, 0xFF, 0xFF}
		} else {
			steps := min(numCols, 32)
			for i := 0; i < steps; i++ {
				v := uint8((i * 255) / (steps - 1))
				pal[i] = color.RGBA{R: v, G: v, B: v, A: 255}
			}
		}
	}

	// Apply Invert
	if s.Invert {
		numCols := min(1<<s.Planes, 32)
		for i := 0; i < numCols; i++ {
			pal[i].R = 255 - pal[i].R
			pal[i].G = 255 - pal[i].G
			pal[i].B = 255 - pal[i].B
		}
	}

	// Apply Brightness bias
	if s.Brightness != 0 {
		bias := int16(s.Brightness) * 20
		numCols := min(1<<s.Planes, 32)
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

	// Extra Half-Brite (EHB): 6 planes, colors 32..63 are half brightness of 0..31
	for i := 0; i < 32; i++ {
		pal[i+32] = color.RGBA{
			R: pal[i].R >> 1,
			G: pal[i].G >> 1,
			B: pal[i].B >> 1,
			A: 255,
		}
	}

	return pal
}

// DecodeImage decodes planar Amiga graphics from data into an RGBA image.
// If maxPxW or maxPxH are <= 0, the full native bitmap width/height is decoded.
// Returns an *image.RGBA scaled by s.Scale via nearest-neighbor replication.
func (s *BitplaneState) DecodeImage(data []byte, maxPxW, maxPxH int) *image.RGBA {
	rowBytes := max(s.RowBytes, 1)
	height := max(s.Height, 1)
	planes := max(min(s.Planes, 6), 1)
	stride := s.RowStrideBytes()
	scale := max(min(s.Scale, 8), 1)

	widthPx := rowBytes * 8
	visW := widthPx
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

	// Decode 1:1 pixels into flat slice
	rawPixels := make([]color.RGBA, visW*visH)

	for y := 0; y < visH; y++ {
		rowOffset := y * stride
		var lastHAM color.RGBA = palette[0]

		for x := 0; x < visW; x++ {
			byteIdx := x >> 3
			bitShift := 7 - (x & 7)

			var colorIdx int
			for p := 0; p < planes; p++ {
				if (s.VisibleMask & (1 << p)) != 0 {
					offset := int(s.BPL[p]) + rowOffset + byteIdx
					if offset >= 0 && offset < dataLen {
						bit := (data[offset] >> bitShift) & 1
						colorIdx |= int(bit) << p
					}
				}
			}

			var pxColor color.RGBA
			if s.HAM && planes == 6 {
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
				pxColor = palette[colorIdx&63]
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
	s.CachedProtocol = proto
	if proto == ProtocolHalfBlock {
		s.CachedEscapeSeq = ""
		return
	}

	// Decode the FULL native Amiga bitmap scaled by integer Scale
	img := s.DecodeImage(data, 0, 0)
	s.CachedEscapeSeq = EncodeEscapeSeq(img, proto, col, row)
}

// EncodeIFFILBM encodes the bitplane data into a standard Amiga IFF ILBM binary file.
func EncodeIFFILBM(st *BitplaneState, data []byte) ([]byte, error) {
	width := st.WidthPx()
	height := st.Height
	planes := max(min(st.Planes, 6), 1)
	rowBytes := max(st.RowBytes, 1)
	stride := st.RowStrideBytes()
	dataLen := len(data)

	// 1. BMHD chunk (20 bytes)
	bmhd := make([]byte, 20)
	binary.BigEndian.PutUint16(bmhd[0:2], uint16(width))
	binary.BigEndian.PutUint16(bmhd[2:4], uint16(height))
	binary.BigEndian.PutUint16(bmhd[4:6], 0) // x
	binary.BigEndian.PutUint16(bmhd[6:8], 0) // y
	bmhd[8] = uint8(planes)
	bmhd[9] = 0  // masking: mskNone
	bmhd[10] = 0 // compression: cmpNone
	bmhd[11] = 0 // pad
	binary.BigEndian.PutUint16(bmhd[12:14], 0) // transparentColor
	bmhd[14] = 10 // xAspect
	bmhd[15] = 11 // yAspect (PAL standard)
	binary.BigEndian.PutUint16(bmhd[16:18], uint16(width))
	binary.BigEndian.PutUint16(bmhd[18:20], uint16(height))

	// 2. CMAP chunk
	numColors := 1 << planes
	if numColors > 32 && !st.HAM {
		numColors = 32 // EHB stores base 32 colors in CMAP
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
