package tui

import (
	"encoding/binary"
	"image/color"
	"testing"

	"github.com/mikolas/hunks/internal/amiga"
)

func TestBitplaneStateGeometry(t *testing.T) {
	st := NewBitplaneState(0x1000)
	if st.WidthPx() != 320 {
		t.Fatalf("expected WidthPx 320, got %d", st.WidthPx())
	}
	if st.Height != 200 {
		t.Fatalf("expected Height 200, got %d", st.Height)
	}
	if st.Planes != 1 {
		t.Fatalf("expected Planes 1, got %d", st.Planes)
	}
	if st.Scale < 1 {
		t.Fatalf("expected Scale >= 1, got %d", st.Scale)
	}
	if st.BPL[0] != 0x1000 {
		t.Fatalf("expected BPL[0] 0x1000, got 0x%X", st.BPL[0])
	}
}

func Test1PlaneBlackAndWhitePalette(t *testing.T) {
	st := NewBitplaneState(0)
	st.Planes = 1
	st.PaletteMode = PaletteGrayscale

	pal := st.BuildDefaultPalette()
	if pal[0] != (color.RGBA{R: 0, G: 0, B: 0, A: 255}) {
		t.Fatalf("expected pal[0] black, got %+v", pal[0])
	}
	if pal[1] != (color.RGBA{R: 255, G: 255, B: 255, A: 255}) {
		t.Fatalf("expected pal[1] pure white (255), got %+v", pal[1])
	}

	// Invert
	st.Invert = true
	palInv := st.BuildDefaultPalette()
	if palInv[0] != (color.RGBA{R: 255, G: 255, B: 255, A: 255}) {
		t.Fatalf("expected inverted pal[0] white, got %+v", palInv[0])
	}
	if palInv[1] != (color.RGBA{R: 0, G: 0, B: 0, A: 255}) {
		t.Fatalf("expected inverted pal[1] black, got %+v", palInv[1])
	}
}

func TestMultiPlaneGrayscaleRamp(t *testing.T) {
	st := NewBitplaneState(0)
	st.Planes = 2 // 4 colors: 0, 85, 170, 255
	pal := st.BuildDefaultPalette()
	if pal[0].R != 0 {
		t.Fatalf("expected pal[0]=0, got %d", pal[0].R)
	}
	if pal[1].R != 85 {
		t.Fatalf("expected pal[1]=85, got %d", pal[1].R)
	}
	if pal[2].R != 170 {
		t.Fatalf("expected pal[2]=170, got %d", pal[2].R)
	}
	if pal[3].R != 255 {
		t.Fatalf("expected pal[3]=255, got %d", pal[3].R)
	}
}

func TestBitplaneControlSelectionAndStep(t *testing.T) {
	st := NewBitplaneState(0x1000)
	st.Planes = 3
	st.Height = 10
	st.RowBytes = 4
	st.ControlMask = 0x07 // All 3 planes armed initially
	st.AutoSnapPlanes()

	// Select planes 2 and 3 only (mask bit 1 and bit 2, clear bit 0)
	st.ControlMask = 0x06

	// Step control planes by +16 bytes
	st.StepControlPlanes(16)

	if st.BPL[0] != 0x1000 {
		t.Fatalf("unselected plane 1 should not move: got 0x%X", st.BPL[0])
	}
	if st.BPL[1] != 0x1000+40+16 {
		t.Fatalf("control plane 2 should advance: got 0x%X", st.BPL[1])
	}
	if st.BPL[2] != 0x1000+80+16 {
		t.Fatalf("control plane 3 should advance: got 0x%X", st.BPL[2])
	}
}

func TestBitplaneVisibleMaskAndDecode(t *testing.T) {
	// 2 planes, 16 pixels wide, 1 scanline
	data := make([]byte, 100)
	// Plane 1: row 0 byte 0 = 0x80 (pixel 0 has bit 0 set)
	data[0] = 0x80
	// Plane 2: row 0 byte 0 = 0x80 (pixel 0 has bit 1 set)
	data[2] = 0x80

	st := NewBitplaneState(0)
	st.RowBytes = 2
	st.Height = 1
	st.Planes = 2
	st.Scale = 1
	st.BPL[0] = 0
	st.BPL[1] = 2
	st.PaletteMode = PaletteHighContrast

	// Case 1: Both planes visible -> pixel 0 has color 3
	st.VisibleMask = 0x03
	img := st.DecodeImage(data, 16, 1)
	cBoth := img.RGBAAt(0, 0)

	// Case 2: Only Plane 1 visible -> pixel 0 has color 1
	st.VisibleMask = 0x01
	imgP1 := st.DecodeImage(data, 16, 1)
	cP1 := imgP1.RGBAAt(0, 0)

	// Case 3: Only Plane 2 visible -> pixel 0 has color 2
	st.VisibleMask = 0x02
	imgP2 := st.DecodeImage(data, 16, 1)
	cP2 := imgP2.RGBAAt(0, 0)

	// Case 4: Neither visible -> pixel 0 has background color 0
	st.VisibleMask = 0x00
	imgNone := st.DecodeImage(data, 16, 1)
	cNone := imgNone.RGBAAt(0, 0)

	if cBoth == cP1 || cBoth == cP2 || cP1 == cP2 {
		t.Fatalf("expected distinct colors for different visible plane masks: both=%+v, p1=%+v, p2=%+v", cBoth, cP1, cP2)
	}
	if cNone != (color.RGBA{0, 0, 0, 255}) {
		t.Fatalf("expected black/bg color when all visible planes muted, got %+v", cNone)
	}
}

func TestDecodeImage1PlaneAndScaling(t *testing.T) {
	data := make([]byte, 100)
	// Set first byte of row 0 to 0x80 (pixel 0 is 1, rest 0)
	data[0] = 0x80

	st := NewBitplaneState(0)
	st.RowBytes = 2 // 16 px width
	st.Height = 2
	st.Planes = 1
	st.Scale = 1
	st.AutoSnapPlanes()

	img := st.DecodeImage(data, 16, 2)
	// Pixel 0,0 must be pure white (Color 1)
	if img.RGBAAt(0, 0) != (color.RGBA{R: 255, G: 255, B: 255, A: 255}) {
		t.Fatalf("expected white at (0,0), got %+v", img.RGBAAt(0, 0))
	}
	// Pixel 1,0 must be black (Color 0)
	if img.RGBAAt(1, 0) != (color.RGBA{R: 0, G: 0, B: 0, A: 255}) {
		t.Fatalf("expected black at (1,0), got %+v", img.RGBAAt(1, 0))
	}

	// Test 2x scaling
	st.Scale = 2
	img2 := st.DecodeImage(data, 16, 2)
	if img2.Bounds().Dx() != 32 || img2.Bounds().Dy() != 4 {
		t.Fatalf("expected 32x4 scaled bounds, got %dx%d", img2.Bounds().Dx(), img2.Bounds().Dy())
	}
	if img2.RGBAAt(0, 0) != (color.RGBA{R: 255, G: 255, B: 255, A: 255}) ||
		img2.RGBAAt(1, 0) != (color.RGBA{R: 255, G: 255, B: 255, A: 255}) {
		t.Fatalf("expected replicated white pixel at (0,0) and (1,0)")
	}
}

func TestEncodeIFFILBM(t *testing.T) {
	data := make([]byte, 100)
	st := NewBitplaneState(0)
	st.RowBytes = 4
	st.Height = 8
	st.Planes = 2
	st.AutoSnapPlanes()

	iff, err := EncodeIFFILBM(st, data)
	if err != nil {
		t.Fatalf("failed to encode IFF ILBM: %v", err)
	}
	if string(iff[0:4]) != "FORM" || string(iff[8:12]) != "ILBM" {
		t.Fatalf("invalid IFF header: %q", string(iff[0:12]))
	}
}

func TestCalculateBitplaneScale(t *testing.T) {
	app := &App{
		Width:       160,
		Height:      50,
		PixelWidth:  1920,
		PixelHeight: 1200,
	}
	app.CellWidth = app.PixelWidth / app.Width
	app.CellHeight = app.PixelHeight / app.Height

	scale := app.CalculateBitplaneScale(320, 200)
	if scale != 5 {
		t.Fatalf("expected scale 5 for 320x200 in 1920x1200 window, got %d", scale)
	}

	scaleHires := app.CalculateBitplaneScale(640, 512)
	if scaleHires != 2 {
		t.Fatalf("expected scale 2 for 640x512 in 1920x1200 window, got %d", scaleHires)
	}
}

func TestWideBitmapClippingAndModulos(t *testing.T) {
	st := NewBitplaneState(0)
	// Buffer in RAM is 48 bytes wide = 384 pixels
	st.RowBytes = 48
	st.Height = 200

	// 1. Lowres visible window is 320 px (40 B)
	if st.VisibleWidth() != 320 {
		t.Fatalf("expected VisibleWidth 320, got %d", st.VisibleWidth())
	}
	if st.VisibleRowBytes() != 40 {
		t.Fatalf("expected VisibleRowBytes 40, got %d", st.VisibleRowBytes())
	}

	// 2. Hardware Modulo: cut = 48 - 40 = 8 bytes
	mod1, mod2 := st.HardwareModulos()
	if mod1 != 8 || mod2 != 8 {
		t.Fatalf("expected modulos 8, got %d, %d", mod1, mod2)
	}

	// 3. Interleaved mode with 3 planes: (3-1)*48 + 8 = 104 bytes
	st.Interleaved = true
	st.VisibleMask = 0x07 // 3 planes active
	mod1Int, mod2Int := st.HardwareModulos()
	if mod1Int != 104 || mod2Int != 104 {
		t.Fatalf("expected interleaved modulos 104, got %d, %d", mod1Int, mod2Int)
	}

	// 4. Verify DecodeImage cuts extra pixels to 320 width
	st.Interleaved = false
	data := make([]byte, 48*200)
	img := st.DecodeImage(data, 0, 0)
	if img.Bounds().Dx() != 320*st.Scale {
		t.Fatalf("expected decoded image width %d (clipped to 320), got %d", 320*st.Scale, img.Bounds().Dx())
	}
}

func TestInstantBitplaneTogglingWithoutPrerequisites(t *testing.T) {
	app := &App{}
	st := NewBitplaneState(0x1000)
	app.Modal = Modal{
		Kind:          ModalBitplane,
		Bitplane:      st,
		PixelProtocol: ProtocolHalfBlock,
	}

	// Initial state: only plane 1 active
	if st.ControlMask != 1 || st.VisibleMask != 1 {
		t.Fatalf("expected initial masks 1, got ctrl=%d, vis=%d", st.ControlMask, st.VisibleMask)
	}

	// Instantly toggle plane 3 in control without any prerequisites
	app.HandleKey("3")
	if (st.ControlMask & (1 << 2)) == 0 {
		t.Fatalf("expected plane 3 to be armed in ControlMask")
	}

	// Instantly toggle plane 4 in visible without any prerequisites
	app.HandleKey("$")
	if (st.VisibleMask & (1 << 3)) == 0 {
		t.Fatalf("expected plane 4 to be enabled in VisibleMask")
	}
	if st.EffectivePlanes() != 4 {
		t.Fatalf("expected EffectivePlanes 4, got %d", st.EffectivePlanes())
	}
}

func TestBPUHardwareRegistersAndNordicKeys(t *testing.T) {
	app := &App{}
	st := NewBitplaneState(0x1000)
	app.Modal = Modal{
		Kind:          ModalBitplane,
		Bitplane:      st,
		PixelProtocol: ProtocolHalfBlock,
	}

	// 1. Verify BPLCON0 register calculation for all depths 1..7
	expectedBPLCON0 := map[int]uint16{
		1: 0x1200,
		2: 0x2200,
		3: 0x3200,
		4: 0x4200,
		5: 0x5200,
		6: 0x6200,
		7: 0x7200,
	}
	for bpu, expected := range expectedBPLCON0 {
		st.SetBPU(bpu)
		if st.BPLCON0Hex() != expected {
			t.Fatalf("expected BPLCON0 $%04X for BPU %d, got $%04X", expected, bpu, st.BPLCON0Hex())
		}
	}

	// HAM6
	st.SetBPU(6)
	st.HAM = true
	if st.BPLCON0Hex() != 0x6A00 {
		t.Fatalf("expected BPLCON0 $6A00 for HAM6, got $%04X", st.BPLCON0Hex())
	}
	st.HAM = false

	// HIRES
	st.SetBPU(4)
	st.Hires = true
	if st.BPLCON0Hex() != 0xC200 {
		t.Fatalf("expected BPLCON0 $C200 for 4 planes HIRES, got $%04X", st.BPLCON0Hex())
	}
	st.Hires = false

	// 2. Test Scandinavian / Nordic direct depth keys:
	// Shift+1: ! -> BPU 1
	app.HandleKey("!")
	if st.BPU() != 1 {
		t.Fatalf("expected BPU 1 after '!', got %d", st.BPU())
	}
	// Shift+2: " -> BPU 2
	app.HandleKey("\"")
	if st.BPU() != 2 {
		t.Fatalf("expected BPU 2 after '\"', got %d", st.BPU())
	}
	// Shift+3: # -> BPU 3
	app.HandleKey("#")
	if st.BPU() != 3 {
		t.Fatalf("expected BPU 3 after '#', got %d", st.BPU())
	}
	// Shift+4: ¤ -> BPU 4
	app.HandleKey("¤")
	if st.BPU() != 4 {
		t.Fatalf("expected BPU 4 after '¤', got %d", st.BPU())
	}
	// Shift+5: % -> BPU 5
	app.HandleKey("%")
	if st.BPU() != 5 {
		t.Fatalf("expected BPU 5 after %q, got %d", "%", st.BPU())
	}
	// Shift+6: & -> BPU 6
	app.HandleKey("&")
	if st.BPU() != 6 {
		t.Fatalf("expected BPU 6 after '&', got %d", st.BPU())
	}
	// Shift+7: / -> BPU 7 (special case)
	app.HandleKey("/")
	if st.BPU() != 7 {
		t.Fatalf("expected BPU 7 after '/', got %d", st.BPU())
	}

	// 3. Test +/- depth stepping
	st.SetBPU(1)
	for i := 2; i <= 7; i++ {
		app.HandleKey("+")
		if st.BPU() != i {
			t.Fatalf("expected BPU %d after '+', got %d", i, st.BPU())
		}
	}
	// Cannot exceed 7
	app.HandleKey("+")
	if st.BPU() != 7 {
		t.Fatalf("expected BPU to clamp at 7, got %d", st.BPU())
	}

	for i := 6; i >= 1; i-- {
		app.HandleKey("-")
		if st.BPU() != i {
			t.Fatalf("expected BPU %d after '-', got %d", i, st.BPU())
		}
	}
	// Cannot go below 1
	app.HandleKey("-")
	if st.BPU() != 1 {
		t.Fatalf("expected BPU to clamp at 1, got %d", st.BPU())
	}

	// 4. Test Plane 7 Synced pointer arming via key "7"
	app.HandleKey("7")
	if (st.ControlMask & (1 << 6)) != 0 {
		t.Fatalf("expected plane 7 to be disarmed after '7'")
	}
	app.HandleKey("7")
	if (st.ControlMask & (1 << 6)) == 0 {
		t.Fatalf("expected plane 7 to be re-armed after second '7'")
	}
}

func TestAutoSnapPreservesSoloedPlaneAndInterleavedStep(t *testing.T) {
	app := &App{}
	st := NewBitplaneState(0x1000)
	st.RowBytes = 40
	st.Height = 200
	st.SetBPU(3)
	st.ControlMask = 0x07
	st.AutoSnapPlanes()

	// Solo plane 2 only (bit 1 = 0x02), step it to a custom offset 0x5000
	st.ControlMask = 0x02
	st.BPL[1] = 0x5000

	// Adjusting height should NOT snap plane 2 back to BPL[0] (0x1000)
	app.Modal = Modal{
		Kind:          ModalBitplane,
		Bitplane:      st,
		PixelProtocol: ProtocolHalfBlock,
	}
	app.HandleKey("S") // Height + 1
	if st.BPL[1] != 0x5000 {
		t.Fatalf("expected soloed BPL[1] to stay at 0x5000, got 0x%X", st.BPL[1])
	}

	// Arm planes 2 and 3 (0x06): plane 2 is anchor (0x5000), plane 3 snaps relative to plane 2
	st.ControlMask = 0x06
	st.AutoSnapPlanes()
	expectedBPL2 := uint32(0x5000 + 40*201)
	if st.BPL[2] != expectedBPL2 {
		t.Fatalf("expected BPL[2] to snap relative to BPL[1] (0x%X), got 0x%X", expectedBPL2, st.BPL[2])
	}

	// Interleaved up/down stepping uses RowStrideBytes (40 * 3 = 120)
	st.Interleaved = true
	st.ControlMask = 0x07
	st.BPL[0] = 0x1000
	st.AutoSnapPlanes()
	app.HandleKey("down")
	if st.BPL[0] != 0x1000+120 {
		t.Fatalf("expected down in 3-plane interleaved mode to advance by 120 bytes, got 0x%X", st.BPL[0])
	}

	// ByteSpan in interleaved mode: 201 rows * 120 bytes = 24120 bytes total from BPL[0]
	minOff, maxOff := st.ByteSpan()
	if maxOff-minOff != uint32(201*120) {
		t.Fatalf("expected interleaved ByteSpan length %d, got %d", 201*120, maxOff-minOff)
	}
}

func TestParseTextAreaPixelsResponse(t *testing.T) {
	// Standard XTWINOPS \x1b[4;<height>;<width>t response
	w, h, ok := ParseTextAreaPixelsResponse([]byte("\x1b[4;1080;1920t"))
	if !ok || w != 1920 || h != 1080 {
		t.Fatalf("expected 1920x1080 ok=true, got %dx%d ok=%v", w, h, ok)
	}

	// Response preceded by stray bytes
	w, h, ok = ParseTextAreaPixelsResponse([]byte("noise\x1b[4;1440;2560ttrailing"))
	if !ok || w != 2560 || h != 1440 {
		t.Fatalf("expected 2560x1440 ok=true, got %dx%d ok=%v", w, h, ok)
	}

	// Incomplete or invalid responses
	if _, _, ok := ParseTextAreaPixelsResponse([]byte("\x1b[4;1080;1920")); ok {
		t.Fatalf("expected incomplete response without 't' to return ok=false")
	}
	if _, _, ok := ParseTextAreaPixelsResponse([]byte("\x1b[4;0;1920t")); ok {
		t.Fatalf("expected zero height to return ok=false")
	}
}

func TestAddPlanesConsecutiveAfterSteppingPlane1(t *testing.T) {
	app := &App{}
	st := NewBitplaneState(0x0000)
	st.RowBytes = 40
	st.Height = 200
	app.Modal = Modal{
		Kind:          ModalBitplane,
		Bitplane:      st,
		PixelProtocol: ProtocolHalfBlock,
	}

	// 1. User steps Plane 1 (BPU=1, ControlMask=0x01) forward by 2 KB to find bitplane 1
	app.HandleKey("x") // +1024
	app.HandleKey("x") // +1024 -> BPL[0] = 0x0800
	if st.BPL[0] != 0x0800 {
		t.Fatalf("expected BPL[0] at 0x0800, got 0x%X", st.BPL[0])
	}

	// 2. User presses '+' to add Plane 2 and '+' again to add Plane 3
	planeSize := uint32(40 * 200) // 8000 bytes
	app.HandleKey("+")
	if st.BPU() != 2 || st.BPL[1] != 0x0800+planeSize {
		t.Fatalf("expected BPL[1] at 0x%X after '+', got 0x%X", 0x0800+planeSize, st.BPL[1])
	}
	app.HandleKey("+")
	if st.BPU() != 3 || st.BPL[2] != 0x0800+2*planeSize {
		t.Fatalf("expected BPL[2] at 0x%X after second '+', got 0x%X", 0x0800+2*planeSize, st.BPL[2])
	}

	// 3. Direct jump from BPU=1 to BPU=3 via '#' also snaps Planes 2 and 3 consecutively
	app.HandleKey("!") // Back to BPU=1
	app.HandleKey("x") // Step Plane 1 to 0x0C00
	app.HandleKey("#") // Jump to BPU=3
	if st.BPU() != 3 || st.ControlMask != 0x07 {
		t.Fatalf("expected BPU=3 ControlMask=0x07 after '#', got BPU=%d mask=0x%02X", st.BPU(), st.ControlMask)
	}
	if st.BPL[1] != 0x0C00+planeSize || st.BPL[2] != 0x0C00+2*planeSize {
		t.Fatalf("expected consecutive BPL[1]=0x%X BPL[2]=0x%X, got 0x%X 0x%X",
			0x0C00+planeSize, 0x0C00+2*planeSize, st.BPL[1], st.BPL[2])
	}
}

func TestApplyCustomSnapshot(t *testing.T) {
	var snap amiga.CustomSnapshot
	binary.BigEndian.PutUint16(snap[0x08E:0x090], 0x2C81) // DIWSTRT (vstart=44)
	binary.BigEndian.PutUint16(snap[0x090:0x092], 0x2CC1) // DIWSTOP (vstop=300 -> height 256)
	binary.BigEndian.PutUint16(snap[0x092:0x094], 0x0038) // DDFSTRT
	binary.BigEndian.PutUint16(snap[0x094:0x096], 0x00D0) // DDFSTOP (20 words -> 40 bytes/row)
	binary.BigEndian.PutUint32(snap[0x0E0:0x0E4], 0x00028000)
	binary.BigEndian.PutUint32(snap[0x0E4:0x0E8], 0x0002A800)
	binary.BigEndian.PutUint32(snap[0x0E8:0x0EC], 0x0002D000)
	binary.BigEndian.PutUint32(snap[0x0EC:0x0F0], 0x0002F800)
	binary.BigEndian.PutUint16(snap[0x100:0x102], 0x4200) // BPLCON0: 4 planes, COLOR
	binary.BigEndian.PutUint16(snap[0x108:0x10A], 0x0004) // BPL1MOD: 4
	binary.BigEndian.PutUint16(snap[0x10A:0x10C], 0x0004) // BPL2MOD: 4
	binary.BigEndian.PutUint16(snap[0x180:0x182], 0x0123) // COLOR00
	binary.BigEndian.PutUint16(snap[0x182:0x184], 0x0F80) // COLOR01

	st := NewBitplaneState(0)
	st.ApplyCustomSnapshot(&snap, 0, 0)

	if st.BPU() != 4 {
		t.Fatalf("expected BPU 4, got %d", st.BPU())
	}
	if st.BPL[0] != 0x28000 || st.BPL[3] != 0x2F800 {
		t.Fatalf("unexpected BPL pointers: %#x .. %#x", st.BPL[0], st.BPL[3])
	}
	if st.Modulo != 4 {
		t.Fatalf("expected Modulo=4, got %d", st.Modulo)
	}
	if st.PaletteMode != PaletteCustom || st.CustomPalette[1] != Convert0RGBToRGBA(0x0F80) {
		t.Fatalf("expected custom palette with COLOR01=$0F80, got mode=%d col1=%v", st.PaletteMode, st.CustomPalette[1])
	}
}
