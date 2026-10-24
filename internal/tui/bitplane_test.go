package tui

import (
	"image/color"
	"testing"
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
