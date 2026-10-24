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
