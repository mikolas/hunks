package tui

import (
	"image"
	"image/color"
	"strings"
	"testing"
)

func TestPixelProtocolDetectAndString(t *testing.T) {
	if ProtocolKitty.String() != "Kitty" {
		t.Fatalf("expected Kitty, got %s", ProtocolKitty.String())
	}
	if ProtocolHalfBlock.String() != "Half-Block" {
		t.Fatalf("expected Half-Block, got %s", ProtocolHalfBlock.String())
	}

	proto := DetectProtocol()
	t.Logf("Detected protocol: %s", proto.String())
}

func TestEncodeKittyPNGAndClear(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 16, 16))
	img.Set(0, 0, color.RGBA{R: 255, G: 0, B: 0, A: 255})
	img.Set(15, 15, color.RGBA{R: 0, G: 255, B: 0, A: 255})

	seq := EncodeKittyPNG(img, 2, 5)
	if !strings.HasPrefix(seq, "\x1b7\x1b_Ga=d,d=a,q=2\x1b\\\x1b[5;2H\x1b_Ga=T,f=100") {
		t.Fatalf("unexpected kitty prefix: %q", seq[:min(len(seq), 50)])
	}
	if !strings.HasSuffix(seq, "\x1b8") {
		t.Fatalf("expected cursor restore suffix \\x1b8, got: %q", seq[max(0, len(seq)-10):])
	}
	if !strings.Contains(seq, "q=2") {
		t.Fatalf("expected quiet mode q=2 in kitty sequence")
	}

	clr := ClearKittyPlacements()
	if clr != "\x1b_Ga=d,d=a,q=2\x1b\\" {
		t.Fatalf("unexpected clear sequence: %q", clr)
	}
}

func TestEncodeItermPNG(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 8, 8))
	img.Set(0, 0, color.RGBA{R: 255, G: 255, B: 255, A: 255})

	seq := EncodeItermPNG(img, 2, 5)
	if !strings.HasPrefix(seq, "\x1b7\x1b[5;2H\x1b]1337;File=inline=1") {
		t.Fatalf("unexpected iterm prefix: %q", seq[:min(len(seq), 40)])
	}
	if !strings.HasSuffix(seq, "\a\x1b8") {
		t.Fatalf("expected iterm suffix, got: %q", seq[max(0, len(seq)-10):])
	}
}

func TestEncodeSixel(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 12, 12))
	for y := 0; y < 12; y++ {
		for x := 0; x < 12; x++ {
			if (x+y)%2 == 0 {
				img.Set(x, y, color.RGBA{R: 255, G: 255, B: 255, A: 255})
			} else {
				img.Set(x, y, color.RGBA{R: 0, G: 0, B: 0, A: 255})
			}
		}
	}

	seq := EncodeSixel(img, 2, 5)
	if !strings.HasPrefix(seq, "\x1b7\x1b[5;2H\x1bPq") {
		t.Fatalf("unexpected sixel prefix: %q", seq[:min(len(seq), 30)])
	}
	if !strings.HasSuffix(seq, "\x1b\\\x1b8") {
		t.Fatalf("expected sixel suffix \\x1b\\\\\\x1b8, got %q", seq[max(0, len(seq)-10):])
	}
}
