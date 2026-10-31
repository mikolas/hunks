package amiga

import (
	"encoding/binary"
	"fmt"
)

// CustomSnapshotLen is the byte length of the Amiga custom chip register aperture ($DFF000..$DFF1FF).
const CustomSnapshotLen = 512

// CustomSnapshot wraps the 512-byte ($DFF000..$DFF1FF) custom chip register block
// returned by Amiberry's GDB stub (`save_custom` in `custom.cpp`).
type CustomSnapshot [CustomSnapshotLen]byte

// Word reads a big-endian 16-bit word at a register offset relative to $DFF000 ($000..$1FE).
func (s *CustomSnapshot) Word(offset uint16) uint16 {
	off := int(offset & 0x1FE)
	if off+2 > len(s) {
		return 0
	}
	return binary.BigEndian.Uint16(s[off : off+2])
}

// Long reads a big-endian 32-bit longword at a register offset relative to $DFF000 ($000..$1FC).
func (s *CustomSnapshot) Long(offset uint16) uint32 {
	off := int(offset & 0x1FE)
	if off+4 > len(s) {
		return 0
	}
	return binary.BigEndian.Uint32(s[off : off+4])
}

// DMACON returns the active DMA control bits (reading $096 DMACON, with fallback to $002 DMACONR).
func (s *CustomSnapshot) DMACON() uint16 {
	if v := s.Word(0x096); v != 0 {
		return v & 0x7FFF
	}
	return s.Word(0x002) & 0x7FFF
}

// INTENA returns the active interrupt enable mask (reading $09A INTENA, with fallback to $01C INTENAR).
func (s *CustomSnapshot) INTENA() uint16 {
	if v := s.Word(0x09A); v != 0 {
		return v & 0x7FFF
	}
	return s.Word(0x01C) & 0x7FFF
}

// INTREQ returns the active interrupt request bits (reading $09C INTREQ, with fallback to $01E INTREQR).
func (s *CustomSnapshot) INTREQ() uint16 {
	if v := s.Word(0x09C); v != 0 {
		return v & 0x7FFF
	}
	return s.Word(0x01E) & 0x7FFF
}

// ADKCON returns the audio/disk/UART control word (reading $09E ADKCON, with fallback to $010 ADKCONR).
func (s *CustomSnapshot) ADKCON() uint16 {
	if v := s.Word(0x09E); v != 0 {
		return v & 0x7FFF
	}
	return s.Word(0x010) & 0x7FFF
}

// COP1LC returns the 24-bit word-aligned Copper list 1 pointer ($080..$083).
func (s *CustomSnapshot) COP1LC() uint32 {
	return s.Long(0x080) & 0x00FFFFFE
}

// COP2LC returns the 24-bit word-aligned Copper list 2 pointer ($084..$087).
func (s *CustomSnapshot) COP2LC() uint32 {
	return s.Long(0x084) & 0x00FFFFFE
}

// DIWSTRT returns the display window start register ($08E).
func (s *CustomSnapshot) DIWSTRT() uint16 { return s.Word(0x08E) }

// DIWSTOP returns the display window stop register ($090).
func (s *CustomSnapshot) DIWSTOP() uint16 { return s.Word(0x090) }

// DDFSTRT returns the display data fetch start register ($092).
func (s *CustomSnapshot) DDFSTRT() uint16 { return s.Word(0x092) }

// DDFSTOP returns the display data fetch stop register ($094).
func (s *CustomSnapshot) DDFSTOP() uint16 { return s.Word(0x094) }

// BPLPT returns the 8 bitplane pointers ($0E0..$0FE), masked to 24-bit even addresses.
func (s *CustomSnapshot) BPLPT() [8]uint32 {
	var pts [8]uint32
	for i := range pts {
		pts[i] = s.Long(uint16(0x0E0+i*4)) & 0x00FFFFFE
	}
	return pts
}

// BPLCON0 returns the bitplane control register 0 ($100).
func (s *CustomSnapshot) BPLCON0() uint16 { return s.Word(0x100) }

// BPLCON1 returns the bitplane control register 1 ($102).
func (s *CustomSnapshot) BPLCON1() uint16 { return s.Word(0x102) }

// BPLCON2 returns the bitplane control register 2 ($104).
func (s *CustomSnapshot) BPLCON2() uint16 { return s.Word(0x104) }

// BPL1MOD returns the signed odd-bitplane modulo ($108).
func (s *CustomSnapshot) BPL1MOD() int16 { return int16(s.Word(0x108)) }

// BPL2MOD returns the signed even-bitplane modulo ($10A).
func (s *CustomSnapshot) BPL2MOD() int16 { return int16(s.Word(0x10A)) }

// ActivePlanes returns the number of enabled bitplanes (0..8) decoded from BPLCON0.
func (s *CustomSnapshot) ActivePlanes() int {
	con0 := s.BPLCON0()
	bpu := int((con0 >> 12) & 0x7)
	if bpu == 0 && (con0&0x0010) != 0 {
		return 8
	}
	return bpu
}

// Hires reports whether BPLCON0 bit 15 (HIRES) is set.
func (s *CustomSnapshot) Hires() bool {
	return (s.BPLCON0() & 0x8000) != 0
}

// HAM reports whether BPLCON0 bit 11 (HOMOD) is set.
func (s *CustomSnapshot) HAM() bool {
	return (s.BPLCON0() & 0x0800) != 0
}

// SPRPT returns the 8 hardware sprite pointers ($120..$13E), masked to 24-bit even addresses.
func (s *CustomSnapshot) SPRPT() [8]uint32 {
	var pts [8]uint32
	for i := range pts {
		pts[i] = s.Long(uint16(0x120+i*4)) & 0x00FFFFFE
	}
	return pts
}

// Palette12 returns the 32 12-bit ($0RGB) color registers ($180..$1BE).
func (s *CustomSnapshot) Palette12() [32]uint16 {
	var pal [32]uint16
	for i := range pal {
		pal[i] = s.Word(uint16(0x180+i*2)) & 0x0FFF
	}
	return pal
}

// SummaryMap produces a compact key-value map of the key active custom chip registers
// suitable for storing in `project.json` (`snapshot.custom_info`).
func (s *CustomSnapshot) SummaryMap() map[string]string {
	m := map[string]string{
		"DMACON":  fmt.Sprintf("0x%04X", s.DMACON()),
		"INTENA":  fmt.Sprintf("0x%04X", s.INTENA()),
		"INTREQ":  fmt.Sprintf("0x%04X", s.INTREQ()),
		"COP1LC":  fmt.Sprintf("0x%06X", s.COP1LC()),
		"COP2LC":  fmt.Sprintf("0x%06X", s.COP2LC()),
		"BPLCON0": fmt.Sprintf("0x%04X", s.BPLCON0()),
		"BPL1MOD": fmt.Sprintf("%d", s.BPL1MOD()),
		"BPL2MOD": fmt.Sprintf("%d", s.BPL2MOD()),
	}
	planes := s.ActivePlanes()
	bpl := s.BPLPT()
	for i := 0; i < min(planes, len(bpl)); i++ {
		if bpl[i] != 0 {
			m[fmt.Sprintf("BPL%dPT", i+1)] = fmt.Sprintf("0x%06X", bpl[i])
		}
	}
	return m
}
