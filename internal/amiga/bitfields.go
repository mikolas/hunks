package amiga

import (
	"fmt"
	"strings"
)

type bitFlag struct {
	mask uint16
	name string
}

var dmaconFlags = []bitFlag{
	{1 << 14, "BBUSY"},
	{1 << 13, "BZERO"},
	{1 << 10, "BLTPRI"},
	{1 << 9, "DMAEN"},
	{1 << 8, "BPLEN"},
	{1 << 7, "COPEN"},
	{1 << 6, "BLTEN"},
	{1 << 5, "SPREN"},
	{1 << 4, "DSKEN"},
	{1 << 3, "AUD3EN"},
	{1 << 2, "AUD2EN"},
	{1 << 1, "AUD1EN"},
	{1 << 0, "AUD0EN"},
}

var intFlags = []bitFlag{
	{1 << 14, "INTEN"},
	{1 << 13, "EXTER"},
	{1 << 12, "DSKSYN"},
	{1 << 11, "RBF"},
	{1 << 10, "AUD3"},
	{1 << 9, "AUD2"},
	{1 << 8, "AUD1"},
	{1 << 7, "AUD0"},
	{1 << 6, "BLIT"},
	{1 << 5, "VERTB"},
	{1 << 4, "COPER"},
	{1 << 3, "PORTS"},
	{1 << 2, "SOFT"},
	{1 << 1, "DSKBLK"},
	{1 << 0, "TBE"},
}

var adkconFlags = []bitFlag{
	{1 << 14, "PRECOMP1"},
	{1 << 13, "PRECOMP0"},
	{1 << 12, "MFMPREC"},
	{1 << 11, "UARTBRK"},
	{1 << 10, "WORDSYNC"},
	{1 << 9, "MSBSYNC"},
	{1 << 8, "FAST"},
	{1 << 7, "USE3PN"},
	{1 << 6, "USE2P3"},
	{1 << 5, "USE1P2"},
	{1 << 4, "USE0P1"},
	{1 << 3, "USE3VN"},
	{1 << 2, "USE2V3"},
	{1 << 1, "USE1V2"},
	{1 << 0, "USE0V1"},
}

func decodeSetClrFlags(val uint16, flags []bitFlag) string {
	if (val & 0x7FFF) == 0 {
		return ""
	}
	var parts []string
	if (val & 0x8000) != 0 {
		parts = append(parts, "SET")
	} else {
		parts = append(parts, "CLR")
	}
	for _, f := range flags {
		if (val & f.mask) != 0 {
			parts = append(parts, f.name)
		}
	}
	if len(parts) <= 1 {
		return ""
	}
	return strings.Join(parts, "|")
}

func blitterMintermDesc(lf uint8) string {
	switch lf {
	case 0x00:
		return "D=0"
	case 0xFF:
		return "D=1"
	case 0xF0:
		return "D=A"
	case 0x0F:
		return "D=~A"
	case 0xCC:
		return "D=B"
	case 0x33:
		return "D=~B"
	case 0xAA:
		return "D=C"
	case 0x55:
		return "D=~C"
	case 0xCA:
		return "D=AB+~AC"
	case 0xAC:
		return "D=AC+~AB"
	case 0xFC:
		return "D=A|B"
	case 0xFA:
		return "D=A|C"
	case 0xEE:
		return "D=B|C"
	case 0xFE:
		return "D=A|B|C"
	case 0xC0:
		return "D=A&B"
	case 0xA0:
		return "D=A&C"
	case 0x88:
		return "D=B&C"
	case 0x80:
		return "D=A&B&C"
	case 0x3C:
		return "D=A^B"
	case 0x5A:
		return "D=A^C"
	case 0x66:
		return "D=B^C"
	case 0x4A:
		return "D=AB+~AC (line/xor)"
	case 0xB8:
		return "D=AB+~BC"
	case 0xE2:
		return "D=BC+~BC"
	}
	return ""
}

// DecodeCustomRegWrite decodes a 16-bit immediate write to custom register offset (addr - 0xDFF000)
// into a concise bitfield summary for AutoComment, or returns "" if not applicable.
func DecodeCustomRegWrite(offset uint32, val uint16) string {
	switch offset {
	case 0x096: // DMACON
		return decodeSetClrFlags(val, dmaconFlags)
	case 0x09A, 0x09C: // INTENA, INTREQ
		return decodeSetClrFlags(val, intFlags)
	case 0x09E: // ADKCON
		return decodeSetClrFlags(val, adkconFlags)
	case 0x100: // BPLCON0
		bpu := int((val >> 12) & 0x7)
		if (val & (1 << 4)) != 0 {
			bpu |= 8
		}
		var parts []string
		if (val & 0x8000) != 0 {
			parts = append(parts, "HIRES")
		}
		switch {
		case bpu == 0:
			parts = append(parts, "0BPU")
		case bpu == 6 && (val&(1<<11)) == 0 && (val&(1<<10)) == 0:
			parts = append(parts, "6BPU (EHB 64c)")
		case bpu == 6 && (val&(1<<11)) != 0:
			parts = append(parts, "6BPU (HAM6)")
		case bpu == 8 && (val&(1<<11)) != 0:
			parts = append(parts, "8BPU (HAM8)")
		default:
			parts = append(parts, fmt.Sprintf("%dBPU (%dc)", bpu, 1<<bpu))
		}
		if (val & (1 << 11)) != 0 {
			parts = append(parts, "HAM")
		}
		if (val & (1 << 10)) != 0 {
			parts = append(parts, "DPF")
		}
		if (val & (1 << 9)) != 0 {
			parts = append(parts, "COLOR")
		}
		if (val & (1 << 8)) != 0 {
			parts = append(parts, "GAUD")
		}
		if (val & (1 << 2)) != 0 {
			parts = append(parts, "LACE")
		}
		return strings.Join(parts, "|")

	case 0x040: // BLTCON0
		ash := (val >> 12) & 0xF
		var parts []string
		if ash > 0 {
			parts = append(parts, fmt.Sprintf("ASH=%d", ash))
		}
		if (val & (1 << 11)) != 0 {
			parts = append(parts, "USEA")
		}
		if (val & (1 << 10)) != 0 {
			parts = append(parts, "USEB")
		}
		if (val & (1 << 9)) != 0 {
			parts = append(parts, "USEC")
		}
		if (val & (1 << 8)) != 0 {
			parts = append(parts, "USED")
		}
		lf := uint8(val & 0xFF)
		if desc := blitterMintermDesc(lf); desc != "" {
			parts = append(parts, fmt.Sprintf("LF=$%02X (%s)", lf, desc))
		} else {
			parts = append(parts, fmt.Sprintf("LF=$%02X", lf))
		}
		return strings.Join(parts, "|")

	case 0x042: // BLTCON1
		if val == 0 {
			return ""
		}
		bsh := (val >> 12) & 0xF
		var parts []string
		if bsh > 0 {
			parts = append(parts, fmt.Sprintf("BSH=%d", bsh))
		}
		if (val & 1) != 0 {
			parts = append(parts, "LINE")
			if (val & (1 << 6)) != 0 {
				parts = append(parts, "SIGN")
			}
			if (val & (1 << 1)) != 0 {
				parts = append(parts, "SING")
			}
		} else {
			if (val & (1 << 4)) != 0 {
				parts = append(parts, "EFE")
			}
			if (val & (1 << 3)) != 0 {
				parts = append(parts, "IFE")
			}
			if (val & (1 << 2)) != 0 {
				parts = append(parts, "FCI")
			}
			if (val & (1 << 1)) != 0 {
				parts = append(parts, "DESC")
			}
		}
		return strings.Join(parts, "|")

	case 0x058: // BLTSIZE
		h := int((val >> 6) & 0x3FF)
		if h == 0 {
			h = 1024
		}
		w := int(val & 0x3F)
		if w == 0 {
			w = 64
		}
		return fmt.Sprintf("%dw x %dh (%dx%d px)", w, h, w*16, h)
	}
	return ""
}

// DecodeCustomRegLongWrite decodes a 32-bit immediate write to two consecutive 16-bit custom registers
// at offset and offset+2 (e.g. move.l #$09F00000,_custom+BLTCON0).
func DecodeCustomRegLongWrite(offset uint32, val uint32) string {
	hi := uint16(val >> 16)
	lo := uint16(val & 0xFFFF)
	hiDesc := DecodeCustomRegWrite(offset, hi)
	loDesc := DecodeCustomRegWrite(offset+2, lo)
	if hiDesc == "" && loDesc == "" {
		return ""
	}
	hiName := customRegs[offset]
	if hiName == "" {
		hiName = fmt.Sprintf("CUSTOM_%03X", offset)
	}
	loName := customRegs[offset+2]
	if loName == "" {
		loName = fmt.Sprintf("CUSTOM_%03X", offset+2)
	}
	if hiDesc != "" && loDesc != "" {
		return fmt.Sprintf("%s: %s | %s: %s", hiName, hiDesc, loName, loDesc)
	}
	if hiDesc != "" {
		return fmt.Sprintf("%s: %s", hiName, hiDesc)
	}
	return fmt.Sprintf("%s: %s", loName, loDesc)
}
