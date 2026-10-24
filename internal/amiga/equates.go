package amiga

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

const (
	CustomBase uint32 = 0xDFF000
	CIAABase   uint32 = 0xBFE001
	CIABBase   uint32 = 0xBFD000
)

var m68kVectors = map[uint32]string{
	0x00: "Reset_ISP",
	0x04: "Reset_PC",
	0x08: "Bus_Error",
	0x0C: "Address_Error",
	0x10: "Illegal_Instruction",
	0x14: "Zero_Divide",
	0x18: "CHK_Instruction",
	0x1C: "TRAPV_Instruction",
	0x20: "Privilege_Violation",
	0x24: "Trace",
	0x28: "Line_1010_Emulator",
	0x2C: "Line_1111_Emulator",
	0x30: "Unassigned_Reserved",
	0x34: "Coprocessor_Protocol_Violation",
	0x38: "Format_Error",
	0x3C: "Uninitialized_Interrupt",
	0x60: "Spurious_Interrupt",
	0x64: "Level_1_Interrupt",
	0x68: "Level_2_Interrupt",
	0x6C: "Level_3_Interrupt",
	0x70: "Level_4_Interrupt",
	0x74: "Level_5_Interrupt",
	0x78: "Level_6_Interrupt",
	0x7C: "Level_7_Interrupt",
}

func GetM68kVectors() map[uint32]string {
	return m68kVectors
}

func GetTrapName(addr uint32) (string, bool) {
	if addr >= 0x80 && addr < 0xC0 && addr%4 == 0 {
		trapNum := (addr - 0x80) / 4
		return fmt.Sprintf("Trap_%d", trapNum), true
	}
	return "", false
}

var customRegs = map[uint32]string{
	0x000: "BLTDDAT", 0x002: "DMACONR", 0x004: "VPOSR",
	0x006: "VHPOSR", 0x008: "DSKDATR", 0x00A: "JOY0DAT",
	0x00C: "JOY1DAT", 0x00E: "CLXDAT", 0x010: "ADKCONR",
	0x012: "POT0DAT", 0x014: "POT1DAT", 0x016: "POTGOR",
	0x018: "SERDATR", 0x01A: "DSKBYTR", 0x01C: "INTENAR",
	0x01E: "INTREQR", 0x020: "DSKPTH", 0x022: "DSKPTL",
	0x024: "DSKLEN", 0x026: "DSKDAT", 0x028: "REFPTR",
	0x02A: "VPOSW", 0x02C: "VHPOSW", 0x02E: "COPCON",
	0x030: "SERDAT", 0x032: "SERPER", 0x034: "POTGO",
	0x036: "JOYTEST", 0x038: "STREQU", 0x03A: "STRVBL",
	0x03C: "STRHOR", 0x03E: "STRLONG", 0x040: "BLTCON0",
	0x042: "BLTCON1", 0x044: "BLTAFWM", 0x046: "BLTALWM",
	0x048: "BLTCPTH", 0x04A: "BLTCPTL", 0x04C: "BLTBPTH",
	0x04E: "BLTBPTL", 0x050: "BLTAPTH", 0x052: "BLTAPTL",
	0x054: "BLTDPTH", 0x056: "BLTDPTL", 0x058: "BLTSIZE",
	0x05A: "BLTCON0L", 0x05C: "BLTSIZV", 0x05E: "BLTSIZH",
	0x060: "BLTCMOD", 0x062: "BLTBMOD", 0x064: "BLTAMOD",
	0x066: "BLTDMOD", 0x070: "BLTCDAT", 0x072: "BLTBDAT",
	0x074: "BLTADAT", 0x078: "SPRHDAT", 0x07C: "DENISEID",
	0x07E: "DSKSYNC", 0x080: "COP1LCH", 0x082: "COP1LCL",
	0x084: "COP2LCH", 0x086: "COP2LCL", 0x088: "COPJMP1",
	0x08A: "COPJMP2", 0x08C: "COPINS", 0x08E: "DIWSTRT",
	0x090: "DIWSTOP", 0x092: "DDFSTRT", 0x094: "DDFSTOP",
	0x096: "DMACON", 0x098: "CLXCON", 0x09A: "INTENA",
	0x09C: "INTREQ", 0x09E: "ADKCON",
	// Audio
	0x0A0: "AUD0LCH", 0x0A2: "AUD0LCL", 0x0A4: "AUD0LEN",
	0x0A6: "AUD0PER", 0x0A8: "AUD0VOL", 0x0AA: "AUD0DAT",
	0x0B0: "AUD1LCH", 0x0B2: "AUD1LCL", 0x0B4: "AUD1LEN",
	0x0B6: "AUD1PER", 0x0B8: "AUD1VOL", 0x0BA: "AUD1DAT",
	0x0C0: "AUD2LCH", 0x0C2: "AUD2LCL", 0x0C4: "AUD2LEN",
	0x0C6: "AUD2PER", 0x0C8: "AUD2VOL", 0x0CA: "AUD2DAT",
	0x0D0: "AUD3LCH", 0x0D2: "AUD3LCL", 0x0D4: "AUD3LEN",
	0x0D6: "AUD3PER", 0x0D8: "AUD3VOL", 0x0DA: "AUD3DAT",
	// Bitplanes
	0x0E0: "BPL1PTH", 0x0E2: "BPL1PTL", 0x0E4: "BPL2PTH",
	0x0E6: "BPL2PTL", 0x0E8: "BPL3PTH", 0x0EA: "BPL3PTL",
	0x0EC: "BPL4PTH", 0x0EE: "BPL4PTL", 0x0F0: "BPL5PTH",
	0x0F2: "BPL5PTL", 0x0F4: "BPL6PTH", 0x0F6: "BPL6PTL",
	0x100: "BPLCON0", 0x102: "BPLCON1", 0x104: "BPLCON2",
	0x106: "BPLCON3", 0x108: "BPL1MOD", 0x10A: "BPL2MOD",
	0x110: "BPL1DAT", 0x112: "BPL2DAT", 0x114: "BPL3DAT",
	0x116: "BPL4DAT", 0x118: "BPL5DAT", 0x11A: "BPL6DAT",
	// Sprite pointers
	0x120: "SPR0PTH", 0x122: "SPR0PTL", 0x124: "SPR1PTH",
	0x126: "SPR1PTL", 0x128: "SPR2PTH", 0x12A: "SPR2PTL",
	0x12C: "SPR3PTH", 0x12E: "SPR3PTL", 0x130: "SPR4PTH",
	0x132: "SPR4PTL", 0x134: "SPR5PTH", 0x136: "SPR5PTL",
	0x138: "SPR6PTH", 0x13A: "SPR6PTL", 0x13C: "SPR7PTH",
	0x13E: "SPR7PTL",
	// Sprite control/data
	0x140: "SPR0POS", 0x142: "SPR0CTL", 0x144: "SPR0DATA",
	0x146: "SPR0DATB", 0x148: "SPR1POS", 0x14A: "SPR1CTL",
	0x14C: "SPR1DATA", 0x14E: "SPR1DATB", 0x150: "SPR2POS",
	0x152: "SPR2CTL", 0x154: "SPR2DATA", 0x156: "SPR2DATB",
	0x158: "SPR3POS", 0x15A: "SPR3CTL", 0x15C: "SPR3DATA",
	0x15E: "SPR3DATB", 0x160: "SPR4POS", 0x162: "SPR4CTL",
	0x164: "SPR4DATA", 0x166: "SPR4DATB", 0x168: "SPR5POS",
	0x16A: "SPR5CTL", 0x16C: "SPR5DATA", 0x16E: "SPR5DATB",
	0x170: "SPR6POS", 0x172: "SPR6CTL", 0x174: "SPR6DATA",
	0x176: "SPR6DATB", 0x178: "SPR7POS", 0x17A: "SPR7CTL",
	0x17C: "SPR7DATA", 0x17E: "SPR7DATB",
	// Color palette
	0x180: "COLOR00", 0x182: "COLOR01", 0x184: "COLOR02",
	0x186: "COLOR03", 0x188: "COLOR04", 0x18A: "COLOR05",
	0x18C: "COLOR06", 0x18E: "COLOR07", 0x190: "COLOR08",
	0x192: "COLOR09", 0x194: "COLOR10", 0x196: "COLOR11",
	0x198: "COLOR12", 0x19A: "COLOR13", 0x19C: "COLOR14",
	0x19E: "COLOR15", 0x1A0: "COLOR16", 0x1A2: "COLOR17",
	0x1A4: "COLOR18", 0x1A6: "COLOR19", 0x1A8: "COLOR20",
	0x1AA: "COLOR21", 0x1AC: "COLOR22", 0x1AE: "COLOR23",
	0x1B0: "COLOR24", 0x1B2: "COLOR25", 0x1B4: "COLOR26",
	0x1B6: "COLOR27", 0x1B8: "COLOR28", 0x1BA: "COLOR29",
	0x1BC: "COLOR30", 0x1BE: "COLOR31",
	// ECS beam / display window extensions
	0x1C0: "HTOTAL", 0x1C2: "HSSTOP", 0x1C4: "HBSTRT",
	0x1C6: "HBSTOP", 0x1C8: "VTOTAL", 0x1CA: "VSSTOP",
	0x1CC: "VBSTRT", 0x1CE: "VBSTOP", 0x1DC: "BEAMCON0",
	0x1DE: "HSSTRT", 0x1E0: "VSSTRT", 0x1E2: "HCENTER",
	0x1E4: "DIWHIGH",
}

var ciaARegs = map[uint32]string{
	0x0000: "CIAA_PRA", 0x0100: "CIAA_PRB",
	0x0200: "CIAA_DDRA", 0x0300: "CIAA_DDRB",
	0x0400: "CIAA_TALO", 0x0500: "CIAA_TAHI",
	0x0600: "CIAA_TBLO", 0x0700: "CIAA_TBHI",
	0x0800: "CIAA_TODLO", 0x0900: "CIAA_TODMID",
	0x0A00: "CIAA_TODHI", 0x0C00: "CIAA_SDR",
	0x0D00: "CIAA_ICR", 0x0E00: "CIAA_CRA",
	0x0F00: "CIAA_CRB",
}

var ciaBRegs = map[uint32]string{
	0x0000: "CIAB_PRA", 0x0100: "CIAB_PRB",
	0x0200: "CIAB_DDRA", 0x0300: "CIAB_DDRB",
	0x0400: "CIAB_TALO", 0x0500: "CIAB_TAHI",
	0x0600: "CIAB_TBLO", 0x0700: "CIAB_TBHI",
	0x0800: "CIAB_TODLO", 0x0900: "CIAB_TODMID",
	0x0A00: "CIAB_TODHI", 0x0C00: "CIAB_SDR",
	0x0D00: "CIAB_ICR", 0x0E00: "CIAB_CRA",
	0x0F00: "CIAB_CRB",
}

func GetCustomRegs() map[uint32]string { return customRegs }
func GetCIAARegs() map[uint32]string   { return ciaARegs }
func GetCIABRegs() map[uint32]string   { return ciaBRegs }

func GetAmigaHWLabel(addr uint32) (string, bool) {
	if addr >= 0xDFF000 && addr <= 0xDFF1FF {
		offset := addr - 0xDFF000
		if name, ok := customRegs[offset]; ok {
			return name, true
		}
		return fmt.Sprintf("CUSTOM_%03X", offset), true
	} else if addr >= 0xBFE001 && addr <= 0xBFEFFF && (addr&1) == 1 {
		offset := addr - 0xBFE001
		if name, ok := ciaARegs[offset]; ok {
			return name, true
		}
		return fmt.Sprintf("CIAA_%04X", offset), true
	} else if addr >= 0xBFD000 && addr <= 0xBFDFFF && (addr&1) == 0 {
		offset := addr - 0xBFD000
		if name, ok := ciaBRegs[offset]; ok {
			return name, true
		}
		return fmt.Sprintf("CIAB_%04X", offset), true
	}
	return "", false
}

// GetAmigaHWOperand returns the base-qualified absolute operand form of a
// hardware register for emission, e.g. `$DFF096` -> `_custom+DMACON`.
func GetAmigaHWOperand(addr uint32) (string, bool) {
	name, ok := GetAmigaHWLabel(addr)
	if !ok {
		return "", false
	}
	base := "_custom"
	if strings.HasPrefix(name, "CIAA_") {
		base = "_ciaa"
	} else if strings.HasPrefix(name, "CIAB_") {
		base = "_ciab"
	} else {
		for _, n := range ciaARegs {
			if n == name {
				base = "_ciaa"
				break
			}
		}
		if base == "_custom" {
			for _, n := range ciaBRegs {
				if n == name {
					base = "_ciab"
					break
				}
			}
		}
	}
	return fmt.Sprintf("%s+%s", base, name), true
}

// GetAmigaHWLabelSub resolves sub-register byte offsets to `<REG>+<n>` for
// human-readable comment annotation only.
func GetAmigaHWLabelSub(addr uint32) (string, bool) {
	name, ok := GetAmigaHWLabel(addr)
	if !ok {
		return "", false
	}
	if !strings.HasPrefix(name, "CUSTOM_") {
		return name, true
	}
	offset := addr - 0xDFF000
	var found bool
	var maxBase uint32
	for o := range customRegs {
		if o < offset && (!found || o > maxBase) {
			maxBase = o
			found = true
		}
	}
	if found {
		return fmt.Sprintf("%s+%d", customRegs[maxBase], offset-maxBase), true
	}
	return fmt.Sprintf("CUSTOM_%03X", offset), true
}

// GetAllEquates returns all named hardware equates for `equates.i` (offset-valued
// registers plus the three `_custom`/`_ciaa`/`_ciab` base equates).
func GetAllEquates() map[string]uint32 {
	equates := make(map[string]uint32, len(customRegs)+len(ciaARegs)+len(ciaBRegs)+3)
	equates["_custom"] = CustomBase
	equates["_ciaa"] = CIAABase
	equates["_ciab"] = CIABBase
	for offset, name := range customRegs {
		equates[name] = offset
	}
	for offset, name := range ciaARegs {
		equates[name] = offset
	}
	for offset, name := range ciaBRegs {
		equates[name] = offset
	}
	return equates
}

// ParseHWLabelAddr resolves a custom/CIA register name or synthetic label to its
// absolute address.
func ParseHWLabelAddr(label string) (uint32, bool) {
	switch label {
	case "_custom":
		return CustomBase, true
	case "_ciaa":
		return CIAABase, true
	case "_ciab":
		return CIABBase, true
	}
	if hexStr, ok := strings.CutPrefix(label, "CUSTOM_"); ok {
		if off, err := strconv.ParseUint(hexStr, 16, 32); err == nil {
			return CustomBase + uint32(off), true
		}
		return 0, false
	}
	if hexStr, ok := strings.CutPrefix(label, "CIAA_"); ok {
		if off, err := strconv.ParseUint(hexStr, 16, 32); err == nil {
			return CIAABase + uint32(off), true
		}
		return 0, false
	}
	if hexStr, ok := strings.CutPrefix(label, "CIAB_"); ok {
		if off, err := strconv.ParseUint(hexStr, 16, 32); err == nil {
			return CIABBase + uint32(off), true
		}
		return 0, false
	}
	for off, n := range customRegs {
		if n == label {
			return CustomBase + off, true
		}
	}
	for off, n := range ciaARegs {
		if n == label {
			return CIAABase + off, true
		}
	}
	for off, n := range ciaBRegs {
		if n == label {
			return CIABBase + off, true
		}
	}
	return 0, false
}

// HWRefProvider is implemented by db.Controller to supply operand strings
// containing hardware references without coupling internal/amiga to internal/db.
type HWRefProvider interface {
	OpStrsWithHWRefs() []string
}

func CollectUsedHWEquates(provider HWRefProvider, equates map[string]uint32) {
	for _, opStr := range provider.OpStrsWithHWRefs() {
		tokens := strings.FieldsFunc(opStr, func(r rune) bool {
			return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_'
		})
		for _, token := range tokens {
			if hexStr, ok := strings.CutPrefix(token, "CUSTOM_"); ok {
				if off, err := strconv.ParseUint(hexStr, 16, 32); err == nil {
					equates[token] = uint32(off)
				}
			} else if hexStr, ok := strings.CutPrefix(token, "CIAA_"); ok {
				if off, err := strconv.ParseUint(hexStr, 16, 32); err == nil {
					equates[token] = uint32(off)
				}
			} else if hexStr, ok := strings.CutPrefix(token, "CIAB_"); ok {
				if off, err := strconv.ParseUint(hexStr, 16, 32); err == nil {
					equates[token] = uint32(off)
				}
			}
		}
	}
}
