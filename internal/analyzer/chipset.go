package analyzer

import "encoding/binary"

// --- Paula INTENA / INTREQ bit definitions ----------------------------------
const (
	IntTBE     uint16 = 1 << 0  // Level 1 ($64): serial TX buffer empty
	IntDSKBLK  uint16 = 1 << 1  // Level 1 ($64): disk DMA block finished
	IntSOFT    uint16 = 1 << 2  // Level 1 ($64): software interrupt
	IntPORTS   uint16 = 1 << 3  // Level 2 ($68): CIA-A / ports
	IntCOPER   uint16 = 1 << 4  // Level 3 ($6C): Copper
	IntVERTB   uint16 = 1 << 5  // Level 3 ($6C): vertical blank start
	IntBLIT    uint16 = 1 << 6  // Level 3 ($6C): blitter finished
	IntAUD0    uint16 = 1 << 7  // Level 4 ($70): audio channel 0
	IntAUD1    uint16 = 1 << 8  // Level 4 ($70): audio channel 1
	IntAUD2    uint16 = 1 << 9  // Level 4 ($70): audio channel 2
	IntAUD3    uint16 = 1 << 10 // Level 4 ($70): audio channel 3
	IntRBF     uint16 = 1 << 11 // Level 5 ($74): serial RX buffer full
	IntDSKSYNC uint16 = 1 << 12 // Level 5 ($74): disk sync word matched
	IntEXTER   uint16 = 1 << 13 // Level 6 ($78): CIA-B / external
	IntMASTER  uint16 = 1 << 14 // Master enable (INTENA) / INT14 (INTREQ)
)

var levelMasks = [6]struct {
	level uint8
	mask  uint16
}{
	{6, IntMASTER | IntEXTER},
	{5, IntDSKSYNC | IntRBF},
	{4, IntAUD3 | IntAUD2 | IntAUD1 | IntAUD0},
	{3, IntBLIT | IntVERTB | IntCOPER},
	{2, IntPORTS},
	{1, IntSOFT | IntDSKBLK | IntTBE},
}

// --- DMACON / DMACONR bit definitions ---------------------------------------
const (
	DmaCOPPER    uint16 = 1 << 7
	DmaMASTER    uint16 = 1 << 9
	dmaconrBZERO uint16 = 1 << 13
	dmaconrBBUSY uint16 = 1 << 14
)

// --- BLTCON0 / BLTCON1 bit definitions --------------------------------------
const (
	bltcon0USEA     uint16 = 1 << 11
	bltcon0USEB     uint16 = 1 << 10
	bltcon0USEC     uint16 = 1 << 9
	bltcon0USED     uint16 = 1 << 8
	bltcon0LFMASK   uint16 = 0x00FF
	bltcon0ASHSHIFT uint16 = 12
	bltcon1LINE     uint16 = 1 << 0
	bltcon1DESC     uint16 = 1 << 1
	bltcon1FCI      uint16 = 1 << 2
	bltcon1IFE      uint16 = 1 << 3
	bltcon1EFE      uint16 = 1 << 4
)

// --- Custom-chip register offsets ($DFF000 base) ----------------------------
const (
	offDMACONR  uint16 = 0x002
	offVPOSR    uint16 = 0x004
	offVHPOSR   uint16 = 0x006
	offADKCONR  uint16 = 0x010
	offPOTGOR   uint16 = 0x016
	offSERDATR  uint16 = 0x018
	offDSKBYTR  uint16 = 0x01A
	offINTENAR  uint16 = 0x01C
	offINTREQR  uint16 = 0x01E
	offDSKPTH   uint16 = 0x020
	offDSKPTL   uint16 = 0x022
	offDSKLEN   uint16 = 0x024
	offVPOSW    uint16 = 0x02A
	offCOPCON   uint16 = 0x02E
	offSERDAT   uint16 = 0x030
	offSERPER   uint16 = 0x032
	offBLTCON0  uint16 = 0x040
	offBLTCON1  uint16 = 0x042
	offBLTAFWM  uint16 = 0x044
	offBLTALWM  uint16 = 0x046
	offBLTCPTH  uint16 = 0x048
	offBLTCPTL  uint16 = 0x04A
	offBLTBPTH  uint16 = 0x04C
	offBLTBPTL  uint16 = 0x04E
	offBLTAPTH  uint16 = 0x050
	offBLTAPTL  uint16 = 0x052
	offBLTDPTH  uint16 = 0x054
	offBLTDPTL  uint16 = 0x056
	offBLTSIZE  uint16 = 0x058
	offBLTCMOD  uint16 = 0x060
	offBLTBMOD  uint16 = 0x062
	offBLTAMOD  uint16 = 0x064
	offBLTDMOD  uint16 = 0x066
	offBLTCDAT  uint16 = 0x070
	offBLTBDAT  uint16 = 0x072
	offBLTADAT  uint16 = 0x074
	offDENISEID uint16 = 0x07C
	offDSKSYNC  uint16 = 0x07E
	offCOP1LCH  uint16 = 0x080
	offCOP1LCL  uint16 = 0x082
	offCOP2LCH  uint16 = 0x084
	offCOP2LCL  uint16 = 0x086
	offCOPJMP1  uint16 = 0x088
	offCOPJMP2  uint16 = 0x08A
	offDMACON   uint16 = 0x096
	offINTENA   uint16 = 0x09A
	offINTREQ   uint16 = 0x09C
	offADKCON   uint16 = 0x09E
)

const (
	copperMaxSteps      = 1024
	HPosPerLine    uint32 = 227
	VPosPerFrame   uint32 = 313
	CyclesPerLine  uint32 = HPosPerLine * 2            // 454 CPU cycles
	CyclesPerFrame uint32 = VPosPerFrame * CyclesPerLine // 142,102 CPU cycles

	dsksyncPeriodCycles uint32 = 12800
)

// --- 8520 CIA bit definitions -----------------------------------------------
const (
	IcrTA   uint8 = 1 << 0
	IcrTB   uint8 = 1 << 1
	IcrALRM uint8 = 1 << 2
	IcrSP   uint8 = 1 << 3
	IcrFLG  uint8 = 1 << 4

	CraSTART   uint8 = 1 << 0
	CraRUNMODE uint8 = 1 << 3
	CraLOAD    uint8 = 1 << 4
	CraINMODE  uint8 = 1 << 5
	CraSPMODE  uint8 = 1 << 6

	CrbSTART      uint8 = 1 << 0
	CrbRUNMODE    uint8 = 1 << 3
	CrbLOAD       uint8 = 1 << 4
	CrbINMODEMASK uint8 = 0x60
	CrbALARM      uint8 = 1 << 7
)

func applySetClr(cur, val uint16) uint16 {
	bits := val & 0x7FFF
	if val&0x8000 != 0 {
		return cur | bits
	}
	return cur &^ bits
}

func csReadBeU32(mem []byte, addr uint32) uint32 {
	a := int(addr & 0x00FFFFFF)
	if a+4 > len(mem) {
		return 0
	}
	return binary.BigEndian.Uint32(mem[a : a+4])
}

func csReadBeU16(mem []byte, addr uint32) uint16 {
	a := int(addr & 0x00FFFFFE)
	if a+2 > len(mem) {
		return 0
	}
	return binary.BigEndian.Uint16(mem[a : a+2])
}

func csWriteBeU16(mem []byte, addr uint32, val uint16) {
	a := int(addr & 0x00FFFFFE)
	if a+2 <= len(mem) {
		binary.BigEndian.PutUint16(mem[a:a+2], val)
	}
}

// evalMinterm evaluates the 8-bit Blitter logic function `lf` (`BLTCON0` bits 0..7)
// bitwise across 16-bit channel words `a`, `b`, and `c`.
func evalMinterm(lf uint8, a, b, c uint16) uint16 {
	var d uint16
	if lf&0x01 != 0 {
		d |= ^a & ^b & ^c
	}
	if lf&0x02 != 0 {
		d |= ^a & ^b & c
	}
	if lf&0x04 != 0 {
		d |= ^a & b & ^c
	}
	if lf&0x08 != 0 {
		d |= ^a & b & c
	}
	if lf&0x10 != 0 {
		d |= a & ^b & ^c
	}
	if lf&0x20 != 0 {
		d |= a & ^b & c
	}
	if lf&0x40 != 0 {
		d |= a & b & ^c
	}
	if lf&0x80 != 0 {
		d |= a & b & c
	}
	return d
}

// Agnus models the beam counter and DMA/Copper address state.
type Agnus struct {
	VPos          uint16
	HPos          uint16
	CckRem        uint32
	LOF           bool
	DMACON        uint16
	COPCON        uint16
	COP1LC        uint32
	COP2LC        uint32
	COP1LCWritten bool
	COP2LCWritten bool
}

// AudCh models per-channel Paula audio timer state (AUD0..AUD3).
type AudCh struct {
	LC        uint32
	Len       uint16
	Per       uint16
	Vol       uint16
	DMAActive bool
	RemCycles uint32
}

// Paula models the interrupt controller, disk DMA/sync timers, serial port, and audio timers.
type Paula struct {
	INTENA      uint16
	INTREQ      uint16
	ADKCON      uint16
	SERPER      uint16
	SerTXCycles uint32
	SerRXCycles uint32
	DSKPT       uint32
	DSKLEN      uint16
	DSKLENArmed bool
	DskCycles   uint32
	DSKSYNC     uint16
	SyncCycles  uint32
	Aud         [4]AudCh
}

// CIA models a minimal 8520 CIA state machine.
type CIA struct {
	PRA         uint8
	PRB         uint8
	DDRA        uint8
	DDRB        uint8
	TACount     uint16
	TALatch     uint16
	TBCount     uint16
	TBLatch     uint16
	CRA         uint8
	CRB         uint8
	TOD         uint32
	TODLatch    uint32
	TODAlarm    uint32
	TODLatched  bool
	TODStopped  bool
	TODMatching bool
	SDR         uint8
	SDRRemTA    uint8
	ICRData     uint8
	ICRMask     uint8
}

func newCIA() CIA {
	return CIA{
		PRA:      0xFF,
		PRB:      0xFF,
		TACount:  0xFFFF,
		TALatch:  0xFFFF,
		TBCount:  0xFFFF,
		TBLatch:  0xFFFF,
		TODAlarm: 0x00FFFFFF,
	}
}

func (c *CIA) IRQAsserted() bool {
	return (c.ICRData & c.ICRMask & 0x1F) != 0
}

func (c *CIA) checkTODAlarm() {
	matching := c.TOD == c.TODAlarm
	if matching && !c.TODMatching {
		c.ICRData |= IcrALRM
	}
	c.TODMatching = matching
}

func (c *CIA) readReg(reg uint8, isCIAB bool, headCyl uint8) uint8 {
	switch reg & 0x0F {
	case 0x0:
		if isCIAB {
			return c.PRA & c.DDRA
		}
		var tk0 uint8
		if headCyl != 0 {
			tk0 = 0x10
		}
		inputs := uint8(0xC0) | tk0 | 0x0C
		return (c.PRA & c.DDRA) | (inputs &^ c.DDRA)
	case 0x1:
		return (c.PRB & c.DDRB) | ^c.DDRB
	case 0x2:
		return c.DDRA
	case 0x3:
		return c.DDRB
	case 0x4:
		return uint8(c.TACount & 0xFF)
	case 0x5:
		return uint8(c.TACount >> 8)
	case 0x6:
		return uint8(c.TBCount & 0xFF)
	case 0x7:
		return uint8(c.TBCount >> 8)
	case 0x8:
		v := c.TOD
		if c.TODLatched {
			v = c.TODLatch
		}
		c.TODLatched = false
		return uint8(v & 0xFF)
	case 0x9:
		v := c.TOD
		if c.TODLatched {
			v = c.TODLatch
		}
		return uint8((v >> 8) & 0xFF)
	case 0xA:
		c.TODLatch = c.TOD
		c.TODLatched = true
		return uint8((c.TODLatch >> 16) & 0xFF)
	case 0xC:
		return c.SDR
	case 0xD:
		irq := c.IRQAsserted()
		out := c.ICRData & 0x1F
		if irq {
			out |= 0x80
		}
		c.ICRData = 0
		return out
	case 0xE:
		return c.CRA
	case 0xF:
		return c.CRB
	default:
		return 0
	}
}

func (c *CIA) writeReg(reg, val uint8, isCIAB bool, headCyl *uint8) {
	switch reg & 0x0F {
	case 0x0:
		c.PRA = val
	case 0x1:
		if isCIAB {
			prevStep := c.PRB & 0x01
			newStep := val & 0x01
			driveSelected := (val & 0x78) != 0x78
			if driveSelected && prevStep != 0 && newStep == 0 {
				if val&0x02 == 0 {
					if *headCyl < 83 {
						*headCyl++
					}
				} else if *headCyl > 0 {
					*headCyl--
				}
			}
		}
		c.PRB = val
	case 0x2:
		c.DDRA = val
	case 0x3:
		c.DDRB = val
	case 0x4:
		c.TALatch = (c.TALatch & 0xFF00) | uint16(val)
	case 0x5:
		c.TALatch = (c.TALatch & 0x00FF) | (uint16(val) << 8)
		if c.CRA&CraSTART == 0 || c.CRA&CraRUNMODE != 0 {
			c.TACount = c.TALatch
		}
		if c.CRA&CraRUNMODE != 0 {
			c.CRA |= CraSTART
		}
	case 0x6:
		c.TBLatch = (c.TBLatch & 0xFF00) | uint16(val)
	case 0x7:
		c.TBLatch = (c.TBLatch & 0x00FF) | (uint16(val) << 8)
		if c.CRB&CrbSTART == 0 || c.CRB&CrbRUNMODE != 0 {
			c.TBCount = c.TBLatch
		}
		if c.CRB&CrbRUNMODE != 0 {
			c.CRB |= CrbSTART
		}
	case 0x8:
		if c.CRB&CrbALARM != 0 {
			c.TODAlarm = (c.TODAlarm & 0x00FFFF00) | uint32(val)
		} else {
			c.TOD = (c.TOD & 0x00FFFF00) | uint32(val)
			c.TODStopped = false
		}
		c.checkTODAlarm()
	case 0x9:
		if c.CRB&CrbALARM != 0 {
			c.TODAlarm = (c.TODAlarm & 0x00FF00FF) | (uint32(val) << 8)
		} else {
			c.TOD = (c.TOD & 0x00FF00FF) | (uint32(val) << 8)
		}
		c.checkTODAlarm()
	case 0xA:
		if c.CRB&CrbALARM != 0 {
			c.TODAlarm = (c.TODAlarm & 0x0000FFFF) | (uint32(val) << 16)
		} else {
			c.TOD = (c.TOD & 0x0000FFFF) | (uint32(val) << 16)
			c.TODStopped = true
		}
		c.checkTODAlarm()
	case 0xC:
		c.SDR = val
		if c.CRA&CraSPMODE != 0 {
			c.SDRRemTA = 16
		}
	case 0xD:
		if val&0x80 != 0 {
			c.ICRMask |= val & 0x1F
		} else {
			c.ICRMask &^= val & 0x1F
		}
	case 0xE:
		if val&CraLOAD != 0 {
			c.TACount = c.TALatch
		}
		c.CRA = val &^ CraLOAD
	case 0xF:
		if val&CrbLOAD != 0 {
			c.TBCount = c.TBLatch
		}
		c.CRB = val &^ CrbLOAD
	}
}

func (c *CIA) tick(eClocks, todTicks uint32, indexPulse bool) {
	var taUnderflows uint32
	if (c.CRA&CraSTART != 0) && (c.CRA&CraINMODE == 0) && eClocks > 0 {
		rem := eClocks
		for rem > 0 && (c.CRA&CraSTART != 0) {
			step := max(uint32(c.TACount), 1)
			if rem >= step {
				rem -= step
				taUnderflows++
				c.ICRData |= IcrTA
				c.TACount = c.TALatch
				if c.CRA&CraRUNMODE != 0 {
					c.CRA &^= CraSTART
					break
				}
				if c.TALatch == 0 {
					break
				}
			} else {
				c.TACount -= uint16(rem)
				rem = 0
			}
		}
	}

	if c.SDRRemTA > 0 && taUnderflows > 0 {
		if taUnderflows >= uint32(c.SDRRemTA) {
			c.SDRRemTA = 0
			c.ICRData |= IcrSP
		} else {
			c.SDRRemTA -= uint8(taUnderflows)
		}
	}

	tbInmode := c.CRB & CrbINMODEMASK
	var tbPulses uint32
	if tbInmode == 0x00 {
		tbPulses = eClocks
	} else if tbInmode >= 0x40 {
		tbPulses = taUnderflows
	}
	if (c.CRB&CrbSTART != 0) && tbPulses > 0 {
		rem := tbPulses
		for rem > 0 && (c.CRB&CrbSTART != 0) {
			step := max(uint32(c.TBCount), 1)
			if rem >= step {
				rem -= step
				c.ICRData |= IcrTB
				c.TBCount = c.TBLatch
				if c.CRB&CrbRUNMODE != 0 {
					c.CRB &^= CrbSTART
					break
				}
				if c.TBLatch == 0 {
					break
				}
			} else {
				c.TBCount -= uint16(rem)
				rem = 0
			}
		}
	}

	if !c.TODStopped && todTicks > 0 {
		for range todTicks {
			c.TOD = (c.TOD + 1) & 0x00FFFFFF
			c.checkTODAlarm()
		}
	}

	if indexPulse && (c.PRB&0x78) != 0x78 {
		c.ICRData |= IcrFLG
	}
}

// Blitter models synchronous Blitter register and execution state ($DFF040..=$DFF074).
type Blitter struct {
	CON0 uint16
	CON1 uint16
	AFWM uint16
	ALWM uint16
	APT  uint32
	BPT  uint32
	CPT  uint32
	DPT  uint32
	AMOD int16
	BMOD int16
	CMOD int16
	DMOD int16
	ADAT uint16
	BDAT uint16
	CDAT uint16
	Zero bool
}

func newBlitter() Blitter {
	return Blitter{
		AFWM: 0xFFFF,
		ALWM: 0xFFFF,
		Zero: true,
	}
}

// executeNormal runs a synchronous Blitter block operation of height `h` lines by `w`
// words per line when `BLTSIZE` is written in non-line mode (`BLTCON1` bit 0 == 0).
// It models ascending and descending barrel shifts (`ASH`/`BSH`), first/last word masks
// (`BLTAFWM`/`BLTALWM`), 256-minterm combinational logic (`evalMinterm`), inclusive and
// exclusive area fill (`IFE`/`EFE` with fill carry-in `FCI`), signed even-aligned channel
// modulos (`AMOD`..`DMOD`), and the `BZERO` status flag.
func (b *Blitter) executeNormal(h, w uint32, mem []byte) {
	ash := uint32((b.CON0 >> bltcon0ASHSHIFT) & 0xF)
	bsh := uint32((b.CON1 >> bltcon0ASHSHIFT) & 0xF)
	useA := (b.CON0 & bltcon0USEA) != 0
	useB := (b.CON0 & bltcon0USEB) != 0
	useC := (b.CON0 & bltcon0USEC) != 0
	useD := (b.CON0 & bltcon0USED) != 0
	lf := uint8(b.CON0 & bltcon0LFMASK)

	desc := (b.CON1 & bltcon1DESC) != 0
	efe := (b.CON1 & bltcon1EFE) != 0
	ife := (b.CON1 & bltcon1IFE) != 0
	fci := (b.CON1 & bltcon1FCI) != 0

	step := int32(2)
	if desc {
		step = -2
	}
	amod := int32(b.AMOD &^ 1)
	bmod := int32(b.BMOD &^ 1)
	cmod := int32(b.CMOD &^ 1)
	dmod := int32(b.DMOD &^ 1)

	var aPrev, bPrev uint16
	allZero := true

	for range h {
		fillCarry := fci
		for x := range w {
			if useA {
				b.ADAT = csReadBeU16(mem, b.APT)
				b.APT = uint32(int32(b.APT)+step) & 0x001FFFFE
			}
			aMasked := b.ADAT
			if x == 0 {
				aMasked &= b.AFWM
			}
			if x+1 == w {
				aMasked &= b.ALWM
			}
			var aShifted uint16
			if !desc {
				aShifted = uint16(((uint32(aPrev) << 16) | uint32(aMasked)) >> ash)
			} else if ash == 0 {
				aShifted = aMasked
			} else {
				aShifted = (aMasked << ash) | (aPrev >> (16 - ash))
			}
			aPrev = aMasked

			if useB {
				b.BDAT = csReadBeU16(mem, b.BPT)
				b.BPT = uint32(int32(b.BPT)+step) & 0x001FFFFE
			}
			bVal := b.BDAT
			var bShifted uint16
			if !desc {
				bShifted = uint16(((uint32(bPrev) << 16) | uint32(bVal)) >> bsh)
			} else if bsh == 0 {
				bShifted = bVal
			} else {
				bShifted = (bVal << bsh) | (bPrev >> (16 - bsh))
			}
			bPrev = bVal

			if useC {
				b.CDAT = csReadBeU16(mem, b.CPT)
				b.CPT = uint32(int32(b.CPT)+step) & 0x001FFFFE
			}

			dWord := evalMinterm(lf, aShifted, bShifted, b.CDAT)

			if ife || efe {
				var filled uint16
				for bit := range 16 {
					srcBit := ((dWord >> bit) & 1) != 0
					var outBit bool
					if ife {
						outBit = srcBit || fillCarry
					} else {
						outBit = srcBit != fillCarry
					}
					if outBit {
						filled |= 1 << bit
					}
					if srcBit {
						fillCarry = !fillCarry
					}
				}
				dWord = filled
			}

			if dWord != 0 {
				allZero = false
			}

			if useD {
				csWriteBeU16(mem, b.DPT, dWord)
				b.DPT = uint32(int32(b.DPT)+step) & 0x001FFFFE
			}
		}

		rowAdj := func(pt uint32, m int32) uint32 {
			delta := m
			if desc {
				delta = -m
			}
			return uint32(int32(pt)+delta) & 0x001FFFFE
		}
		if useA {
			b.APT = rowAdj(b.APT, amod)
		}
		if useB {
			b.BPT = rowAdj(b.BPT, bmod)
		}
		if useC {
			b.CPT = rowAdj(b.CPT, cmod)
		}
		if useD {
			b.DPT = rowAdj(b.DPT, dmod)
		}
	}

	b.Zero = allZero
}

// Chipset models the minimal custom-chip and CIA state machine owned by TraceBus.
type Chipset struct {
	Agnus      Agnus
	Paula      Paula
	CIAA       CIA
	CIAB       CIA
	Blitter    Blitter
	ERem       uint32
	HeadCyl    uint8
	BlitCycles uint32
	inCopper   bool
}

func NewChipset() *Chipset {
	return &Chipset{
		Agnus:   Agnus{LOF: true},
		CIAA:    newCIA(),
		CIAB:    newCIA(),
		Blitter: newBlitter(),
	}
}

// RunCopperList walks a Copper instruction list in Chip RAM starting at `startPC`
// (bounded to `copperMaxSteps` instructions to prevent infinite `COPJMP` loops).
// WAIT/SKIP instructions (`ir1 & 1 != 0`) are stepped over, `$FFFF,$FFFE` terminates
// the list, and Copper MOVE instructions targeting Blitter registers (`$040..$074`),
// Copper pointer/strobe registers (`$080..$08A`), or `INTREQ` (`$09C`) are executed
// against `Chipset` so Copper-driven blits and Copper-raised interrupts are observed.
func (cs *Chipset) RunCopperList(startPC uint32, mem []byte) {
	if cs.inCopper || startPC == 0 {
		return
	}
	cs.inCopper = true
	defer func() { cs.inCopper = false }()

	pc := startPC & 0x001FFFFE
	for range copperMaxSteps {
		ir1 := csReadBeU16(mem, pc)
		ir2 := csReadBeU16(mem, pc+2)
		pc = (pc + 4) & 0x001FFFFE

		if ir1 == 0xFFFF && ir2 == 0xFFFE {
			break
		}
		if ir1&0x0001 != 0 {
			continue
		}
		reg := ir1 & 0x01FE
		if reg < 0x040 {
			break
		}
		switch {
		case reg == offCOPJMP1:
			if cs.Agnus.COP1LCWritten && cs.Agnus.COP1LC != 0 {
				pc = cs.Agnus.COP1LC & 0x001FFFFE
			} else {
				return
			}
		case reg == offCOPJMP2:
			if cs.Agnus.COP2LCWritten && cs.Agnus.COP2LC != 0 {
				pc = cs.Agnus.COP2LC & 0x001FFFFE
			} else {
				return
			}
		case (reg >= 0x040 && reg <= 0x074) || (reg >= 0x080 && reg <= 0x086) || reg == offINTREQ:
			cs.WriteCustomWord(0x00DFF000|uint32(reg), ir2, mem)
		}
	}
}

func (cs *Chipset) SyncCIAIRQs() {
	if cs.CIAA.IRQAsserted() {
		cs.Paula.INTREQ |= IntPORTS
	}
	if cs.CIAB.IRQAsserted() {
		cs.Paula.INTREQ |= IntEXTER
	}
}

func decodeCIAAddr(addr uint32) (isCIAB bool, reg uint8, ok bool) {
	reg = uint8((addr >> 8) & 0x0F)
	sel := (addr >> 12) & 0x3
	switch sel {
	case 0x2:
		if addr&1 == 1 {
			return false, reg, true
		}
		return false, 0, false
	case 0x1:
		if addr&1 == 0 {
			return true, reg, true
		}
		return false, 0, false
	default:
		return addr&1 == 0, reg, true
	}
}

func (cs *Chipset) ReadCIAByte(addr uint32) uint8 {
	isCIAB, reg, ok := decodeCIAAddr(addr)
	if !ok {
		return 0xFF
	}
	var out uint8
	if isCIAB {
		out = cs.CIAB.readReg(reg, true, cs.HeadCyl)
	} else {
		out = cs.CIAA.readReg(reg, false, cs.HeadCyl)
	}
	cs.SyncCIAIRQs()
	return out
}

func (cs *Chipset) WriteCIAByte(addr uint32, val uint8) {
	isCIAB, reg, ok := decodeCIAAddr(addr)
	if !ok {
		return
	}
	if isCIAB {
		cs.CIAB.writeReg(reg, val, true, &cs.HeadCyl)
	} else {
		cs.CIAA.writeReg(reg, val, false, &cs.HeadCyl)
	}
	cs.SyncCIAIRQs()
}

func (cs *Chipset) MasterIntEnabled() bool {
	return cs.Paula.INTENA&IntMASTER != 0
}

func (cs *Chipset) CanWakeStop() bool {
	return cs.MasterIntEnabled() && (cs.Paula.INTENA&0x3FFF) != 0
}

func (cs *Chipset) ReadCustomWord(addr uint32) uint16 {
	off := uint16(addr & 0x01FE)
	switch off {
	case offDMACONR:
		var busy, zero uint16
		if cs.BlitCycles > 0 {
			busy = dmaconrBBUSY
		}
		if cs.Blitter.Zero {
			zero = dmaconrBZERO
		}
		return (cs.Agnus.DMACON & 0x07FF) | busy | zero
	case offVPOSR:
		var lof uint16
		if cs.Agnus.LOF {
			lof = 1 << 15
		}
		return lof | ((cs.Agnus.VPos >> 8) & 1)
	case offVHPOSR:
		return ((cs.Agnus.VPos & 0xFF) << 8) | (cs.Agnus.HPos & 0xFF)
	case offADKCONR:
		return cs.Paula.ADKCON
	case offPOTGOR:
		return 0x5500
	case offSERDATR:
		var rbf, tbe, tsre uint16
		if cs.Paula.INTREQ&IntRBF != 0 {
			rbf = 1 << 14
		}
		if cs.Paula.SerTXCycles == 0 || (cs.Paula.INTREQ&IntTBE != 0) {
			tbe = 1 << 13
		}
		if cs.Paula.SerTXCycles == 0 {
			tsre = 1 << 12
		}
		return rbf | tbe | tsre
	case offDSKBYTR:
		var dmaon, dskwrite uint16
		if cs.Paula.DskCycles > 0 {
			dmaon = 1 << 14
		}
		if cs.Paula.DSKLEN&0x4000 != 0 {
			dskwrite = 1 << 13
		}
		return dmaon | dskwrite | 0x1000
	case offINTENAR:
		return cs.Paula.INTENA
	case offINTREQR:
		return cs.Paula.INTREQ
	case offDENISEID:
		return 0xFFFF
	default:
		return 0
	}
}

func (cs *Chipset) ReadCustomByte(addr uint32) uint8 {
	w := cs.ReadCustomWord(addr &^ 1)
	if addr&1 == 0 {
		return uint8(w >> 8)
	}
	return uint8(w)
}

func (cs *Chipset) WriteCustomWord(addr uint32, val uint16, mem []byte) {
	off := uint16(addr & 0x01FE)
	switch {
	case off == offDSKPTH:
		cs.Paula.DSKPT = (cs.Paula.DSKPT & 0x0000FFFF) | ((uint32(val) & 0x1F) << 16)
	case off == offDSKPTL:
		cs.Paula.DSKPT = (cs.Paula.DSKPT & 0x001F0000) | (uint32(val) & 0xFFFE)
	case off == offDSKLEN:
		cs.Paula.DSKLEN = val
		if val&0x8000 != 0 {
			if cs.Paula.DSKLENArmed {
				cs.Paula.DSKLENArmed = false
				words := uint32(val & 0x3FFF)
				cs.Paula.DskCycles = max(words*64, 256)
				cs.Paula.SyncCycles = 64
			} else {
				cs.Paula.DSKLENArmed = true
			}
		} else {
			cs.Paula.DSKLENArmed = false
			cs.Paula.DskCycles = 0
		}
	case off == offVPOSW:
		cs.Agnus.LOF = (val & 0x8000) != 0
	case off == offCOPCON:
		cs.Agnus.COPCON = val & 0x0002
	case off == offSERDAT:
		cs.Paula.INTREQ |= IntTBE
		div := uint32(cs.Paula.SERPER&0x7FFF) + 1
		cs.Paula.SerTXCycles = max(div*20, 200)
	case off == offSERPER:
		cs.Paula.SERPER = val
	case off == offBLTCON0:
		cs.Blitter.CON0 = val
	case off == offBLTCON1:
		cs.Blitter.CON1 = val
	case off == offBLTAFWM:
		cs.Blitter.AFWM = val
	case off == offBLTALWM:
		cs.Blitter.ALWM = val
	case off == offBLTCPTH:
		cs.Blitter.CPT = (cs.Blitter.CPT & 0x0000FFFF) | ((uint32(val) & 0x1F) << 16)
	case off == offBLTCPTL:
		cs.Blitter.CPT = (cs.Blitter.CPT & 0x001F0000) | (uint32(val) & 0xFFFE)
	case off == offBLTBPTH:
		cs.Blitter.BPT = (cs.Blitter.BPT & 0x0000FFFF) | ((uint32(val) & 0x1F) << 16)
	case off == offBLTBPTL:
		cs.Blitter.BPT = (cs.Blitter.BPT & 0x001F0000) | (uint32(val) & 0xFFFE)
	case off == offBLTAPTH:
		cs.Blitter.APT = (cs.Blitter.APT & 0x0000FFFF) | ((uint32(val) & 0x1F) << 16)
	case off == offBLTAPTL:
		cs.Blitter.APT = (cs.Blitter.APT & 0x001F0000) | (uint32(val) & 0xFFFE)
	case off == offBLTDPTH:
		cs.Blitter.DPT = (cs.Blitter.DPT & 0x0000FFFF) | ((uint32(val) & 0x1F) << 16)
	case off == offBLTDPTL:
		cs.Blitter.DPT = (cs.Blitter.DPT & 0x001F0000) | (uint32(val) & 0xFFFE)
	case off == offBLTSIZE:
		h := uint32(val >> 6)
		w := uint32(val & 0x3F)
		if h == 0 {
			h = 1024
		}
		if w == 0 {
			w = 64
		}
		if cs.Blitter.CON1&bltcon1LINE == 0 {
			cs.Blitter.executeNormal(h, w, mem)
		}
		if cs.BlitCycles > 0 {
			cs.Paula.INTREQ |= IntBLIT
		}
		cs.BlitCycles = max(h*w*2, 64)
	case off == offBLTCMOD:
		cs.Blitter.CMOD = int16(val &^ 1)
	case off == offBLTBMOD:
		cs.Blitter.BMOD = int16(val &^ 1)
	case off == offBLTAMOD:
		cs.Blitter.AMOD = int16(val &^ 1)
	case off == offBLTDMOD:
		cs.Blitter.DMOD = int16(val &^ 1)
	case off == offBLTCDAT:
		cs.Blitter.CDAT = val
	case off == offBLTBDAT:
		cs.Blitter.BDAT = val
	case off == offBLTADAT:
		cs.Blitter.ADAT = val
	case off == offDSKSYNC:
		cs.Paula.DSKSYNC = val
		if cs.Paula.SyncCycles == 0 {
			cs.Paula.SyncCycles = 1024
		}
	case off == offCOP1LCH:
		cs.Agnus.COP1LC = (cs.Agnus.COP1LC & 0x0000FFFF) | ((uint32(val) & 0x1F) << 16)
		cs.Agnus.COP1LCWritten = true
	case off == offCOP1LCL:
		cs.Agnus.COP1LC = (cs.Agnus.COP1LC & 0x001F0000) | (uint32(val) & 0xFFFE)
		cs.Agnus.COP1LCWritten = true
	case off == offCOP2LCH:
		cs.Agnus.COP2LC = (cs.Agnus.COP2LC & 0x0000FFFF) | ((uint32(val) & 0x1F) << 16)
		cs.Agnus.COP2LCWritten = true
	case off == offCOP2LCL:
		cs.Agnus.COP2LC = (cs.Agnus.COP2LC & 0x001F0000) | (uint32(val) & 0xFFFE)
		cs.Agnus.COP2LCWritten = true
	case off == offCOPJMP1:
		copDMA := (cs.Agnus.DMACON & (DmaMASTER | DmaCOPPER)) == (DmaMASTER | DmaCOPPER)
		if copDMA && cs.Agnus.COP1LCWritten && cs.Agnus.COP1LC != 0 {
			cs.RunCopperList(cs.Agnus.COP1LC, mem)
		}
	case off == offCOPJMP2:
		copDMA := (cs.Agnus.DMACON & (DmaMASTER | DmaCOPPER)) == (DmaMASTER | DmaCOPPER)
		if copDMA && cs.Agnus.COP2LCWritten && cs.Agnus.COP2LC != 0 {
			cs.RunCopperList(cs.Agnus.COP2LC, mem)
		}
	case off == offDMACON:
		cs.Agnus.DMACON = applySetClr(cs.Agnus.DMACON, val) & 0x07FF
		master := cs.Agnus.DMACON&DmaMASTER != 0
		for ch := range 4 {
			en := master && (cs.Agnus.DMACON&(1<<ch) != 0)
			aud := &cs.Paula.Aud[ch]
			if en && !aud.DMAActive {
				aud.DMAActive = true
				aud.RemCycles = CyclesPerLine
			} else if !en && aud.DMAActive {
				aud.DMAActive = false
				aud.RemCycles = 0
			}
		}
	case off == offINTENA:
		cs.Paula.INTENA = applySetClr(cs.Paula.INTENA, val)
		if cs.Paula.INTENA&IntRBF != 0 && cs.Paula.SerRXCycles == 0 {
			cs.Paula.SerRXCycles = CyclesPerFrame
		}
		if cs.Paula.INTENA&IntDSKSYNC != 0 && cs.Paula.SyncCycles == 0 {
			cs.Paula.SyncCycles = dsksyncPeriodCycles
		}
	case off == offINTREQ:
		cs.Paula.INTREQ = applySetClr(cs.Paula.INTREQ, val)
		cs.SyncCIAIRQs()
	case off == offADKCON:
		cs.Paula.ADKCON = applySetClr(cs.Paula.ADKCON, val)
		if cs.Paula.ADKCON&0x0400 != 0 && cs.Paula.SyncCycles == 0 {
			cs.Paula.SyncCycles = dsksyncPeriodCycles
		}
	case off >= 0x0A0 && off <= 0x0DF:
		ch := int((off - 0x0A0) >> 4)
		reg := (off - 0x0A0) & 0x0E
		aud := &cs.Paula.Aud[ch]
		switch reg {
		case 0x00:
			aud.LC = (aud.LC & 0x0000FFFF) | ((uint32(val) & 0x1F) << 16)
		case 0x02:
			aud.LC = (aud.LC & 0x001F0000) | (uint32(val) & 0xFFFE)
		case 0x04:
			aud.Len = val
		case 0x06:
			aud.Per = val
		case 0x08:
			aud.Vol = val
		case 0x0A:
			if !aud.DMAActive {
				per := max(uint32(aud.Per), 1)
				aud.RemCycles = max(per*4, 64)
			}
		}
	}
}

// Tick advances all seven custom-chip and CIA subsystems by `cycles` 68000 CPU cycles:
//  1. Agnus PAL beam counter (`VPos`/`HPos`), raising `IntVERTB` and running `COP1LC`
//     (or raising `IntCOPER`) on each vertical blank wrap.
//  2. Blitter busy countdown (`BlitCycles`), raising `IntBLIT` on completion.
//  3. Paula disk DMA countdown (`DskCycles`), raising `IntDSKBLK` after double-write `DSKLEN`.
//  4. Paula disk sync timer (`SyncCycles`), raising `IntDSKSYNC` periodically when enabled.
//  5. Paula serial port TX (`IntTBE`) and RX (`IntRBF`) timers.
//  6. Paula audio channels 0..3 (`IntAUD0`..`IntAUD3`) period × length timers.
//  7. 8520 CIA-A and CIA-B E-clock timers (`cpuCycles / 10`), TOD counters, and disk index pulse,
//     synchronizing asserted CIA IRQs into `IntPORTS` (Level 2) and `IntEXTER` (Level 6).
func (cs *Chipset) Tick(cycles uint32, mem []byte) {
	// 1. Agnus beam counter
	totalCPU := cs.Agnus.CckRem + cycles
	ccks := totalCPU / 2
	cs.Agnus.CckRem = totalCPU % 2
	totalH := uint32(cs.Agnus.HPos) + ccks
	lines := totalH / HPosPerLine
	cs.Agnus.HPos = uint16(totalH % HPosPerLine)
	var frames uint32
	if lines > 0 {
		totalV := uint32(cs.Agnus.VPos) + lines
		frames = totalV / VPosPerFrame
		cs.Agnus.VPos = uint16(totalV % VPosPerFrame)
		if frames > 0 {
			cs.Paula.INTREQ |= IntVERTB
			copDMA := (cs.Agnus.DMACON & (DmaMASTER | DmaCOPPER)) == (DmaMASTER | DmaCOPPER)
			if copDMA {
				if cs.Agnus.COP1LCWritten && cs.Agnus.COP1LC != 0 {
					cs.RunCopperList(cs.Agnus.COP1LC, mem)
				} else if (cs.Paula.INTENA & IntCOPER) != 0 {
					cs.Paula.INTREQ |= IntCOPER
				}
			}
		}
	}

	// 2. Blitter completion timer
	if cs.BlitCycles > 0 {
		if cycles >= cs.BlitCycles {
			cs.BlitCycles = 0
			cs.Paula.INTREQ |= IntBLIT
		} else {
			cs.BlitCycles -= cycles
		}
	}

	// 3. Paula disk DMA block completion
	if cs.Paula.DskCycles > 0 {
		if cycles >= cs.Paula.DskCycles {
			cs.Paula.DskCycles = 0
			cs.Paula.INTREQ |= IntDSKBLK
		} else {
			cs.Paula.DskCycles -= cycles
		}
	}

	// 4. Paula disk sync word match
	syncActive := cs.Paula.DskCycles > 0 ||
		(cs.Paula.ADKCON&0x0400 != 0) ||
		(cs.Paula.INTENA&IntDSKSYNC != 0)
	if cs.Paula.SyncCycles > 0 {
		if cycles >= cs.Paula.SyncCycles {
			cs.Paula.INTREQ |= IntDSKSYNC
			if syncActive {
				cs.Paula.SyncCycles = dsksyncPeriodCycles
			} else {
				cs.Paula.SyncCycles = 0
			}
		} else {
			cs.Paula.SyncCycles -= cycles
		}
	}

	// 5. Paula serial TX and RX
	if cs.Paula.SerTXCycles > 0 {
		if cycles >= cs.Paula.SerTXCycles {
			cs.Paula.SerTXCycles = 0
			cs.Paula.INTREQ |= IntTBE
		} else {
			cs.Paula.SerTXCycles -= cycles
		}
	}
	if cs.Paula.SerRXCycles > 0 {
		if cycles >= cs.Paula.SerRXCycles {
			cs.Paula.INTREQ |= IntRBF
			if cs.Paula.INTENA&IntRBF != 0 {
				cs.Paula.SerRXCycles = CyclesPerFrame
			} else {
				cs.Paula.SerRXCycles = 0
			}
		} else {
			cs.Paula.SerRXCycles -= cycles
		}
	}

	// 6. Paula audio channels 0..3
	for ch := range 4 {
		aud := &cs.Paula.Aud[ch]
		if aud.RemCycles > 0 {
			if cycles >= aud.RemCycles {
				cs.Paula.INTREQ |= IntAUD0 << ch
				if aud.DMAActive {
					length := uint32(aud.Len)
					if length == 0 {
						length = 65536
					}
					per := max(uint32(aud.Per), 124)
					prod := uint64(length) * uint64(per) * 4
					if prod > 0xFFFFFFFF {
						prod = 0xFFFFFFFF
					}
					aud.RemCycles = max(uint32(prod), CyclesPerLine)
				} else {
					aud.RemCycles = 0
				}
			} else {
				aud.RemCycles -= cycles
			}
		}
	}

	// 7. 8520 CIA-A and CIA-B
	totalE := cs.ERem + cycles
	eClocks := totalE / 10
	cs.ERem = totalE % 10
	if eClocks > 0 || frames > 0 || lines > 0 {
		cs.CIAA.tick(eClocks, frames, false)
		cs.CIAB.tick(eClocks, lines, frames > 0)
		cs.SyncCIAIRQs()
	}
}

// DeliverableIPL returns the highest-priority enabled and pending interrupt level (1..6)
// whose autovector slot (`0x60 + level*4`) in `mem` contains a non-zero handler address,
// or 0 if master interrupts are disabled (`INTENA` bit 14 == 0) or no vector is installed.
func (cs *Chipset) DeliverableIPL(mem []byte) uint8 {
	if !cs.MasterIntEnabled() {
		return 0
	}
	pending := cs.Paula.INTENA & cs.Paula.INTREQ
	if pending == 0 {
		return 0
	}
	for _, lm := range levelMasks {
		if pending&lm.mask != 0 {
			vecAddr := 0x60 + uint32(lm.level)*4
			if csReadBeU32(mem, vecAddr)&0x00FFFFFF != 0 {
				return lm.level
			}
		}
	}
	return 0
}
