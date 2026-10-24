package modules

import (
	"encoding/binary"

	"github.com/jenska/m68kemu"
)

const (
	// SandboxModBase is the base guest address at which the module image is placed in the sandbox.
	SandboxModBase uint32 = 0x00010000
	// SandboxRAMLen is the total sandbox RAM window length (8 MiB, strictly less than 24-bit space).
	SandboxRAMLen uint32 = 0x00800000
	// SandboxStackTop is the initial stack pointer.
	SandboxStackTop uint32 = 0x00700000
	// SandboxSentinel is the sentinel return address pushed on the stack; a clean RTS lands here.
	SandboxSentinel uint32 = 0x007FFFFE
	// SandboxDefaultBudget is the hard instruction budget guarding against non-terminating driver code.
	SandboxDefaultBudget uint32 = 4_000_000
)

type sandboxAccess int

const (
	accessInWindow sandboxAccess = iota
	accessMMIO
	accessFault
)

type sandboxDevice struct {
	mem   []byte
	fault bool
}

func newSandboxDevice() *sandboxDevice {
	return &sandboxDevice{
		mem: make([]byte, SandboxRAMLen),
	}
}

func (d *sandboxDevice) AddressRange() (uint32, uint32) {
	return 0, 0x00FFFFFF
}

func (d *sandboxDevice) Reset() {}

func (d *sandboxDevice) classify(addr uint32, span uint32) sandboxAccess {
	addr &= 0x00FFFFFF
	if (addr >= 0x00DF0000 && addr <= 0x00DFFFFF) ||
		(addr >= 0x00BF0000 && addr <= 0x00BFFFFF) ||
		(addr >= 0x00E80000 && addr <= 0x00EFFFFF) {
		return accessMMIO
	}
	if uint64(addr)+uint64(span) > uint64(SandboxRAMLen) {
		d.fault = true
		return accessFault
	}
	return accessInWindow
}

func (d *sandboxDevice) Read(s m68kemu.Size, address uint32) (uint32, error) {
	address &= 0x00FFFFFF
	switch d.classify(address, uint32(s)) {
	case accessInWindow:
		switch s {
		case m68kemu.Byte:
			return uint32(d.mem[address]), nil
		case m68kemu.Word:
			return uint32(binary.BigEndian.Uint16(d.mem[address : address+2])), nil
		case m68kemu.Long:
			return binary.BigEndian.Uint32(d.mem[address : address+4]), nil
		}
	case accessMMIO:
		return 0, nil
	}
	return 0, m68kemu.BusError(address)
}

func (d *sandboxDevice) Write(s m68kemu.Size, address uint32, value uint32) error {
	address &= 0x00FFFFFF
	switch d.classify(address, uint32(s)) {
	case accessInWindow:
		switch s {
		case m68kemu.Byte:
			d.mem[address] = byte(value)
		case m68kemu.Word:
			binary.BigEndian.PutUint16(d.mem[address:address+2], uint16(value))
		case m68kemu.Long:
			binary.BigEndian.PutUint32(d.mem[address:address+4], value)
		}
		return nil
	case accessMMIO:
		return nil
	}
	return m68kemu.BusError(address)
}

// ProbeSetup holds the initial register setup for a probe run.
type ProbeSetup struct {
	EntryOff     uint32
	A            [7]uint32
	AModRelative [7]bool
}

// ProbeResult holds the final A0..A7 and D0..D7 register file after a clean sentinel return.
type ProbeResult struct {
	A [8]uint32
	D [8]uint32
}

// ARel interprets address register An (n = 0..7) as an offset from SandboxModBase,
// or returns (_, false) if it points below SandboxModBase.
func (r *ProbeResult) ARel(n int) (uint32, bool) {
	if n < 0 || n >= 8 || r.A[n] < SandboxModBase {
		return 0, false
	}
	return r.A[n] - SandboxModBase, true
}

// RunProbe runs data (a module image) in the sandbox from setup.EntryOff, returning
// the final register file on a clean sentinel return, or nil on any fault, trap, or
// budget exhaustion.
func RunProbe(data []byte, setup *ProbeSetup, budget uint32, prePatch func([]byte)) *ProbeResult {
	if uint64(len(data))+uint64(SandboxModBase) >= uint64(SandboxStackTop) {
		return nil
	}

	dev := newSandboxDevice()
	copy(dev.mem[SandboxModBase:int(SandboxModBase)+len(data)], data)
	if prePatch != nil {
		prePatch(dev.mem[SandboxModBase : int(SandboxModBase)+len(data)])
	}

	binary.BigEndian.PutUint32(dev.mem[SandboxStackTop:SandboxStackTop+4], SandboxSentinel)
	binary.BigEndian.PutUint32(dev.mem[0:4], SandboxStackTop)
	binary.BigEndian.PutUint32(dev.mem[4:8], SandboxModBase+setup.EntryOff)

	bus := m68kemu.NewBus(dev)
	cpu, err := m68kemu.NewCPU(bus)
	if err != nil {
		return nil
	}

	regs := cpu.Registers()
	for i := range 7 {
		v := setup.A[i]
		if setup.AModRelative[i] {
			v += SandboxModBase
		}
		regs.A[i] = v
	}
	regs.A[7] = SandboxStackTop
	regs.SSP = SandboxStackTop
	regs.USP = SandboxStackTop
	regs.PC = SandboxModBase + setup.EntryOff
	cpu.SetRegisters(regs)

	res, err := cpu.RunUntil(m68kemu.RunUntilOptions{
		MaxInstructions: uint64(budget),
		StopOnException: true,
		StopOnIllegal:   true,
		StopAtPC:        []uint32{SandboxSentinel},
	})
	if err != nil || dev.fault {
		return nil
	}
	if res.Reason == m68kemu.RunStopPC && (res.PC&0x00FFFFFF) == SandboxSentinel {
		finalRegs := cpu.Registers()
		return &ProbeResult{
			A: finalRegs.A,
			D: finalRegs.D,
		}
	}
	return nil
}

// ModReadU32 reads a big-endian uint32 from the module image at a module-relative offset.
func ModReadU32(data []byte, off uint32) (uint32, bool) {
	return beU32(data, int(off))
}
