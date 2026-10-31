package analyzer

import (
	"encoding/binary"
	"fmt"
	"slices"
	"strings"

	"github.com/jenska/m68kemu"
	"github.com/mikolas/hunks/internal/amiga"
	"github.com/mikolas/hunks/internal/db"
	"github.com/mikolas/hunks/internal/m68k"
	"github.com/mikolas/hunks/internal/project"
)

const (
	traceRAMLen     uint32 = 0x00800000
	traceRangerBase uint32 = 0x00C00000
	traceRangerLen  uint32 = 0x00180000
)

// traceDevice implements m68kemu.Device over an 8 MiB flat RAM window plus a minimal
// Amiga 24-bit MMIO bus (Custom chips at $DFF000, CIAs at $BF0000, Ranger RAM at
// $C00000..$D7FFFF, and Zorro II Autoconfig at $E80000..$EFFFFF).
// Out-of-bounds memory accesses outside traceRAMLen and MMIO ranges latch the offending
// address in `fault` so the trace loop can stop cleanly with `StopFault`.
type traceDevice struct {
	mem     []byte
	ranger  []byte
	fault   *uint32
	chipset *Chipset
}

func newTraceDevice(image []byte, base uint32) *traceDevice {
	d := &traceDevice{
		mem:     make([]byte, traceRAMLen),
		chipset: NewChipset(),
	}
	d.loadSegment(base, image)
	return d
}

func (d *traceDevice) loadSegment(base uint32, data []byte) {
	if len(data) == 0 {
		return
	}
	b := base & 0x00FFFFFF
	if b >= traceRangerBase && b < traceRangerBase+traceRangerLen {
		if d.ranger == nil {
			d.ranger = make([]byte, traceRangerLen)
		}
		off := int(b - traceRangerBase)
		end := min(off+len(data), len(d.ranger))
		copy(d.ranger[off:end], data[:end-off])
		return
	}
	if int(b) < len(d.mem) {
		end := min(int(b)+len(data), len(d.mem))
		copy(d.mem[b:end], data[:end-int(b)])
	}
}

func (d *traceDevice) AddressRange() (uint32, uint32) {
	return 0, 0x00FFFFFF
}

func (d *traceDevice) Reset() {}

func isTraceMMIO(addr uint32) bool {
	return (addr >= 0x00C00000 && addr <= 0x00D7FFFF) ||
		(addr >= 0x00DF0000 && addr <= 0x00DFFFFF) ||
		(addr >= 0x00BF0000 && addr <= 0x00BFFFFF) ||
		(addr >= 0x00E80000 && addr <= 0x00EFFFFF)
}

func (d *traceDevice) check(addr, span uint32) bool {
	if uint64(addr)+uint64(span) > uint64(traceRAMLen) {
		if d.fault == nil {
			a := addr
			d.fault = &a
		}
		return false
	}
	return true
}

func (d *traceDevice) readByte(a uint32) uint8 {
	a &= 0x00FFFFFF
	if a >= 0x00DFF000 && a <= 0x00DFF1FF {
		return d.chipset.ReadCustomByte(a)
	}
	if a >= 0x00BF0000 && a <= 0x00BFFFFF {
		return d.chipset.ReadCIAByte(a)
	}
	if d.ranger != nil && a >= traceRangerBase && a < traceRangerBase+traceRangerLen {
		return d.ranger[a-traceRangerBase]
	}
	if isTraceMMIO(a) {
		return 0
	}
	if !d.check(a, 1) {
		return 0
	}
	return d.mem[a]
}

func (d *traceDevice) readWord(a uint32) uint16 {
	a &= 0x00FFFFFF
	if a >= 0x00DFF000 && a <= 0x00DFF1FF {
		return d.chipset.ReadCustomWord(a)
	}
	if a >= 0x00BF0000 && a <= 0x00BFFFFF {
		return (uint16(d.readByte(a)) << 8) | uint16(d.readByte(a+1))
	}
	if d.ranger != nil && a >= traceRangerBase && a+2 <= traceRangerBase+traceRangerLen {
		off := a - traceRangerBase
		return binary.BigEndian.Uint16(d.ranger[off : off+2])
	}
	if isTraceMMIO(a) {
		return 0
	}
	if !d.check(a, 2) {
		return 0
	}
	return binary.BigEndian.Uint16(d.mem[a : a+2])
}

func (d *traceDevice) readLong(a uint32) uint32 {
	return (uint32(d.readWord(a)) << 16) | uint32(d.readWord(a+2))
}

func (d *traceDevice) writeByte(a uint32, v uint8) {
	a &= 0x00FFFFFF
	if a >= 0x00BF0000 && a <= 0x00BFFFFF {
		d.chipset.WriteCIAByte(a, v)
		return
	}
	if d.ranger != nil && a >= traceRangerBase && a < traceRangerBase+traceRangerLen {
		d.ranger[a-traceRangerBase] = v
		return
	}
	if isTraceMMIO(a) {
		return
	}
	if !d.check(a, 1) {
		return
	}
	d.mem[a] = v
}

func (d *traceDevice) writeWord(a uint32, v uint16) {
	aa := a & 0x00FFFFFF
	if aa >= 0x00DFF000 && aa <= 0x00DFF1FF {
		d.chipset.WriteCustomWord(aa, v, d.mem)
		return
	}
	d.writeByte(a, uint8(v>>8))
	d.writeByte(a+1, uint8(v))
}

func (d *traceDevice) writeLong(a uint32, v uint32) {
	d.writeWord(a, uint16(v>>16))
	d.writeWord(a+2, uint16(v))
}

func (d *traceDevice) Read(s m68kemu.Size, address uint32) (uint32, error) {
	switch s {
	case m68kemu.Byte:
		v := uint32(d.readByte(address))
		if d.fault != nil {
			return 0, m68kemu.BusError(address)
		}
		return v, nil
	case m68kemu.Word:
		v := uint32(d.readWord(address))
		if d.fault != nil {
			return 0, m68kemu.BusError(address)
		}
		return v, nil
	case m68kemu.Long:
		v := d.readLong(address)
		if d.fault != nil {
			return 0, m68kemu.BusError(address)
		}
		return v, nil
	}
	return 0, nil
}

func (d *traceDevice) Write(s m68kemu.Size, address uint32, value uint32) error {
	switch s {
	case m68kemu.Byte:
		d.writeByte(address, uint8(value))
	case m68kemu.Word:
		d.writeWord(address, uint16(value))
	case m68kemu.Long:
		d.writeLong(address, value)
	}
	if d.fault != nil {
		return m68kemu.BusError(address)
	}
	return nil
}

// Dispatch classifies an indirect jmp/jsr instruction.
type Dispatch struct {
	Mode   m68k.EAMode
	IsCall bool
	BaseAn int8
}

func indirectDispatch(op uint16) (Dispatch, bool) {
	mode, isCall, baseAn, ok := m68k.ClassifyIndirectDispatch(op)
	if !ok {
		return Dispatch{}, false
	}
	return Dispatch{Mode: mode, IsCall: isCall, BaseAn: baseAn}, true
}

// StopKind identifies why a trace stopped.
type StopKind string

const (
	StopBudget    StopKind = "Budget"
	StopFault     StopKind = "Fault"
	StopLeftImage StopKind = "LeftImage"
	StopIllegal   StopKind = "Illegal"
	StopTrap      StopKind = "Trap"
	StopStopped   StopKind = "Stopped"
	StopStuckWait StopKind = "StuckWait"
)

// StopReason describes why the trace stopped.
type StopReason struct {
	Kind     StopKind
	Budget   uint64
	Addr     uint32
	To       uint32
	AtPC     uint32
	Step     uint64
	Opcode   uint16
	TrapKind string
}

func (s StopReason) String() string {
	switch s.Kind {
	case StopBudget:
		return fmt.Sprintf("budget exhausted (%d instructions)", s.Budget)
	case StopFault:
		return fmt.Sprintf("fault at %#08X (pc %#08X, step %d)", s.Addr, s.AtPC, s.Step)
	case StopLeftImage:
		return fmt.Sprintf("PC left image -> %#08X (from %#08X, step %d)", s.To, s.AtPC, s.Step)
	case StopIllegal:
		return fmt.Sprintf("illegal instruction %#06X (pc %#08X, step %d)", s.Opcode, s.AtPC, s.Step)
	case StopTrap:
		return fmt.Sprintf("%s (pc %#08X, step %d)", s.TrapKind, s.AtPC, s.Step)
	case StopStopped:
		return fmt.Sprintf("STOP instruction (pc %#08X, step %d)", s.AtPC, s.Step)
	case StopStuckWait:
		return fmt.Sprintf("stuck external wait at %#08X (pc frozen, no interrupt released it; step %d)", s.AtPC, s.Step)
	default:
		return string(s.Kind)
	}
}

// DispatchSite is an observed indirect dispatch site and the targets taken.
type DispatchSite struct {
	Addr    uint32
	Mode    m68k.EAMode
	IsCall  bool
	BaseAn  int8
	Targets map[uint32]uint64
}

// RegContext maps each reached instruction address to the 16 registers (D0-D7, A0-A7) entering it.
type RegContext map[uint32][16]uint32

// VectorEntry pairs a vector number (2..63) with its installed handler address.
type VectorEntry struct {
	Vec     uint8
	Handler uint32
}

// TraceReport is the report produced by a trace run.
type TraceReport struct {
	Entry        uint32
	Base         uint32
	ImageLen     int
	Instructions uint64
	DistinctPCs  int
	PCLo         uint32
	PCHi         uint32
	ServicedInts [6]uint64
	ServicedExcs uint64
	Stop         StopReason
	Sites        []DispatchSite
	Regs         RegContext
	Vectors      []VectorEntry
}

// TraceSegment represents an additional RAM segment loaded into the trace bus.
type TraceSegment struct {
	Base uint32
	Data []byte
}

// TraceOptions configures a trace run.
type TraceOptions struct {
	Budget     uint64
	StuckN     uint64
	Snapshot   *project.SnapshotState
	CustomSnap *amiga.CustomSnapshot
	Segments   []TraceSegment
}

// DefaultTraceOptions returns the default trace options.
func DefaultTraceOptions() TraceOptions {
	return TraceOptions{
		Budget: 20_000_000,
		StuckN: 200_000,
	}
}

// takeAutovectorInterrupt delivers a 68000 Level 1..6 autovector interrupt (vectors 25..30
// at $64..$78) if `ipl` exceeds the current SR interrupt priority mask. It switches to
// supervisor mode, pushes the 6-byte exception stack frame (SR + 32-bit PC), and jumps
// to the handler address installed at `0x60 + ipl*4`.
func takeAutovectorInterrupt(cpu *m68kemu.CPU, dev *traceDevice, ipl uint8) bool {
	regs := cpu.Registers()
	srMask := uint8((regs.SR >> 8) & 7)
	if ipl == 0 || ipl <= srMask {
		return false
	}
	origPC := regs.PC & 0x00FFFFFF
	origSR := regs.SR
	newSR := (origSR &^ 0x0700) | 0x2000 | (uint16(ipl) << 8)
	if (origSR & 0x2000) == 0 {
		regs.USP = regs.A[7]
		regs.A[7] = regs.SSP
	}
	sp := regs.A[7]
	sp -= 4
	dev.writeLong(sp, origPC)
	sp -= 2
	dev.writeWord(sp, origSR)
	regs.A[7] = sp
	regs.SR = newSR
	handler := dev.readLong(0x60+uint32(ipl)*4) & 0x00FFFFFF
	regs.PC = handler
	cpu.SetRegisters(regs)
	cpu.SetPC(handler)
	return true
}

// RunTrace executes `image` loaded at `base` starting from `entry` inside a bounded
// `m68kemu` sandbox coupled to `Chipset` (`internal/analyzer/chipset.go`).
//
// On every instruction step inside `[base, base+len(image))`, RunTrace:
//   - Snapshots pre-instruction `D0..D7`/`A0..A7` into `Regs[pc]` so base-register
//     hardware accesses (`(An)`, `(An)+`, `-(An)`, `d16(An)`) can be annotated with their
//     observed runtime base values (`ApplyTraceHWRegs`) and so statically-unresolved
//     register-indirect dispatches can be resolved from the observed base
//     (`ApplyTraceRegDispatches`).
//   - Detects indirect `JMP`/`JSR` dispatches (`(An)`, `d16(An)`, `d8(An,Xn)`, `d8(PC,Xn)`)
//     and records every concrete target PC reached in `Sites`.
//   - Distinguishes self-installed `TRAP`/A-line/F-line/exception handlers (which are
//     followed into the handler) from uninitialized zero vectors (which stop the trace).
//   - Advances the Agnus/Paula/Blitter/Copper/CIA chipset state machine by the elapsed
//     CPU cycles, servicing pending autovector interrupts and fast-forwarding up to 2 PAL
//     frames when waking a `STOP #imm` instruction.
//   - Detects tight polling loops waiting on unmodeled external state (`StopStuckWait`)
//     when a short backward branch repeats `opts.StuckN` times with identical registers.
func RunTrace(image []byte, base, entry uint32, opts TraceOptions) TraceReport {
	if opts.Budget == 0 {
		opts.Budget = DefaultTraceOptions().Budget
	}
	if opts.StuckN == 0 {
		opts.StuckN = DefaultTraceOptions().StuckN
	}

	dev := newTraceDevice(image, base)
	for _, seg := range opts.Segments {
		dev.loadSegment(seg.Base, seg.Data)
	}
	if opts.CustomSnap != nil {
		dev.chipset.LoadCustomSnapshot(opts.CustomSnap)
	}

	stackTop := uint32(0x00700000)
	if base >= 0x2000 {
		stackTop = (base - 0x1000) &^ 1
	}

	bus := m68kemu.NewBus(dev)
	cpu, _ := m68kemu.NewCPU(bus)
	initRegs := cpu.Registers()
	if opts.Snapshot != nil {
		initRegs.D = opts.Snapshot.D
		initRegs.A = opts.Snapshot.A
		if initRegs.A[7] == 0 {
			initRegs.A[7] = stackTop
		}
		initRegs.SSP = initRegs.A[7]
		initRegs.USP = initRegs.A[7]
		if opts.Snapshot.PC != 0 {
			entry = opts.Snapshot.PC & 0x00FFFFFF
		}
		initRegs.PC = entry
		if opts.Snapshot.SR != 0 {
			initRegs.SR = opts.Snapshot.SR
		} else {
			initRegs.SR = 0x2000
		}
	} else {
		dev.writeLong(0, stackTop)
		dev.writeLong(4, entry)
		initRegs.A[7] = stackTop
		initRegs.SSP = stackTop
		initRegs.USP = stackTop
		initRegs.PC = entry
		initRegs.SR = 0x2000
	}
	cpu.SetRegisters(initRegs)
	cpu.SetPC(entry)

	var stepExc *m68kemu.ExceptionInfo
	cpu.SetHooks(m68kemu.Hooks{
		Exception: func(info m68kemu.ExceptionInfo) {
			cp := info
			stepExc = &cp
		},
	})

	imgEnd := uint64(base) + uint64(len(image))
	isAddrInLoadedSegments := func(addr uint32) bool {
		if uint64(addr) >= uint64(base) && uint64(addr) < imgEnd {
			return true
		}
		for _, seg := range opts.Segments {
			if uint64(addr) >= uint64(seg.Base) && uint64(addr) < uint64(seg.Base)+uint64(len(seg.Data)) {
				return true
			}
		}
		return false
	}
	var steps uint64
	var servicedInts [6]uint64
	var servicedExcs uint64
	pcLo := entry
	pcHi := entry

	type siteAccum struct {
		disp    Dispatch
		targets map[uint32]uint64
	}
	sitesMap := make(map[uint32]*siteAccum)
	regs := make(RegContext)

	lastBranchPC := uint32(0xFFFFFFFF)
	var lastBranchDAR [16]uint32
	var frozenReps uint64

	var outsideSteps int
	var hasTrampOrigin bool
	var trampOriginPC uint32
	var trampFirstOutPC uint32
	var trampOriginDisp Dispatch

	var stop StopReason
	for {
		if steps >= opts.Budget {
			stop = StopReason{Kind: StopBudget, Budget: opts.Budget}
			break
		}
		curRegs := cpu.Registers()
		pc := curRegs.PC & 0x00FFFFFF
		inImage := isAddrInLoadedSegments(pc)
		if !inImage {
			if outsideSteps == 0 {
				trampFirstOutPC = pc
			}
			outsideSteps++
			validRAM := uint64(pc) < uint64(traceRAMLen) || (dev.ranger != nil && pc >= traceRangerBase && pc < traceRangerBase+traceRangerLen)
			if outsideSteps > 8 || pc%2 != 0 || !validRAM || dev.readWord(pc) == 0 {
				stop = StopReason{Kind: StopLeftImage, To: trampFirstOutPC, AtPC: trampFirstOutPC, Step: steps}
				break
			}
		} else {
			outsideSteps = 0
			pcLo = min(pcLo, pc)
			pcHi = max(pcHi, pc)
		}

		op := dev.readWord(pc)
		var dispatch Dispatch
		var hasDispatch bool
		var darPre [16]uint32
		if inImage {
			dispatch, hasDispatch = indirectDispatch(op)
			copy(darPre[0:8], curRegs.D[:])
			copy(darPre[8:16], curRegs.A[:])
			regs[pc] = darPre
		}

		// Check self-installed vs unhandled TRAP / A-line / F-line before stepping.
		if (op & 0xF000) == 0xA000 {
			if dev.readLong(10*4)&0x00FFFFFF == 0 {
				stop = StopReason{Kind: StopTrap, TrapKind: "A-line trap (no handler)", AtPC: pc, Step: steps}
				break
			}
		} else if (op & 0xF000) == 0xF000 {
			if dev.readLong(11*4)&0x00FFFFFF == 0 {
				stop = StopReason{Kind: StopTrap, TrapKind: "F-line trap (no handler)", AtPC: pc, Step: steps}
				break
			}
		} else if (op & 0xFFF0) == 0x4E40 {
			trapNum := uint32(op & 0xF)
			if dev.readLong((32+trapNum)*4)&0x00FFFFFF == 0 {
				stop = StopReason{Kind: StopTrap, TrapKind: "TRAP (no handler)", AtPC: pc, Step: steps}
				break
			}
		}

		dev.fault = nil
		stepExc = nil
		cycBefore := cpu.Cycles()
		_ = cpu.Step()
		steps++
		cycDelta := uint32(max(cpu.Cycles()-cycBefore, 4))
		dev.chipset.Tick(cycDelta, dev.mem)

		if dev.fault != nil {
			stop = StopReason{Kind: StopFault, Addr: *dev.fault, AtPC: pc, Step: steps}
			break
		}

		if stepExc != nil {
			v := stepExc.Vector
			if v == m68kemu.XIllegal {
				stop = StopReason{Kind: StopIllegal, Opcode: op, AtPC: pc, Step: steps}
				break
			}
			if v == m68kemu.XLineA || v == m68kemu.XLineF || (v >= m68kemu.XTrap && v < m68kemu.XTrap+16) {
				servicedExcs++
				continue
			}
			if dev.readLong(v*4)&0x00FFFFFF == 0 {
				stop = StopReason{Kind: StopTrap, TrapKind: fmt.Sprintf("exception vector %d (no handler)", v), AtPC: pc, Step: steps}
				break
			}
		}

		postRegs := cpu.Registers()
		newPC := postRegs.PC & 0x00FFFFFF
		if newPC <= pc && pc-newPC <= 64 {
			if pc == lastBranchPC && darPre == lastBranchDAR {
				frozenReps++
				if frozenReps >= opts.StuckN {
					stop = StopReason{Kind: StopStuckWait, AtPC: pc, Step: steps}
					break
				}
			} else {
				lastBranchPC = pc
				lastBranchDAR = darPre
				frozenReps = 0
			}
		}

		newInImage := isAddrInLoadedSegments(newPC)
		if inImage {
			if newInImage {
				hasTrampOrigin = false
				if hasDispatch {
					sa, ok := sitesMap[pc]
					if !ok {
						sa = &siteAccum{disp: dispatch, targets: make(map[uint32]uint64)}
						sitesMap[pc] = sa
					}
					sa.targets[newPC]++
				}
			} else {
				trampOriginPC = pc
				if hasDispatch {
					hasTrampOrigin = true
					trampOriginDisp = dispatch
				} else if (op&0xFFC0) == 0x4E80 || (op&0xFFC0) == 0x4EC0 || (op&0xFF00) == 0x6000 || (op&0xFF00) == 0x6100 {
					hasTrampOrigin = true
					isCall := (op&0xFFC0) == 0x4E80 || (op&0xFF00) == 0x6100
					mode := m68k.EAAbsShort
					if (op & 0x003F) == 0x0039 {
						mode = m68k.EAAbsLong
					}
					trampOriginDisp = Dispatch{Mode: mode, IsCall: isCall, BaseAn: -1}
				} else {
					hasTrampOrigin = false
				}
			}
		} else if newInImage && hasTrampOrigin {
			// Bounced back into image from an out-of-image trampoline!
			if op != 0x4E75 && op != 0x4E73 && op != 0x4E77 {
				sa, ok := sitesMap[trampOriginPC]
				if !ok {
					sa = &siteAccum{disp: trampOriginDisp, targets: make(map[uint32]uint64)}
					sitesMap[trampOriginPC] = sa
				}
				sa.targets[newPC]++
			}
			hasTrampOrigin = false
		}

		if op == 0x4E72 {
			// STOP #imm instruction
			srMask := (postRegs.SR >> 8) & 7
			woke := false
			if srMask < 7 && dev.chipset.CanWakeStop() {
				const ffBudget = CyclesPerFrame * 2
				const ffQuantum uint32 = 256
				var elapsed uint32
				for {
					ipl := dev.chipset.DeliverableIPL(dev.mem)
					if takeAutovectorInterrupt(cpu, dev, ipl) {
						servicedInts[ipl-1]++
						woke = true
						break
					}
					if elapsed >= ffBudget {
						break
					}
					dt := min(ffQuantum, ffBudget-elapsed)
					dev.chipset.Tick(dt, dev.mem)
					elapsed += dt
				}
			}
			if !woke {
				stop = StopReason{Kind: StopStopped, AtPC: pc, Step: steps}
				break
			}
		} else {
			ipl := dev.chipset.DeliverableIPL(dev.mem)
			if takeAutovectorInterrupt(cpu, dev, ipl) {
				servicedInts[ipl-1]++
			}
		}

		if dev.fault != nil {
			stop = StopReason{Kind: StopFault, Addr: *dev.fault, AtPC: pc, Step: steps}
			break
		}
	}

	siteAddrs := make([]uint32, 0, len(sitesMap))
	for addr := range sitesMap {
		siteAddrs = append(siteAddrs, addr)
	}
	slices.Sort(siteAddrs)
	sites := make([]DispatchSite, 0, len(siteAddrs))
	for _, addr := range siteAddrs {
		sa := sitesMap[addr]
		sites = append(sites, DispatchSite{
			Addr:    addr,
			Mode:    sa.disp.Mode,
			IsCall:  sa.disp.IsCall,
			BaseAn:  sa.disp.BaseAn,
			Targets: sa.targets,
		})
	}

	var vectors []VectorEntry
	for v := uint32(2); v < 64; v++ {
		h := dev.readLong(v*4) & 0x00FFFFFF
		if h != 0 {
			vectors = append(vectors, VectorEntry{Vec: uint8(v), Handler: h})
		}
	}

	return TraceReport{
		Entry:        entry,
		Base:         base,
		ImageLen:     len(image),
		Instructions: steps,
		DistinctPCs:  len(regs),
		PCLo:         pcLo,
		PCHi:         pcHi,
		ServicedInts: servicedInts,
		ServicedExcs: servicedExcs,
		Stop:         stop,
		Sites:        sites,
		Regs:         regs,
		Vectors:      vectors,
	}
}

// --- Analyzer trace integration methods ---

func isResolvableDispatchMode(mode m68k.EAMode) bool {
	switch mode {
	case m68k.EAAddrInd, m68k.EADisp16, m68k.EAIndex, m68k.EAPCIndex, m68k.EAAbsShort, m68k.EAAbsLong:
		return true
	default:
		return false
	}
}

func (a *Analyzer) isCodeCell(addr uint32) bool {
	c, err := a.DB.GetCell(addr)
	return err == nil && c != nil && c.Type.IsCode()
}

// TraceSeedTargets collects code seeds from trace-observed dispatch sites that land in a CODE segment.
func (a *Analyzer) TraceSeedTargets(sites []DispatchSite) []uint32 {
	var seeds []uint32
	for _, s := range sites {
		if !isResolvableDispatchMode(s.Mode) {
			continue
		}
		for target := range s.Targets {
			if a.IsInCodeSegment(target) {
				seeds = append(seeds, target)
			}
		}
	}
	slices.Sort(seeds)
	return slices.Compact(seeds)
}

// ApplyTraceDispatches applies trace-observed dispatch facts as non-byte-affecting annotations.
func (a *Analyzer) ApplyTraceDispatches(sites []DispatchSite) {
	for _, s := range sites {
		if !isResolvableDispatchMode(s.Mode) || !a.isCodeCell(s.Addr) {
			continue
		}
		var annotated []uint32
		for target := range s.Targets {
			if !a.isCodeCell(target) {
				continue
			}
			src := s.Addr
			a.AddLabel(&src, target)
			edge := db.EdgeUncond
			xref := db.XrefCodeBranch
			if s.IsCall {
				edge = db.EdgeCall
				xref = db.XrefCodeCall
				labelName := a.GetOrDefaultLabel(target)
				_ = a.DB.InsertFunction(target, labelName, ConfHigh)
			}
			_ = a.DB.InsertEdge(s.Addr, target, edge)
			_ = a.DB.InsertXref(s.Addr, target, xref)
			annotated = append(annotated, target)
		}
		if len(annotated) == 0 {
			continue
		}
		slices.Sort(annotated)
		names := make([]string, len(annotated))
		for i, t := range annotated {
			if lbl, ok := a.LabelsCache[t]; ok && lbl != "" {
				names[i] = lbl
			} else {
				names[i] = fmt.Sprintf("$%X", t)
			}
		}
		var frag string
		if len(names) == 1 {
			frag = fmt.Sprintf("-> %s (observed)", names[0])
		} else {
			frag = fmt.Sprintf("-> %d observed: %s", len(names), strings.Join(names, ", "))
		}
		a.appendCellComment(s.Addr, frag)
	}
}

// TraceVectorSeeds collects code seeds from trace-discovered interrupt/exception vectors.
func (a *Analyzer) TraceVectorSeeds(vectors []VectorEntry) []uint32 {
	var seeds []uint32
	for _, v := range vectors {
		if a.IsInCodeSegment(v.Handler) {
			seeds = append(seeds, v.Handler)
		}
	}
	slices.Sort(seeds)
	return slices.Compact(seeds)
}

// ApplyTraceVectors annotates trace-discovered interrupt/exception handlers.
func (a *Analyzer) ApplyTraceVectors(vectors []VectorEntry) {
	vecNames := amiga.GetM68kVectors()
	for _, v := range vectors {
		if !a.isCodeCell(v.Handler) {
			continue
		}
		a.AddLabel(nil, v.Handler)
		vecAddr := uint32(v.Vec) * 4
		var vlabel string
		if tn, ok := amiga.GetTrapName(vecAddr); ok {
			vlabel = tn
		} else if vn, ok := vecNames[vecAddr]; ok {
			vlabel = vn
		} else {
			vlabel = fmt.Sprintf("vector $%X", vecAddr)
		}
		a.appendCellComment(v.Handler, fmt.Sprintf("interrupt/exception handler (%s)", vlabel))
	}
}

// ApplyTraceHWRegs annotates hardware-register accesses observed during the trace.
func (a *Analyzer) ApplyTraceHWRegs(regs RegContext) {
	addrs := make([]uint32, 0, len(regs))
	for addr := range regs {
		addrs = append(addrs, addr)
	}
	slices.Sort(addrs)

	for _, addr := range addrs {
		regvals := regs[addr]
		cell, err := a.DB.GetCell(addr)
		if err != nil || cell == nil || !cell.Type.IsCode() {
			continue
		}
		cellComment := a.DB.GetAddressComment(addr).AutoComment
		insn, ok := a.DecodeValidInsn(addr, false)
		if !ok {
			continue
		}

		opSize := int64(2)
		if sz := insn.Suffix.Bytes(); sz != 0 {
			opSize = int64(sz)
		}

		for _, op := range insn.Operands() {
			if op.Reg > 7 {
				continue
			}
			idx := 8 + int(op.Reg)
			baseName := m68k.RegAName(op.Reg)
			var targetI64 int64
			var eaStr string
			switch op.Mode {
			case m68k.EAAddrInd:
				targetI64 = int64(regvals[idx])
				eaStr = fmt.Sprintf("(%s)", baseName)
			case m68k.EAPostInc:
				targetI64 = int64(regvals[idx])
				eaStr = fmt.Sprintf("(%s)+", baseName)
			case m68k.EAPreDec:
				targetI64 = int64(regvals[idx]) - opSize
				eaStr = fmt.Sprintf("-(%s)", baseName)
			case m68k.EADisp16:
				disp := int64(op.Disp)
				targetI64 = int64(regvals[idx]) + disp
				if disp == 0 {
					eaStr = fmt.Sprintf("(%s)", baseName)
				} else {
					eaStr = fmt.Sprintf("%d(%s)", disp, baseName)
				}
			default:
				continue
			}

			baseVal := regvals[idx]
			target := uint32(targetI64) & 0x00FFFFFF
			if hw, ok := amiga.GetAmigaHWLabelSub(target); ok {
				prefix := fmt.Sprintf("%s = ", eaStr)
				already := false
				for _, part := range strings.Split(cellComment, "; ") {
					if strings.HasPrefix(part, prefix) {
						already = true
						break
					}
				}
				if already {
					continue
				}
				frag := fmt.Sprintf("%s = %s (observed %s=%#08X)", eaStr, hw, baseName, baseVal)
				a.appendCellComment(addr, frag)
				if cellComment == "" {
					cellComment = frag
				} else {
					cellComment += "; " + frag
				}
			}
		}
	}
}

// ApplyTraceRegDispatches resolves indirect `JMP`/`JSR` dispatch sites from the trace's
// observed per-PC register file (ANALYZER_HEURISTICS_SPEC.md §3.6).
//
// Where static base-register propagation left an indirect dispatch through `(An)`,
// `d16(An)`, or `d8(An,Xn)` unresolved (no existing control-flow edge from the site), the
// concrete base value the trace observed in `regs[pc]` is used to compute the target. A
// resolved in-segment code target is recorded as a ConfHigh (trace-observed, not
// ConfDefinite) CALL/UNCOND edge + XREF with a `-> target (trace)` comment. It never
// overrides a statically resolved edge and changes no payload bytes.
func (a *Analyzer) ApplyTraceRegDispatches(regs RegContext) {
	addrs := make([]uint32, 0, len(regs))
	for addr := range regs {
		addrs = append(addrs, addr)
	}
	slices.Sort(addrs)

	for _, addr := range addrs {
		cell, err := a.DB.GetCell(addr)
		if err != nil || cell == nil || !cell.Type.IsCode() {
			continue
		}
		insn, ok := a.DecodeValidInsn(addr, false)
		if !ok {
			continue
		}
		if insn.Op != m68k.OpJMP && insn.Op != m68k.OpJSR {
			continue
		}
		if insn.NumOps == 0 {
			continue
		}
		op := insn.Ops[0]
		if op.Reg > 7 {
			continue
		}
		// Only An-relative indirect modes have an observable base register here;
		// PC-relative and absolute modes are resolved statically.
		switch op.Mode {
		case m68k.EAAddrInd, m68k.EADisp16, m68k.EAIndex:
		default:
			continue
		}
		// Skip sites static analysis already resolved.
		if _, resolved := a.DB.FirstControlEdgeTarget(addr); resolved {
			continue
		}

		baseVal := regs[addr][8+int(op.Reg)]
		target := uint32(int64(baseVal)+int64(op.Disp)) & 0x00FFFFFF
		if target%2 != 0 || !a.IsInCodeSegment(target) {
			continue
		}

		isCall := insn.Op == m68k.OpJSR
		src := addr
		a.AddLabel(&src, target)
		if isCall {
			_ = a.DB.InsertEdge(addr, target, db.EdgeCall)
			_ = a.DB.InsertXref(addr, target, db.XrefCodeCall)
			labelName := a.GetOrDefaultLabel(target)
			_ = a.DB.InsertFunction(target, labelName, ConfHigh)
		} else {
			_ = a.DB.InsertEdge(addr, target, db.EdgeUncond)
			_ = a.DB.InsertXref(addr, target, db.XrefCodeBranch)
		}
		name := a.GetOrDefaultLabel(target)
		a.appendCellComment(addr, fmt.Sprintf("-> %s (trace)", name))
	}
}
