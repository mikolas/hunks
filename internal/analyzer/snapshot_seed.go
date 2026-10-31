package analyzer

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/mikolas/hunks/internal/amiga"
	"github.com/mikolas/hunks/internal/db"
	"github.com/mikolas/hunks/internal/m68k"
	"github.com/mikolas/hunks/internal/project"
)

// SeedSummary reports the symbols and entry points seeded from a captured GDB snapshot.
type SeedSummary struct {
	EntryPC      uint32
	VectorSeeds  []string
	StackSeeds   []uint32
	BaseRegHints []string
	CustomLabels []string
}

// SeedFromSnapshot seeds entry points, interrupt/trap handler labels, stack return addresses,
// base-register hints ($DFF000), and custom chip DMA pointer labels (COP1LC, COP2LC, BPLxPT, SPRxPT)
// from `proj.Data.Snapshot` into `proj` and `ctrl`.
func SeedFromSnapshot(proj *project.Project, ctrl *db.Controller) SeedSummary {
	var summary SeedSummary
	if proj == nil || proj.Data.Snapshot == nil || ctrl == nil {
		return summary
	}
	snap := proj.Data.Snapshot

	segDataMap := make(map[string][]byte, len(proj.Data.Segments))
	for i := range proj.Data.Segments {
		seg := &proj.Data.Segments[i]
		segDataMap[seg.Name] = seg.LoadBinaryData()
	}

	readBytesAt := func(addr uint32, length int) ([]byte, *project.Segment) {
		seg := proj.SegmentAtAddr(addr)
		if seg == nil {
			return nil, nil
		}
		data := segDataMap[seg.Name]
		off := int(addr - seg.Base)
		if off < 0 || off+length > len(data) {
			return nil, nil
		}
		return data[off : off+length], seg
	}

	hasEntryPoint := func(addr uint32) bool {
		for _, ep := range proj.Data.EntryPoints {
			if ep.Addr == addr {
				return true
			}
		}
		return false
	}

	addCodeEntry := func(addr uint32, preferredName string) bool {
		addr &= 0x00FFFFFE
		raw, seg := readBytesAt(addr, 2)
		if seg == nil || len(raw) < 2 {
			return false
		}
		if binary.BigEndian.Uint16(raw) == 0x0000 {
			return false
		}
		name := preferredName
		if name == "" {
			name = proj.AutoLabel(addr)
		}
		if !hasEntryPoint(addr) {
			proj.Data.EntryPoints = append(proj.Data.EntryPoints, project.EntryPoint{
				Addr:    addr,
				Name:    name,
				Segment: seg.Name,
			})
		}
		ctrl.WithActiveSeg(seg.Name, func() {
			if existing, ok, _ := ctrl.GetLabel(addr); !ok || existing == "" || strings.HasPrefix(existing, "LAB_") {
				isAuto := preferredName == "" || strings.HasPrefix(preferredName, "LAB_")
				_ = ctrl.SetLabel(addr, name, db.LabelLab, isAuto)
			}
		})
		return true
	}

	setDataLabelIfUnset := func(addr uint32, name string) bool {
		addr &= 0x00FFFFFE
		if addr == 0 {
			return false
		}
		_, seg := readBytesAt(addr, 2)
		if seg == nil {
			return false
		}
		added := false
		ctrl.WithActiveSeg(seg.Name, func() {
			if existing, ok, _ := ctrl.GetLabel(addr); !ok || existing == "" {
				_ = ctrl.SetLabel(addr, name, db.LabelDat, false)
				added = true
			}
		})
		return added
	}

	// 1. Live PC Entry Point
	pc := snap.PC & 0x00FFFFFF
	if pc%2 == 0 && addCodeEntry(pc, "Entry_PC") {
		summary.EntryPC = pc
	}

	// 2. Active M68k Autovectors ($64..$7C) and Trap Vectors ($80..$BC)
	for vecAddr := uint32(0x64); vecAddr < 0xC0; vecAddr += 4 {
		vecName, ok := amiga.GetM68kVectorLabel(vecAddr)
		if !ok {
			continue
		}
		raw, _ := readBytesAt(vecAddr, 4)
		if len(raw) < 4 {
			continue
		}
		handler := binary.BigEndian.Uint32(raw) & 0x00FFFFFF
		if handler == 0 || handler%2 != 0 {
			continue
		}
		handlerName := vecName + "_Handler"
		if addCodeEntry(handler, handlerName) {
			summary.VectorSeeds = append(summary.VectorSeeds, fmt.Sprintf("$%02X->%s(0x%X)", vecAddr, handlerName, handler))
		}
	}

	// 3. Active Stack Return-Address Discovery (A7)
	sp := snap.A[7] & 0x00FFFFFE
	if sp != 0 {
		for off := uint32(0); off < 128; off += 2 {
			raw, _ := readBytesAt(sp+off, 4)
			if len(raw) < 4 {
				break
			}
			retAddr := binary.BigEndian.Uint32(raw) & 0x00FFFFFF
			if retAddr < 6 || retAddr%2 != 0 {
				continue
			}
			// Check if 2, 4, or 6 bytes before retAddr is a valid BSR or JSR instruction.
			var matchedCall bool
			var callTarget uint32
			for _, insnLen := range []uint32{2, 4, 6} {
				callSite := retAddr - insnLen
				codeBytes, seg := readBytesAt(callSite, int(insnLen))
				if seg == nil || len(codeBytes) < int(insnLen) {
					continue
				}
				insn, ok := m68k.Decode(codeBytes, callSite)
				if !ok || uint32(insn.Size) != insnLen {
					continue
				}
				if insn.Op == m68k.OpBSR || insn.Op == m68k.OpJSR {
					matchedCall = true
					if insn.NumOps > 0 {
						switch insn.Ops[0].Mode {
						case m68k.EABranch, m68k.EAPCDisp16, m68k.EAAbsLong, m68k.EAAbsShort:
							callTarget = insn.Ops[0].UVal & 0x00FFFFFF
						}
					}
					break
				}
			}
			if matchedCall {
				if addCodeEntry(retAddr, "") {
					summary.StackSeeds = append(summary.StackSeeds, retAddr)
				}
				if callTarget != 0 && callTarget%2 == 0 {
					addCodeEntry(callTarget, "")
				}
			}
		}
	}

	// 4. Live Base Registers (A0..A6)
	for r := 0; r <= 6; r++ {
		val := snap.A[r] & 0x00FFFFFF
		if val == amiga.CustomBase {
			regName := fmt.Sprintf("a%d", r)
			_ = ctrl.SetBaseReg("global", "", regName, amiga.CustomBase, "hint")
			summary.BaseRegHints = append(summary.BaseRegHints, fmt.Sprintf("%s=0x%06X", regName, amiga.CustomBase))
		}
	}

	// 5. Custom Chip DMA Pointers ($DFF000..$DFF1FF)
	if custom, ok := proj.LoadCustomSnapshot(); ok {
		cop1 := custom.COP1LC()
		if setDataLabelIfUnset(cop1, "CopperList_1") {
			summary.CustomLabels = append(summary.CustomLabels, fmt.Sprintf("CopperList_1@0x%X", cop1))
		}
		cop2 := custom.COP2LC()
		if cop2 != cop1 && setDataLabelIfUnset(cop2, "CopperList_2") {
			summary.CustomLabels = append(summary.CustomLabels, fmt.Sprintf("CopperList_2@0x%X", cop2))
		}
		planes := custom.ActivePlanes()
		bpl := custom.BPLPT()
		for i := 0; i < min(planes, len(bpl)); i++ {
			lbl := fmt.Sprintf("Bitplane_%d", i+1)
			if setDataLabelIfUnset(bpl[i], lbl) {
				summary.CustomLabels = append(summary.CustomLabels, fmt.Sprintf("%s@0x%X", lbl, bpl[i]))
			}
		}
		spr := custom.SPRPT()
		for i := range spr {
			if spr[i] == 0 {
				continue
			}
			// Only label sprites whose 4-byte POS/CTL header is non-zero.
			if hdr, _ := readBytesAt(spr[i], 4); len(hdr) == 4 && binary.BigEndian.Uint32(hdr) != 0 {
				lbl := fmt.Sprintf("Sprite_%d", i)
				if setDataLabelIfUnset(spr[i], lbl) {
					summary.CustomLabels = append(summary.CustomLabels, fmt.Sprintf("%s@0x%X", lbl, spr[i]))
				}
			}
		}
	}

	return summary
}
