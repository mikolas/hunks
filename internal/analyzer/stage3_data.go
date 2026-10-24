package analyzer

import (
	"cmp"
	"slices"

	"github.com/mikolas/hunks/internal/db"
	"github.com/mikolas/hunks/internal/hunk"
)

// stage3ClassifyData partitions all remaining unmapped byte ranges in non-BSS segments
// into structured data cells (`DATA_B`, `DATA_W`, `DATA_L`, `POINTER`, `STRING`, `DATA_ZERO`).
//
// Every multi-byte cell (strings, zero-runs, 32-bit longs, 16-bit words) is strictly bounded
// by existing labels (`labelAddrs`) and relocation sites (`a.Relocs`) so that no data item
// ever crosses a symbolic label or splits a relocated 32-bit pointer.
func (a *Analyzer) stage3ClassifyData() {
	_ = a.DB.DeleteNoncodeCellsBelowConf(100)

	hunkMode := len(a.Relocs) > 0
	if !hunkMode {
		a.harvestFlatPointerClusters()
	}

	a.RefreshCaches()
	labelAddrs := make(map[uint32]struct{}, len(a.LabelsCache))
	for addr := range a.LabelsCache {
		labelAddrs[addr] = struct{}{}
	}

	a.DB.Begin()

	prevActiveSeg := a.DB.ActiveSeg()
	for segIdx := range a.Segments {
		segType := a.Segments[segIdx].HunkType
		if segType == hunk.HunkTypeBss {
			continue
		}
		segName := a.Segments[segIdx].Name
		segBase := a.Segments[segIdx].Base
		segEnd := a.Segments[segIdx].End
		segData := a.Segments[segIdx].Data
		dataLen := len(segData)
		a.DB.SetActiveSeg(segName)
		gaps := a.GetUnmappedGapsInRange(segBase, segEnd)

		for _, gap := range gaps {
			start := gap.Start
			end := gap.End
			addr := start
			for addr < end {
				off := int(addr - segBase)
				if off >= dataLen {
					break
				}

				// 1. Odd alignment -> 1-byte DATA_B
				if addr%2 != 0 {
					_ = a.DB.InsertCell(&db.Cell{
						Seg:        segName,
						Addr:       addr,
						Size:       1,
						Type:       db.CellDataB,
						Confidence: ConfLow,
						RawBytes:   segData[off : off+1],
					})
					addr++
					continue
				}

				// 2. Relocated 32-bit pointer from HUNK_RELOC32
				if targetVal, ok := a.Relocs[addr]; ok && addr+4 <= end && off+4 <= dataLen {
					label := a.GetLabelName(targetVal)
					var opStr *string
					if label != "" {
						opStr = &label
					}
					_ = a.DB.InsertCell(&db.Cell{
						Seg:        segName,
						Addr:       addr,
						Size:       4,
						Type:       db.CellPointer,
						Confidence: ConfHigh,
						OpStr:      opStr,
						RawBytes:   segData[off : off+4],
					})
					_ = a.DB.InsertXref(addr, targetVal, db.XrefDataAddr)
					addr += 4
					continue
				}

				// 3. Printable ASCII string (>= 4 printable characters + null byte), never crossing a label or reloc
				maxAvail := min(int(end-addr), dataLen-off)
				asciiLen := 0
				for asciiLen < maxAvail {
					curA := addr + uint32(asciiLen)
					if asciiLen > 0 {
						if _, hasReloc := a.Relocs[curA]; hasReloc {
							break
						}
						if _, hasLbl := labelAddrs[curA]; hasLbl {
							break
						}
					}
					b := segData[off+asciiLen]
					if (b >= 0x20 && b <= 0x7E) || b == '\t' || b == '\r' || b == '\n' {
						asciiLen++
					} else {
						break
					}
				}

				if asciiLen >= 4 && asciiLen < maxAvail && segData[off+asciiLen] == 0 {
					nullA := addr + uint32(asciiLen)
					_, nullReloc := a.Relocs[nullA]
					_, nullLbl := labelAddrs[nullA]
					if !nullReloc && !nullLbl {
						totalStrLen := asciiLen + 1
						_ = a.DB.InsertCell(&db.Cell{
							Seg:        segName,
							Addr:       addr,
							Size:       uint32(totalStrLen),
							Type:       db.CellStr,
							Confidence: ConfMedium,
							RawBytes:   segData[off : off+totalStrLen],
						})
						addr += uint32(totalStrLen)
						continue
					}
				}

				// 4. Zero Run (>= 4 zero bytes), never crossing a label or reloc
				zeroLen := 0
				for zeroLen < maxAvail && segData[off+zeroLen] == 0 {
					curA := addr + uint32(zeroLen)
					if zeroLen > 0 {
						if _, hasReloc := a.Relocs[curA]; hasReloc {
							break
						}
						if _, hasLbl := labelAddrs[curA]; hasLbl {
							break
						}
					}
					zeroLen++
				}

				if zeroLen >= 4 {
					numLongs := zeroLen / 4
					zeroSize := uint32(numLongs * 4)
					_ = a.DB.InsertCell(&db.Cell{
						Seg:        segName,
						Addr:       addr,
						Size:       zeroSize,
						Type:       db.CellDataZero,
						Confidence: ConfLow,
						RawBytes:   segData[off : off+int(zeroSize)],
					})
					addr += zeroSize
					continue
				}

				// 5. Default structured data: DATA_L, DATA_W, or DATA_B (splitting at any label or reloc)
				_, r1 := a.Relocs[addr+1]
				_, r2 := a.Relocs[addr+2]
				_, r3 := a.Relocs[addr+3]
				_, l1 := labelAddrs[addr+1]
				_, l2 := labelAddrs[addr+2]
				_, l3 := labelAddrs[addr+3]

				if addr+4 <= end && off+4 <= dataLen && !r1 && !r2 && !r3 && !l1 && !l2 && !l3 {
					_ = a.DB.InsertCell(&db.Cell{
						Seg:        segName,
						Addr:       addr,
						Size:       4,
						Type:       db.CellDataL,
						Confidence: ConfLow,
						RawBytes:   segData[off : off+4],
					})
					addr += 4
				} else if addr+2 <= end && off+2 <= dataLen && !r1 && !l1 {
					_ = a.DB.InsertCell(&db.Cell{
						Seg:        segName,
						Addr:       addr,
						Size:       2,
						Type:       db.CellDataW,
						Confidence: ConfLow,
						RawBytes:   segData[off : off+2],
					})
					addr += 2
				} else {
					_ = a.DB.InsertCell(&db.Cell{
						Seg:        segName,
						Addr:       addr,
						Size:       1,
						Type:       db.CellDataB,
						Confidence: ConfLow,
						RawBytes:   segData[off : off+1],
					})
					addr++
				}
			}
		}
	}
	a.DB.SetActiveSeg(prevActiveSeg)
	a.DB.Commit()
}

type ptrPair struct {
	addr uint32
	val  uint32
}

// harvestFlatPointerClusters scans unmapped gaps in non-relocatable flat segments for
// contiguous runs of at least 3 valid 32-bit segment pointers (`scanFlatPointerCluster`),
// marking them as `CellPointer` (or `CellDataL` for null sentinels) and seeding labels
// at their target addresses before general Stage 3 data classification runs.
func (a *Analyzer) harvestFlatPointerClusters() {
	a.cellRanges = nil
	a.cellRangesLoaded = false
	labelAddrs := make(map[uint32]struct{})
	for _, la := range a.DB.LabelAddrs(nil) {
		labelAddrs[la] = struct{}{}
	}

	a.DB.Begin()
	prevActiveSeg := a.DB.ActiveSeg()
	totalMarked := uint32(0)
	for _, seg := range a.Segments {
		if seg.HunkType == hunk.HunkTypeBss || seg.Relocatable {
			continue
		}
		a.DB.SetActiveSeg(seg.Name)
		gaps := a.GetUnmappedGapsInRange(seg.Base, seg.End)
		for _, gap := range gaps {
			addr := gap.Start
			if addr%2 != 0 {
				addr++
			}
			for addr+4 <= gap.End {
				if totalMarked >= 500 {
					a.DB.SetActiveSeg(prevActiveSeg)
					a.DB.Commit()
					return
				}
				if val, ok := a.ReadU32(addr); ok && val != 0 && a.IsInAnySegment(val) && val%2 == 0 {
					cluster := a.scanFlatPointerCluster(addr, gap.End, labelAddrs)
					if len(cluster) >= 3 {
						for _, p := range cluster {
							b := a.ReadBytes(p.addr, 4)
							if len(b) != 4 {
								continue
							}
							ct := db.CellPointer
							if p.val == 0 {
								ct = db.CellDataL
							}
							_ = a.DB.InsertCell(&db.Cell{
								Seg:        seg.Name,
								Addr:       p.addr,
								Size:       4,
								Type:       ct,
								Confidence: ConfLow,
								RawBytes:   b,
							})
							if p.val != 0 {
								src := p.addr
								a.AddLabel(&src, p.val)
								_ = a.DB.InsertXref(p.addr, p.val, db.XrefDataAddr)
								labelAddrs[p.val] = struct{}{}
							}
							totalMarked++
						}
						a.cellRanges = nil
						a.cellRangesLoaded = false
						addr = cluster[len(cluster)-1].addr + 4
						continue
					}
				}
				addr += 2
			}
		}
	}
	a.DB.SetActiveSeg(prevActiveSeg)
	a.DB.Commit()
}

func (a *Analyzer) scanFlatPointerCluster(start, end uint32, labelAddrs map[uint32]struct{}) []ptrPair {
	var cluster []ptrPair
	addr := start
	validCount := 0

	for addr+4 <= end {
		_, l1 := labelAddrs[addr+1]
		_, l2 := labelAddrs[addr+2]
		_, l3 := labelAddrs[addr+3]
		if l1 || l2 || l3 {
			break
		}
		val, ok := a.ReadU32(addr)
		if !ok {
			break
		}
		if val == 0 {
			cluster = append(cluster, ptrPair{addr: addr, val: 0})
			addr += 4
			continue
		}
		if a.IsInAnySegment(val) && val%2 == 0 && !a.PointsMidCell(val) {
			cluster = append(cluster, ptrPair{addr: addr, val: val})
			validCount++
			addr += 4
		} else {
			break
		}
	}

	if validCount >= 3 {
		return cluster
	}
	return nil
}

// PointsMidCell returns true if val lands strictly inside an already-decoded cell (c.Addr != val).
func (a *Analyzer) PointsMidCell(val uint32) bool {
	if !a.cellRangesLoaded {
		a.cellRanges = a.DB.SpaceCellRanges()
		a.cellRangesLoaded = true
	}
	idx, found := slices.BinarySearchFunc(a.cellRanges, val, func(r db.AddrRange, target uint32) int {
		return cmp.Compare(r.Start, target)
	})
	if found {
		return false
	}
	if idx > 0 {
		prev := a.cellRanges[idx-1]
		if val > prev.Start && val < prev.End {
			return true
		}
	}
	return false
}
