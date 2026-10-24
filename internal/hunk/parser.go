// Package hunk parses AmigaDOS LoadSeg() multi-hunk executables (HUNK_HEADER 0x03F3).
//
// It extracts per-hunk memory attributes (Public, Chip, Fast), advertised allocation
// sizes, initialized payloads (HUNK_CODE, HUNK_DATA, HUNK_BSS), 32-bit relocation
// tables (HUNK_RELOC32, HUNK_DREL32, HUNK_RELOC32SHORT), and symbol tables
// (HUNK_SYMBOL), and computes disjoint synthetic base addresses so all hunks can share
// a unified 32-bit analysis address space.
package hunk

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
)

const (
	HunkName         uint32 = 0x03E8
	HunkCode         uint32 = 0x03E9
	HunkData         uint32 = 0x03EA
	HunkBss          uint32 = 0x03EB
	HunkReloc32      uint32 = 0x03EC
	HunkReloc16      uint32 = 0x03ED
	HunkReloc8       uint32 = 0x03EE
	HunkExt          uint32 = 0x03EF
	HunkSymbol       uint32 = 0x03F0
	HunkDebug        uint32 = 0x03F1
	HunkEnd          uint32 = 0x03F2
	HunkHeader       uint32 = 0x03F3
	HunkDRel32       uint32 = 0x03F7
	HunkDRel16       uint32 = 0x03F8
	HunkDRel8        uint32 = 0x03F9
	HunkReloc32Short uint32 = 0x03FC
	HunkRelReloc32   uint32 = 0x03FD

	HunkSizeMask uint32 = 0x3FFFFFFF
	MemfChipFlag uint32 = 0x40000000
	MemfFastFlag uint32 = 0x80000000
)

type HunkType string

const (
	HunkTypeCode HunkType = "Code"
	HunkTypeData HunkType = "Data"
	HunkTypeBss  HunkType = "Bss"
)

func (h HunkType) ToVasmType() string {
	switch h {
	case HunkTypeData:
		return "DATA"
	case HunkTypeBss:
		return "BSS"
	default:
		return "CODE"
	}
}

func (h *HunkType) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	switch HunkType(s) {
	case "", HunkTypeCode:
		*h = HunkTypeCode
	case HunkTypeData:
		*h = HunkTypeData
	case HunkTypeBss:
		*h = HunkTypeBss
	default:
		return fmt.Errorf("unknown HunkType %q", s)
	}
	return nil
}

type MemoryType string

const (
	MemoryPublic MemoryType = "Public"
	MemoryChip   MemoryType = "Chip"
	MemoryFast   MemoryType = "Fast"
)

func MemoryTypeFromRaw(raw uint32) MemoryType {
	if (raw & MemfChipFlag) != 0 {
		return MemoryChip
	}
	if (raw & MemfFastFlag) != 0 {
		return MemoryFast
	}
	return MemoryPublic
}

func (m MemoryType) ToVasmAttr() string {
	switch m {
	case MemoryChip:
		return ",CHIP"
	case MemoryFast:
		return ",FAST"
	default:
		return ""
	}
}

func (m *MemoryType) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	switch MemoryType(s) {
	case "", MemoryPublic:
		*m = MemoryPublic
	case MemoryChip:
		*m = MemoryChip
	case MemoryFast:
		*m = MemoryFast
	default:
		return fmt.Errorf("unknown MemoryType %q", s)
	}
	return nil
}

type RelocationBlock struct {
	TargetHunk int
	Offsets    []uint32
}

type SymbolEntry struct {
	Name   string
	Offset uint32
}

// ParsedHunk holds the parsed contents and metadata of a single hunk in an AmigaDOS executable.
//
// AllocSize is the full runtime allocation in bytes from HUNK_HEADER (or the hunk body tag when
// the header size is 0), whereas FileDataLen is the on-disk byte length of the HUNK_CODE or
// HUNK_DATA payload before any zero-extended BSS tail.
type ParsedHunk struct {
	Index       int
	HunkType    HunkType
	MemoryType  MemoryType
	AllocSize   uint32
	FileDataLen int
	Data        []byte
	Reloc32     []RelocationBlock
	Symbols     []SymbolEntry
}

// ParsedHunkFile represents a complete parsed AmigaDOS multi-hunk executable.
type ParsedHunkFile struct {
	TableSize uint32
	FirstHunk int
	LastHunk  int
	Hunks     []ParsedHunk
}

// CalculateSyntheticBases assigns a deterministic, non-overlapping synthetic base address
// to each hunk in sequential order. Even zero-length hunks advance the next base by at
// least 4 bytes so that every hunk has a distinct base address in the shared address space.
func (f *ParsedHunkFile) CalculateSyntheticBases() []uint32 {
	bases := make([]uint32, 0, len(f.Hunks))
	var currentBase uint32
	for _, h := range f.Hunks {
		bases = append(bases, currentBase)
		step := h.AllocSize
		if step < 4 {
			step = 4
		}
		currentBase += step
	}
	return bases
}

func (f *ParsedHunkFile) TotalRelocations() int {
	total := 0
	for _, h := range f.Hunks {
		for _, r := range h.Reloc32 {
			total += len(r.Offsets)
		}
	}
	return total
}

type hunkReader struct {
	data []byte
	pos  int
}

func (r *hunkReader) remaining() int {
	if r.pos >= len(r.data) {
		return 0
	}
	return len(r.data) - r.pos
}

func (r *hunkReader) readU32() (uint32, error) {
	if r.remaining() < 4 {
		return 0, fmt.Errorf("unexpected EOF reading u32 at offset 0x%X (total size: 0x%X)", r.pos, len(r.data))
	}
	v := binary.BigEndian.Uint32(r.data[r.pos : r.pos+4])
	r.pos += 4
	return v, nil
}

func (r *hunkReader) readU16() (uint16, error) {
	if r.remaining() < 2 {
		return 0, fmt.Errorf("unexpected EOF reading u16 at offset 0x%X (total size: 0x%X)", r.pos, len(r.data))
	}
	v := binary.BigEndian.Uint16(r.data[r.pos : r.pos+2])
	r.pos += 2
	return v, nil
}

func (r *hunkReader) readBytes(length int) ([]byte, error) {
	if r.remaining() < length {
		return nil, fmt.Errorf("unexpected EOF reading %d bytes at offset 0x%X (total size: 0x%X)", length, r.pos, len(r.data))
	}
	slice := r.data[r.pos : r.pos+length]
	r.pos += length
	return slice, nil
}

func (r *hunkReader) alignWord() {
	r.pos = (r.pos + 3) & ^3
}

func (r *hunkReader) skip(length int) error {
	if r.remaining() < length {
		return fmt.Errorf("unexpected EOF skipping %d bytes at offset 0x%X (total size: 0x%X)", length, r.pos, len(r.data))
	}
	r.pos += length
	return nil
}

// ParseHunkFile parses an AmigaDOS HUNK_HEADER executable image into its constituent hunks.
//
// Key format subtleties handled during parsing:
//   - Upper bits 30 and 31 on hunk size/tag longwords encode MEMF_CHIP and MEMF_FAST;
//     the low 30 bits (HunkSizeMask) give the longword count or tag ID.
//   - HUNK_DREL32 (0x03F7) and HUNK_RELOC32SHORT (0x03FC) pack count, target hunk, and
//     relocation offsets as 16-bit big-endian words, padded to a 32-bit longword boundary
//     after the terminating zero count word.
//   - Linkers may emit HUNK_CODE or HUNK_DATA blocks whose on-disk payload is shorter than
//     the HUNK_HEADER allocation size; ParseHunkFile zero-pads Data up to AllocSize for
//     in-bounds analysis while preserving the original FileDataLen so the emitter can emit
//     `dx.l`/`dx.b` for the uninitialized tail.
func ParseHunkFile(data []byte) (*ParsedHunkFile, error) {
	reader := &hunkReader{data: data}
	headerMagic, err := reader.readU32()
	if err != nil {
		return nil, fmt.Errorf("failed to read header magic: %w", err)
	}
	if (headerMagic & HunkSizeMask) != HunkHeader {
		return nil, fmt.Errorf("invalid hunk magic: expected 0x%04X, found 0x%04X", HunkHeader, headerMagic)
	}

	// Resident library names string table (if any)
	for {
		strLen, err := reader.readU32()
		if err != nil {
			return nil, fmt.Errorf("failed to read resident string length: %w", err)
		}
		if strLen == 0 {
			break
		}
		if err := reader.skip(int(strLen) * 4); err != nil {
			return nil, err
		}
	}

	tableSize, err := reader.readU32()
	if err != nil {
		return nil, fmt.Errorf("failed to read table size: %w", err)
	}
	firstU32, err := reader.readU32()
	if err != nil {
		return nil, fmt.Errorf("failed to read first hunk index: %w", err)
	}
	lastU32, err := reader.readU32()
	if err != nil {
		return nil, fmt.Errorf("failed to read last hunk index: %w", err)
	}
	firstHunk := int(firstU32)
	lastHunk := int(lastU32)
	if lastHunk < firstHunk {
		return nil, fmt.Errorf("invalid hunk range in header: first=%d, last=%d", firstHunk, lastHunk)
	}
	numHunks := lastHunk - firstHunk + 1

	type hunkHeaderDef struct {
		allocSize  uint32
		memoryType MemoryType
	}
	headerDefs := make([]hunkHeaderDef, 0, numHunks)
	for i := 0; i < numHunks; i++ {
		raw, err := reader.readU32()
		if err != nil {
			return nil, fmt.Errorf("failed to read header size for hunk %d: %w", firstHunk+i, err)
		}
		headerDefs = append(headerDefs, hunkHeaderDef{
			allocSize:  (raw & HunkSizeMask) * 4,
			memoryType: MemoryTypeFromRaw(raw),
		})
	}

	parsedHunks := make([]ParsedHunk, 0, numHunks)
	for hunkIdx, hDef := range headerDefs {
		hunkType := HunkTypeCode
		memoryType := hDef.memoryType
		allocSize := hDef.allocSize
		fileDataLen := 0
		var hunkData []byte
		var reloc32 []RelocationBlock
		var symbols []SymbolEntry

		for reader.remaining() > 0 {
			tagRaw, err := reader.readU32()
			if err != nil {
				return nil, fmt.Errorf("failed to read tag for hunk %d: %w", firstHunk+hunkIdx, err)
			}
			tagMem := MemoryTypeFromRaw(tagRaw)
			if tagMem != MemoryPublic && memoryType == MemoryPublic {
				memoryType = tagMem
			}
			tag := tagRaw & HunkSizeMask

			switch tag {
			case HunkName:
				slen, err := reader.readU32()
				if err != nil {
					return nil, err
				}
				if err := reader.skip(int(slen) * 4); err != nil {
					return nil, err
				}
			case HunkCode:
				hunkType = HunkTypeCode
				numLongsRaw, err := reader.readU32()
				if err != nil {
					return nil, err
				}
				byteLen := int(numLongsRaw&HunkSizeMask) * 4
				b, err := reader.readBytes(byteLen)
				if err != nil {
					return nil, err
				}
				hunkData = append([]byte(nil), b...)
				fileDataLen = byteLen
				if allocSize == 0 {
					allocSize = uint32(byteLen)
				}
			case HunkData:
				hunkType = HunkTypeData
				numLongsRaw, err := reader.readU32()
				if err != nil {
					return nil, err
				}
				byteLen := int(numLongsRaw&HunkSizeMask) * 4
				b, err := reader.readBytes(byteLen)
				if err != nil {
					return nil, err
				}
				hunkData = append([]byte(nil), b...)
				fileDataLen = byteLen
				if allocSize == 0 {
					allocSize = uint32(byteLen)
				}
			case HunkBss:
				hunkType = HunkTypeBss
				numLongsRaw, err := reader.readU32()
				if err != nil {
					return nil, err
				}
				byteLen := (numLongsRaw & HunkSizeMask) * 4
				if allocSize == 0 {
					allocSize = byteLen
				}
				fileDataLen = 0
				hunkData = nil
			case HunkReloc32:
				for {
					count, err := reader.readU32()
					if err != nil {
						return nil, err
					}
					if count == 0 {
						break
					}
					targetHunk, err := reader.readU32()
					if err != nil {
						return nil, err
					}
					offsets := make([]uint32, 0, count)
					for i := uint32(0); i < count; i++ {
						off, err := reader.readU32()
						if err != nil {
							return nil, err
						}
						offsets = append(offsets, off)
					}
					reloc32 = append(reloc32, RelocationBlock{
						TargetHunk: int(targetHunk),
						Offsets:    offsets,
					})
				}
			case HunkDRel32, HunkReloc32Short:
				for {
					count, err := reader.readU16()
					if err != nil {
						return nil, err
					}
					if count == 0 {
						break
					}
					targetHunk, err := reader.readU16()
					if err != nil {
						return nil, err
					}
					offsets := make([]uint32, 0, count)
					for i := uint16(0); i < count; i++ {
						off, err := reader.readU16()
						if err != nil {
							return nil, err
						}
						offsets = append(offsets, uint32(off))
					}
					reloc32 = append(reloc32, RelocationBlock{
						TargetHunk: int(targetHunk),
						Offsets:    offsets,
					})
				}
				reader.alignWord()
			case HunkSymbol:
				for {
					slen, err := reader.readU32()
					if err != nil {
						return nil, err
					}
					if slen == 0 {
						break
					}
					nameBytes, err := reader.readBytes(int(slen) * 4)
					if err != nil {
						return nil, err
					}
					end := bytes.IndexByte(nameBytes, 0)
					if end < 0 {
						end = len(nameBytes)
					}
					name := string(nameBytes[:end])
					sval, err := reader.readU32()
					if err != nil {
						return nil, err
					}
					if name != "" {
						symbols = append(symbols, SymbolEntry{Name: name, Offset: sval})
					}
				}
			case HunkDebug:
				dlen, err := reader.readU32()
				if err != nil {
					return nil, err
				}
				if err := reader.skip(int(dlen) * 4); err != nil {
					return nil, err
				}
			case HunkEnd:
				goto nextHunk
			default:
				return nil, fmt.Errorf("unsupported or unrecognized hunk tag 0x%04X at offset 0x%X in hunk %d", tag, reader.pos-4, firstHunk+hunkIdx)
			}
		}
	nextHunk:
		if int(allocSize) > len(hunkData) && hunkType != HunkTypeBss {
			padded := make([]byte, int(allocSize))
			copy(padded, hunkData)
			hunkData = padded
		}

		parsedHunks = append(parsedHunks, ParsedHunk{
			Index:       firstHunk + hunkIdx,
			HunkType:    hunkType,
			MemoryType:  memoryType,
			AllocSize:   allocSize,
			FileDataLen: fileDataLen,
			Data:        hunkData,
			Reloc32:     reloc32,
			Symbols:     symbols,
		})
	}

	return &ParsedHunkFile{
		TableSize: tableSize,
		FirstHunk: firstHunk,
		LastHunk:  lastHunk,
		Hunks:     parsedHunks,
	}, nil
}
