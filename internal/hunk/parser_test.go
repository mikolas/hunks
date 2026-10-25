package hunk

import (
	"encoding/binary"
	"reflect"
	"testing"
)

func TestParseSyntheticMultiHunkBinary(t *testing.T) {
	var raw []byte
	push := func(val uint32) {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], val)
		raw = append(raw, buf[:]...)
	}

	// HUNK_HEADER: 3 hunks (CODE public 8B, DATA chip 8B, BSS chip 64B)
	push(HunkHeader)
	push(0)              // resident libs
	push(3)              // table_size = 3
	push(0)              // first_hunk = 0
	push(2)              // last_hunk = 2
	push(2)              // hunk0: 2 longs (8B) public
	push((1 << 30) | 2)  // hunk1: 2 longs (8B) chip
	push((1 << 30) | 16) // hunk2: 16 longs (64B) chip

	// Hunk 0: CODE + RELOC32 to hunk 1
	push(HunkCode)
	push(2)
	push(0x20790000) // movea.l $00000004.l,a0
	push(0x00044E75) // ... ; rts
	push(HunkReloc32)
	push(1) // 1 offset
	push(1) // target hunk 1
	push(2) // offset 2
	push(0) // end relocs
	push(HunkEnd)

	// Hunk 1: DATA
	push(HunkData)
	push(2)
	push(0x11223344)
	push(0x55667788)
	push(HunkEnd)

	// Hunk 2: BSS
	push(HunkBss)
	push(16)
	push(HunkEnd)

	parsed, err := ParseHunkFile(raw)
	if err != nil {
		t.Fatalf("ParseHunkFile failed: %v", err)
	}
	if len(parsed.Hunks) != 3 {
		t.Fatalf("len(parsed.Hunks) = %d, want 3", len(parsed.Hunks))
	}
	if parsed.Hunks[0].HunkType != HunkTypeCode || parsed.Hunks[0].MemoryType != MemoryPublic {
		t.Errorf("unexpected hunk 0: %+v", parsed.Hunks[0])
	}
	if parsed.Hunks[1].HunkType != HunkTypeData || parsed.Hunks[1].MemoryType != MemoryChip {
		t.Errorf("unexpected hunk 1: %+v", parsed.Hunks[1])
	}
	if parsed.Hunks[2].HunkType != HunkTypeBss || parsed.Hunks[2].MemoryType != MemoryChip || parsed.Hunks[2].AllocSize != 64 {
		t.Errorf("unexpected hunk 2: %+v", parsed.Hunks[2])
	}
	if parsed.TotalRelocations() != 1 {
		t.Errorf("TotalRelocations() = %d, want 1", parsed.TotalRelocations())
	}
	bases := parsed.CalculateSyntheticBases()
	wantBases := []uint32{0, 8, 16}
	if !reflect.DeepEqual(bases, wantBases) {
		t.Errorf("bases = %v, want %v", bases, wantBases)
	}
}

func TestEmptyHunkSyntheticBases(t *testing.T) {
	parsed := &ParsedHunkFile{
		TableSize: 3,
		FirstHunk: 0,
		LastHunk:  2,
		Hunks: []ParsedHunk{
			{Index: 0, HunkType: HunkTypeCode, MemoryType: MemoryPublic, AllocSize: 0x20, FileDataLen: 0x20, Data: make([]byte, 0x20)},
			{Index: 1, HunkType: HunkTypeData, MemoryType: MemoryPublic, AllocSize: 0, FileDataLen: 0},
			{Index: 2, HunkType: HunkTypeBss, MemoryType: MemoryPublic, AllocSize: 0x10, FileDataLen: 0},
		},
	}
	bases := parsed.CalculateSyntheticBases()
	want := []uint32{0x00, 0x20, 0x24}
	if !reflect.DeepEqual(bases, want) {
		t.Errorf("CalculateSyntheticBases() = %v, want %v", bases, want)
	}
}

func TestHunkDataZeroExtendTail(t *testing.T) {
	var buf []byte
	putU32 := func(v uint32) {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], v)
		buf = append(buf, b[:]...)
	}
	putU32(0x3F3) // HUNK_HEADER
	putU32(0)     // strings
	putU32(1)     // table_size
	putU32(0)     // first_hunk
	putU32(0)     // last_hunk
	putU32(5)     // hunk 0 alloc_size = 5 longs (20 bytes)
	putU32(0x3EA) // HUNK_DATA
	putU32(2)     // 2 longs in file (8 bytes)
	buf = append(buf, 1, 2, 3, 4, 5, 6, 7, 8)
	putU32(0x3F2) // HUNK_END

	parsed, err := ParseHunkFile(buf)
	if err != nil {
		t.Fatalf("ParseHunkFile failed: %v", err)
	}
	if len(parsed.Hunks) != 1 {
		t.Fatalf("len(Hunks) = %d, want 1", len(parsed.Hunks))
	}
	h := parsed.Hunks[0]
	if h.AllocSize != 20 || h.FileDataLen != 8 || len(h.Data) != 20 {
		t.Fatalf("alloc=%d fileDataLen=%d len(Data)=%d, want 20, 8, 20", h.AllocSize, h.FileDataLen, len(h.Data))
	}
	if !reflect.DeepEqual(h.Data[:8], []byte{1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Errorf("Data[:8] = %v", h.Data[:8])
	}
	if !reflect.DeepEqual(h.Data[8:], make([]byte, 12)) {
		t.Errorf("Data[8:] not zero-filled: %v", h.Data[8:])
	}
}

func TestDRel32ShortRelocAndSymbolCapture(t *testing.T) {
	var buf []byte
	putU32 := func(v uint32) {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], v)
		buf = append(buf, b[:]...)
	}
	putU16 := func(v uint16) {
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], v)
		buf = append(buf, b[:]...)
	}
	putU32(0x3F3) // HUNK_HEADER
	putU32(0)     // strings
	putU32(1)     // table_size
	putU32(0)     // first_hunk
	putU32(0)     // last_hunk
	putU32(4)     // hunk 0 alloc = 4 longs (16 bytes)
	putU32(0x3E9) // HUNK_CODE
	putU32(4)     // 4 longs file data
	buf = append(buf, make([]byte, 16)...)

	// HUNK_DREL32 (0x3F7): 16-bit count=2, target_hunk=0, offsets 0x0004, 0x0008; then count=0; pad.
	putU32(0x3F7)
	putU16(2)
	putU16(0)
	putU16(0x0004)
	putU16(0x0008)
	putU16(0)
	putU16(0)

	// HUNK_SYMBOL: one symbol "main" (1 long name) @ offset 0x0004; then 0.
	putU32(0x3F0)
	putU32(1)
	buf = append(buf, []byte("main")...)
	putU32(0x0004)
	putU32(0)

	putU32(0x3F2) // HUNK_END

	parsed, err := ParseHunkFile(buf)
	if err != nil {
		t.Fatalf("ParseHunkFile failed: %v", err)
	}
	if len(parsed.Hunks) != 1 {
		t.Fatalf("len(Hunks) = %d, want 1", len(parsed.Hunks))
	}
	h := parsed.Hunks[0]
	if len(h.Reloc32) != 1 || h.Reloc32[0].TargetHunk != 0 || !reflect.DeepEqual(h.Reloc32[0].Offsets, []uint32{0x0004, 0x0008}) {
		t.Errorf("Reloc32 = %+v", h.Reloc32)
	}
	wantSyms := []SymbolEntry{{Name: "main", Offset: 0x0004}}
	if !reflect.DeepEqual(h.Symbols, wantSyms) {
		t.Errorf("Symbols = %+v, want %+v", h.Symbols, wantSyms)
	}
}
