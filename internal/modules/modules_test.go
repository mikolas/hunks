package modules

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestBeHelpersBoundsChecked(t *testing.T) {
	d := []byte{0x12, 0x34, 0x56, 0x78}
	if v, ok := beU16(d, 0); !ok || v != 0x1234 {
		t.Fatalf("beU16(0) = (%x, %v), want (0x1234, true)", v, ok)
	}
	if v, ok := beU32(d, 0); !ok || v != 0x12345678 {
		t.Fatalf("beU32(0) = (%x, %v), want (0x12345678, true)", v, ok)
	}
	if _, ok := beU16(d, 3); ok {
		t.Fatalf("beU16(3) should fail")
	}
	if _, ok := beU32(d, 1); ok {
		t.Fatalf("beU32(1) should fail")
	}
}

func TestEmptyAndShortBuffersYieldNothing(t *testing.T) {
	if got := Scan(nil); len(got) != 0 {
		t.Fatalf("Scan(nil) = %v, want empty", got)
	}
	if got := Scan([]byte{0, 1, 2}); len(got) != 0 {
		t.Fatalf("Scan(short) = %v, want empty", got)
	}
}

// ---- ProTracker synthetic tests ----

func ptBase31(tag string, numPatterns uint8, sampleBytes int) []byte {
	total := ptHeaderLen + int(numPatterns)*ptPatternLen + sampleBytes
	m := make([]byte, total)
	if numPatterns > 0 {
		m[ptOrderBase] = numPatterns - 1
	}
	copy(m[ptTagOffset:ptTagOffset+4], tag)
	return m
}

func ptMakeTagPath(sampleWords uint16, numPatterns uint8) []byte {
	m := ptBase31("M.K.", numPatterns, int(sampleWords)*2)
	m[0] = 0x0D
	m[6] = byte(sampleWords >> 8)
	m[7] = byte(sampleWords & 0xFF)
	return m
}

func ptMakeTitlePath(tag, title string, sampleWords uint16, numPatterns uint8) []byte {
	m := ptBase31(tag, numPatterns, int(sampleWords)*2)
	copy(m[0:min(len(title), 20)], title)
	m[42] = byte(sampleWords >> 8)
	m[43] = byte(sampleWords & 0xFF)
	return m
}

func TestProTrackerDetectsMKViaTagPathDirtyTitle(t *testing.T) {
	m := ptMakeTagPath(100, 2)
	got := (ProTracker{}).Detect(m, ptTagOffset)
	if got == nil {
		t.Fatalf("expected ProTracker match")
	}
	if got.FormatID != 23 || got.Variant != "SoundTracker" || got.Start() != 0 || got.PrimaryEnd() != len(m) || len(got.Regions) != 1 {
		t.Fatalf("unexpected match: %+v", got)
	}
}

func TestProTrackerDetectsMBangKBangViaMaskTitlePath(t *testing.T) {
	m := ptMakeTitlePath("M!K!", "clean title", 40, 1)
	got := (ProTracker{}).Detect(m, ptTagOffset)
	if got == nil || got.Variant != "ProTracker" {
		t.Fatalf("expected ProTracker variant, got %+v", got)
	}
}

func TestProTrackerRejectsInvalidCases(t *testing.T) {
	m1 := ptMakeTagPath(10, 1)
	m1[1] = 65 // volume > 64
	if (ProTracker{}).Detect(m1, ptTagOffset) != nil {
		t.Fatalf("expected volume > 64 rejection")
	}

	m2 := ptMakeTitlePath("M.K.", "clean", 10, 1)
	m2[ptOrderBase] = 0x80 // negative order index
	if (ProTracker{}).Detect(m2, ptTagOffset) != nil {
		t.Fatalf("expected negative order rejection")
	}

	m3 := ptMakeTitlePath("M.K.", "clean", 10, 1)
	m3 = m3[:len(m3)-2] // truncated
	if (ProTracker{}).Detect(m3, ptTagOffset) != nil {
		t.Fatalf("expected truncated rejection")
	}
}

func TestProTrackerStarTrekkerFLT4AddsAMCompanionRegion(t *testing.T) {
	m := ptMakeTitlePath("FLT4", "clean", 0, 1)
	m[42], m[43] = 0, 0
	m[44], m[45] = 0, 0
	m[46], m[47] = 0, 0
	m[48], m[49] = 0, 1

	amHdr := len(m)
	am := make([]byte, amStructSpan)
	copy(am[0:14], "audiosculpture")
	for i := range 32 {
		am[112+i] = '0'
	}
	m = append(m, am...)

	got := (ProTracker{}).Detect(m, ptTagOffset)
	if got == nil {
		t.Fatalf("expected StarTrekker FLT4 match")
	}
	if got.Variant != "StarTrekker" || len(got.Regions) != 2 {
		t.Fatalf("unexpected match: %+v", got)
	}
	if got.Regions[1].Role != RegionSamples || got.Regions[1].Start != amHdr || got.Regions[1].Len != amStructSpan {
		t.Fatalf("unexpected companion region: %+v", got.Regions[1])
	}
}

func TestProTrackerScanFindsModuleWithPrefixPadding(t *testing.T) {
	m := ptMakeTitlePath("M.K.", "clean", 50, 1)
	pad := 16
	buf := append(make([]byte, pad), m...)
	found := ScanWith(buf, []Recognizer{ProTracker{}})
	if len(found) != 1 || found[0].Start() != pad || found[0].Name != "ProTracker" {
		t.Fatalf("unexpected ScanWith result: %+v", found)
	}
}

// ---- SoundTracker 2.6 synthetic tests ----

func st26Make(tag, title string, patternCount uint8, sampleWords uint16) []byte {
	patBytes := int(patternCount) * st26PatternLen
	sampBytes := int(sampleWords) * 2
	total := st26TagOffset + 4 + patBytes + sampBytes
	m := make([]byte, total)
	copy(m[0:min(len(title), 20)], title)
	m[st26OrderBase] = 1
	m[st26OrderBase+1] = patternCount
	if patternCount > 0 {
		m[st26OrderBase+2] = patternCount - 1
	}
	m[st26SampleLenBase] = byte(sampleWords >> 8)
	m[st26SampleLenBase+1] = byte(sampleWords & 0xFF)
	copy(m[st26TagOffset:st26TagOffset+4], tag)
	return m
}

func TestSoundTracker26DetectionAndRejection(t *testing.T) {
	m1 := st26Make("MTN\x00", "title here", 3, 100)
	got1 := (SoundTracker26{}).Detect(m1, st26TagOffset)
	if got1 == nil || got1.FormatID != 22 || got1.Variant != "SoundTracker 2.6" || got1.PrimaryEnd() != len(m1) {
		t.Fatalf("unexpected MTN0 match: %+v", got1)
	}

	m2 := st26Make("IT10", "ice", 2, 40)
	got2 := (SoundTracker26{}).Detect(m2, st26TagOffset)
	if got2 == nil || got2.Variant != "IceTracker 1.0" || got2.PrimaryEnd() != len(m2) {
		t.Fatalf("unexpected IT10 match: %+v", got2)
	}

	mMismatch := st26Make("MTN\x00", "title", 3, 10)
	mMismatch[st26OrderBase+1] = 7
	if (SoundTracker26{}).Detect(mMismatch, st26TagOffset) != nil {
		t.Fatalf("expected pattern count mismatch rejection")
	}
}

// ---- Old SoundTracker synthetic tests ----

func ostMake(title string, songLen, numPatterns uint8, sampleWords uint16) []byte {
	patBytes := int(numPatterns) * ostPatternLen
	sampBytes := int(sampleWords) * 2
	total := ostHeaderLen + patBytes + sampBytes
	m := make([]byte, total)
	copy(m[0:min(len(title), ostTitleLen)], title)
	m[468] = 0
	m[469] = 0
	m[ostSongLenOff] = songLen
	m[471] = ostRestartMarker
	if numPatterns > 0 {
		m[ostOrderOff] = numPatterns - 1
	}
	m[ostValidFlagField+1] = 1
	m[ostValidFlagField+ostSampleStride+1] = 1
	m[ostSampleLenField] = byte(sampleWords >> 8)
	m[ostSampleLenField+1] = byte(sampleWords & 0xFF)
	return m
}

func TestOldSoundTrackerDetectionAndRejection(t *testing.T) {
	m := ostMake("old st tune", 4, 3, 100)
	got := (OldSoundTracker{}).Detect(m, ostScanDelta)
	if got == nil || got.FormatID != 42 || got.Variant != "Old SoundTracker" || got.PrimaryEnd() != len(m) {
		t.Fatalf("unexpected Old SoundTracker match: %+v", got)
	}

	mBadMarker := ostMake("tune", 4, 2, 10)
	mBadMarker[471] = 0x7F
	if (OldSoundTracker{}).Detect(mBadMarker, ostScanDelta) != nil {
		t.Fatalf("expected wrong restart marker rejection")
	}

	mFewSamples := ostMake("tune", 4, 2, 10)
	mFewSamples[ostValidFlagField+ostSampleStride+1] = 0
	if (OldSoundTracker{}).Detect(mFewSamples, ostScanDelta) != nil {
		t.Fatalf("expected too few valid samples rejection")
	}
}

// ---- Future Composer synthetic tests ----

func TestFutureComposerDetectionAndRejection(t *testing.T) {
	song := uint32(200)
	sample := uint32(100)
	total := int(song + sample)
	mSMOD := make([]byte, max(total, 64))
	copy(mSMOD[0:4], "SMOD")
	binary.BigEndian.PutUint32(mSMOD[fcSongLenOff:], song)
	binary.BigEndian.PutUint32(mSMOD[fcSampleLenOff:], sample)
	for i := range smodNumSections {
		binary.BigEndian.PutUint32(mSMOD[smodSectionBase+i*4:], uint32(i*10))
	}
	gotSMOD := (FutureComposer{}).Detect(mSMOD, 0)
	if gotSMOD == nil || gotSMOD.FormatID != 5 || gotSMOD.Variant != "FutureComposer 1.3 SMOD" || gotSMOD.PrimaryLen() != total {
		t.Fatalf("unexpected SMOD match: %+v", gotSMOD)
	}

	songFC14 := uint32(100)
	sampleFC14 := uint32(400)
	seqBytes := (3 + 3) * 2
	totalFC14 := int(sampleFC14) + seqBytes
	mFC14 := make([]byte, max(totalFC14, fc14SeqBase+fc14SeqLen))
	copy(mFC14[0:4], "FC14")
	binary.BigEndian.PutUint32(mFC14[fcSongLenOff:], songFC14)
	binary.BigEndian.PutUint32(mFC14[fcSampleLenOff:], sampleFC14)
	mFC14[fc14SeqBase] = 3
	mFC14[fc14SeqBase+1] = 3
	gotFC14 := (FutureComposer{}).Detect(mFC14, 0)
	if gotFC14 == nil || gotFC14.FormatID != 6 || gotFC14.Variant != "FutureComposer 1.4" || gotFC14.PrimaryLen() != totalFC14 {
		t.Fatalf("unexpected FC14 match: %+v", gotFC14)
	}
}

// ---- Delta Music 1.0 synthetic tests ----

func dmMake(sectionBytes, sampleBytes uint32) []byte {
	total := dmHeaderLen + int(sectionBytes) + int(sampleBytes)
	m := make([]byte, max(total, dmHeaderLen))
	copy(m[0:4], "ALL ")
	binary.BigEndian.PutUint32(m[dmSectionBase+4:], sectionBytes)
	binary.BigEndian.PutUint32(m[dmSampleLenOff:], sampleBytes)
	return m
}

func TestDeltaMusicDetectionAndRejection(t *testing.T) {
	m := dmMake(500, 200)
	got := (DeltaMusic{}).Detect(m, 0)
	if got == nil || got.FormatID != 43 || got.Variant != "DeltaMusic 1.0" || got.PrimaryLen() != dmHeaderLen+500+200 {
		t.Fatalf("unexpected DeltaMusic match: %+v", got)
	}

	mBadReserved := dmMake(100, 0)
	mBadReserved[4] = 0x12
	mBadReserved[5] = 0x34
	if (DeltaMusic{}).Detect(mBadReserved, 0) != nil {
		t.Fatalf("expected non-zero reserved word rejection")
	}
}

// ---- Sandbox M68000 probe synthetic tests ----

func TestSandboxRunsAndReturnsOnSentinel(t *testing.T) {
	// 203C 1234 5678 = move.l #$12345678,d0 ; 4E75 = rts
	prog := []byte{0x20, 0x3C, 0x12, 0x34, 0x56, 0x78, 0x4E, 0x75}
	setup := ProbeSetup{EntryOff: 0}
	r := RunProbe(prog, &setup, 1000, nil)
	if r == nil {
		t.Fatalf("expected clean return from sandbox")
	}
	if r.D[0] != 0x12345678 {
		t.Fatalf("r.D[0] = 0x%08X, want 0x12345678", r.D[0])
	}
}

func TestSandboxBudgetRejectsInfiniteLoop(t *testing.T) {
	// 60FE = bra.s -2 (branch to self)
	prog := []byte{0x60, 0xFE}
	setup := ProbeSetup{EntryOff: 0}
	if RunProbe(prog, &setup, 10000, nil) != nil {
		t.Fatalf("expected infinite loop to be rejected by budget")
	}
}

func TestSandboxOOBAccessRejected(t *testing.T) {
	// 2039 00F0 0000 = move.l $00F00000,d0 ; 4E75 = rts
	prog := []byte{0x20, 0x39, 0x00, 0xF0, 0x00, 0x00, 0x4E, 0x75}
	setup := ProbeSetup{EntryOff: 0}
	if RunProbe(prog, &setup, 1000, nil) != nil {
		t.Fatalf("expected OOB access ($00F00000) to be rejected")
	}
}

func TestCorpusMatchesManifest(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata")
	manifest := filepath.Join(dir, "expected.tsv")
	rawText, err := os.ReadFile(manifest)
	if err != nil {
		t.Logf("corpus: no testdata/expected.tsv — skipping")
		return
	}

	type expectRow struct {
		relpath string
		format  string
		start   int
		length  int
		regions int
	}
	var expects []expectRow
	for _, line := range strings.Split(string(rawText), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) < 5 {
			t.Fatalf("malformed expected.tsv line: %q", line)
		}
		sHex := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(cols[2]), "0x"), "0X")
		startVal, err := strconv.ParseUint(sHex, 16, 64)
		if err != nil {
			t.Fatalf("start must be hex: %q", cols[2])
		}
		lenVal, err := strconv.Atoi(strings.TrimSpace(cols[3]))
		if err != nil {
			t.Fatalf("len must be decimal: %q", cols[3])
		}
		regVal, err := strconv.Atoi(strings.TrimSpace(cols[4]))
		if err != nil {
			t.Fatalf("regions must be decimal: %q", cols[4])
		}
		expects = append(expects, expectRow{
			relpath: cols[0],
			format:  cols[1],
			start:   int(startVal),
			length:  lenVal,
			regions: regVal,
		})
	}
	if len(expects) == 0 {
		t.Logf("corpus: testdata/expected.tsv has no entries yet — skipping")
		return
	}

	var failures []string
	for _, e := range expects {
		p := filepath.Join(dir, e.relpath)
		data, err := os.ReadFile(p)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: cannot read (%v)", e.relpath, err))
			continue
		}
		matches := Scan(data)
		var hit *Match
		for i := range matches {
			if matches[i].Start() == e.start {
				hit = &matches[i]
				break
			}
		}
		if hit == nil {
			failures = append(failures, fmt.Sprintf(
				"%s: expected %s @ $%X len %d regions %d, but no match at that offset (found %d total)",
				e.relpath, e.format, e.start, e.length, e.regions, len(matches)))
			continue
		}
		if hit.Name != e.format {
			failures = append(failures, fmt.Sprintf("%s: format mismatch — expected %s, got %s", e.relpath, e.format, hit.Name))
		}
		if hit.PrimaryLen() != e.length {
			failures = append(failures, fmt.Sprintf("%s: length mismatch — expected %d, got %d", e.relpath, e.length, hit.PrimaryLen()))
		}
		if len(hit.Regions) != e.regions {
			failures = append(failures, fmt.Sprintf("%s: region-count mismatch — expected %d, got %d", e.relpath, e.regions, len(hit.Regions)))
		}
	}
	if len(failures) > 0 {
		t.Fatalf("corpus: %d/%d entries failed:\n%s", len(failures), len(expects), strings.Join(failures, "\n"))
	}
}
