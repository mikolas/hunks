package modules

const (
	ostScanDelta       = 468
	ostRestartMarker   = 0x78
	ostTitleLen        = 20
	ostSampleStride    = 30
	ostNumSamples      = 15
	ostSampleLenField  = 42
	ostValidFlagField  = 48
	ostSongLenOff      = 470
	ostOrderOff        = 472
	ostHeaderLen       = 600
	ostPatternLen      = 1024
	ostMinValidSamples = 2
)

type OldSoundTracker struct{}

func (OldSoundTracker) Name() string {
	return "Old SoundTracker"
}

func (OldSoundTracker) Detect(data []byte, offset int) *Match {
	if offset < ostScanDelta {
		return nil
	}
	start := offset - ostScanDelta
	if start+472 > len(data) {
		return nil
	}

	b468 := data[start+468]
	b469 := data[start+469]
	songLen := data[start+ostSongLenOff]
	restart := data[start+471]
	if restart != ostRestartMarker {
		return nil
	}
	if b468 != 0 || (b469&^1) != 0 {
		return nil
	}
	if songLen == 0 || songLen > ostRestartMarker {
		return nil
	}

	if !titleIsClean(data[start : start+ostTitleLen]) {
		return nil
	}

	var validSamples uint16
	for i := range ostNumSamples {
		flag, ok := beU16(data, start+ostValidFlagField+i*ostSampleStride)
		if !ok {
			return nil
		}
		if flag == 1 {
			validSamples++
		}
	}
	if validSamples < ostMinValidSamples {
		return nil
	}

	if start+ostOrderOff+int(songLen) > len(data) {
		return nil
	}
	order := data[start+ostOrderOff : start+ostOrderOff+int(songLen)]
	var maxOrder uint8
	for _, b := range order {
		if b > maxOrder {
			maxOrder = b
		}
	}
	numPatterns := int(maxOrder) + 1
	patternBytes := numPatterns * ostPatternLen

	var words uint64
	for i := range ostNumSamples {
		rec := start + ostSampleLenField + i*ostSampleStride
		lenW, ok := beU16(data, rec)
		if !ok {
			return nil
		}
		if lenW != 0 {
			repLenW, ok := beU16(data, rec+6)
			if !ok || repLenW > lenW {
				return nil
			}
			words += uint64(lenW)
		}
	}
	sampleBytes := int(words) * 2

	modLen := ostHeaderLen + patternBytes + sampleBytes
	if start+modLen > len(data) {
		return nil
	}

	return &Match{
		FormatID: 42,
		Name:     "Old SoundTracker",
		Variant:  "Old SoundTracker",
		Regions: []Region{{
			Start: start,
			Len:   modLen,
			Role:  RegionPrimary,
		}},
	}
}
