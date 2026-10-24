package modules

const (
	st26TagOffset     = 1464
	st26OrderBase     = 950
	st26NumSamples    = 31
	st26SampleLenBase = 42
	st26SampleStride  = 30
	st26PatternLen    = 256

	tagMTN0 uint32 = 0x4D544E00 // "MTN\0" -> SoundTracker 2.6
	tagIT10 uint32 = 0x49543130 // "IT10"  -> IceTracker 1.0
)

type SoundTracker26 struct{}

func (SoundTracker26) Name() string {
	return "SoundTracker 2.6"
}

func (SoundTracker26) Detect(data []byte, offset int) *Match {
	tag, ok := beU32(data, offset)
	if !ok {
		return nil
	}
	var variant string
	switch tag {
	case tagMTN0:
		variant = "SoundTracker 2.6"
	case tagIT10:
		variant = "IceTracker 1.0"
	default:
		return nil
	}
	if offset < st26TagOffset {
		return nil
	}
	start := offset - st26TagOffset
	return validateST26(data, start, offset, variant)
}

func validateST26(data []byte, start, tagPos int, variant string) *Match {
	if start+20 > len(data) {
		return nil
	}
	if !titleIsClean(data[start : start+20]) {
		return nil
	}

	if start+st26OrderBase+2 > len(data) {
		return nil
	}
	songLen := data[start+st26OrderBase]
	if songLen == 0 {
		return nil
	}
	restart := data[start+st26OrderBase+1]
	if restart == 0 {
		return nil
	}

	orderBase := start + st26OrderBase + 2
	span := int(songLen) * 4
	if orderBase+span > len(data) {
		return nil
	}
	order := data[orderBase : orderBase+span]
	var maxPat uint8
	for _, b := range order {
		if b > maxPat {
			maxPat = b
		}
	}
	patternCount := int(maxPat) + 1
	if patternCount != int(restart) {
		return nil
	}

	patternBytes := patternCount * st26PatternLen
	audioEnd := tagPos + 4 + patternBytes

	p := start + st26SampleLenBase
	for range st26NumSamples {
		lenWords, ok := beU16(data, p)
		if !ok {
			return nil
		}
		audioEnd += int(lenWords) * 2
		p += st26SampleStride
	}

	if audioEnd < start || audioEnd > len(data) {
		return nil
	}
	modLen := audioEnd - start

	return &Match{
		FormatID: 22,
		Name:     "SoundTracker 2.6",
		Variant:  variant,
		Regions: []Region{{
			Start: start,
			Len:   modLen,
			Role:  RegionPrimary,
		}},
	}
}
