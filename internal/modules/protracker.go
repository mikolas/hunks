package modules

const (
	ptTagOffset       = 1080
	st15StartDelta    = 948
	ptHeaderLen       = 1084
	ptOrderBase       = 952
	ptPatternLen      = 1024
	ptOrderTableLen   = 128
	ptNumSamples      = 31
	ptSampleFieldBase = 42
	ptSampleStride    = 30
	amStructSpan      = 0x8336
)

type ProTracker struct{}

func (ProTracker) Name() string {
	return "ProTracker"
}

func (p ProTracker) Detect(data []byte, offset int) *Match {
	word, ok := beU32(data, offset)
	if !ok {
		return nil
	}

	is31Tag := word == 0x45584F34 ||
		word == 0x464C5434 ||
		word == 0x3443484E ||
		(word&0xFFF0FFF0) == 0x4D204B20
	if is31Tag {
		return p.detectTagged(data, offset)
	}

	if word&0xFF == 0x7F && (word&0xFFFF80FF) == 0x0001007F {
		return p.detectLow7F(data, offset)
	}

	return nil
}

func (p ProTracker) detectTagged(data []byte, tagPos int) *Match {
	if tagPos < ptTagOffset {
		return nil
	}
	start := tagPos - ptTagOffset
	collide, ok := beU32(data, start+948)
	if !ok {
		return nil
	}
	if collide&0xFFFF80FF == 0x0001007F {
		return nil
	}
	return p.validate(data, start)
}

func (p ProTracker) detectLow7F(data []byte, sigPos int) *Match {
	if sigPos < st15StartDelta {
		return nil
	}
	start := sigPos - st15StartDelta
	return p.validate(data, start)
}

func (ProTracker) validate(data []byte, start int) *Match {
	if start < 0 || start+ptHeaderLen > len(data) {
		return nil
	}
	hdr := data[start : start+ptHeaderLen]

	titleOK := titleIsClean(hdr[0:20])

	hasTagPathSampleBytes := false
	tagPathSampleBytes := 0
	startrekkerAM := false

	if !titleOK {
		tag, ok := beU32(hdr, ptTagOffset)
		if !ok || tag != 0x4D2E4B2E {
			return nil
		}
		var words uint64
		pos := 0
		for range ptNumSamples {
			if pos+14 > len(hdr) {
				return nil
			}
			finetune := hdr[pos]
			if finetune&0xF0 != 0 {
				return nil
			}
			volume := hdr[pos+1]
			if volume > 64 {
				return nil
			}
			lenW, ok := beU16(hdr, pos+6)
			if !ok {
				return nil
			}
			if lenW != 0 {
				repLenW, ok := beU16(hdr, pos+12)
				if !ok || repLenW > lenW {
					return nil
				}
			}
			words += uint64(lenW)
			pos += 16
		}
		hasTagPathSampleBytes = true
		tagPathSampleBytes = int(words) * 2
	}

	if ptOrderBase+ptOrderTableLen > len(hdr) {
		return nil
	}
	order := hdr[ptOrderBase : ptOrderBase+ptOrderTableLen]
	var maxOrder uint8
	for _, b := range order {
		if b&0x80 != 0 {
			return nil
		}
		if b > maxOrder {
			maxOrder = b
		}
	}
	numPatterns := int(maxOrder) + 1
	headerPlusPatterns := ptHeaderLen + numPatterns*ptPatternLen

	var sampleBytes int
	if hasTagPathSampleBytes {
		sampleBytes = tagPathSampleBytes
	} else {
		var words uint64
		pos := ptSampleFieldBase
		for range ptNumSamples {
			lenW, ok := beU16(hdr, pos)
			if !ok {
				return nil
			}
			if lenW != 0 {
				repLenW, ok := beU16(hdr, pos+6)
				if !ok || repLenW > lenW {
					return nil
				}
				words += uint64(lenW)
			} else {
				fv, ok1 := beU16(hdr, pos+2)
				repStart, ok2 := beU16(hdr, pos+4)
				repLen, ok3 := beU16(hdr, pos+6)
				if !ok1 || !ok2 || !ok3 {
					return nil
				}
				if fv == 0 && repStart == 0 && repLen == 1 {
					startrekkerAM = true
				}
			}
			pos += ptSampleStride
		}
		sampleBytes = int(words) * 2
	}

	if startrekkerAM {
		tag, _ := beU32(hdr, ptTagOffset)
		hi := uint16(tag >> 16)
		if hi != 0x464C && hi != 0x4558 {
			startrekkerAM = false
		}
	}

	modLen := headerPlusPatterns + sampleBytes
	if start+modLen > len(data) {
		return nil
	}

	var variant string
	tag16, _ := beU16(hdr, ptTagOffset)
	switch {
	case hasTagPathSampleBytes:
		variant = "SoundTracker"
	case tag16 == 0x574E:
		variant = "NoiseTracker"
	case startrekkerAM || isStartrekkerBits(hdr):
		variant = "StarTrekker"
	default:
		variant = "ProTracker"
	}

	regions := []Region{{
		Start: start,
		Len:   modLen,
		Role:  RegionPrimary,
	}}

	if startrekkerAM {
		if am, ok := scanAMCompanion(data); ok {
			regions = append(regions, am)
		}
	}

	return &Match{
		FormatID: 23,
		Name:     "ProTracker",
		Variant:  variant,
		Regions:  regions,
	}
}

func isStartrekkerBits(hdr []byte) bool {
	var acc uint32
	pos := 38
	for range ptNumSamples {
		if v, ok := beU32(hdr, pos); ok {
			acc |= v
		}
		pos += ptSampleStride
	}
	return acc != 0 && (acc&0xFFE00001) == 0
}

func scanAMCompanion(data []byte) (Region, bool) {
	for a := 0; a+16 <= len(data); a += 2 {
		w0, ok := beU32(data, a)
		if !ok {
			return Region{}, false
		}
		w0 |= 0x20202020
		if w0 == 0x61756469 {
			w4, ok1 := lcU32(data, a+4)
			w8, ok2 := lcU32(data, a+8)
			w12, ok3 := lcU16(data, a+12)
			if ok1 && w4 == 0x6F736375 && ok2 && w8 == 0x6C707475 && ok3 && w12 == 0x7265 && amZerosOK(data, a) {
				return Region{Start: a, Len: amStructSpan, Role: RegionSamples}, true
			}
		} else if w0 == 0x7374312E {
			w6, ok1 := lcU32(data, a+6)
			w10, ok2 := lcU32(data, a+10)
			w14, ok3 := lcU16(data, a+14)
			if ok1 && w6 == 0x6D6F6475 && ok2 && w10 == 0x6C65696E && ok3 && w14 == 0x666F && amZerosOK(data, a) {
				return Region{Start: a, Len: amStructSpan, Role: RegionSamples}, true
			}
		}
	}
	return Region{}, false
}

func amZerosOK(data []byte, hdr int) bool {
	if hdr+112+32 > len(data) {
		return false
	}
	for _, b := range data[hdr+112 : hdr+112+32] {
		if b != 0x30 {
			return false
		}
	}
	return true
}

func lcU32(data []byte, at int) (uint32, bool) {
	v, ok := beU32(data, at)
	return v | 0x20202020, ok
}

func lcU16(data []byte, at int) (uint16, bool) {
	v, ok := beU16(data, at)
	return v | 0x2020, ok
}
