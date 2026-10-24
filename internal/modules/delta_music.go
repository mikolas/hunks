package modules

const (
	tagALL uint32 = 0x414C4C20 // "ALL "

	dmNullWordOff  = 4
	dmSectionBase  = 4
	dmNumSections  = 24
	dmHeaderLen    = 104
	dmSampleLenOff = 100
	dmMaxRegion    = 64 * 1024 * 1024
)

type DeltaMusic struct{}

func (DeltaMusic) Name() string {
	return "Delta Music"
}

func (DeltaMusic) Detect(data []byte, offset int) *Match {
	tag, ok := beU32(data, offset)
	if !ok || tag != tagALL {
		return nil
	}
	nullWord, ok := beU16(data, offset+dmNullWordOff)
	if !ok || nullWord != 0 {
		return nil
	}

	var totalSections uint64
	for i := range dmNumSections {
		s, ok := beU32(data, offset+dmSectionBase+i*4)
		if !ok {
			return nil
		}
		totalSections += uint64(s)
		if totalSections > dmMaxRegion {
			return nil
		}
	}

	sampleBytes, ok := beU32(data, offset+dmSampleLenOff)
	if !ok {
		return nil
	}

	modLen := uint64(dmHeaderLen) + totalSections + uint64(sampleBytes)
	if modLen > dmMaxRegion || uint64(offset)+modLen > uint64(len(data)) {
		return nil
	}

	return &Match{
		FormatID: 43,
		Name:     "Delta Music",
		Variant:  "DeltaMusic 1.0",
		Regions: []Region{{
			Start: offset,
			Len:   int(modLen),
			Role:  RegionPrimary,
		}},
	}
}
