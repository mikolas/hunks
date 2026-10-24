package modules

const (
	tagSMOD uint32 = 0x534D4F44 // "SMOD"
	tagFC14 uint32 = 0x46433134 // "FC14"

	fcSongLenOff      = 32
	fcSampleLenOff    = 36
	smodSectionBase   = 4
	smodNumSections   = 7
	fc14SeqBase       = 100
	fc14SeqLen        = 80
	fc14SeqMax        = 0x80
	fcMaxRegionLength = 64 * 1024 * 1024
)

type FutureComposer struct{}

func (FutureComposer) Name() string {
	return "Future Composer"
}

func (FutureComposer) Detect(data []byte, offset int) *Match {
	tag, ok := beU32(data, offset)
	if !ok {
		return nil
	}
	switch tag {
	case tagSMOD:
		return detectSMOD(data, offset)
	case tagFC14:
		return detectFC14(data, offset)
	default:
		return nil
	}
}

func detectSMOD(data []byte, start int) *Match {
	song, ok := beU32(data, start+fcSongLenOff)
	if !ok || song > fcMaxRegionLength {
		return nil
	}
	for i := range smodNumSections {
		section, ok := beU32(data, start+smodSectionBase+i*4)
		if !ok || section > song {
			return nil
		}
	}
	sample, ok := beU32(data, start+fcSampleLenOff)
	if !ok || sample > fcMaxRegionLength {
		return nil
	}
	modLen := int(song) + int(sample)
	if start+modLen > len(data) {
		return nil
	}
	return &Match{
		FormatID: 5,
		Name:     "Future Composer",
		Variant:  "FutureComposer 1.3 SMOD",
		Regions: []Region{{
			Start: start,
			Len:   modLen,
			Role:  RegionPrimary,
		}},
	}
}

func detectFC14(data []byte, start int) *Match {
	song, ok1 := beU32(data, start+fcSongLenOff)
	sample, ok2 := beU32(data, start+fcSampleLenOff)
	if !ok1 || !ok2 {
		return nil
	}
	if sample&0x80000000 != 0 {
		return nil
	}
	if sample < song {
		return nil
	}
	if start+fc14SeqBase+fc14SeqLen > len(data) {
		return nil
	}
	seq := data[start+fc14SeqBase : start+fc14SeqBase+fc14SeqLen]
	seqBytes := 0
	for _, b := range seq {
		if b > fc14SeqMax {
			return nil
		}
		seqBytes += int(b) * 2
	}
	modLen := int(sample) + seqBytes
	if modLen > fcMaxRegionLength || start+modLen > len(data) {
		return nil
	}
	return &Match{
		FormatID: 6,
		Name:     "Future Composer",
		Variant:  "FutureComposer 1.4",
		Regions: []Region{{
			Start: start,
			Len:   modLen,
			Role:  RegionPrimary,
		}},
	}
}
