package modules

const (
	tagFNL           uint32 = 0x2E464E4C // ".FNL"
	fnlTagOffset            = 3014
	fnlInitOpcodeOff        = 516
	fnlCIAOff               = 512
	fnlPatchOff      uint32 = 630
	fnlNumSamples           = 15
	fnlTrailerPad    uint32 = 96
)

type FinalMusicSystem struct{}

func (FinalMusicSystem) Name() string {
	return "Final Music System"
}

func (FinalMusicSystem) Detect(data []byte, offset int) *Match {
	tag, ok := beU32(data, offset)
	if !ok || tag != tagFNL {
		return nil
	}
	if offset < fnlTagOffset {
		return nil
	}
	start := offset - fnlTagOffset

	initOp, ok := beU16(data, start+fnlInitOpcodeOff)
	if !ok || initOp != 0x41FA {
		return nil
	}
	cia, ok := beU32(data, start+fnlCIAOff)
	if !ok || cia != 0x00BFE001 {
		return nil
	}

	image := data[start:]
	setup := ProbeSetup{
		EntryOff: uint32(fnlInitOpcodeOff),
	}
	setup.A[0] = 0
	setup.AModRelative[0] = true

	result := RunProbe(image, &setup, SandboxDefaultBudget, func(mem []byte) {
		if int(fnlPatchOff)+2 <= len(mem) {
			mem[fnlPatchOff] = 0x4E
			mem[fnlPatchOff+1] = 0x75
		}
	})
	if result == nil {
		return nil
	}

	tableOff, ok := result.ARel(0)
	if !ok {
		return nil
	}

	endOff := uint64(tableOff)
	p := tableOff
	for range fnlNumSamples {
		sLen, ok := ModReadU32(image, p)
		if !ok {
			return nil
		}
		endOff += uint64(sLen)
		p += 4
	}
	endOff += uint64(fnlTrailerPad)

	modLen := int(endOff)
	if modLen <= fnlTagOffset || start+modLen > len(data) {
		return nil
	}

	return &Match{
		FormatID: 2,
		Name:     "Final Music System",
		Variant:  "Delta Music 2.0 FNL",
		Regions: []Region{{
			Start: start,
			Len:   modLen,
			Role:  RegionPrimary,
		}},
	}
}
