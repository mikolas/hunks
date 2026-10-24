package modules

const (
	dwInitOpcode   uint32 = 0x33FC00FF // MOVE.W #$00FF,...
	dwADKCON       uint32 = 0x00DFF09E
	dwDMACON       uint32 = 0x00DFF096
	dwUnpackLoop   uint32 = 0x24183618
	dwMaxSample    int64  = 0x20000
	dwMaxSampleOff int64  = 0x493E0
)

type Whittaker struct{}

func (Whittaker) Name() string {
	return "David Whittaker"
}

func dwB16(d []byte, o int64) (uint16, bool) {
	if o < 0 {
		return 0, false
	}
	return beU16(d, int(o))
}

func dwB32(d []byte, o int64) (uint32, bool) {
	if o < 0 {
		return 0, false
	}
	return beU32(d, int(o))
}

func dwBB(d []byte, o int64) (uint8, bool) {
	if o < 0 || o >= int64(len(d)) {
		return 0, false
	}
	return d[o], true
}

func dwS16(v uint16) int64 {
	return int64(int16(v))
}

func (Whittaker) Detect(data []byte, offset int) *Match {
	initOp, ok := dwB32(data, int64(offset))
	if !ok || initOp != dwInitOpcode {
		return nil
	}
	a0 := int64(offset)
	n := int64(len(data))

	// Stage A: driver shape
	adk, ok := dwB32(data, a0+4)
	if !ok || adk != dwADKCON {
		return nil
	}
	dmacon := int64(-1)
	{
		p := a0 - 4
		for range 18 {
			if v, ok := dwB32(data, p); ok && v == dwDMACON {
				dmacon = p
				break
			}
			p -= 2
		}
	}
	if dmacon < 0 {
		p := a0 + 12
		for range 18 {
			if v, ok := dwB32(data, p); ok && v == dwDMACON {
				dmacon = p
				break
			}
			p += 2
		}
	}
	if dmacon < 0 {
		return nil
	}
	opBefore, ok := dwB16(data, dmacon-2)
	if !ok || opBefore&0xFFF0 != 0 {
		return nil
	}

	// Stage B: alt-flag
	alt := true
	{
		rts := int64(-1)
		p := a0
		for range 32 {
			p -= 2
			if p < 0 {
				break
			}
			if v, ok := dwB16(data, p); ok && v == 0x4E75 {
				rts = p
				break
			}
		}
		if rts >= 0 {
			v, ok := dwB16(data, rts-8)
			alt = !ok || v != 0x50EB
		}
	}

	// Stage C: locate LEA (module data pointer) and jsr entry
	lea := int64(-1)
	{
		p := a0
		for range 24 {
			p -= 2
			if p < 0 {
				break
			}
			w, ok := dwB16(data, p)
			if !ok {
				return nil
			}
			if w&0xF1FF == 0x41FA {
				lea = p
				break
			}
		}
	}
	if lea < 0 {
		p := a0 + 8
		for range 32 {
			w, ok := dwB16(data, p)
			if !ok {
				return nil
			}
			if w == 0x4E75 {
				break
			}
			if w&0xF1FF == 0x41FA {
				lea = p
				break
			}
			p += 2
		}
	}
	if lea < 0 {
		return nil
	}
	disp, ok := dwB16(data, lea+2)
	if !ok {
		return nil
	}
	dataptr := (lea + 2) + dwS16(disp)

	entry := int64(-1)
	{
		p := lea
		for range 24 {
			p -= 2
			if p < 0 {
				break
			}
			w, ok := dwB16(data, p)
			if !ok {
				return nil
			}
			if w == 0x48E7 || (w&0xFFF0) == 0x2F00 {
				entry = p
				break
			}
			if w == 0x4E75 {
				entry = p + 2
				break
			}
		}
	}
	if entry < 0 || entry >= n {
		return nil
	}

	// Stage D: run the driver init in the sandbox
	setup := ProbeSetup{
		EntryOff: uint32(entry),
	}
	setup.AModRelative[0] = true
	if RunProbe(data, &setup, SandboxDefaultBudget, nil) == nil {
		return nil
	}

	mstart := dataptr
	if !alt {
		p := mstart - 2
		for range 2048 {
			p += 2
			w0, ok0 := dwB16(data, p)
			w8, ok8 := dwB16(data, p+8)
			w10, ok10 := dwB16(data, p+10)
			w12, ok12 := dwB16(data, p+12)
			w14, ok14 := dwB16(data, p+14)
			w16, ok16 := dwB16(data, p+16)
			if ok0 && w0 == 0x48E7 &&
				ok8 && w8 == 0x4CDF &&
				ok10 && w10 == 0x7F8F &&
				ok12 && w12 == 0x4E75 &&
				ok14 && w14 == 0x48E7 &&
				ok16 && w16 == 0xF1FE {
				mstart = p
				break
			}
		}
	}
	if mstart < 0 || mstart >= n {
		return nil
	}

	// Stage E / F: primary or fallback sizer
	end, ok := dwPrimarySizer(data, mstart, alt, n)
	if !ok {
		end, ok = dwFallbackSizer(data, mstart, n)
	}
	if !ok || end <= mstart || end > n {
		return nil
	}

	return &Match{
		FormatID: 35,
		Name:     "David Whittaker",
		Variant:  "David Whittaker / J.C. Brooke",
		Regions: []Region{{
			Start: int(mstart),
			Len:   int(end - mstart),
			Role:  RegionPrimary,
		}},
	}
}

func dwPrimarySizer(data []byte, mstart int64, alt bool, n int64) (int64, bool) {
	bestEnd := int64(-1)
	a1 := mstart
	scan := 0
	for scan < 5375 && a1+4 <= n {
		if v, ok := dwB32(data, a1); ok && v == dwUnpackLoop {
			if end, ok := dwSizeOneUnpack(data, a1, alt); ok && end > bestEnd {
				bestEnd = end
			}
		}
		a1 += 2
		scan++
	}
	return bestEnd, bestEnd >= 0
}

func dwSizeOneUnpack(data []byte, a1 int64, alt bool) (int64, bool) {
	cnt := int64(-1)
	{
		p := a1
		for range 16 {
			p -= 2
			if p < 0 {
				break
			}
			if b, ok := dwBB(data, p); ok && b == 0x72 {
				b1, ok := dwBB(data, p+1)
				if !ok {
					return 0, false
				}
				cnt = int64(b1)
				break
			}
		}
	}
	if cnt < 0 {
		return 0, false
	}

	lt := int64(-1)
	{
		p := a1 - 2
		for range 16 {
			if w, ok := dwB16(data, p); ok && w == 0x41FA {
				lt = p
				break
			}
			p -= 2
			if p < 0 {
				break
			}
		}
	}
	if lt < 0 {
		return 0, false
	}
	var extra int64
	if w, ok := dwB16(data, lt+4); ok && w == 0xD1FC {
		imm, ok := dwB32(data, lt+6)
		if !ok {
			return 0, false
		}
		if imm&1 == 0 {
			extra = int64(imm)
		}
	}
	disp, ok := dwB16(data, lt+2)
	if !ok {
		return 0, false
	}
	a2 := (lt + 2) + dwS16(disp) + extra
	for i := int64(0); i <= cnt; i++ {
		rawLen, ok := dwB32(data, a2)
		if !ok {
			return 0, false
		}
		sLen := int64(int32(rawLen))
		if sLen < 0 || sLen > dwMaxSample {
			return 0, false
		}
		a2 += 4
		a2 += 2 + sLen
	}

	apply64 := alt
	if !alt {
		a5 := a1 + 4
		for {
			w, ok := dwB16(data, a5)
			if !ok {
				break
			}
			a5 += 2
			if w == 0x4E75 || w == 0x207A || w == 0x41FA {
				break
			}
			if w == 0xD0FC {
				apply64 = true
				break
			}
			if wPrev, ok := dwB16(data, a5-4); ok && wPrev == 0xD1FC {
				apply64 = true
				break
			}
		}
	}
	if apply64 {
		a2 += 64
	}
	return a2, true
}

func dwFallbackSizer(data []byte, mstart, n int64) (int64, bool) {
	a1 := mstart
	for range 2048 {
		if a1+6 > n {
			break
		}
		w0, ok0 := dwB16(data, a1)
		w2, ok2 := dwB16(data, a1+2)
		w4, ok4 := dwB16(data, a1+4)
		if ok0 && w0 == 0xC2FC && ok2 && w2 == 0x000A && ok4 && w4 == 0x45FA {
			disp, ok := dwB16(data, a1+6)
			if !ok {
				return 0, false
			}
			tbl := (a1 + 6) + dwS16(disp)
			a2 := tbl + 12
			var maxOff, maxLen int64
			for range 50 {
				rawOff, ok := dwB32(data, a2)
				if !ok {
					return 0, false
				}
				off := int64(int32(rawOff))
				if off <= maxOff {
					a2 += 10
					continue
				}
				if off > dwMaxSampleOff {
					break
				}
				maxOff = off
				wLen, ok := dwB16(data, a2+4)
				if !ok {
					return 0, false
				}
				maxLen = int64(wLen)
				a2 += 10
			}
			if maxOff > 0 {
				return mstart + maxOff + maxLen, true
			}
			break
		}
		a1 += 2
	}
	return 0, false
}
