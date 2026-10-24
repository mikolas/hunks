// Package modules implements Amiga music-module recognizers — a pure,
// dependency-free subsystem (plus sandboxed M68000 probing for self-executing
// drivers).
package modules

import "encoding/binary"

// RegionRole classifies the role a region plays within a (possibly multipart) module.
type RegionRole string

const (
	// RegionPrimary is the primary module body (song/pattern/header data). Always Regions[0].
	RegionPrimary RegionRole = "Primary"
	// RegionSamples is a separate sample/waveform block (e.g. StarTrekker AM, TFMX smpl).
	RegionSamples RegionRole = "Samples"
)

// Region is one contiguous byte extent of a module within the scanned buffer.
type Region struct {
	Start int
	Len   int
	Role  RegionRole
}

// End returns the exclusive end offset within the buffer.
func (r Region) End() int {
	return r.Start + r.Len
}

// Match represents a detected module: its identity plus the one-or-more regions that make it up.
type Match struct {
	FormatID uint32
	Name     string
	Variant  string
	Regions  []Region
}

// Primary returns the primary region (module body).
func (m *Match) Primary() Region {
	return m.Regions[0]
}

// Start returns the start offset of the primary region.
func (m *Match) Start() int {
	return m.Regions[0].Start
}

// PrimaryLen returns the length of the primary region (used for scan auto-skip).
func (m *Match) PrimaryLen() int {
	return m.Regions[0].Len
}

// PrimaryEnd returns the exclusive end of the primary region.
func (m *Match) PrimaryEnd() int {
	return m.Regions[0].End()
}

// TotalLen returns the total bytes across all regions.
func (m *Match) TotalLen() int {
	total := 0
	for _, r := range m.Regions {
		total += r.Len
	}
	return total
}

// Recognizer is a single-format detector. Pure: inspects data at/around offset and returns
// a Match iff a valid module of this format is present.
type Recognizer interface {
	Name() string
	Detect(data []byte, offset int) *Match
}

// Recognizers returns the built-in recognizer registry in ExoticRipper format-ID order:
//   2 Final Music System, 5/6 Future Composer, 22 SoundTracker 2.6, 23 ProTracker,
//   35 David Whittaker, 42 Old SoundTracker, 43 Delta Music 1.0.
func Recognizers() []Recognizer {
	return []Recognizer{
		FinalMusicSystem{},
		FutureComposer{},
		SoundTracker26{},
		ProTracker{},
		Whittaker{},
		OldSoundTracker{},
		DeltaMusic{},
	}
}

// Scan sweeps data word-by-word, trying every recognizer at each 2-byte-aligned position.
// On a hit, it records the Match and skips past the primary region so the scan never
// reports a false sub-match inside the body.
func Scan(data []byte) []Match {
	return ScanWith(data, Recognizers())
}

// ScanWith scans data against a caller-supplied recognizer set.
func ScanWith(data []byte, recs []Recognizer) []Match {
	var out []Match
	pos := 0
	for pos+4 <= len(data) {
		var hit *Match
		for _, r := range recs {
			if m := r.Detect(data, pos); m != nil {
				hit = m
				break
			}
		}
		if hit != nil {
			next := max(hit.PrimaryEnd(), pos+2)
			out = append(out, *hit)
			pos = next
		} else {
			pos += 2
		}
	}
	return out
}

func beU16(data []byte, at int) (uint16, bool) {
	if at < 0 || at+2 > len(data) {
		return 0, false
	}
	return binary.BigEndian.Uint16(data[at : at+2]), true
}

func beU32(data []byte, at int) (uint32, bool) {
	if at < 0 || at+4 > len(data) {
		return 0, false
	}
	return binary.BigEndian.Uint32(data[at : at+4]), true
}

func titleIsClean(title []byte) bool {
	for i, c := range title {
		if c == 0 {
			for _, rem := range title[i:] {
				if rem != 0 {
					return false
				}
			}
			return true
		}
		if c < 0x20 || c > 0x7A {
			return false
		}
	}
	return true
}
