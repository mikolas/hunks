package project

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/mikolas/hunks/internal/db"
	"github.com/mikolas/hunks/internal/hunk"
)

func formatHex(v uint32) string {
	return fmt.Sprintf("0x%X", v)
}

// ParseHex parses a 32-bit hexadecimal string with optional "0x", "0X", or "$" prefix.
func ParseHex(s string) (uint32, error) {
	clean := strings.TrimSpace(s)
	clean = strings.TrimPrefix(clean, "0x")
	clean = strings.TrimPrefix(clean, "0X")
	clean = strings.TrimPrefix(clean, "$")
	v, err := strconv.ParseUint(clean, 16, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid hex uint32 %q: %w", s, err)
	}
	return uint32(v), nil
}

// ParseUint32 parses a 32-bit integer: hex if prefixed with "0x", "0X", or "$", otherwise decimal (with hex fallback).
func ParseUint32(s string) (uint32, error) {
	trimmed := strings.TrimSpace(s)
	if strings.HasPrefix(trimmed, "0x") || strings.HasPrefix(trimmed, "0X") || strings.HasPrefix(trimmed, "$") {
		return ParseHex(trimmed)
	}
	if v, err := strconv.ParseUint(trimmed, 10, 32); err == nil {
		return uint32(v), nil
	}
	return ParseHex(trimmed)
}

func parseHexJSON(raw json.RawMessage) (uint32, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if v, err := ParseHex(s); err == nil {
			return v, nil
		}
		if v, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32); err == nil {
			return uint32(v), nil
		}
		return 0, fmt.Errorf("invalid hex uint32 %q", s)
	}
	var n uint32
	if err := json.Unmarshal(raw, &n); err == nil {
		return n, nil
	}
	return 0, fmt.Errorf("invalid uint32 JSON: %s", string(raw))
}

type EntryPoint struct {
	Addr    uint32 `json:"addr"`
	Name    string `json:"name"`
	Segment string `json:"segment,omitempty"`
}

func (e EntryPoint) MarshalJSON() ([]byte, error) {
	type wire struct {
		Addr    string `json:"addr"`
		Name    string `json:"name"`
		Segment string `json:"segment"`
	}
	return json.Marshal(wire{
		Addr:    formatHex(e.Addr),
		Name:    e.Name,
		Segment: e.Segment,
	})
}

func (e *EntryPoint) UnmarshalJSON(data []byte) error {
	var wire struct {
		Addr    json.RawMessage `json:"addr"`
		Name    string          `json:"name"`
		Segment string          `json:"segment"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	addr, err := parseHexJSON(wire.Addr)
	if err != nil {
		return err
	}
	e.Addr = addr
	e.Name = wire.Name
	e.Segment = wire.Segment
	return nil
}

type MemoryRegion struct {
	Name  string `json:"name"`
	Start uint32 `json:"start"`
	End   uint32 `json:"end"`
}

func (m MemoryRegion) MarshalJSON() ([]byte, error) {
	type wire struct {
		Name  string `json:"name"`
		Start string `json:"start"`
		End   string `json:"end"`
	}
	return json.Marshal(wire{
		Name:  m.Name,
		Start: formatHex(m.Start),
		End:   formatHex(m.End),
	})
}

func (m *MemoryRegion) UnmarshalJSON(data []byte) error {
	var wire struct {
		Name  string          `json:"name"`
		Start json.RawMessage `json:"start"`
		End   json.RawMessage `json:"end"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	start, err := parseHexJSON(wire.Start)
	if err != nil {
		return err
	}
	end, err := parseHexJSON(wire.End)
	if err != nil {
		return err
	}
	m.Name = wire.Name
	m.Start = start
	m.End = end
	return nil
}

type Segment struct {
	Name        string          `json:"name"`
	HunkIndex   int             `json:"hunk_index"`
	HunkType    hunk.HunkType   `json:"hunk_type"`
	MemoryType  hunk.MemoryType `json:"memory_type"`
	AllocSize   uint32          `json:"alloc_size"`
	FileDataLen *uint32         `json:"file_data_len"`
	File        *string         `json:"file"`
	Base        uint32          `json:"base"`
	DB          string          `json:"db"`
	Relocatable bool            `json:"relocatable"`
}

func (s Segment) MarshalJSON() ([]byte, error) {
	ht := s.HunkType
	if ht == "" {
		ht = hunk.HunkTypeCode
	}
	mt := s.MemoryType
	if mt == "" {
		mt = hunk.MemoryPublic
	}
	type wire struct {
		Name        string          `json:"name"`
		HunkIndex   int             `json:"hunk_index"`
		HunkType    hunk.HunkType   `json:"hunk_type"`
		MemoryType  hunk.MemoryType `json:"memory_type"`
		AllocSize   uint32          `json:"alloc_size"`
		FileDataLen *uint32         `json:"file_data_len"`
		File        *string         `json:"file"`
		Base        string          `json:"base"`
		DB          string          `json:"db"`
		Relocatable bool            `json:"relocatable"`
	}
	return json.Marshal(wire{
		Name:        s.Name,
		HunkIndex:   s.HunkIndex,
		HunkType:    ht,
		MemoryType:  mt,
		AllocSize:   s.AllocSize,
		FileDataLen: s.FileDataLen,
		File:        s.File,
		Base:        formatHex(s.Base),
		DB:          s.DB,
		Relocatable: s.Relocatable,
	})
}

func (s *Segment) UnmarshalJSON(data []byte) error {
	var wire struct {
		Name        string          `json:"name"`
		HunkIndex   int             `json:"hunk_index"`
		HunkType    hunk.HunkType   `json:"hunk_type"`
		MemoryType  hunk.MemoryType `json:"memory_type"`
		AllocSize   uint32          `json:"alloc_size"`
		FileDataLen *uint32         `json:"file_data_len"`
		File        *string         `json:"file"`
		Base        json.RawMessage `json:"base"`
		DB          string          `json:"db"`
		Relocatable bool            `json:"relocatable"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	base, err := parseHexJSON(wire.Base)
	if err != nil {
		return err
	}
	ht := wire.HunkType
	if ht == "" {
		ht = hunk.HunkTypeCode
	}
	mt := wire.MemoryType
	if mt == "" {
		mt = hunk.MemoryPublic
	}
	s.Name = wire.Name
	s.HunkIndex = wire.HunkIndex
	s.HunkType = ht
	s.MemoryType = mt
	s.AllocSize = wire.AllocSize
	s.FileDataLen = wire.FileDataLen
	s.File = wire.File
	s.Base = base
	s.DB = wire.DB
	s.Relocatable = wire.Relocatable
	return nil
}

func (s *Segment) IsRelocatable() bool {
	return s.Relocatable || strings.HasPrefix(s.Name, "hunk")
}

func (s *Segment) FileSize() uint32 {
	if s.AllocSize > 0 {
		return s.AllocSize
	}
	if s.File != nil {
		if info, err := os.Stat(*s.File); err == nil {
			return uint32(info.Size())
		}
	}
	return s.AllocSize
}

func (s *Segment) EndAddr() uint32 {
	return s.Base + s.FileSize()
}

func (s *Segment) Contains(addr uint32) bool {
	end := s.EndAddr()
	if end == s.Base {
		return addr == s.Base
	}
	return addr >= s.Base && addr < end
}

func (s *Segment) AutoLabel(addr uint32) string {
	if s.IsRelocatable() {
		var offset uint32
		if addr > s.Base {
			offset = addr - s.Base
		}
		idx := s.HunkIndex
		if idx == 0 && s.Name != "hunk0" {
			if suffix, ok := strings.CutPrefix(s.Name, "hunk"); ok {
				if parsed, err := strconv.Atoi(suffix); err == nil {
					idx = parsed
				}
			}
		}
		return fmt.Sprintf("LAB_%d_%05X", idx, offset)
	}
	return fmt.Sprintf("LAB_%05X", addr)
}

func (s *Segment) LoadBinaryData() []byte {
	if s.File != nil {
		if data, err := os.ReadFile(*s.File); err == nil {
			return data
		}
		return nil
	}
	return make([]byte, s.AllocSize)
}

type Space struct {
	Name     string   `json:"name"`
	Segments []string `json:"segments"`
}

type AnalysisData struct {
	CodeBytes          uint32   `json:"code_bytes"`
	TotalBytes         uint32   `json:"total_bytes"`
	IndirectAddressing []string `json:"indirect_addressing"`
}

type ProjectData struct {
	TargetName      string                       `json:"target_name"`
	Segments        []Segment                    `json:"segments"`
	Spaces          []Space                      `json:"spaces"`
	ActiveSpace     string                       `json:"active_space"`
	Output          string                       `json:"output"`
	EntryPoints     []EntryPoint                 `json:"entry_points"`
	MemoryRegions   []MemoryRegion               `json:"memory_regions"`
	Structs         map[string]map[string]string `json:"structs"`
	RegisterAliases map[string]string            `json:"register_aliases"`
	Analysis        AnalysisData                 `json:"_analysis"`
}

type Project struct {
	Filepath          string
	WorkspaceRoot     string
	Data              ProjectData
	ActiveSegmentName string
}

func New(filepath string) *Project {
	return &Project{
		Filepath:      filepath,
		WorkspaceRoot: ".",
		Data: ProjectData{
			Segments:        []Segment{},
			Spaces:          []Space{},
			EntryPoints:     []EntryPoint{},
			MemoryRegions:   []MemoryRegion{},
			Structs:         make(map[string]map[string]string),
			RegisterAliases: make(map[string]string),
			Analysis: AnalysisData{
				IndirectAddressing: []string{},
			},
		},
	}
}

var stripExts = []string{"exe", "bin", "raw", "img", "rom", "prg", "hunk", "slave"}

// DeduceTargetName deduces a clean target namespace from a binary path
// (e.g. "assets/frontier" -> "frontier", "assets/intro.exe" -> "intro", "assets/Disk.1" -> "Disk_1").
func DeduceTargetName(pathStr string) string {
	fileName := filepath.Base(pathStr)
	if fileName == "" || fileName == "." || fileName == "/" {
		fileName = "target"
	}

	stripped := fileName
	if idx := strings.LastIndexByte(fileName, '.'); idx > 0 {
		stem := fileName[:idx]
		extLower := strings.ToLower(fileName[idx+1:])
		if stem != "" && slices.Contains(stripExts, extLower) {
			stripped = stem
		}
	}

	var sb strings.Builder
	sb.Grow(len(stripped))
	for _, r := range stripped {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			sb.WriteRune(r)
		} else {
			sb.WriteByte('_')
		}
	}
	res := sb.String()
	if res == "" {
		return "target"
	}
	return res
}

func (p *Project) Load() error {
	raw, err := os.ReadFile(p.Filepath)
	if err != nil {
		return fmt.Errorf("failed to read project file: %w", err)
	}
	if err := json.Unmarshal(raw, &p.Data); err != nil {
		return fmt.Errorf("failed to parse project JSON: %w", err)
	}
	if p.Data.Structs == nil {
		p.Data.Structs = make(map[string]map[string]string)
	}
	if p.Data.RegisterAliases == nil {
		p.Data.RegisterAliases = make(map[string]string)
	}
	if p.Data.Segments == nil {
		p.Data.Segments = []Segment{}
	}
	if p.Data.Spaces == nil {
		p.Data.Spaces = []Space{}
	}
	if p.Data.EntryPoints == nil {
		p.Data.EntryPoints = []EntryPoint{}
	}
	if p.Data.MemoryRegions == nil {
		p.Data.MemoryRegions = []MemoryRegion{}
	}
	if p.Data.Analysis.IndirectAddressing == nil {
		p.Data.Analysis.IndirectAddressing = []string{}
	}
	return nil
}

func (p *Project) Save() error {
	out, err := json.MarshalIndent(&p.Data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize project data: %w", err)
	}
	if err := os.WriteFile(p.Filepath, out, 0o644); err != nil {
		return fmt.Errorf("failed to write project file: %w", err)
	}
	return nil
}

func (p *Project) ActiveSpace() *Space {
	for i := range p.Data.Spaces {
		if p.Data.Spaces[i].Name == p.Data.ActiveSpace {
			return &p.Data.Spaces[i]
		}
	}
	return nil
}

// ActiveSegments returns segments in the active space, in order (last = highest priority).
func (p *Project) ActiveSegments() []*Segment {
	var out []*Segment
	if sp := p.ActiveSpace(); sp != nil {
		for _, name := range sp.Segments {
			for i := range p.Data.Segments {
				if p.Data.Segments[i].Name == name {
					out = append(out, &p.Data.Segments[i])
					break
				}
			}
		}
		return out
	}
	for i := range p.Data.Segments {
		out = append(out, &p.Data.Segments[i])
	}
	return out
}

// SegmentAtAddr finds which segment in the active space owns addr (last listed wins).
func (p *Project) SegmentAtAddr(addr uint32) *Segment {
	segs := p.ActiveSegments()
	for i := len(segs) - 1; i >= 0; i-- {
		if segs[i].Contains(addr) {
			return segs[i]
		}
	}
	return nil
}

// SharedDB returns the single shared SQLite database name used by all segments.
func (p *Project) SharedDB() string {
	if len(p.Data.Segments) > 0 && p.Data.Segments[0].DB != "" {
		return p.Data.Segments[0].DB
	}
	return "project.db"
}

func (p *Project) SegmentByName(name string) *Segment {
	for i := range p.Data.Segments {
		if strings.EqualFold(p.Data.Segments[i].Name, name) {
			return &p.Data.Segments[i]
		}
	}
	return nil
}

func (p *Project) CurrentSegment() *Segment {
	if p.ActiveSegmentName != "" {
		return p.SegmentByName(p.ActiveSegmentName)
	}
	segs := p.ActiveSegments()
	if len(segs) > 0 {
		return segs[0]
	}
	return nil
}

func (p *Project) SyncDBScope(ctrl *db.Controller) {
	activeSegs := p.ActiveSegments()
	spaceSegs := make([]db.SpaceSeg, 0, len(activeSegs)+1)
	for _, s := range activeSegs {
		spaceSegs = append(spaceSegs, db.SpaceSeg{
			Name: s.Name,
			Base: s.Base,
			End:  s.EndAddr(),
		})
	}
	if cur := p.CurrentSegment(); cur != nil {
		found := false
		for _, ss := range spaceSegs {
			if ss.Name == cur.Name {
				found = true
				break
			}
		}
		if !found {
			spaceSegs = append(spaceSegs, db.SpaceSeg{
				Name: cur.Name,
				Base: cur.Base,
				End:  cur.EndAddr(),
			})
		}
	}
	ctrl.SetSpaceSegs(spaceSegs)
	active := ""
	if cur := p.CurrentSegment(); cur != nil {
		active = cur.Name
	}
	ctrl.SetActiveSeg(active)
}

func (p *Project) RefreshCoverageStats(ctrl *db.Controller) {
	p.SyncDBScope(ctrl)
	p.Data.Analysis.CodeBytes = ctrl.CodeCoverageBytes()
	var total uint32
	for _, s := range p.ActiveSegments() {
		if s.HunkType != hunk.HunkTypeBss {
			total += s.FileSize()
		}
	}
	p.Data.Analysis.TotalBytes = total
}

func (p *Project) AutoLabel(addr uint32) string {
	if seg := p.SegmentAtAddr(addr); seg != nil {
		return seg.AutoLabel(addr)
	}
	for i := range p.Data.Segments {
		if p.Data.Segments[i].Contains(addr) {
			return p.Data.Segments[i].AutoLabel(addr)
		}
	}
	return fmt.Sprintf("LAB_%05X", addr)
}

func (p *Project) QualifiedLabel(addr uint32, rawOrRenamed string) string {
	if seg := p.SegmentAtAddr(addr); seg != nil {
		if seg.IsRelocatable() || len(p.Data.Segments) > 1 {
			return fmt.Sprintf("%s:%s", seg.Name, rawOrRenamed)
		}
	}
	return rawOrRenamed
}

// ResolveTarget resolves a user/LLM target specifier into a synthetic project address.
func (p *Project) ResolveTarget(ctrl *db.Controller, input string) (uint32, bool) {
	s := strings.TrimSpace(input)
	if s == "" {
		return 0, false
	}

	// 1. Check `<segment>:<rest>`
	if segPart, rest, hasColon := strings.Cut(s, ":"); hasColon {
		if seg := p.SegmentByName(strings.TrimSpace(segPart)); seg != nil {
			rest = strings.TrimSpace(rest)
			if offStr, ok := strings.CutPrefix(rest, "+"); ok {
				if off, err := ParseHex(offStr); err == nil {
					return seg.Base + off, true
				}
			}
			var resolved uint32
			var found bool
			ctrl.WithActiveSeg(seg.Name, func() {
				resolved, found = p.ResolveTarget(ctrl, rest)
			})
			if found {
				return resolved, true
			}
			if off, err := ParseHex(rest); err == nil {
				return seg.Base + off, true
			}
		}
	}

	// 2. Check `<base>+<disp>`
	if basePart, dispPart, hasPlus := strings.Cut(s, "+"); hasPlus && strings.TrimSpace(basePart) != "" {
		if baseAddr, ok := p.ResolveTarget(ctrl, strings.TrimSpace(basePart)); ok {
			if disp, err := ParseHex(dispPart); err == nil {
				return baseAddr + disp, true
			}
		}
	}

	// 3. Check leading `+<offset>` relative to CurrentSegment
	if offStr, ok := strings.CutPrefix(s, "+"); ok {
		if off, err := ParseHex(offStr); err == nil {
			var base uint32
			if cur := p.CurrentSegment(); cur != nil {
				base = cur.Base
			}
			return base + off, true
		}
	}

	// 4. Exact or case-insensitive lookup in DB `labels` and `renames`
	if a, ok := ctrl.LabelAddrByName(s, false); ok {
		return a, true
	}
	if orig, ok := ctrl.RenameOriginalOf(s, false); ok {
		if a, ok := ctrl.LabelAddrByName(orig, false); ok {
			return a, true
		}
	}
	if a, ok := ctrl.LabelAddrByName(s, true); ok {
		return a, true
	}
	if orig, ok := ctrl.RenameOriginalOf(s, true); ok {
		if a, ok := ctrl.LabelAddrByName(orig, false); ok {
			return a, true
		}
	}

	// 5. Pattern `LAB_<hunk>_<offset>` even if not in DB labels table
	rest, hasLab := strings.CutPrefix(s, "LAB_")
	if !hasLab {
		rest, hasLab = strings.CutPrefix(s, "lab_")
	}
	if hasLab {
		if hunkStr, offStr, hasUnderscore := strings.Cut(rest, "_"); hasUnderscore {
			hunkIdx, err1 := strconv.Atoi(hunkStr)
			off, err2 := strconv.ParseUint(offStr, 16, 32)
			if err1 == nil && err2 == nil {
				for i := range p.Data.Segments {
					seg := &p.Data.Segments[i]
					if seg.HunkIndex == hunkIdx && seg.IsRelocatable() {
						return seg.Base + uint32(off), true
					}
				}
			}
		}
	}

	// 6. Explicit hex `0x...`, `$...`, or bare hex
	if v, err := ParseHex(s); err == nil {
		return v, true
	}
	return 0, false
}
