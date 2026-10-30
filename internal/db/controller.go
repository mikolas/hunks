package db

import (
	"cmp"
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"

	_ "modernc.org/sqlite"
)

type Cell struct {
	Seg        string
	Addr       uint32
	Size       uint32
	Type       CellType
	Confidence uint8
	Mnemonic   *string
	OpStr      *string
	RawBytes   []byte
}

type AddressComment struct {
	Seg          string
	Addr         uint32
	Comment      string
	BlockComment string
	AutoComment  string
}

func (ac AddressComment) EffectiveComment() string {
	switch {
	case ac.Comment == "" && ac.AutoComment == "":
		return ""
	case ac.Comment == "":
		return ac.AutoComment
	case ac.AutoComment == "":
		return ac.Comment
	default:
		if strings.Contains(ac.Comment, ac.AutoComment) {
			return ac.Comment
		}
		return ac.Comment + "; " + ac.AutoComment
	}
}

type XrefRecord struct {
	SourceAddr uint32
	TargetAddr uint32
	Type       string
}

func StrPtr(s string) *string { return &s }

func (c *Cell) MnemonicStr() string {
	if c.Mnemonic == nil {
		return ""
	}
	return *c.Mnemonic
}

func (c *Cell) OpStrVal() string {
	if c.OpStr == nil {
		return ""
	}
	return *c.OpStr
}

const cellColumns = "seg, addr, size, type, confidence, mnemonic, op_str, raw_bytes"

type rowScanner interface {
	Scan(dest ...any) error
}

func scanCell(r rowScanner) (Cell, error) {
	var c Cell
	var typStr string
	var mnem, op sql.NullString
	var raw []byte
	if err := r.Scan(&c.Seg, &c.Addr, &c.Size, &typStr, &c.Confidence, &mnem, &op, &raw); err != nil {
		return Cell{}, err
	}
	ct, err := ParseCellType(typStr)
	if err != nil {
		return Cell{}, err
	}
	c.Type = ct
	if mnem.Valid {
		s := mnem.String
		c.Mnemonic = &s
	}
	if op.Valid {
		s := op.String
		c.OpStr = &s
	}
	if raw != nil {
		c.RawBytes = raw
	}
	return c, nil
}

func scanEdge(r rowScanner) (Edge, error) {
	var e Edge
	var kStr string
	if err := r.Scan(&e.Seg, &e.Source, &e.Target, &kStr); err != nil {
		return Edge{}, err
	}
	k, err := ParseEdgeKind(kStr)
	if err != nil {
		return Edge{}, err
	}
	e.Kind = k
	return e, nil
}

func scanXref(r rowScanner) (Xref, error) {
	var x Xref
	var kStr string
	if err := r.Scan(&x.Seg, &x.Source, &x.Target, &kStr); err != nil {
		return Xref{}, err
	}
	k, err := ParseXrefKind(kStr)
	if err != nil {
		return Xref{}, err
	}
	x.Kind = k
	return x, nil
}

type Label struct {
	Seg        string
	Addr       uint32
	Name       string
	Type       LabelKind
	IsAuto     bool
	IsExported bool
}

func scanLabel(r rowScanner) (Label, error) {
	var l Label
	var kStr string
	if err := r.Scan(&l.Seg, &l.Addr, &l.Name, &kStr, &l.IsAuto, &l.IsExported); err != nil {
		return Label{}, err
	}
	k, err := ParseLabelKind(kStr)
	if err != nil {
		return Label{}, err
	}
	l.Type = k
	return l, nil
}

type BaseReg struct {
	ScopeKind string // "global" | "segment" | "function"
	ScopeKey  string // "" | "hunkN" | "LAB_x_xxxxx"
	Reg       string // "a4" | "a5" | "a6" (lowercased)
	BaseAddr  uint32
	Source    string // "auto" | "hint"
}

type SpaceSeg struct {
	Name string
	Base uint32
	End  uint32
}

type AddrRange struct {
	Start uint32
	End   uint32
}

type CellTextUpdate struct {
	Addr     uint32
	Mnemonic string
	OpStr    string
}

type CellTypeInfo struct {
	Addr uint32
	Type CellType
	Size uint32
}

type AddrText struct {
	Addr uint32
	Text string
}

type Controller struct {
	conn            *sql.DB
	mu              sync.RWMutex
	activeSeg       string
	spaceSegs       []SpaceSeg
	stmtInsertCell  *sql.Stmt
	stmtInsertEdge  *sql.Stmt
	stmtInsertXref  *sql.Stmt
	stmtInsertFunc  *sql.Stmt
	stmtSetLabel    *sql.Stmt
	stmtSetLabelExp *sql.Stmt
	stmtMarkExp     *sql.Stmt
}

func New(dbPath string) (*Controller, error) {
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	// Pin to 1 connection so :memory: DBs and manual BEGIN/COMMIT transactions
	// behave deterministically on a single SQLite session.
	conn.SetMaxOpenConns(1)

	c := &Controller{
		conn: conn,
	}
	if err := c.initSchema(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := c.initStmts(); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

func (c *Controller) initStmts() (err error) {
	if c.stmtInsertCell, err = c.conn.Prepare(
		"INSERT OR REPLACE INTO cells (seg, addr, size, type, confidence, mnemonic, op_str, raw_bytes) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
	); err != nil {
		return err
	}
	if c.stmtInsertEdge, err = c.conn.Prepare(
		"INSERT OR REPLACE INTO edges (seg, source_addr, target_addr, type) VALUES (?1, ?2, ?3, ?4)",
	); err != nil {
		return err
	}
	if c.stmtInsertXref, err = c.conn.Prepare(
		"INSERT OR REPLACE INTO xrefs (seg, source_addr, target_addr, type) VALUES (?1, ?2, ?3, ?4)",
	); err != nil {
		return err
	}
	if c.stmtInsertFunc, err = c.conn.Prepare(
		"INSERT OR IGNORE INTO functions (seg, entry_addr, name, confidence) VALUES (?1, ?2, ?3, ?4)",
	); err != nil {
		return err
	}
	if c.stmtSetLabel, err = c.conn.Prepare(
		`INSERT OR REPLACE INTO labels (seg, addr, name, type, is_auto, is_exported)
		 VALUES (?1, ?2, ?3, ?4, ?5, COALESCE((SELECT is_exported FROM labels WHERE seg = ?1 AND addr = ?2), 0))`,
	); err != nil {
		return err
	}
	if c.stmtSetLabelExp, err = c.conn.Prepare(
		"INSERT OR REPLACE INTO labels (seg, addr, name, type, is_auto, is_exported) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
	); err != nil {
		return err
	}
	if c.stmtMarkExp, err = c.conn.Prepare(
		"UPDATE labels SET is_exported = 1 WHERE seg = ?1 AND addr = ?2",
	); err != nil {
		return err
	}
	return nil
}

func (c *Controller) Close() error {
	for _, s := range []*sql.Stmt{
		c.stmtInsertCell,
		c.stmtInsertEdge,
		c.stmtInsertXref,
		c.stmtInsertFunc,
		c.stmtSetLabel,
		c.stmtSetLabelExp,
		c.stmtMarkExp,
	} {
		if s != nil {
			_ = s.Close()
		}
	}
	return c.conn.Close()
}

func (c *Controller) SetActiveSeg(name string) {
	c.mu.Lock()
	c.activeSeg = name
	c.mu.Unlock()
}

func (c *Controller) ActiveSeg() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.activeSeg
}

func (c *Controller) SetSpaceSegs(segs []SpaceSeg) {
	c.mu.Lock()
	c.spaceSegs = slices.Clone(segs)
	c.mu.Unlock()
}

func (c *Controller) WithActiveSeg(name string, fn func()) {
	prev := c.ActiveSeg()
	c.SetActiveSeg(name)
	defer c.SetActiveSeg(prev)
	fn()
}

func inSegRange(base, end, a uint32) bool {
	if base == end {
		return a == base
	}
	return a >= base && a < end
}

// SegOf resolves an address to its owning segment in the current view/analysis scope:
//  1. If activeSeg is in spaceSegs and addr lies in its [base, end), return activeSeg.
//  2. Otherwise return the segment in spaceSegs (last-listed-wins) containing addr.
//  3. Otherwise fall back to activeSeg ("" when unset).
func (c *Controller) SegOf(addr uint32) string {
	c.mu.RLock()
	active := c.activeSeg
	space := c.spaceSegs
	c.mu.RUnlock()

	if active != "" {
		foundInSpace := false
		for _, s := range space {
			if s.Name == active {
				foundInSpace = true
				if inSegRange(s.Base, s.End, addr) {
					return active
				}
				break
			}
		}
		if !foundInSpace {
			return active
		}
	}
	for i := len(space) - 1; i >= 0; i-- {
		s := space[i]
		if inSegRange(s.Base, s.End, addr) {
			return s.Name
		}
	}
	return active
}

func (c *Controller) EffectiveSpaceSegs() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.spaceSegs) == 0 {
		return []string{c.activeSeg}
	}
	out := make([]string, len(c.spaceSegs))
	for i, s := range c.spaceSegs {
		out[i] = s.Name
	}
	return out
}

func (c *Controller) orderedSpaceSegs() []string {
	v := c.EffectiveSpaceSegs()
	active := c.ActiveSeg()
	if active != "" {
		if idx := slices.Index(v, active); idx >= 0 {
			v = slices.Delete(v, idx, idx+1)
			v = append(v, active)
		}
	}
	return v
}

func (c *Controller) orderedSpaceSegsWithEmpty() []string {
	v := c.orderedSpaceSegs()
	if !slices.Contains(v, "") {
		v = append([]string{""}, v...)
	}
	return v
}

func (c *Controller) activeFirstSpaceSegs() []string {
	var v []string
	active := c.ActiveSeg()
	if active != "" {
		v = append(v, active)
	}
	eff := c.EffectiveSpaceSegs()
	for i := len(eff) - 1; i >= 0; i-- {
		s := eff[i]
		if !slices.Contains(v, s) {
			v = append(v, s)
		}
	}
	if !slices.Contains(v, "") {
		v = append(v, "")
	}
	return v
}

func (c *Controller) spaceSegInClause(includeEmpty bool) string {
	var segs []string
	if includeEmpty {
		segs = c.orderedSpaceSegsWithEmpty()
	} else {
		segs = c.orderedSpaceSegs()
	}
	parts := make([]string, len(segs))
	for i, s := range segs {
		parts[i] = fmt.Sprintf("'%s'", strings.ReplaceAll(s, "'", "''"))
	}
	return strings.Join(parts, ",")
}

func (c *Controller) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS cells (
		seg TEXT NOT NULL DEFAULT '',
		addr INTEGER NOT NULL,
		size INTEGER NOT NULL,
		type TEXT NOT NULL,
		confidence INTEGER NOT NULL DEFAULT 0,
		mnemonic TEXT,
		op_str TEXT,
		raw_bytes BLOB,
		PRIMARY KEY (seg, addr)
	);

	CREATE TABLE IF NOT EXISTS comments (
		seg TEXT NOT NULL DEFAULT '',
		addr INTEGER NOT NULL,
		comment TEXT NOT NULL DEFAULT '',
		block_comment TEXT NOT NULL DEFAULT '',
		auto_comment TEXT NOT NULL DEFAULT '',
		PRIMARY KEY (seg, addr)
	);

	CREATE TABLE IF NOT EXISTS labels (
		seg TEXT NOT NULL DEFAULT '',
		addr INTEGER NOT NULL,
		name TEXT NOT NULL,
		type TEXT NOT NULL DEFAULT 'DAT',
		is_auto BOOLEAN DEFAULT 1,
		is_exported BOOLEAN NOT NULL DEFAULT 0,
		PRIMARY KEY (seg, addr)
	);

	CREATE TABLE IF NOT EXISTS edges (
		seg TEXT NOT NULL DEFAULT '',
		source_addr INTEGER NOT NULL,
		target_addr INTEGER NOT NULL,
		type TEXT,
		PRIMARY KEY (seg, source_addr, target_addr)
	);

	CREATE TABLE IF NOT EXISTS xrefs (
		seg TEXT NOT NULL DEFAULT '',
		source_addr INTEGER NOT NULL,
		target_addr INTEGER NOT NULL,
		type TEXT NOT NULL DEFAULT 'DATA_ADDR',
		PRIMARY KEY (seg, source_addr, target_addr)
	);

	CREATE TABLE IF NOT EXISTS functions (
		seg TEXT NOT NULL DEFAULT '',
		entry_addr INTEGER NOT NULL,
		name TEXT,
		end_addr INTEGER,
		is_noreturn BOOLEAN DEFAULT 0,
		stack_frame INTEGER,
		confidence INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (seg, entry_addr)
	);

	CREATE TABLE IF NOT EXISTS renames (
		seg TEXT NOT NULL DEFAULT '',
		original TEXT NOT NULL,
		renamed TEXT NOT NULL,
		PRIMARY KEY (seg, original)
	);

	CREATE TABLE IF NOT EXISTS operand_formats (
		seg TEXT NOT NULL DEFAULT '',
		addr INTEGER NOT NULL,
		format TEXT NOT NULL,
		PRIMARY KEY (seg, addr)
	);

	CREATE TABLE IF NOT EXISTS relocs (
		seg TEXT NOT NULL DEFAULT '',
		site_addr INTEGER NOT NULL,
		target_addr INTEGER NOT NULL,
		PRIMARY KEY (seg, site_addr)
	);

	CREATE TABLE IF NOT EXISTS base_regs (
		scope_kind TEXT NOT NULL,
		scope_key TEXT NOT NULL,
		reg TEXT NOT NULL,
		base_addr INTEGER NOT NULL,
		source TEXT NOT NULL DEFAULT 'auto',
		PRIMARY KEY (scope_kind, scope_key, reg)
	);

	CREATE INDEX IF NOT EXISTS idx_edges_seg_target ON edges(seg, target_addr);
	CREATE INDEX IF NOT EXISTS idx_xrefs_seg_target ON xrefs(seg, target_addr);
	CREATE INDEX IF NOT EXISTS idx_cells_seg_type ON cells(seg, type);`
	_, err := c.conn.Exec(schema)
	return err
}

func (c *Controller) InsertReloc(siteAddr, targetAddr uint32) error {
	seg := c.SegOf(siteAddr)
	_, err := c.conn.Exec(
		"INSERT OR REPLACE INTO relocs (seg, site_addr, target_addr) VALUES (?1, ?2, ?3)",
		seg, siteAddr, targetAddr,
	)
	return err
}

func (c *Controller) forEachSegRow(query string, includeEmpty bool, visit func(*sql.Rows) error, args ...any) error {
	stmt, err := c.conn.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()

	segs := c.orderedSpaceSegs()
	if includeEmpty {
		segs = c.orderedSpaceSegsWithEmpty()
	}
	qArgs := make([]any, 1+len(args))
	copy(qArgs[1:], args)
	for _, seg := range segs {
		qArgs[0] = seg
		rows, err := stmt.Query(qArgs...)
		if err != nil {
			return err
		}
		for rows.Next() {
			if err := visit(rows); err != nil {
				_ = rows.Close()
				return err
			}
		}
		if err := rows.Close(); err != nil {
			return err
		}
	}
	return nil
}

// queryUint32s runs a single-column uint32 query and returns the collected values.
// A query or row-iteration error yields the rows collected so far (matching the prior
// best-effort accessors); callers that need strict errors should use a dedicated path.
func (c *Controller) queryUint32s(query string, args ...any) []uint32 {
	var out []uint32
	rows, err := c.conn.Query(query, args...)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var v uint32
		if rows.Scan(&v) == nil {
			out = append(out, v)
		}
	}
	return out
}

func (c *Controller) GetAllRelocs() (map[uint32]uint32, error) {
	m := make(map[uint32]uint32)
	err := c.forEachSegRow("SELECT site_addr, target_addr FROM relocs WHERE seg = ?1", false, func(rows *sql.Rows) error {
		var site, target uint32
		if err := rows.Scan(&site, &target); err != nil {
			return err
		}
		m[site] = target
		return nil
	})
	if err != nil {
		return nil, err
	}
	return m, nil
}

func (c *Controller) SetBaseReg(scopeKind, scopeKey, reg string, baseAddr uint32, source string) error {
	_, err := c.conn.Exec(
		"INSERT OR REPLACE INTO base_regs (scope_kind, scope_key, reg, base_addr, source) VALUES (?1, ?2, ?3, ?4, ?5)",
		scopeKind, scopeKey, strings.ToLower(reg), baseAddr, source,
	)
	return err
}

func (c *Controller) ClearAutoBaseRegs() error {
	_, err := c.conn.Exec("DELETE FROM base_regs WHERE source = 'auto'")
	return err
}

func (c *Controller) GetAllBaseRegs() ([]BaseReg, error) {
	rows, err := c.conn.Query("SELECT scope_kind, scope_key, reg, base_addr, source FROM base_regs")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []BaseReg
	for rows.Next() {
		var b BaseReg
		if err := rows.Scan(&b.ScopeKind, &b.ScopeKey, &b.Reg, &b.BaseAddr, &b.Source); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (c *Controller) InsertCell(cell *Cell) error {
	seg := cell.Seg
	if seg == "" {
		seg = c.SegOf(cell.Addr)
	}
	_, err := c.stmtInsertCell.Exec(
		seg, cell.Addr, cell.Size, cell.Type.AsStr(), cell.Confidence, cell.Mnemonic, cell.OpStr, cell.RawBytes,
	)
	return err
}

func (c *Controller) InsertCellsBatch(cells []Cell) error {
	for i := range cells {
		if err := c.InsertCell(&cells[i]); err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) SetLabel(addr uint32, name string, kind LabelKind, isAuto bool) error {
	seg := c.SegOf(addr)
	_, err := c.stmtSetLabel.Exec(seg, addr, name, kind.AsStr(), isAuto)
	return err
}

func (c *Controller) SetLabelExported(addr uint32, name string, kind LabelKind, isAuto, isExported bool) error {
	seg := c.SegOf(addr)
	_, err := c.stmtSetLabelExp.Exec(seg, addr, name, kind.AsStr(), isAuto, isExported)
	return err
}

func (c *Controller) MarkExported(addr uint32) error {
	seg := c.SegOf(addr)
	_, err := c.stmtMarkExp.Exec(seg, addr)
	return err
}

func (c *Controller) GetExportedLabels() ([]string, error) {
	seg := c.ActiveSeg()
	rows, err := c.conn.Query(
		`SELECT COALESCE(r.renamed, l.name)
		 FROM labels l LEFT JOIN renames r ON r.seg = l.seg AND r.original = l.name
		 WHERE (l.seg = ?1 OR l.seg = '') AND l.is_exported = 1 ORDER BY l.name`,
		seg,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		names = append(names, n)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	slices.Sort(names)
	names = slices.Compact(names)
	return names, nil
}

func (c *Controller) GetExportedLabelsInRange(startAddr, endAddr uint32) ([]string, error) {
	seg := c.SegOf(startAddr)
	rows, err := c.conn.Query(
		`SELECT COALESCE(r.renamed, l.name)
		 FROM labels l LEFT JOIN renames r ON r.seg = l.seg AND r.original = l.name
		 WHERE (l.seg = ?1 OR l.seg = '') AND l.is_exported = 1 AND l.addr >= ?2 AND l.addr < ?3 ORDER BY l.name`,
		seg, startAddr, endAddr,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		names = append(names, n)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	slices.Sort(names)
	names = slices.Compact(names)
	return names, nil
}

func (c *Controller) GetAllLabelsResolved() (map[uint32]string, error) {
	m := make(map[uint32]string)
	err := c.forEachSegRow(
		`SELECT l.addr, COALESCE(r.renamed, r2.renamed, l.name)
		 FROM labels l
		 LEFT JOIN renames r ON r.seg = l.seg AND r.original = l.name
		 LEFT JOIN renames r2 ON r2.seg = l.seg AND (
		     (l.name LIKE 'EQU_%' AND r2.original = 'LAB_' || SUBSTR(l.name, 5)) OR
		     (l.name LIKE 'LAB_%' AND r2.original = 'EQU_' || SUBSTR(l.name, 5))
		 )
		 WHERE l.seg = ?1 ORDER BY l.addr ASC`,
		true,
		func(rows *sql.Rows) error {
			var addr uint32
			var resolved string
			if err := rows.Scan(&addr, &resolved); err != nil {
				return err
			}
			m[addr] = resolved
			return nil
		},
	)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func (c *Controller) GetLabel(addr uint32) (string, bool, error) {
	seg := c.SegOf(addr)
	var name string
	err := c.conn.QueryRow(
		"SELECT name FROM labels WHERE (seg = ?1 OR seg = '') AND addr = ?2 ORDER BY (seg = ?1) DESC LIMIT 1",
		seg, addr,
	).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return name, true, nil
}

func (c *Controller) GetLabelFull(addr uint32) (*Label, error) {
	seg := c.SegOf(addr)
	row := c.conn.QueryRow(
		"SELECT seg, addr, name, type, is_auto, is_exported FROM labels WHERE (seg = ?1 OR seg = '') AND addr = ?2 ORDER BY (seg = ?1) DESC LIMIT 1",
		seg, addr,
	)
	lbl, err := scanLabel(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &lbl, nil
}

func (c *Controller) LabelAddrByName(name string, ci bool) (uint32, bool) {
	query := "SELECT addr FROM labels WHERE seg = ?1 AND name = ?2"
	if ci {
		query = "SELECT addr FROM labels WHERE seg = ?1 AND LOWER(name) = LOWER(?2)"
	}
	stmt, err := c.conn.Prepare(query)
	if err != nil {
		return 0, false
	}
	defer stmt.Close()

	for _, seg := range c.activeFirstSpaceSegs() {
		var addr uint32
		if err := stmt.QueryRow(seg, name).Scan(&addr); err == nil {
			return addr, true
		}
	}
	return 0, false
}

func (c *Controller) RenameOriginalOf(renamed string, ci bool) (string, bool) {
	query := "SELECT original FROM renames WHERE seg = ?1 AND renamed = ?2"
	if ci {
		query = "SELECT original FROM renames WHERE seg = ?1 AND LOWER(renamed) = LOWER(?2)"
	}
	stmt, err := c.conn.Prepare(query)
	if err != nil {
		return "", false
	}
	defer stmt.Close()

	for _, seg := range c.activeFirstSpaceSegs() {
		var orig string
		if err := stmt.QueryRow(seg, renamed).Scan(&orig); err == nil {
			return orig, true
		}
	}
	return "", false
}

func (c *Controller) LabelAddrs(rng *AddrRange) []uint32 {
	seen := make(map[uint32]struct{})
	visit := func(rows *sql.Rows) error {
		var a uint32
		if rows.Scan(&a) == nil {
			seen[a] = struct{}{}
		}
		return nil
	}
	if rng != nil {
		_ = c.forEachSegRow("SELECT addr FROM labels WHERE seg = ?1 AND addr >= ?2 AND addr < ?3", true, visit, rng.Start, rng.End)
	} else {
		_ = c.forEachSegRow("SELECT addr FROM labels WHERE seg = ?1", true, visit)
	}
	return slices.Sorted(maps.Keys(seen))
}

func (c *Controller) SetCellText(addr uint32, mnemonic, opStr string) error {
	seg := c.SegOf(addr)
	_, err := c.conn.Exec(
		"UPDATE cells SET mnemonic = ?1, op_str = ?2 WHERE seg = ?3 AND addr = ?4",
		mnemonic, opStr, seg, addr,
	)
	return err
}

func (c *Controller) SetCellOp(addr uint32, opStr string) error {
	seg := c.SegOf(addr)
	_, err := c.conn.Exec(
		"UPDATE cells SET op_str = ?1 WHERE seg = ?2 AND addr = ?3",
		opStr, seg, addr,
	)
	return err
}

func (c *Controller) SetCellTexts(updates []CellTextUpdate) error {
	return c.WithTransaction(func() error {
		stmt, err := c.conn.Prepare("UPDATE cells SET mnemonic = ?1, op_str = ?2 WHERE seg = ?3 AND addr = ?4")
		if err != nil {
			return err
		}
		defer stmt.Close()

		for _, u := range updates {
			seg := c.SegOf(u.Addr)
			if _, err := stmt.Exec(u.Mnemonic, u.OpStr, seg, u.Addr); err != nil {
				return err
			}
		}
		return nil
	})
}

func (c *Controller) CodeCoverageBytes() uint32 {
	inClause := c.spaceSegInClause(false)
	query := fmt.Sprintf("SELECT COALESCE(SUM(size),0) FROM cells WHERE seg IN (%s) AND type = 'CODE'", inClause)
	var sum uint32
	if err := c.conn.QueryRow(query).Scan(&sum); err != nil {
		return 0
	}
	return sum
}

func (c *Controller) DeleteSegment(seg string) error {
	tables := []string{
		"cells",
		"labels",
		"edges",
		"xrefs",
		"functions",
		"renames",
		"operand_formats",
		"relocs",
	}
	for _, table := range tables {
		query := fmt.Sprintf("DELETE FROM %s WHERE seg = ?1", table)
		if _, err := c.conn.Exec(query, seg); err != nil {
			return err
		}
	}
	_, err := c.conn.Exec("DELETE FROM base_regs WHERE scope_kind = 'segment' AND scope_key = ?1", seg)
	return err
}

func (c *Controller) DeleteAllCells() error {
	for _, seg := range c.EffectiveSpaceSegs() {
		if _, err := c.conn.Exec("DELETE FROM cells WHERE seg = ?1", seg); err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) DeleteCodeCells() error {
	for _, seg := range c.EffectiveSpaceSegs() {
		if _, err := c.conn.Exec("DELETE FROM cells WHERE seg = ?1 AND type = 'CODE'", seg); err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) ProtectedNoncodeRanges(conf uint8) []AddrRange {
	var out []AddrRange
	inClause := c.spaceSegInClause(false)
	query := fmt.Sprintf(
		"SELECT addr, size FROM cells WHERE seg IN (%s) AND type != 'CODE' AND confidence >= ?1 ORDER BY addr ASC",
		inClause,
	)
	rows, err := c.conn.Query(query, conf)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var a, s uint32
		if rows.Scan(&a, &s) == nil {
			out = append(out, AddrRange{Start: a, End: a + s})
		}
	}
	return out
}

func (c *Controller) Begin() {
	_, _ = c.conn.Exec("BEGIN TRANSACTION")
}

func (c *Controller) Commit() {
	_, _ = c.conn.Exec("COMMIT")
}

func (c *Controller) CellRangesIn(start, end uint32) []AddrRange {
	var out []AddrRange
	seg := c.SegOf(start)
	rows, err := c.conn.Query(
		"SELECT addr, size FROM cells WHERE seg = ?1 AND addr >= ?2 AND addr < ?3 ORDER BY addr ASC",
		seg, start, end,
	)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var a, s uint32
		if rows.Scan(&a, &s) == nil {
			out = append(out, AddrRange{Start: a, End: a + s})
		}
	}
	return out
}

func (c *Controller) RelocsInRange(start, end uint32) []uint32 {
	seg := c.SegOf(start)
	return c.queryUint32s(
		"SELECT site_addr FROM relocs WHERE seg = ?1 AND site_addr >= ?2 AND site_addr < ?3 ORDER BY site_addr ASC",
		seg, start, end,
	)
}

func (c *Controller) DeleteCellsInRange(start, end uint32) error {
	seg := c.SegOf(start)
	_, err := c.conn.Exec(
		"DELETE FROM cells WHERE seg = ?1 AND addr >= ?2 AND addr < ?3",
		seg, start, end,
	)
	return err
}

func (c *Controller) DeleteCellAt(addr uint32) error {
	seg := c.SegOf(addr)
	_, err := c.conn.Exec("DELETE FROM cells WHERE seg = ?1 AND addr = ?2", seg, addr)
	return err
}

func (c *Controller) DeleteCellAndEdges(addr uint32) error {
	seg := c.SegOf(addr)
	if _, err := c.conn.Exec("DELETE FROM cells WHERE seg = ?1 AND addr = ?2", seg, addr); err != nil {
		return err
	}
	_, _ = c.conn.Exec("UPDATE comments SET auto_comment = '' WHERE seg = ?1 AND addr = ?2", seg, addr)
	_, _ = c.conn.Exec("DELETE FROM comments WHERE seg = ?1 AND addr = ?2 AND comment = '' AND block_comment = '' AND auto_comment = ''", seg, addr)
	_, err := c.conn.Exec("DELETE FROM edges WHERE seg = ?1 AND source_addr = ?2", seg, addr)
	return err
}

func (c *Controller) DeleteLabelAt(addr uint32) error {
	seg := c.SegOf(addr)
	_, err := c.conn.Exec("DELETE FROM labels WHERE (seg = ?1 OR seg = '') AND addr = ?2", seg, addr)
	return err
}

func (c *Controller) DeleteEdgesFrom(sourceAddr uint32) error {
	seg := c.SegOf(sourceAddr)
	_, err := c.conn.Exec("DELETE FROM edges WHERE seg = ?1 AND source_addr = ?2", seg, sourceAddr)
	return err
}

func (c *Controller) DeleteXrefsFrom(sourceAddr uint32) error {
	seg := c.SegOf(sourceAddr)
	_, err := c.conn.Exec("DELETE FROM xrefs WHERE seg = ?1 AND source_addr = ?2", seg, sourceAddr)
	return err
}

func (c *Controller) DeleteEdgesAndXrefsTo(targetAddr uint32) error {
	seg := c.SegOf(targetAddr)
	_, _ = c.conn.Exec("DELETE FROM edges WHERE (seg = ?1 OR seg = '') AND target_addr = ?2", seg, targetAddr)
	_, err := c.conn.Exec("DELETE FROM xrefs WHERE (seg = ?1 OR seg = '') AND target_addr = ?2", seg, targetAddr)
	return err
}

func (c *Controller) DeleteFunctionAt(entryAddr uint32) error {
	seg := c.SegOf(entryAddr)
	_, err := c.conn.Exec("DELETE FROM functions WHERE (seg = ?1 OR seg = '') AND entry_addr = ?2", seg, entryAddr)
	return err
}

func (c *Controller) DeleteLabelAndRename(addr uint32) error {
	seg := c.SegOf(addr)
	if lbl, err := c.GetLabelFull(addr); err == nil && lbl != nil {
		_, _ = c.conn.Exec(
			"DELETE FROM renames WHERE (seg = ?1 OR seg = '') AND (original = ?2 OR renamed = ?2)",
			seg, lbl.Name,
		)
	}
	if _, err := c.conn.Exec("DELETE FROM labels WHERE (seg = ?1 OR seg = '') AND addr = ?2", seg, addr); err != nil {
		return err
	}
	_, _ = c.conn.Exec("DELETE FROM functions WHERE (seg = ?1 OR seg = '') AND entry_addr = ?2", seg, addr)
	return nil
}

func (c *Controller) RenameLabelAt(addr uint32, name string) error {
	seg := c.SegOf(addr)
	_, err := c.conn.Exec("UPDATE labels SET name = ?1 WHERE seg = ?2 AND addr = ?3", name, seg, addr)
	return err
}

func (c *Controller) SetCellComment(addr uint32, comment string) error {
	return c.UpdateComment(addr, comment)
}

func (c *Controller) DeleteRename(original string) error {
	seg := c.ActiveSeg()
	_, err := c.conn.Exec("DELETE FROM renames WHERE seg = ?1 AND original = ?2", seg, original)
	return err
}

func (c *Controller) FirstControlEdgeTarget(sourceAddr uint32) (uint32, bool) {
	seg := c.SegOf(sourceAddr)
	var target uint32
	err := c.conn.QueryRow(
		"SELECT target_addr FROM edges WHERE seg = ?1 AND source_addr = ?2 AND type IN ('CALL','UNCOND','COND_TRUE') LIMIT 1",
		seg, sourceAddr,
	).Scan(&target)
	if err != nil {
		return 0, false
	}
	return target, true
}

func (c *Controller) FirstXrefTargetIn(start, end uint32) (uint32, bool) {
	seg := c.SegOf(start)
	var target uint32
	err := c.conn.QueryRow(
		`SELECT target_addr FROM xrefs
		 WHERE seg = ?1 AND source_addr >= ?2 AND source_addr < ?3
		 ORDER BY CASE type WHEN 'CODE_CALL' THEN 0 WHEN 'CODE_BRANCH' THEN 1 WHEN 'DATA_ADDR' THEN 2 ELSE 3 END, source_addr ASC
		 LIMIT 1`,
		seg, start, end,
	).Scan(&target)
	if err != nil {
		return 0, false
	}
	return target, true
}

func (c *Controller) CellTypeMapIn(start, end uint32) []CellTypeInfo {
	var out []CellTypeInfo
	seg := c.SegOf(start)
	rows, err := c.conn.Query(
		"SELECT addr, type, size FROM cells WHERE seg = ?1 AND addr >= ?2 AND addr < ?3",
		seg, start, end,
	)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var addr, size uint32
		var typStr string
		if rows.Scan(&addr, &typStr, &size) == nil {
			if ct, err := ParseCellType(typStr); err == nil {
				out = append(out, CellTypeInfo{Addr: addr, Type: ct, Size: size})
			}
		}
	}
	return out
}

func (c *Controller) CrossRegionControlSources(start, end uint32) []uint32 {
	seg := c.SegOf(start)
	return c.queryUint32s(
		`SELECT DISTINCT source_addr FROM edges
		 WHERE seg = ?1 AND source_addr >= ?2 AND source_addr < ?3
		 AND (target_addr < ?2 OR target_addr >= ?3)
		 AND type IN ('CALL','UNCOND','COND_TRUE')`,
		seg, start, end,
	)
}

func (c *Controller) NearestLabelAtOrBefore(floor, addr uint32) (string, bool) {
	seg := c.SegOf(addr)
	var name string
	err := c.conn.QueryRow(
		"SELECT name FROM labels WHERE (seg = ?1 OR seg = '') AND addr >= ?2 AND addr <= ?3 ORDER BY addr DESC, (seg = ?1) DESC LIMIT 1",
		seg, floor, addr,
	).Scan(&name)
	if err != nil {
		return "", false
	}
	return name, true
}

func (c *Controller) RefsTo(addr uint32) []AddrText {
	var out []AddrText
	inEmpty := c.spaceSegInClause(true)
	query := fmt.Sprintf(
		`SELECT source_addr, type FROM xrefs WHERE seg IN (%s) AND target_addr = ?1
		 UNION
		 SELECT source_addr, type FROM edges WHERE seg IN (%s) AND target_addr = ?1 AND type != 'FALLTHROUGH'
		 ORDER BY source_addr`,
		inEmpty, inEmpty,
	)
	rows, err := c.conn.Query(query, addr)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var src uint32
		var typ string
		if rows.Scan(&src, &typ) == nil {
			out = append(out, AddrText{Addr: src, Text: typ})
		}
	}
	return out
}

func (c *Controller) FunctionLabelAddrs() []uint32 {
	inClause := c.spaceSegInClause(false)
	inEmpty := c.spaceSegInClause(true)
	queryInto := func(q string) []uint32 {
		var out []uint32
		rows, err := c.conn.Query(q)
		if err != nil {
			return out
		}
		defer rows.Close()
		for rows.Next() {
			var a uint32
			if rows.Scan(&a) == nil {
				out = append(out, a)
			}
		}
		return out
	}
	sql1 := fmt.Sprintf(
		`SELECT DISTINCT addr FROM (
			SELECT l.addr AS addr FROM labels l JOIN cells c ON c.seg = l.seg AND c.addr = l.addr
			WHERE c.seg IN (%s) AND c.type = 'CODE' AND (
			    l.type = 'SUB'
			    OR l.is_exported = 1
			    OR EXISTS (SELECT 1 FROM edges e WHERE e.seg IN (%s) AND e.target_addr = l.addr AND e.type = 'CALL')
			    OR (
			        EXISTS (SELECT 1 FROM xrefs x WHERE x.seg IN (%s) AND x.target_addr = l.addr AND x.type != 'CODE_BRANCH')
			        AND NOT EXISTS (SELECT 1 FROM xrefs xb WHERE xb.seg IN (%s) AND xb.target_addr = l.addr AND xb.type = 'CODE_BRANCH')
			    )
			)
			UNION
			SELECT f.entry_addr AS addr FROM functions f JOIN cells c ON c.seg = f.seg AND c.addr = f.entry_addr
			WHERE c.seg IN (%s) AND c.type = 'CODE'
			AND NOT EXISTS (SELECT 1 FROM xrefs xb WHERE xb.seg IN (%s) AND xb.target_addr = f.entry_addr AND xb.type = 'CODE_BRANCH')
		) ORDER BY addr ASC`,
		inClause, inClause, inEmpty, inEmpty, inClause, inEmpty,
	)
	return queryInto(sql1)
}

func (c *Controller) DataReadWriteTargets() []uint32 {
	inClause := c.spaceSegInClause(false)
	return c.queryUint32s(fmt.Sprintf(
		"SELECT DISTINCT target_addr FROM xrefs WHERE seg IN (%s) AND type IN ('DATA_READ', 'DATA_WRITE')",
		inClause,
	))
}

func (c *Controller) searchBoundsAndClause(rng *AddrRange, col string, includeEmpty bool) (uint32, uint32, string) {
	if rng != nil {
		seg := strings.ReplaceAll(c.SegOf(rng.Start), "'", "''")
		if includeEmpty {
			return rng.Start, rng.End, fmt.Sprintf("(%s = '%s' OR %s = '')", col, seg, col)
		}
		return rng.Start, rng.End, fmt.Sprintf("%s = '%s'", col, seg)
	}
	return 0, 0xFFFFFFFF, fmt.Sprintf("%s IN (%s)", col, c.spaceSegInClause(includeEmpty))
}

func (c *Controller) SearchLabels(needle string, rng *AddrRange, limit int) []AddrText {
	var out []AddrText
	pat := fmt.Sprintf("%%%s%%", needle)
	lo, hi, segFilter := c.searchBoundsAndClause(rng, "l.seg", true)
	query := fmt.Sprintf(
		`SELECT l.addr, COALESCE(r.renamed, l.name) as resolved
		 FROM labels l LEFT JOIN renames r ON r.seg = l.seg AND r.original = l.name
		 WHERE %s AND (resolved LIKE ?1 OR l.name LIKE ?1) AND l.addr >= ?2 AND l.addr < ?3
		 ORDER BY l.addr LIMIT ?4`,
		segFilter,
	)
	rows, err := c.conn.Query(query, pat, lo, hi, limit)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var a uint32
		var t string
		if rows.Scan(&a, &t) == nil {
			out = append(out, AddrText{Addr: a, Text: t})
		}
	}
	return out
}

func (c *Controller) SearchComments(needle string, rng *AddrRange, limit int) []AddrText {
	var out []AddrText
	pat := fmt.Sprintf("%%%s%%", needle)
	lo, hi, segFilter := c.searchBoundsAndClause(rng, "seg", false)
	query := fmt.Sprintf(
		`SELECT addr, CASE WHEN comment != '' THEN comment WHEN block_comment != '' THEN block_comment ELSE auto_comment END as cmt FROM comments
		 WHERE %s AND (comment LIKE ?1 OR block_comment LIKE ?1 OR auto_comment LIKE ?1) AND addr >= ?2 AND addr < ?3
		 ORDER BY addr LIMIT ?4`,
		segFilter,
	)
	rows, err := c.conn.Query(query, pat, lo, hi, limit)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var a uint32
		var t string
		if rows.Scan(&a, &t) == nil {
			out = append(out, AddrText{Addr: a, Text: t})
		}
	}
	return out
}

func (c *Controller) SearchCode(field, needle string, rng *AddrRange, limit int) []AddrText {
	var out []AddrText
	pat := fmt.Sprintf("%%%s%%", needle)
	col := "op_str"
	if field == "m" {
		col = "mnemonic"
	}
	lo, hi, segFilter := c.searchBoundsAndClause(rng, "seg", false)
	query := fmt.Sprintf(
		`SELECT addr, COALESCE(mnemonic,''), COALESCE(op_str,'') FROM cells
		 WHERE %s AND type = 'CODE' AND %s LIKE ?1 AND addr >= ?2 AND addr < ?3
		 ORDER BY addr LIMIT ?4`,
		segFilter, col,
	)
	rows, err := c.conn.Query(query, pat, lo, hi, limit)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var a uint32
		var m, o string
		if rows.Scan(&a, &m, &o) == nil {
			text := m
			if o != "" {
				text = m + "\t" + o
			}
			out = append(out, AddrText{Addr: a, Text: text})
		}
	}
	return out
}

func (c *Controller) SearchStrings(needle string, rng *AddrRange, limit int) []AddrText {
	var out []AddrText
	lo, hi, segFilter := c.searchBoundsAndClause(rng, "seg", false)
	query := fmt.Sprintf(
		`SELECT addr, raw_bytes FROM cells
		 WHERE %s AND type = 'STRING' AND addr >= ?1 AND addr < ?2 ORDER BY addr`,
		segFilter,
	)
	rows, err := c.conn.Query(query, lo, hi)
	if err != nil {
		return out
	}
	defer rows.Close()

	needleLC := strings.ToLower(needle)
	for rows.Next() {
		var addr uint32
		var raw []byte
		if rows.Scan(&addr, &raw) != nil {
			continue
		}
		var sb strings.Builder
		sb.Grow(len(raw))
		for _, b := range raw {
			if b >= 0x20 && b < 0x7F {
				sb.WriteByte(b)
			} else {
				sb.WriteByte('.')
			}
		}
		text := sb.String()
		if strings.Contains(strings.ToLower(text), needleLC) {
			out = append(out, AddrText{Addr: addr, Text: text})
			if len(out) >= limit {
				break
			}
		}
	}
	return out
}

func (c *Controller) DataCellsOrdered() []AddrRange {
	var out []AddrRange
	inClause := c.spaceSegInClause(false)
	query := fmt.Sprintf(
		"SELECT addr, size FROM cells WHERE seg IN (%s) AND type LIKE 'DATA%%' ORDER BY addr ASC",
		inClause,
	)
	rows, err := c.conn.Query(query)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var a, s uint32
		if rows.Scan(&a, &s) == nil {
			out = append(out, AddrRange{Start: a, End: s})
		}
	}
	return out
}

func (c *Controller) SourceAddrsReferencing(targets []uint32) []uint32 {
	seen := make(map[uint32]struct{})
	inEmpty := c.spaceSegInClause(true)
	query := fmt.Sprintf(
		`SELECT source_addr FROM xrefs WHERE seg IN (%s) AND target_addr = ?1
		 UNION
		 SELECT source_addr FROM edges WHERE seg IN (%s) AND target_addr = ?1`,
		inEmpty, inEmpty,
	)
	stmt, err := c.conn.Prepare(query)
	if err != nil {
		return nil
	}
	defer stmt.Close()

	for _, t := range targets {
		rows, err := stmt.Query(t)
		if err != nil {
			continue
		}
		for rows.Next() {
			var a uint32
			if rows.Scan(&a) == nil {
				seen[a] = struct{}{}
			}
		}
		_ = rows.Close()
	}
	return slices.Sorted(maps.Keys(seen))
}

func (c *Controller) DeleteNoncodeCellsBelowConf(conf uint8) error {
	for _, seg := range c.EffectiveSpaceSegs() {
		if _, err := c.conn.Exec(
			"DELETE FROM cells WHERE seg = ?1 AND type != 'CODE' AND confidence < ?2",
			seg, conf,
		); err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) CellsInRange(start, end uint32) ([]Cell, error) {
	seg := c.SegOf(start)
	rows, err := c.conn.Query(
		"SELECT "+cellColumns+" FROM cells WHERE seg = ?1 AND addr >= ?2 AND addr < ?3 ORDER BY addr ASC",
		seg, start, end,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Cell
	for rows.Next() {
		cell, err := scanCell(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, cell)
	}
	return out, rows.Err()
}

func (c *Controller) CellsOverlapping(addr, size uint32) ([]Cell, error) {
	seg := c.SegOf(addr)
	end := addr + size
	rows, err := c.conn.Query(
		"SELECT "+cellColumns+" FROM cells WHERE seg = ?1 AND addr < ?3 AND addr + size > ?2 ORDER BY addr ASC",
		seg, addr, end,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Cell
	for rows.Next() {
		cell, err := scanCell(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, cell)
	}
	return out, rows.Err()
}

func (c *Controller) LabelsNamedInRange(start, end uint32) []AddrText {
	var out []AddrText
	seg := c.SegOf(start)
	rows, err := c.conn.Query(
		`SELECT l.addr, COALESCE(r.renamed, l.name)
		 FROM labels l LEFT JOIN renames r ON r.seg = l.seg AND r.original = l.name
		 WHERE (l.seg = ?1 OR l.seg = '') AND l.addr >= ?2 AND l.addr < ?3 ORDER BY l.addr ASC`,
		seg, start, end,
	)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var a uint32
		var n string
		if rows.Scan(&a, &n) == nil {
			out = append(out, AddrText{Addr: a, Text: n})
		}
	}
	return out
}

func (c *Controller) RefsTargetingRange(start, end uint32) []Ref {
	var out []Ref
	inEmpty := c.spaceSegInClause(true)
	query := fmt.Sprintf(
		`SELECT seg, target_addr, source_addr FROM xrefs WHERE seg IN (%s) AND target_addr >= ?1 AND target_addr < ?2
		 UNION
		 SELECT seg, target_addr, source_addr FROM edges WHERE seg IN (%s) AND target_addr >= ?1 AND target_addr < ?2 AND type != 'FALLTHROUGH'`,
		inEmpty, inEmpty,
	)
	rows, err := c.conn.Query(query, start, end)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var r Ref
		if rows.Scan(&r.Seg, &r.Target, &r.Source) == nil {
			out = append(out, r)
		}
	}
	return out
}

func (c *Controller) OpStrsWithHWRefs() []string {
	var out []string
	inClause := c.spaceSegInClause(false)
	query := fmt.Sprintf(
		"SELECT op_str FROM cells WHERE seg IN (%s) AND (op_str LIKE '%%CUSTOM_%%' OR op_str LIKE '%%CIAA_%%' OR op_str LIKE '%%CIAB_%%')",
		inClause,
	)
	rows, err := c.conn.Query(query)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var s string
		if rows.Scan(&s) == nil {
			out = append(out, s)
		}
	}
	return out
}

func (c *Controller) AllLabelsWithExport() []Label {
	var out []Label
	_ = c.forEachSegRow("SELECT seg, addr, name, type, is_auto, is_exported FROM labels WHERE seg = ?1", true, func(rows *sql.Rows) error {
		if l, err := scanLabel(rows); err == nil {
			out = append(out, l)
		}
		return nil
	})
	return out
}

func (c *Controller) AllEdgesNoFallthrough() []Edge {
	var out []Edge
	inClause := c.spaceSegInClause(false)
	query := fmt.Sprintf(
		"SELECT seg, source_addr, target_addr, type FROM edges WHERE seg IN (%s) AND type != 'FALLTHROUGH'",
		inClause,
	)
	rows, err := c.conn.Query(query)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		if e, err := scanEdge(rows); err == nil {
			out = append(out, e)
		}
	}
	return out
}

func (c *Controller) AllXrefs() []Xref {
	var out []Xref
	inEmpty := c.spaceSegInClause(true)
	query := fmt.Sprintf(
		"SELECT seg, source_addr, target_addr, type FROM xrefs WHERE seg IN (%s)",
		inEmpty,
	)
	rows, err := c.conn.Query(query)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		if x, err := scanXref(rows); err == nil {
			out = append(out, x)
		}
	}
	return out
}

func (c *Controller) CodeCells() []Cell {
	var out []Cell
	_ = c.forEachSegRow("SELECT "+cellColumns+" FROM cells WHERE seg = ?1 AND type = 'CODE' ORDER BY addr ASC", false, func(rows *sql.Rows) error {
		if cell, err := scanCell(rows); err == nil {
			out = append(out, cell)
		}
		return nil
	})
	return out
}

func (c *Controller) HasDataXref(addr uint32) bool {
	inEmpty := c.spaceSegInClause(true)
	query := fmt.Sprintf(
		"SELECT 1 FROM xrefs WHERE seg IN (%s) AND target_addr = ?1 AND type IN ('DATA_ADDR','DATA_READ','DATA_WRITE') LIMIT 1",
		inEmpty,
	)
	var one int
	return c.conn.QueryRow(query, addr).Scan(&one) == nil
}

type AddrBytes struct {
	Addr uint32
	Raw  []byte
}

type CellSlot struct {
	Addr   uint32
	IsCode bool
}

func (c *Controller) SpaceCellSlots() []CellSlot {
	var out []CellSlot
	_ = c.forEachSegRow("SELECT addr, (type = 'CODE') FROM cells WHERE seg = ?1 ORDER BY addr ASC", false, func(rows *sql.Rows) error {
		var s CellSlot
		if rows.Scan(&s.Addr, &s.IsCode) == nil {
			out = append(out, s)
		}
		return nil
	})
	return out
}

func (c *Controller) CodeCellAddrs() []uint32 {
	var out []uint32
	_ = c.forEachSegRow("SELECT addr FROM cells WHERE seg = ?1 AND type = 'CODE' ORDER BY addr ASC", false, func(rows *sql.Rows) error {
		var addr uint32
		if rows.Scan(&addr) == nil {
			out = append(out, addr)
		}
		return nil
	})
	return out
}

func (c *Controller) SpaceCellRanges() []AddrRange {
	inClause := c.spaceSegInClause(false)
	query := fmt.Sprintf("SELECT addr, size FROM cells WHERE seg IN (%s) ORDER BY addr ASC", inClause)
	rows, err := c.conn.Query(query)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []AddrRange
	for rows.Next() {
		var addr, size uint32
		if rows.Scan(&addr, &size) == nil {
			out = append(out, AddrRange{Start: addr, End: addr + size})
		}
	}
	return out
}

func (c *Controller) CodeCellsWithRaw() []AddrBytes {
	var out []AddrBytes
	_ = c.forEachSegRow("SELECT addr, raw_bytes FROM cells WHERE seg = ?1 AND type = 'CODE' AND raw_bytes IS NOT NULL", false, func(rows *sql.Rows) error {
		var addr uint32
		var raw []byte
		if rows.Scan(&addr, &raw) == nil && len(raw) > 0 {
			out = append(out, AddrBytes{Addr: addr, Raw: raw})
		}
		return nil
	})
	return out
}

func (c *Controller) WithTransaction(fn func() error) error {
	if _, err := c.conn.Exec("BEGIN TRANSACTION"); err != nil {
		return err
	}
	if err := fn(); err != nil {
		_, _ = c.conn.Exec("ROLLBACK")
		return err
	}
	_, err := c.conn.Exec("COMMIT")
	return err
}

func (c *Controller) GetCell(addr uint32) (*Cell, error) {
	seg := c.SegOf(addr)
	row := c.conn.QueryRow(
		"SELECT "+cellColumns+" FROM cells WHERE seg = ?1 AND addr = ?2",
		seg, addr,
	)
	cell, err := scanCell(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &cell, nil
}

func (c *Controller) GetAllCells() ([]Cell, error) {
	var cells []Cell
	err := c.forEachSegRow("SELECT "+cellColumns+" FROM cells WHERE seg = ?1 ORDER BY addr ASC", false, func(rows *sql.Rows) error {
		cell, err := scanCell(rows)
		if err != nil {
			return err
		}
		cells = append(cells, cell)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return cells, nil
}

func (c *Controller) GetCellContaining(addr uint32) (*Cell, error) {
	seg := c.SegOf(addr)
	row := c.conn.QueryRow(
		"SELECT "+cellColumns+" FROM cells WHERE seg = ?1 AND addr <= ?2 ORDER BY addr DESC LIMIT 1",
		seg, addr,
	)
	cell, err := scanCell(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if addr >= cell.Addr && addr < cell.Addr+cell.Size {
		return &cell, nil
	}
	return nil, nil
}

func (c *Controller) UpdateComment(addr uint32, comment string) error {
	seg := c.SegOf(addr)
	if _, err := c.conn.Exec(
		`INSERT INTO comments (seg, addr, comment) VALUES (?1, ?2, ?3)
		 ON CONFLICT(seg, addr) DO UPDATE SET comment = excluded.comment`,
		seg, addr, comment,
	); err != nil {
		return err
	}
	_, err := c.conn.Exec(
		"DELETE FROM comments WHERE seg = ?1 AND addr = ?2 AND comment = '' AND block_comment = '' AND auto_comment = ''",
		seg, addr,
	)
	return err
}

func (c *Controller) UpdateBlockComment(addr uint32, blockComment string) error {
	seg := c.SegOf(addr)
	if _, err := c.conn.Exec(
		`INSERT INTO comments (seg, addr, block_comment) VALUES (?1, ?2, ?3)
		 ON CONFLICT(seg, addr) DO UPDATE SET block_comment = excluded.block_comment`,
		seg, addr, blockComment,
	); err != nil {
		return err
	}
	_, err := c.conn.Exec(
		"DELETE FROM comments WHERE seg = ?1 AND addr = ?2 AND comment = '' AND block_comment = '' AND auto_comment = ''",
		seg, addr,
	)
	return err
}

func (c *Controller) SetAutoComment(addr uint32, autoComment string) error {
	seg := c.SegOf(addr)
	if _, err := c.conn.Exec(
		`INSERT INTO comments (seg, addr, auto_comment) VALUES (?1, ?2, ?3)
		 ON CONFLICT(seg, addr) DO UPDATE SET auto_comment = excluded.auto_comment`,
		seg, addr, autoComment,
	); err != nil {
		return err
	}
	_, err := c.conn.Exec(
		"DELETE FROM comments WHERE seg = ?1 AND addr = ?2 AND comment = '' AND block_comment = '' AND auto_comment = ''",
		seg, addr,
	)
	return err
}

func (c *Controller) AppendAutoComment(addr uint32, frag string) error {
	if frag == "" {
		return nil
	}
	cur := c.GetAddressComment(addr).AutoComment
	if cur != "" {
		if slices.Contains(strings.Split(cur, "; "), frag) {
			return nil
		}
		frag = cur + "; " + frag
	}
	return c.SetAutoComment(addr, frag)
}

func (c *Controller) GetAddressComment(addr uint32) AddressComment {
	seg := c.SegOf(addr)
	var ac AddressComment
	_ = c.conn.QueryRow(
		"SELECT comment, block_comment, auto_comment FROM comments WHERE seg = ?1 AND addr = ?2",
		seg, addr,
	).Scan(&ac.Comment, &ac.BlockComment, &ac.AutoComment)
	return ac
}

func (c *Controller) GetCommentsInRange(start, end uint32) (map[uint32]AddressComment, error) {
	seg := c.SegOf(start)
	rows, err := c.conn.Query(
		"SELECT addr, comment, block_comment, auto_comment FROM comments WHERE seg = ?1 AND addr >= ?2 AND addr < ?3",
		seg, start, end,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := make(map[uint32]AddressComment)
	for rows.Next() {
		var addr uint32
		var ac AddressComment
		if err := rows.Scan(&addr, &ac.Comment, &ac.BlockComment, &ac.AutoComment); err != nil {
			return nil, err
		}
		m[addr] = ac
	}
	return m, rows.Err()
}

func (c *Controller) GetAllTargetComments() (map[uint32]AddressComment, error) {
	m := make(map[uint32]AddressComment)
	err := c.forEachSegRow("SELECT addr, comment, block_comment, auto_comment FROM comments WHERE seg = ?1", false, func(rows *sql.Rows) error {
		var addr uint32
		var ac AddressComment
		if err := rows.Scan(&addr, &ac.Comment, &ac.BlockComment, &ac.AutoComment); err != nil {
			return err
		}
		m[addr] = ac
		return nil
	})
	if err != nil {
		return nil, err
	}
	return m, nil
}

func (c *Controller) IncomingXrefsInRange(start, end uint32) ([]XrefRecord, error) {
	inEmpty := c.spaceSegInClause(true)
	query := fmt.Sprintf(
		`SELECT target_addr, source_addr, type FROM xrefs
		 WHERE seg IN (%s) AND target_addr >= ?1 AND target_addr < ?2
		 UNION
		 SELECT target_addr, source_addr, type FROM edges
		 WHERE seg IN (%s) AND target_addr >= ?1 AND target_addr < ?2 AND type != 'FALLTHROUGH'
		 ORDER BY target_addr ASC, source_addr ASC`,
		inEmpty, inEmpty,
	)
	rows, err := c.conn.Query(query, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []XrefRecord
	for rows.Next() {
		var r XrefRecord
		if err := rows.Scan(&r.TargetAddr, &r.SourceAddr, &r.Type); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (c *Controller) OutgoingTargetsInRange(start, end uint32) (map[uint32]uint32, error) {
	seg := c.SegOf(start)
	rows, err := c.conn.Query(
		`SELECT source_addr, target_addr FROM (
			SELECT source_addr, target_addr, 1 as pri FROM edges
			WHERE seg = ?1 AND source_addr >= ?2 AND source_addr < ?3 AND type IN ('CALL','UNCOND','COND_TRUE')
			UNION ALL
			SELECT source_addr, target_addr,
			       CASE type
			           WHEN 'CODE_CALL'   THEN 1
			           WHEN 'CODE_BRANCH' THEN 2
			           WHEN 'DATA_ADDR'   THEN 3
			           WHEN 'DATA_WRITE'  THEN 4
			           ELSE 5
			       END as pri
			FROM xrefs
			WHERE seg = ?1 AND source_addr >= ?2 AND source_addr < ?3
		) ORDER BY source_addr ASC, pri ASC, target_addr ASC`,
		seg, start, end,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := make(map[uint32]uint32)
	for rows.Next() {
		var src, tgt uint32
		if err := rows.Scan(&src, &tgt); err != nil {
			return nil, err
		}
		if _, exists := m[src]; !exists {
			m[src] = tgt
		}
	}
	return m, rows.Err()
}

func (c *Controller) MarkData(addr, size uint32, cellType CellType) error {
	if err := c.ClearOverlaps(addr, size); err != nil {
		return err
	}
	cell := Cell{
		Seg:        c.SegOf(addr),
		Addr:       addr,
		Size:       size,
		Type:       cellType,
		Confidence: 100,
	}
	return c.InsertCell(&cell)
}

func (c *Controller) ClearOverlaps(addr, size uint32) error {
	seg := c.SegOf(addr)
	end := addr + size

	type partialCell struct {
		addr    uint32
		size    uint32
		typeStr string
		raw     []byte
		conf    uint8
	}
	var partials []partialCell
	rows, err := c.conn.Query(
		"SELECT addr, size, type, raw_bytes, confidence FROM cells WHERE seg = ?1 AND addr < ?3 AND addr + size > ?2",
		seg, addr, end,
	)
	if err != nil {
		return err
	}
	for rows.Next() {
		var p partialCell
		if err := rows.Scan(&p.addr, &p.size, &p.typeStr, &p.raw, &p.conf); err != nil {
			_ = rows.Close()
			return err
		}
		if p.addr < addr || p.addr+p.size > end {
			partials = append(partials, p)
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}

	if _, err := c.conn.Exec("DELETE FROM cells WHERE seg = ?1 AND addr >= ?2 AND addr < ?3", seg, addr, end); err != nil {
		return err
	}
	if _, err := c.conn.Exec("DELETE FROM cells WHERE seg = ?1 AND addr < ?2 AND addr + size > ?2", seg, addr); err != nil {
		return err
	}
	if _, err := c.conn.Exec("UPDATE comments SET auto_comment = '' WHERE seg = ?1 AND addr >= ?2 AND addr < ?3", seg, addr, end); err != nil {
		return err
	}
	if _, err := c.conn.Exec("DELETE FROM comments WHERE seg = ?1 AND addr >= ?2 AND addr < ?3 AND comment = '' AND block_comment = '' AND auto_comment = ''", seg, addr, end); err != nil {
		return err
	}

	// For small cells (<= 16 bytes, non-INCBIN), remnant head/tail bytes are reinserted as
	// individual DATA_B cells to preserve exact emission/label boundaries. Large cells
	// (INCBIN, multi-KB DATA_ZERO, long STRING) are never shattered into thousands of 1-byte
	// rows; their unmapped remnants fall through naturally to BinaryData.
	for _, p := range partials {
		if p.typeStr == CellIncbin.AsStr() || p.size > 16 {
			continue
		}
		cEnd := p.addr + p.size
		if p.addr < addr {
			for bAddr := p.addr; bAddr < addr; bAddr++ {
				var raw []byte
				idx := int(bAddr - p.addr)
				if idx >= 0 && idx < len(p.raw) {
					raw = []byte{p.raw[idx]}
				}
				_ = c.InsertCell(&Cell{
					Seg:        seg,
					Addr:       bAddr,
					Size:       1,
					Type:       CellDataB,
					Confidence: p.conf,
					RawBytes:   raw,
				})
			}
		}
		if cEnd > end {
			for bAddr := end; bAddr < cEnd; bAddr++ {
				var raw []byte
				idx := int(bAddr - p.addr)
				if idx >= 0 && idx < len(p.raw) {
					raw = []byte{p.raw[idx]}
				}
				_ = c.InsertCell(&Cell{
					Seg:        seg,
					Addr:       bAddr,
					Size:       1,
					Type:       CellDataB,
					Confidence: p.conf,
					RawBytes:   raw,
				})
			}
		}
	}
	return nil
}

func (c *Controller) InsertEdge(sourceAddr, targetAddr uint32, kind EdgeKind) error {
	seg := c.SegOf(sourceAddr)
	_, err := c.stmtInsertEdge.Exec(seg, sourceAddr, targetAddr, kind.AsStr())
	return err
}

func (c *Controller) InsertXref(sourceAddr, targetAddr uint32, kind XrefKind) error {
	seg := c.SegOf(sourceAddr)
	_, err := c.stmtInsertXref.Exec(seg, sourceAddr, targetAddr, kind.AsStr())
	return err
}

func (c *Controller) InsertFunction(entryAddr uint32, name string, confidence uint8) error {
	seg := c.SegOf(entryAddr)
	_, err := c.stmtInsertFunc.Exec(seg, entryAddr, name, confidence)
	return err
}

// FunctionMeta carries post-analysis metadata for a single function entry.
// EndAddr/StackFrame are written only when HasEnd/HasFrame are set, so an
// absent value leaves the existing (possibly NULL) column untouched.
type FunctionMeta struct {
	Entry      uint32
	EndAddr    uint32
	IsNoreturn bool
	StackFrame int32
	HasEnd     bool
	HasFrame   bool
}

// UpdateFunctionMetadataBatch populates functions.end_addr / is_noreturn / stack_frame
// for the given entries in a single transaction. end_addr and stack_frame are updated
// only when present (HasEnd / HasFrame); is_noreturn is always set.
func (c *Controller) UpdateFunctionMetadataBatch(metas []FunctionMeta) error {
	if len(metas) == 0 {
		return nil
	}
	return c.WithTransaction(func() error {
		stmt, err := c.conn.Prepare(
			`UPDATE functions
			 SET is_noreturn = ?3,
			     end_addr = CASE WHEN ?4 THEN ?5 ELSE end_addr END,
			     stack_frame = CASE WHEN ?6 THEN ?7 ELSE stack_frame END
			 WHERE seg = ?1 AND entry_addr = ?2`,
		)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for _, m := range metas {
			seg := c.SegOf(m.Entry)
			if _, err := stmt.Exec(seg, m.Entry, m.IsNoreturn, m.HasEnd, m.EndAddr, m.HasFrame, m.StackFrame); err != nil {
				return err
			}
		}
		return nil
	})
}

// GetFunctionMeta reads the recorded metadata for a single function entry in the
// active space. end_addr and stack_frame are nullable; HasEnd/HasFrame report presence.
func (c *Controller) GetFunctionMeta(entry uint32) (*FunctionMeta, bool) {
	seg := c.SegOf(entry)
	var (
		isNoreturn bool
		endAddr    sql.NullInt64
		stackFrame sql.NullInt64
	)
	err := c.conn.QueryRow(
		"SELECT is_noreturn, end_addr, stack_frame FROM functions WHERE seg = ?1 AND entry_addr = ?2",
		seg, entry,
	).Scan(&isNoreturn, &endAddr, &stackFrame)
	if err != nil {
		return nil, false
	}
	m := &FunctionMeta{Entry: entry, IsNoreturn: isNoreturn}
	if endAddr.Valid {
		m.EndAddr = uint32(endAddr.Int64)
		m.HasEnd = true
	}
	if stackFrame.Valid {
		m.StackFrame = int32(stackFrame.Int64)
		m.HasFrame = true
	}
	return m, true
}

// FunctionEntries returns all function entry addresses recorded in the active space,
// sorted ascending.
func (c *Controller) FunctionEntries() []uint32 {
	inClause := c.spaceSegInClause(false)
	return c.queryUint32s(fmt.Sprintf(
		"SELECT entry_addr FROM functions WHERE seg IN (%s) ORDER BY entry_addr ASC",
		inClause,
	))
}

// AllEdges returns every control-flow edge in the active space, including FALLTHROUGH.
func (c *Controller) AllEdges() []Edge {
	var out []Edge
	inClause := c.spaceSegInClause(false)
	query := fmt.Sprintf(
		"SELECT seg, source_addr, target_addr, type FROM edges WHERE seg IN (%s)",
		inClause,
	)
	rows, err := c.conn.Query(query)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		if e, err := scanEdge(rows); err == nil {
			out = append(out, e)
		}
	}
	return out
}

// DeleteEdgeExact removes a single edge identified by (source, target, kind).
func (c *Controller) DeleteEdgeExact(sourceAddr, targetAddr uint32, kind EdgeKind) error {
	seg := c.SegOf(sourceAddr)
	_, err := c.conn.Exec(
		"DELETE FROM edges WHERE seg = ?1 AND source_addr = ?2 AND target_addr = ?3 AND type = ?4",
		seg, sourceAddr, targetAddr, kind.AsStr(),
	)
	return err
}

func (c *Controller) SetRename(original, renamed string) error {
	seg := c.ActiveSeg()
	_, err := c.conn.Exec(
		"INSERT OR REPLACE INTO renames (seg, original, renamed) VALUES (?1, ?2, ?3)",
		seg, original, renamed,
	)
	return err
}

func (c *Controller) GetRename(original string) (string, bool, error) {
	seg := c.ActiveSeg()
	var renamed string
	err := c.conn.QueryRow(
		"SELECT renamed FROM renames WHERE seg = ?1 AND original = ?2",
		seg, original,
	).Scan(&renamed)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return renamed, true, nil
}

func (c *Controller) GetAllRenames() (map[string]string, error) {
	m := make(map[string]string)
	err := c.forEachSegRow("SELECT original, renamed FROM renames WHERE seg = ?1", true, func(rows *sql.Rows) error {
		var orig, ren string
		if err := rows.Scan(&orig, &ren); err != nil {
			return err
		}
		m[orig] = ren
		return nil
	})
	if err != nil {
		return nil, err
	}
	return m, nil
}

func (c *Controller) SetOperandFormat(addr uint32, format string) error {
	seg := c.SegOf(addr)
	if format == "HEX" || format == "" {
		_, err := c.conn.Exec("DELETE FROM operand_formats WHERE seg = ?1 AND addr = ?2", seg, addr)
		return err
	}
	_, err := c.conn.Exec(
		"INSERT OR REPLACE INTO operand_formats (seg, addr, format) VALUES (?1, ?2, ?3)",
		seg, addr, format,
	)
	return err
}

func (c *Controller) GetOperandFormat(addr uint32) (string, bool, error) {
	seg := c.SegOf(addr)
	var format string
	err := c.conn.QueryRow(
		"SELECT format FROM operand_formats WHERE seg = ?1 AND addr = ?2",
		seg, addr,
	).Scan(&format)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return format, true, nil
}

func (c *Controller) GetAllOperandFormats() (map[uint32]string, error) {
	m := make(map[uint32]string)
	err := c.forEachSegRow("SELECT addr, format FROM operand_formats WHERE seg = ?1", false, func(rows *sql.Rows) error {
		var addr uint32
		var format string
		if err := rows.Scan(&addr, &format); err != nil {
			return err
		}
		m[addr] = format
		return nil
	})
	if err != nil {
		return nil, err
	}
	return m, nil
}

func (c *Controller) DetectJumpVectorBases() map[string]uint32 {
	bases := make(map[string]uint32)
	inClause := c.spaceSegInClause(false)
	inEmpty := c.spaceSegInClause(true)
	query := fmt.Sprintf(
		`SELECT c.op_str, r.target_addr FROM relocs r
		 JOIN cells c ON c.seg = r.seg AND c.addr = r.site_addr - 2
		 JOIN cells j0 ON j0.addr = r.target_addr AND j0.type = 'CODE' AND j0.mnemonic = 'jmp' AND j0.size = 6
		 JOIN cells j1 ON j1.seg = j0.seg AND j1.addr = r.target_addr + 6 AND j1.type = 'CODE' AND j1.mnemonic = 'jmp' AND j1.size = 6
		 JOIN cells j2 ON j2.seg = j0.seg AND j2.addr = r.target_addr + 12 AND j2.type = 'CODE' AND j2.mnemonic = 'jmp' AND j2.size = 6
		 WHERE r.seg IN (%s) AND j0.seg IN (%s) AND c.type = 'CODE' AND c.mnemonic IN ('lea', 'lea.l')
		 UNION
		 SELECT c.op_str, x.target_addr FROM xrefs x
		 JOIN cells c ON c.seg = x.seg AND c.addr = x.source_addr
		 JOIN cells j0 ON j0.addr = x.target_addr AND j0.type = 'CODE' AND j0.mnemonic = 'jmp' AND j0.size = 6
		 JOIN cells j1 ON j1.seg = j0.seg AND j1.addr = x.target_addr + 6 AND j1.type = 'CODE' AND j1.mnemonic = 'jmp' AND j1.size = 6
		 JOIN cells j2 ON j2.seg = j0.seg AND j2.addr = x.target_addr + 12 AND j2.type = 'CODE' AND j2.mnemonic = 'jmp' AND j2.size = 6
		 WHERE x.seg IN (%s) AND j0.seg IN (%s) AND c.type = 'CODE' AND c.mnemonic IN ('lea', 'lea.l')`,
		inClause, inClause, inEmpty, inClause,
	)
	rows, err := c.conn.Query(query)
	if err != nil {
		return bases
	}
	defer rows.Close()
	for rows.Next() {
		var opStr sql.NullString
		var tgt uint32
		if rows.Scan(&opStr, &tgt) != nil || !opStr.Valid {
			continue
		}
		if idx := strings.LastIndexByte(opStr.String, ','); idx >= 0 {
			reg := strings.TrimSpace(opStr.String[idx+1:])
			if len(reg) == 2 && reg[0] == 'a' {
				bases[reg] = tgt
			}
		}
	}
	return bases
}

// ParseVectoredOperand parses a register-displacement operand like "42(a5)" into ("a5", 42, true).
func ParseVectoredOperand(opStr string) (reg string, disp int32, ok bool) {
	openIdx := strings.IndexByte(opStr, '(')
	closeIdx := strings.IndexByte(opStr, ')')
	if openIdx < 0 || closeIdx <= openIdx+1 {
		return "", 0, false
	}
	disp64, err := strconv.ParseInt(strings.TrimSpace(opStr[:openIdx]), 10, 32)
	if err != nil {
		return "", 0, false
	}
	return strings.TrimSpace(opStr[openIdx+1 : closeIdx]), int32(disp64), true
}

type JumpVectorSlot struct {
	Reg        string // e.g. "a5"
	Disp       int32  // signed 16-bit byte offset from baseAddr (never 0)
	TrampAddr  uint32 // address of the 6-byte `jmp target.l` slot (e.g. hunk6:0x01B8)
	TargetAddr uint32 // resolved destination function address (e.g. hunk5:0x2959C)
	TargetName string // resolved label at TargetAddr (e.g. "Audio_Command")
	LVOName    string // unique equate symbol (e.g. "_LVO_Audio_Command")
}

// FormatVectoredOpStr rewrites a numeric register-displacement call/jump operand
// like "414(a5)" into "_LVO_Audio_Command(a5)" when mnem is jsr, jmp, or bsr
// and (reg, disp) exists in lvoMap (with disp != 0).
func FormatVectoredOpStr(
	mnem string,
	rawOpStr string,
	lvoMap map[string]map[int32]JumpVectorSlot,
) (formattedOp string, slot JumpVectorSlot, ok bool) {
	if len(lvoMap) == 0 {
		return rawOpStr, JumpVectorSlot{}, false
	}
	switch strings.ToLower(strings.TrimSpace(mnem)) {
	case "jsr", "jmp", "bsr", "bsr.w", "bsr.l":
	default:
		return rawOpStr, JumpVectorSlot{}, false
	}
	reg, disp, parsed := ParseVectoredOperand(rawOpStr)
	if !parsed || disp == 0 {
		return rawOpStr, JumpVectorSlot{}, false
	}
	byDisp, found := lvoMap[reg]
	if !found {
		return rawOpStr, JumpVectorSlot{}, false
	}
	slot, found = byDisp[disp]
	if !found || slot.LVOName == "" {
		return rawOpStr, JumpVectorSlot{}, false
	}
	return fmt.Sprintf("%s(%s)", slot.LVOName, reg), slot, true
}

// SortedJumpVectorSlots returns all JumpVectorSlot entries from lvoMap ordered by (Reg, Disp).
func SortedJumpVectorSlots(lvoMap map[string]map[int32]JumpVectorSlot) []JumpVectorSlot {
	if len(lvoMap) == 0 {
		return nil
	}
	var out []JumpVectorSlot
	for _, reg := range slices.Sorted(maps.Keys(lvoMap)) {
		byDisp := lvoMap[reg]
		for _, disp := range slices.Sorted(maps.Keys(byDisp)) {
			out = append(out, byDisp[disp])
		}
	}
	return out
}

func isAutoSlotLabel(name string, addr uint32, autoLabel func(uint32) string) bool {
	if name == "" || strings.HasPrefix(name, "LAB_") || strings.HasPrefix(name, "EQU_") ||
		strings.HasPrefix(name, "DAT_") || strings.HasPrefix(name, "SUB_") {
		return true
	}
	if autoLabel != nil && name == autoLabel(addr) {
		return true
	}
	return false
}

// BuildJumpVectorLVOMap constructs a map[reg][disp]JumpVectorSlot for all non-zero
// 6-byte `jmp <target>.l` slots reachable from jmpBases.
func (c *Controller) BuildJumpVectorLVOMap(
	jmpBases map[string]uint32,
	allRelocs map[uint32]uint32,
	allLabels map[uint32]string,
	autoLabel func(uint32) string,
) map[string]map[int32]JumpVectorSlot {
	result := make(map[string]map[int32]JumpVectorSlot)
	if len(jmpBases) == 0 {
		return result
	}

	usedNames := make(map[string]bool, len(allLabels))
	for _, lbl := range allLabels {
		if lbl != "" {
			usedNames[lbl] = true
		}
	}

	// Collect any explicit d16(reg) displacements referenced by jsr/jmp/bsr in the space.
	referencedDisps := make(map[string]map[int32]bool)
	inClause := c.spaceSegInClause(false)
	refRows, err := c.conn.Query(fmt.Sprintf(
		"SELECT op_str FROM cells WHERE seg IN (%s) AND type = 'CODE' AND mnemonic IN ('jsr', 'jmp', 'bsr') AND op_str LIKE '%%(a%%)'",
		inClause,
	))
	if err == nil {
		for refRows.Next() {
			var opStr sql.NullString
			if refRows.Scan(&opStr) == nil && opStr.Valid {
				if reg, disp, ok := ParseVectoredOperand(opStr.String); ok && disp != 0 {
					if _, hasBase := jmpBases[reg]; hasBase {
						if referencedDisps[reg] == nil {
							referencedDisps[reg] = make(map[int32]bool)
						}
						referencedDisps[reg][disp] = true
					}
				}
			}
		}
		refRows.Close()
	}

	for _, reg := range slices.Sorted(maps.Keys(jmpBases)) {
		baseAddr := jmpBases[reg]
		baseSeg := c.SegOf(baseAddr)
		var minQueryAddr uint32
		if baseAddr > 32768 {
			minQueryAddr = baseAddr - 32768
		}
		maxQueryAddr := baseAddr + 32767

		rows, err := c.conn.Query(
			`SELECT c.addr, COALESCE(
				(SELECT e.target_addr FROM edges e WHERE e.seg = c.seg AND e.source_addr = c.addr AND e.type IN ('UNCOND', 'CALL') LIMIT 1),
				0
			)
			FROM cells c
			WHERE c.seg = ?1 AND c.addr >= ?2 AND c.addr <= ?3 AND c.type = 'CODE' AND c.mnemonic = 'jmp' AND c.size = 6
			ORDER BY c.addr ASC`,
			baseSeg, minQueryAddr, maxQueryAddr,
		)
		if err != nil {
			continue
		}

		jmpEdgeTarget := make(map[uint32]uint32)
		var jmpAddrs []uint32
		for rows.Next() {
			var addr, edgeTgt uint32
			if rows.Scan(&addr, &edgeTgt) == nil {
				jmpEdgeTarget[addr] = edgeTgt
				jmpAddrs = append(jmpAddrs, addr)
			}
		}
		rows.Close()

		resolveTrampTarget := func(trampAddr uint32) (uint32, bool) {
			edgeTgt, isJmpCell := jmpEdgeTarget[trampAddr]
			if !isJmpCell {
				return 0, false
			}
			if relTgt, ok := allRelocs[trampAddr+2]; ok {
				return relTgt, true
			}
			if edgeTgt != 0 {
				return edgeTgt, true
			}
			return 0, false
		}

		seenDisp := make(map[int32]bool)
		var slots []JumpVectorSlot

		// 1. Contiguous 6-byte jmp table scan starting at baseAddr.
		expectedAddr := baseAddr
		for _, addr := range jmpAddrs {
			if addr < baseAddr {
				continue
			}
			if addr != expectedAddr {
				break
			}
			expectedAddr += 6
			disp := int32(int64(addr) - int64(baseAddr))
			if disp == 0 {
				continue // Parity guard: disp == 0 ((a5)) is 2-byte EAAddrInd, never rewritten to _LVO_
			}
			if disp > 32767 {
				break
			}
			if tgtAddr, ok := resolveTrampTarget(addr); ok {
				seenDisp[disp] = true
				slots = append(slots, JumpVectorSlot{
					Reg:        reg,
					Disp:       disp,
					TrampAddr:  addr,
					TargetAddr: tgtAddr,
				})
			}
		}

		// 2. Also include any explicitly called d16(reg) slots targeting a verified 6-byte jmp cell.
		for disp := range referencedDisps[reg] {
			if disp == 0 || seenDisp[disp] || disp < -32768 || disp > 32767 {
				continue
			}
			trampAddr := uint32(int64(baseAddr) + int64(disp))
			if tgtAddr, ok := resolveTrampTarget(trampAddr); ok {
				seenDisp[disp] = true
				slots = append(slots, JumpVectorSlot{
					Reg:        reg,
					Disp:       disp,
					TrampAddr:  trampAddr,
					TargetAddr: tgtAddr,
				})
			}
		}

		if len(slots) == 0 {
			continue
		}

		slices.SortFunc(slots, func(a, b JumpVectorSlot) int {
			return cmp.Compare(a.Disp, b.Disp)
		})

		targetCounts := make(map[string]int, len(slots))
		for i := range slots {
			tgtName := allLabels[slots[i].TargetAddr]
			if tgtName == "" && autoLabel != nil {
				tgtName = autoLabel(slots[i].TargetAddr)
			}
			if tgtName == "" {
				tgtName = fmt.Sprintf("LAB_%05X", slots[i].TargetAddr)
			}
			tgtName = strings.TrimLeft(tgtName, ".")
			slots[i].TargetName = tgtName
			targetCounts[tgtName]++
		}

		byDisp := make(map[int32]JumpVectorSlot, len(slots))
		for i := range slots {
			slot := &slots[i]
			cand := "_LVO_" + slot.TargetName
			slotLbl := allLabels[slot.TrampAddr]
			hasCustomSlotLbl := !isAutoSlotLabel(slotLbl, slot.TrampAddr, autoLabel)

			if targetCounts[slot.TargetName] > 1 && hasCustomSlotLbl {
				trimmed := strings.TrimPrefix(slotLbl, "JmpVec_")
				trimmed = strings.TrimPrefix(trimmed, "_LVO_")
				trimmed = strings.TrimLeft(trimmed, ".")
				if trimmed != "" {
					cand = "_LVO_" + trimmed
				}
			}
			if usedNames[cand] {
				if hasCustomSlotLbl {
					trimmed := strings.TrimPrefix(slotLbl, "JmpVec_")
					trimmed = strings.TrimPrefix(trimmed, "_LVO_")
					trimmed = strings.TrimLeft(trimmed, ".")
					if trimmed != "" {
						cand = "_LVO_" + trimmed
					}
				}
				if usedNames[cand] {
					cand = fmt.Sprintf("_LVO_%s_%X", slot.TargetName, uint16(slot.Disp))
				}
			}
			for usedNames[cand] {
				cand = fmt.Sprintf("%s_%X", cand, uint16(slot.Disp))
			}
			usedNames[cand] = true
			slot.LVOName = cand
			byDisp[slot.Disp] = *slot
		}
		result[reg] = byDisp
	}

	return result
}

func (c *Controller) ResolveVectoredTarget(opStr string, jmpBases map[string]uint32, allRelocs map[uint32]uint32) (trampAddr, realTarget uint32, ok bool) {
	regStr, disp, ok := ParseVectoredOperand(opStr)
	if !ok {
		return 0, 0, false
	}
	baseAddr, exists := jmpBases[regStr]
	if !exists {
		return 0, 0, false
	}
	trampAddr = uint32(int64(baseAddr) + int64(disp))
	if realTgt, found := allRelocs[trampAddr+2]; found {
		return trampAddr, realTgt, true
	}
	trampSeg := c.SegOf(trampAddr)
	if err := c.conn.QueryRow(
		"SELECT target_addr FROM edges WHERE seg = ?1 AND source_addr = ?2 AND type IN ('UNCOND','CALL') LIMIT 1",
		trampSeg, trampAddr,
	).Scan(&realTarget); err == nil {
		return trampAddr, realTarget, true
	}
	return 0, 0, false
}

func (c *Controller) GetVectoredCallXrefs(
	startAddr, endAddr uint32,
	jmpBases map[string]uint32,
	allRelocs map[uint32]uint32,
	lvoMaps ...map[string]map[int32]JumpVectorSlot,
) map[uint32][]AddrText {
	m := make(map[uint32][]AddrText)
	if len(jmpBases) == 0 {
		return m
	}
	var lvoMap map[string]map[int32]JumpVectorSlot
	if len(lvoMaps) > 0 {
		lvoMap = lvoMaps[0]
	}
	inClause := c.spaceSegInClause(false)
	query := fmt.Sprintf(
		"SELECT addr, mnemonic, op_str FROM cells WHERE seg IN (%s) AND type = 'CODE' AND mnemonic IN ('jsr', 'jmp', 'bsr') AND op_str LIKE '%%(a%%)'",
		inClause,
	)
	rows, err := c.conn.Query(query)
	if err != nil {
		return m
	}
	defer rows.Close()
	for rows.Next() {
		var srcAddr uint32
		var mnem, opStr sql.NullString
		if rows.Scan(&srcAddr, &mnem, &opStr) != nil {
			continue
		}
		if _, realTgt, ok := c.ResolveVectoredTarget(opStr.String, jmpBases, allRelocs); ok {
			if realTgt >= startAddr && realTgt < endAddr {
				dispOp := opStr.String
				if lvoOp, _, ok := FormatVectoredOpStr(mnem.String, dispOp, lvoMap); ok {
					dispOp = lvoOp
				}
				m[realTgt] = append(m[realTgt], AddrText{
					Addr: srcAddr,
					Text: fmt.Sprintf("%s %s", mnem.String, dispOp),
				})
			}
		}
	}
	return m
}

// CellSpan holds lightweight cell geometry and mnemonic metadata for fast in-memory containment lookups.
type CellSpan struct {
	Addr     uint32
	Size     uint32
	Mnemonic string
}

// GetSpaceCellSpans returns a sorted CellSpan slice for all active segments in the space.
func (c *Controller) GetSpaceCellSpans() ([]CellSpan, error) {
	inClause := c.spaceSegInClause(false)
	query := fmt.Sprintf(
		"SELECT seg, addr, size, type, mnemonic FROM cells WHERE seg IN (%s) ORDER BY addr ASC",
		inClause,
	)
	rows, err := c.conn.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CellSpan
	for rows.Next() {
		var seg, typStr string
		var addr, size uint32
		var mnem sql.NullString
		if err := rows.Scan(&seg, &addr, &size, &typStr, &mnem); err != nil {
			return nil, err
		}
		if c.SegOf(addr) != seg {
			continue
		}
		m := mnem.String
		if m == "" {
			if ct, err := ParseCellType(typStr); err == nil && (ct == CellPointer || ct == CellDataL) {
				m = "dc.l"
			}
		}
		out = append(out, CellSpan{Addr: addr, Size: size, Mnemonic: m})
	}
	return out, rows.Err()
}

// GetXrefsToRange returns all cross-references targeting [startAddr, endAddr] in the active space.
// When externalOnly is true, references whose source_addr lies inside [startAddr, endAddr] are excluded.
func (c *Controller) GetXrefsToRange(startAddr, endAddr uint32, externalOnly bool) []Xref {
	var out []Xref
	inEmpty := c.spaceSegInClause(true)
	extClause := ""
	if externalOnly {
		extClause = " AND (source_addr < ?1 OR source_addr > ?2)"
	}
	query := fmt.Sprintf(
		"SELECT seg, source_addr, target_addr, type FROM xrefs WHERE seg IN (%s) AND target_addr >= ?1 AND target_addr <= ?2%s ORDER BY target_addr ASC, source_addr ASC",
		inEmpty, extClause,
	)
	rows, err := c.conn.Query(query, startAddr, endAddr)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		if x, err := scanXref(rows); err == nil {
			out = append(out, x)
		}
	}
	return out
}

// UserCommentRow holds a non-auto inline and/or block comment created by the user or agent.
type UserCommentRow struct {
	Seg          string
	Addr         uint32
	Comment      string
	BlockComment string
}

// GetUserComments returns all rows in `comments` in the active space that have a non-empty
// manual `comment` or `block_comment` (excluding auto_comment-only rows).
func (c *Controller) GetUserComments() []UserCommentRow {
	var out []UserCommentRow
	inEmpty := c.spaceSegInClause(true)
	query := fmt.Sprintf(
		"SELECT seg, addr, comment, block_comment FROM comments WHERE seg IN (%s) AND (comment != '' OR block_comment != '') ORDER BY addr ASC",
		inEmpty,
	)
	rows, err := c.conn.Query(query)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var r UserCommentRow
		if rows.Scan(&r.Seg, &r.Addr, &r.Comment, &r.BlockComment) == nil {
			out = append(out, r)
		}
	}
	return out
}
