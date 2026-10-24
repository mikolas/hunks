package db

import "fmt"

// CellType classifies an analyzed byte range in `cells.type`.
// The string values are a SQLite schema contract.
type CellType string

const (
	CellCode     CellType = "CODE"
	CellDataB    CellType = "DATA_B"
	CellDataW    CellType = "DATA_W"
	CellDataL    CellType = "DATA_L"
	CellDataZero CellType = "DATA_ZERO"
	CellStr      CellType = "STRING"
	CellPointer  CellType = "POINTER"
	CellIncbin   CellType = "INCBIN"
)

func (c CellType) AsStr() string { return string(c) }

func ParseCellType(s string) (CellType, error) {
	switch CellType(s) {
	case CellCode, CellDataB, CellDataW, CellDataL, CellDataZero, CellStr, CellPointer, CellIncbin:
		return CellType(s), nil
	default:
		return "", fmt.Errorf("unknown CellType %q", s)
	}
}

func (c CellType) IsData() bool {
	switch c {
	case CellDataB, CellDataW, CellDataL, CellDataZero, CellStr, CellIncbin:
		return true
	default:
		return false
	}
}

func (c CellType) IsCode() bool {
	return c == CellCode
}

// EdgeKind classifies a control-flow edge in `edges.type`.
type EdgeKind string

const (
	EdgeCall        EdgeKind = "CALL"
	EdgeUncond      EdgeKind = "UNCOND"
	EdgeCondTrue    EdgeKind = "COND_TRUE"
	EdgeCondFalse   EdgeKind = "COND_FALSE"
	EdgeFallthrough EdgeKind = "FALLTHROUGH"
)

func (e EdgeKind) AsStr() string { return string(e) }

func ParseEdgeKind(s string) (EdgeKind, error) {
	switch EdgeKind(s) {
	case EdgeCall, EdgeUncond, EdgeCondTrue, EdgeCondFalse, EdgeFallthrough:
		return EdgeKind(s), nil
	default:
		return "", fmt.Errorf("unknown EdgeKind %q", s)
	}
}

// XrefKind classifies a cross-reference in `xrefs.type`.
type XrefKind string

const (
	XrefCodeCall   XrefKind = "CODE_CALL"
	XrefCodeBranch XrefKind = "CODE_BRANCH"
	XrefDataAddr   XrefKind = "DATA_ADDR"
	XrefDataRead   XrefKind = "DATA_READ"
	XrefDataWrite  XrefKind = "DATA_WRITE"
)

func (x XrefKind) AsStr() string { return string(x) }

func ParseXrefKind(s string) (XrefKind, error) {
	switch XrefKind(s) {
	case XrefCodeCall, XrefCodeBranch, XrefDataAddr, XrefDataRead, XrefDataWrite:
		return XrefKind(s), nil
	default:
		return "", fmt.Errorf("unknown XrefKind %q", s)
	}
}

// LabelKind classifies a label in `labels.type`.
type LabelKind string

const (
	LabelLab LabelKind = "LAB"
	LabelDat LabelKind = "DAT"
	LabelFun LabelKind = "FUN"
	LabelEqu LabelKind = "EQU"
	LabelPtr LabelKind = "PTR"
)

func (l LabelKind) AsStr() string { return string(l) }

func ParseLabelKind(s string) (LabelKind, error) {
	switch LabelKind(s) {
	case LabelLab, LabelDat, LabelFun, LabelEqu, LabelPtr:
		return LabelKind(s), nil
	default:
		return "", fmt.Errorf("unknown LabelKind %q", s)
	}
}

type Edge struct {
	Seg    string
	Source uint32
	Target uint32
	Kind   EdgeKind
}

type Xref struct {
	Seg    string
	Source uint32
	Target uint32
	Kind   XrefKind
}

type Ref struct {
	Seg    string
	Target uint32
	Source uint32
}
