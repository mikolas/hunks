package db

import "testing"

func TestEnumStringRoundtrip(t *testing.T) {
	cells := []CellType{
		CellCode, CellDataB, CellDataW, CellDataL, CellDataZero, CellStr, CellPointer, CellIncbin,
	}
	for _, v := range cells {
		got, err := ParseCellType(v.AsStr())
		if err != nil || got != v {
			t.Errorf("ParseCellType(%q) = %v, %v; want %v", v.AsStr(), got, err, v)
		}
	}
	if _, err := ParseCellType("BOGUS"); err == nil {
		t.Errorf("expected error for BOGUS CellType")
	}

	edges := []EdgeKind{
		EdgeCall, EdgeUncond, EdgeCondTrue, EdgeCondFalse, EdgeFallthrough,
	}
	for _, v := range edges {
		got, err := ParseEdgeKind(v.AsStr())
		if err != nil || got != v {
			t.Errorf("ParseEdgeKind(%q) = %v, %v; want %v", v.AsStr(), got, err, v)
		}
	}
	if _, err := ParseEdgeKind("BOGUS"); err == nil {
		t.Errorf("expected error for BOGUS EdgeKind")
	}

	xrefs := []XrefKind{
		XrefCodeCall, XrefCodeBranch, XrefDataAddr, XrefDataRead, XrefDataWrite,
	}
	for _, v := range xrefs {
		got, err := ParseXrefKind(v.AsStr())
		if err != nil || got != v {
			t.Errorf("ParseXrefKind(%q) = %v, %v; want %v", v.AsStr(), got, err, v)
		}
	}
	if _, err := ParseXrefKind("BOGUS"); err == nil {
		t.Errorf("expected error for BOGUS XrefKind")
	}

	labels := []LabelKind{
		LabelLab, LabelDat, LabelFun, LabelEqu, LabelPtr,
	}
	for _, v := range labels {
		got, err := ParseLabelKind(v.AsStr())
		if err != nil || got != v {
			t.Errorf("ParseLabelKind(%q) = %v, %v; want %v", v.AsStr(), got, err, v)
		}
	}
	if _, err := ParseLabelKind("BOGUS"); err == nil {
		t.Errorf("expected error for BOGUS LabelKind")
	}
}
