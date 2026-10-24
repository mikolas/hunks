package analyzer

import (
	"cmp"
	"slices"

	"github.com/mikolas/hunks/internal/db"
	"github.com/mikolas/hunks/internal/m68k"
)

// termKind classifies how a reachable basic block ends, for no-return inference.
type termKind uint8

const (
	termNone    termKind = iota // not a terminator (falls through / continues)
	termReturn                  // RTS / RTE / RTR — the function can return
	termHalt                    // STOP / ILLEGAL / infinite self-branch — never returns
	termUnknown                 // unresolved indirect jmp/jsr, or other terminator — ambiguous
)

// classifyTerminator decodes the instruction in cell and reports its block-terminating kind.
func (a *Analyzer) classifyTerminator(cell *db.Cell) termKind {
	if len(cell.RawBytes) < 2 {
		return termNone
	}
	insn, ok := a.decodeCached(cell.Addr, cell.RawBytes)
	if !ok {
		return termNone
	}
	if insn.IsReturn() {
		return termReturn
	}
	switch insn.Op {
	case m68k.OpSTOP, m68k.OpILLEGAL:
		return termHalt
	}
	// Infinite self-branch (bra/jmp back to this same instruction): a non-returning spin.
	if insn.IsUnconditionalJump() {
		for _, op := range insn.Operands() {
			if op.Mode == m68k.EABranch && op.UVal == cell.Addr {
				return termHalt
			}
		}
		// A resolved unconditional jump leaves this function via an edge; not a halt by itself.
		return termNone
	}
	if insn.IsTerminator() {
		return termUnknown
	}
	return termNone
}

// stackFrameSize returns the signed LINK frame displacement for a function entry cell,
// or (0, false) if the entry is not `LINK An,#disp`.
func (a *Analyzer) stackFrameSize(cell *db.Cell) (int32, bool) {
	if len(cell.RawBytes) < 2 {
		return 0, false
	}
	insn, ok := a.decodeCached(cell.Addr, cell.RawBytes)
	if !ok || insn.Op != m68k.OpLINK || insn.NumOps < 2 {
		return 0, false
	}
	return insn.Ops[1].Disp, true
}

// stage4FunctionMeta is the R4 post-traversal pass (ANALYZER_HEURISTICS_SPEC.md §3.5).
//
// After Stage 2 has committed all CODE cells and control-flow edges, it walks each
// function's reachable cells over the edge set (bounded by the next function entry) and
// records end_addr, is_noreturn, and stack_frame on the `functions` rows. It then drops
// the speculative FALLTHROUGH edge that Stage 2 inserts after a `jsr`/`bsr` to a
// no-return target, so the CFG no longer shows control resuming past such calls.
//
// It is a pure annotation/CFG-cleanup pass: no instruction or data payload bytes change.
func (a *Analyzer) stage4FunctionMeta() {
	entries := a.DB.FunctionEntries()
	if len(entries) == 0 {
		return
	}

	// Index all CODE cells by address.
	cells := a.DB.CodeCells()
	if len(cells) == 0 {
		return
	}
	cellByAddr := make(map[uint32]*db.Cell, len(cells))
	for i := range cells {
		cellByAddr[cells[i].Addr] = &cells[i]
	}

	// Adjacency: source -> control-flow successor targets (all edge kinds).
	allEdges := a.DB.AllEdges()
	succ := make(map[uint32][]db.Edge, len(entries))
	for _, e := range allEdges {
		succ[e.Source] = append(succ[e.Source], e)
	}

	entrySet := make(map[uint32]struct{}, len(entries))
	for _, e := range entries {
		entrySet[e] = struct{}{}
	}

	noreturn := make(map[uint32]bool, len(entries))
	var metas []db.FunctionMeta

	for i, entry := range entries {
		entryCell := cellByAddr[entry]
		if entryCell == nil {
			continue
		}
		// Upper bound: the next function entry in the same segment (exclusive).
		var bound uint32 = 0xFFFFFFFF
		if i+1 < len(entries) && a.IsSameSegment(entry, entries[i+1]) {
			bound = entries[i+1]
		}

		// Reachable-cell walk bounded to [entry, bound), staying within the function body.
		visited := make(map[uint32]struct{})
		stack := []uint32{entry}
		var endAddr uint32
		sawReturn := false
		sawHalt := false
		sawUnknown := false

		for len(stack) > 0 {
			addr := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if _, seen := visited[addr]; seen {
				continue
			}
			cell := cellByAddr[addr]
			if cell == nil {
				continue
			}
			if addr < entry || addr >= bound {
				continue
			}
			// Do not walk into another function's body (its own entry bounds it).
			if addr != entry {
				if _, isEntry := entrySet[addr]; isEntry {
					continue
				}
			}
			visited[addr] = struct{}{}
			if cEnd := cell.Addr + cell.Size; cEnd > endAddr {
				endAddr = cEnd
			}

			switch a.classifyTerminator(cell) {
			case termReturn:
				sawReturn = true
			case termHalt:
				sawHalt = true
			case termUnknown:
				sawUnknown = true
			}

			for _, e := range succ[addr] {
				// CALL edges leave to another function; the fallthrough models the return.
				if e.Kind == db.EdgeCall {
					continue
				}
				_, isOtherEntry := entrySet[e.Target]
				if e.Target < entry || e.Target >= bound || (e.Target != entry && isOtherEntry) {
					if noreturn[e.Target] {
						sawHalt = true
					} else {
						sawUnknown = true
					}
					continue
				}
				if _, seen := visited[e.Target]; !seen {
					stack = append(stack, e.Target)
				}
			}
		}

		// No-return: reachable, never returns, and definitely halts on every observed exit.
		isNoreturn := sawHalt && !sawReturn && !sawUnknown
		noreturn[entry] = isNoreturn

		meta := db.FunctionMeta{
			Entry:      entry,
			IsNoreturn: isNoreturn,
		}
		if endAddr > entry {
			meta.EndAddr = endAddr
			meta.HasEnd = true
		}
		if frame, ok := a.stackFrameSize(entryCell); ok {
			meta.StackFrame = frame
			meta.HasFrame = true
		}
		metas = append(metas, meta)
	}

	if len(metas) > 0 {
		_ = a.DB.UpdateFunctionMetadataBatch(metas)
	}

	a.pruneNoreturnFallthroughs(allEdges, cellByAddr, noreturn)
}

// pruneNoreturnFallthroughs removes the FALLTHROUGH edge inserted after a `jsr`/`bsr`
// whose CALL target is a no-return function, so the CFG does not show execution
// resuming at the instruction following the call.
func (a *Analyzer) pruneNoreturnFallthroughs(allEdges []db.Edge, cellByAddr map[uint32]*db.Cell, noreturn map[uint32]bool) {
	// Collect (source, fallthroughTarget) pairs to delete.
	type ftKey struct{ src, tgt uint32 }
	fallthroughs := make(map[ftKey]struct{})
	for _, e := range allEdges {
		if e.Kind == db.EdgeFallthrough {
			fallthroughs[ftKey{e.Source, e.Target}] = struct{}{}
		}
	}

	var toDelete []db.Edge
	for _, e := range allEdges {
		if e.Kind != db.EdgeCall || !noreturn[e.Target] {
			continue
		}
		cell := cellByAddr[e.Source]
		if cell == nil {
			continue
		}
		ftTgt := cell.Addr + cell.Size
		if _, ok := fallthroughs[ftKey{e.Source, ftTgt}]; ok {
			toDelete = append(toDelete, db.Edge{Source: e.Source, Target: ftTgt, Kind: db.EdgeFallthrough})
		}
	}
	if len(toDelete) == 0 {
		return
	}
	// Deduplicate deletions (a source can have one fallthrough but multiple call edges).
	slices.SortFunc(toDelete, func(x, y db.Edge) int {
		if c := cmp.Compare(x.Source, y.Source); c != 0 {
			return c
		}
		return cmp.Compare(x.Target, y.Target)
	})
	toDelete = slices.CompactFunc(toDelete, func(x, y db.Edge) bool {
		return x.Source == y.Source && x.Target == y.Target
	})
	_ = a.DB.WithTransaction(func() error {
		for _, e := range toDelete {
			if err := a.DB.DeleteEdgeExact(e.Source, e.Target, db.EdgeFallthrough); err != nil {
				return err
			}
		}
		return nil
	})
}
