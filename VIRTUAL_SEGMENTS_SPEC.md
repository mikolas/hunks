# Specification: Virtual Segment Carve-Outs (`incbin` + Label + Block Comment)

## 1. Core Principles & Invariants

1. **Unified `incbin` Mechanism (Editor Selection & Asset Viewers):**
   - Any contiguous block of memory `[Start, End)` can be carved out as a Virtual Segment (`incbin`) through a single shared [`CarveRange`](file:///home/mikolas/src/hunks/internal/tui/actions.go#L148-L223) workflow:
     - **In the Disassembly Editor:** Mark the start address (`v`), move the cursor to the end address (down to the exact byte via `←`/`→`), and press **`K`** to prompt for the label name (`ModalCarveName`) and create the `incbin`.
     - **In Specialized Viewers (Bitplane Viewer `B` today, Music Ripper in future):** Pressing **`K`** automatically supplies `[Start, End)` from the asset's byte span, pre-fills the `ModalCarveName` prompt with a default label (e.g. `gfx_<W>x<H>x<BPU>[i]`), and attaches the asset's metadata as a **Block Comment** above the label.
2. **Flat Binaries Only for Asset Viewers (`!seg.IsRelocatable()`):**
   - Multi-hunk AmigaOS executables already partition code and data into hunks (`hunk0..hunkN`) and enforce relocation/even-alignment guards.
3. **Immutable Segment Ground Truth:**
   - The underlying segment binary is **never** physically split, truncated, or modified on disk.
4. **Zero New Schema — Built on Existing Primitives (`CellIncbin` + `Label` + `BlockComment`):**
   - Every carved-out virtual segment is represented at `startAddr` by:
     1. **`db.CellIncbin`** (`Confidence = 255`, `Size = endAddr - startAddr`) + `project.Carve` (`File: "assets/<label>.bin"`).
     2. **User Label** (`db.SetLabel(startAddr, label, db.LabelDat, true)`).
     3. **Optional Block Comment (`db.UpdateBlockComment`)** rendered directly above the label in both the TUI listing (`SubRowBlockComment`) and emitted `.asm` source.
5. **100% Bit-for-Bit Reassembly Parity:**
   - On `emit` (`hunks emit` or TUI `e`), `Emitter` writes `BinaryData[startOff:endOff]` to `assets/<label>.bin` and emits the block comment, label, and `incbin "assets/<label>.bin"`, assembling back via `vasmm68k_mot` to a 100% bit-for-bit identical binary.
6. **Atomic & 100% Reversible (`Ctrl-z` Undo & `K` Uncarve):**
   - Carving and uncarving keep `project.db` (`CellIncbin`, `Label`, `BlockComment`) and `project.json` (`Carves`) strictly in sync across both `K` (`UncarveAtCursor`) and `Ctrl-z` (`Undo`).

---

## 2. Unified Carve-Out Workflows

### 2.1 Disassembly Editor Selection (`v` $\rightarrow$ Move $\rightarrow$ `K`)
1. **Mark Start (`v`):**
   - Move cursor to the start address (using `←`/`→` on a 16-byte `dc.b` row for byte-exact positioning) and press `v` (`ToggleSelection`).
2. **Move to End:**
   - Navigate to the end address (`j`/`k`, `PgDn`, `g` Goto, `/` Search, `←`/`→`). The TUI highlights the active `[start..endIncl]` range.
3. **Carve (`K`):**
   - Pressing `K` opens `ModalCarveName` (`Carve Label (for incbin)`).
   - Confirming (`Enter`) calls `CarveRange(start, endIncl, label, "")`, which:
     - Pushes an `UndoEntry` snapshot (`pushUndoForRegion` + `Carves` state) so `Ctrl-z` undoes the carve.
     - Inserts `db.CellIncbin` (`Confidence = 255`) and `label` in a single SQLite transaction.
     - Records `project.Carve{Start: start, End: end, File: "assets/<label>.bin", Name: label}` in `project.json`.
4. **Uncarve (`K` with no selection on an `INCBIN` row):**
   - Pressing `K` when the cursor is on an existing `incbin` row calls `UncarveAtCursor()`, removing the `CellIncbin` and `project.Carve` entry (also undoable via `Ctrl-z`).

### 2.2 Bitplane Image Viewer (`K` in `ModalBitplane`)
1. **Prompt for Label Name (`ModalCarveName`):**
   - Pressing `K` inside `ModalBitplane` computes `[startOff, endOff)` via `st.ByteSpan()` and opens `ModalCarveName` pre-populated with a default convention-based label:
     - `gfx_<W>x<H>x<BPU>[i][h][ham]` (e.g. `gfx_320x200x5i` or `gfx_320x256x4`).
   - Pressing `Esc` cancels and returns to the Bitplane Viewer; pressing `Enter` confirms the label.
2. **Create `CellIncbin` + Block Comment Above the Label:**
   - Replaces the current `MarkData(..., db.CellDataB)` implementation in [`CarveBitplaneRange`](file:///home/mikolas/src/hunks/internal/tui/actions.go#L450-L481) with a call to `CarveRange` that also writes a concise multi-line `BlockComment` above the label:
     ```m68k
     ; Bitmap: 320x200x5 (Interleaved, Lowres, 32 colors)
     ; Span:   $014A00..$01E640 (40000 bytes)
     ; Regs:   BPLCON0=$5200 BPL1MOD=$00A0 BPL2MOD=$00A0 DDF=320px(40B)
     ; Planes: 1:$014A00 2:$014A28 3:$014A50 4:$014A78 5:$014AA0
     ; Pal:    Copper@$004120
     gfx_title_logo:
         incbin  "assets/gfx_title_logo.bin"
     ```
3. **Round-Trip on `B`:**
   - Pressing `B` while the disassembly cursor is on a carved bitmap `incbin` row parses the `BlockComment` (or `gfx_<W>x<H>x<BPU>` label) and reopens the Bitplane Viewer with the saved geometry, pointers, and palette restored.

---

## 3. Future Integrations

1. **Music Ripper Carving (`internal/modules`):**
   - Detected music modules (`ProTracker`, `Future Composer`, `Whittaker`, etc.) will pre-fill `[Start, End)` and a `Music: <Format> (<Variant>)` block comment into the same `ModalCarveName` $\rightarrow$ `CarveRange` flow.
2. **CPU + Copper Hardware Trace Discovery:**
   - Candidate bitmaps and palettes observed during trace execution (`internal/analyzer/chipset.go`) will populate presets in the Bitplane Viewer (`B`), which can then be carved via `K`.
