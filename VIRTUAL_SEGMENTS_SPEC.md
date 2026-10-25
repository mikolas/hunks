# Specification: Virtual Segment Carve-Outs (`incbin` + Label + Block Comment)

## 1. Core Principles & Invariants

1. **Unified `incbin` Mechanism (Editor Selection & Asset Viewers):**
   - Any contiguous block of memory `[Start, End)` can be carved out as a Virtual Segment (`incbin`) through a single shared [`CarveRange`](internal/tui/actions.go) workflow:
     - **In the Disassembly Editor:** Mark the start address (`v`), move the cursor to the end address (down to the exact byte via `←`/`→`), and press **`K`** to prompt for the label name (`ModalCarveName`) and create the `incbin`.
     - **In Specialized Viewers (Bitplane Viewer `B` and Music Ripper `M`):** Pressing **`K`** automatically supplies `[Start, End)` from the asset's byte span, pre-fills the `ModalCarveName` prompt with a default label (e.g. `gfx_<W>x<H>x<BPU>[i]` or `mod_<format>_<off>`), and attaches the asset's metadata as a **Block Comment** above the label.
2. **Flat Binaries Only for Asset Viewers (`!seg.IsRelocatable()`):**
   - Multi-hunk AmigaOS executables already partition code and data into hunks (`hunk0..hunkN`) and enforce relocation/even-alignment guards.
3. **Immutable Segment Ground Truth:**
   - The underlying segment binary is **never** physically split, truncated, or modified on disk.
4. **Zero New Schema — Built on Existing Primitives (`CellIncbin` + `Label` + `BlockComment`):**
   - Every carved-out virtual segment is represented at `startAddr` by:
     1. **`db.CellIncbin`** (`Confidence = 255`, `Size = endAddr - startAddr`) in `project.db`.
     2. **User Label** (`db.SetLabel(startAddr, label, db.LabelDat, isAuto)`).
     3. **Optional Block Comment (`db.UpdateBlockComment`)** rendered directly above the label in both the TUI listing (`SubRowBlockComment`) and emitted `.asm` source.
5. **100% Bit-for-Bit Reassembly Parity:**
   - On `emit` (`hunks emit` or TUI `e`), `Emitter` writes `BinaryData[startOff:endOff]` to `assets/<label>.bin` and emits the block comment, label, and `incbin "assets/<label>.bin"`, assembling back via `vasmm68k_mot` to a 100% bit-for-bit identical binary.
6. **Atomic & 100% Reversible (`Ctrl-z` Undo & `b`/`u`/`K` Uncarve):**
   - Carving and uncarving live 100% in `project.db` (`CellIncbin`, `Label`, `BlockComment`) across `b`/`u`/`K` (`UncarveAtCursor`) and `Ctrl-z` (`Undo`).

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
     - Pushes an `UndoEntry` snapshot (`Cells`, `Comments`, `OldLabels`) so `Ctrl-z` undoes the carve.
     - Inserts `db.CellIncbin` (`Confidence = 255`) and `label` in a single SQLite transaction.
4. **Uncarve (`b`, `u`, or `K` with no selection on an `INCBIN` row):**
   - Pressing `b`, `u`, or `K` when the cursor is on an existing `incbin` row calls `UncarveAtCursor()`, unfolding the `CellIncbin` back into coalesced 16-byte `dc.b` rows (also undoable via `Ctrl-z`). Refuses to uncarve on `dc.x` data rows or non-`INCBIN` rows.

### 2.2 Bitplane Image Viewer (`K` in `ModalBitplane`)
1. **Prompt for Label Name (`ModalCarveName`):**
   - Pressing `K` inside `ModalBitplane` computes `[startOff, endOff)` via `st.ByteSpan()` and opens `ModalCarveName` pre-populated with a default convention-based label:
     - `gfx_<W>x<H>x<BPU>[i][h][ham]` (e.g. `gfx_320x200x5i` or `gfx_320x256x4`).
   - Pressing `Esc` cancels and returns to the Bitplane Viewer; pressing `Enter` confirms the label.
2. **Create `CellIncbin` + Block Comment Above the Label:**
   - Replaces the current `MarkData(..., db.CellDataB)` implementation in [`CarveBitplaneRange`](internal/tui/actions.go) with a transition to `ModalCarveName` (carrying the formatted bitmap `BlockComment`) that invokes `CarveRange` and writes the multi-line `BlockComment` above the label:
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
   - Pressing `B` while the disassembly cursor is on a carved bitmap `incbin` row parses the `BlockComment` (or `gfx_<W>x<H>x<BPU>` label) and reopens the Bitplane Viewer with the saved geometry, `BPL1MOD`/`BPL2MOD` modulo, `VIS`/`SYNC` plane masks, plane pointers, and palette (`Grayscale`, `High-Contrast`, or custom `@+$offset`, plus `inv` and `bias`) restored.

### 2.3 TUI Music Ripper (`M` $\rightarrow$ `ModalMusicRipper`)
1. **Scan & Browse (`M`):**
   - Pressing **`M`** in the disassembly view runs [`modules.Scan(a.BinaryData)`](internal/modules/modules.go) across the current segment and opens `ModalMusicRipper` listing all detected music modules (`ProTracker`, `Future Composer`, `Whittaker`, `SoundTracker 2.6`, `Old SoundTracker`, `Delta Music`, `Final Music System`) and their regions (`Primary`, `Samples`).
   - If no modules are detected in the segment, the status bar reports `"No music modules found in segment"`.
2. **Actions Inside `ModalMusicRipper`:**
   - `j` / `k` (`↑` / `↓`), `PgUp` / `PgDn`, `Home` / `End`: Select a detected module region.
   - `Enter`: Close the modal and jump the disassembly cursor (`GotoAddress`) to the selected module's start address.
   - `w`: Save/rip the selected module's raw bytes directly to `assets/<slug>_<offset>.mod` (or `.bin`, keyed on `FormatID`) for external playback.
   - **`K` (Carve as `incbin`):**
     - Refuses if `seg.IsRelocatable()` (`Flat Binaries Only for Asset Viewers`).
     - Pre-fills `[Start, End)` from the selected region (`a.BaseAddr + uint32(r.Start)` .. `a.BaseAddr + uint32(r.End()) - 1`).
     - Opens `ModalCarveName` pre-populated with a default label (`mod_<format>_<offset:05X>`) and a formatted `BlockComment`:
       ```m68k
       ; Music:  ProTracker (M.K.) — Primary
       ; Span:   $014A00..$028440 (80448 bytes)
       mod_title_theme:
           incbin  "assets/mod_title_theme.bin"
       ```
      - Confirming (`Enter`) invokes `CarveRange` to create the `db.CellIncbin`, user label, and `BlockComment` in `project.db` (or `Esc` returns to `ModalMusicRipper`).

---

## 3. Implementation Gaps to Close in Current Code

1. **`CarveRange` (`internal/tui/actions.go`):**
   - Accept `blockComment string` parameter (`CarveRange(start, endIncl uint32, name, blockComment string)`).
   - Snapshot previous cells, comments (`Comment`, `BlockComment`, `AutoComment`), and labels into `UndoEntry` before mutating so `Ctrl-z` (`Undo()`) restores `project.db` completely.
   - Set `isAuto = (strings.TrimSpace(name) == "")` when calling `a.DB.SetLabel(start, label, db.LabelDat, isAuto)`.
   - Write `a.DB.UpdateBlockComment(start, blockComment)` inside the transaction when `blockComment != ""`.
2. **`UncarveAtCursor` (`internal/tui/actions.go`):**
   - Push an `UndoEntry` snapshot before uncarving so `Ctrl-z` restores the `CellIncbin`, label, and `BlockComment`.
   - Clean up the carve's label and `BlockComment` at `carveStart` on uncarve.
3. **Bitplane Viewer `K` (`internal/tui/keys.go` & `internal/tui/actions.go`):**
   - Refuse carving if `seg.IsRelocatable()` (`Flat Binaries Only for Asset Viewers`).
   - Clear Kitty graphics placements if active, pre-populate `ModalCarveName` with `gfx_<W>x<H>x<BPU>[i][h][ham]` and the formatted bitmap `BlockComment`, and on `Enter` call `CarveRange`.
   - On `OpenBitplaneViewer` (`B`), if the cursor is on a carved bitmap `incbin` with a `; Bitmap:` block comment, restore the saved geometry, modulo, interleave, and plane pointers.
4. **TUI Music Ripper `M` (`internal/tui/types.go`, `internal/tui/keys.go`, `internal/tui/actions.go`, `internal/tui/popups.go`):**
   - Add `ModalMusicRipper` triggered by `M` in the disassembly view (`OpenMusicRipper()`).
   - Support `j`/`k` navigation, `Enter` (`GotoAddress`), `w` (`SaveMusicModule`), and `K` (`CarveMusicModule` $\rightarrow$ `ModalCarveName` $\rightarrow$ `CarveRange` with `; Music:` block comment).

---

## 4. Future Integrations

1. **CPU + Copper Hardware Trace Discovery:**
   - Candidate bitmaps and palettes observed during trace execution (`internal/analyzer/chipset.go`) will populate presets in the Bitplane Viewer (`B`), which can then be carved via `K`.
