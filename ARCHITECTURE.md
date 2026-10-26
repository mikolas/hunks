# Architecture

## System Overview

```
┌──────────────┐     ┌──────────────┐     ┌─────────────────────────┐
│  project.json │     │  project.db  │     │  Amiga Hunk exe /       │
│  (config)     │     │  (Shared DB) │     │  Flat ROM binary        │
└──────┬───────┘     └──────┬───────┘     └────────────┬────────────┘
       │                    │                          │
       ▼                    ▼                          ▼
┌───────────────────────────────────────────────────────────────────┐
│                    Unified 3-Stage Analyzer                        │
│  Stage 1: Ground-Truth Seeding (HUNK_RELOC32, XDEF, Entry Points, │
│           LAB_<hunk>_<offset> / LAB_<addr> Labels)                │
│  Stage 2: Unified Worklist Code Tracer + Jump/Vector/Trampoline   │
│           Tables + Monotonic Sandbox-Validated Gap Sweep          │
│  Stage 3: Label/Reloc-Bounded Data Classification &               │
│           Relocation-Exact Operand Formatting                     │
└───────────────┬───────────────────────────────┬───────────────────┘
                │                               │
                ▼                               ▼
┌───────────────────────────────┐ ┌─────────────────────────────────┐
│  CallGraph (`internal/callgraph`) │ │   Emitter (`internal/emitter`)  │
│  Subroutine & d16(a5) vector  │ │  Slices unified address space   │
│  inference, worklists, --code │ │  + source-linkable `; XREF:`    │
└───────────────────────────────┘ └─────────────┬───────────────────┘
                                                │
                                 ┌──────────────┴──────────────┐
                                 ▼                             ▼
                 ┌─────────────────────────┐   ┌─────────────────────────────────────┐
                 │  TUI (`internal/tui`)   │   │  disasm/Main.asm + src/hunk*.asm    │
                 │  2D cell compositor     │   │  or single out.s (vasmm68k_mot)     │
                 └─────────────────────────┘   └─────────────────────────────────────┘
```

## Package Map

```
cmd/
└── hunks/
    └── main.go             CLI entry point (cobra), command dispatch (`init`, `analyze`, `emit`, `cg`, `tui`, ...)
internal/
├── hunk/
│   └── parser.go           AmigaOS Hunk executable parser (CODE/DATA/BSS, RELOC32/DREL32, CHIP/FAST)
├── project/
│   └── project.go          Project config: segments, HunkType, MemoryType, spaces, AutoLabel & ResolveTarget
├── db/
│   ├── types.go            Domain enums (`CellType`, `EdgeKind`, `XrefKind`, `LabelKind`)
│   └── controller.go       Shared SQLite persistence layer (`modernc.org/sqlite`) + jump-vector XREF resolution
├── amiga/
│   └── equates.go          Hardware register/vector name tables & `equates.i` generator
├── m68k/
│   ├── types.go            Zero-allocation `Insn`, `Op`, `Operand`, `AccessFlags`, `EAMode`, `RegMask`, `FlowFlags`, `ParseMnemonic`
│   ├── decode.go           Strict Motorola 68000 opcode/extension decoder (`Decode`, `ClassifyIndirectDispatch`)
│   └── cycles.go           Exact MC68000 instruction cycle & read/write bus timing (`Timing`, `BusCost`)
├── analyzer/
│   ├── analyzer.go         Unified virtual address space, LoadedSegment map, LAB_ label manager, trace handoff
│   ├── classify.go         RefType classification + M68000 relocation/instruction validator (`internal/m68k`)
│   ├── stage2_code.go      Unified worklist descent, jump/vector/trampoline tables, sandbox gap sweep
│   ├── stage3_data.go      Label/relocation-bounded data & BSS classification
│   ├── stage4_funcmeta.go  Subroutine boundary & register liveness / metadata inference
│   ├── format.go           Relocation-exact (Hunk mode) & range-validated (Flat mode) operand formatter
│   ├── baseregs.go         Base-register (`a4`/`a5`/`a6`) invariant resolution
│   ├── trace.go            Trace-driven analysis (`analyze --trace`): `m68kemu` sandbox recorder + analysis bus
│   └── chipset.go          Minimal 6-level Amiga OCS/ECS chipset state machine (Agnus/Denise/Paula/Blitter/Copper/CIA)
├── emitter/
│   └── emitter.go          Single-file & modular multi-hunk assembly generator + source-linkable XREFs
├── callgraph/
│   └── callgraph.go        Subroutine inference, d16(An) jump-vector resolution, worklists, DOT/Mermaid/JSON/text
├── modules/
│   ├── modules.go          Pure byte-buffer module recognizer registry (`Recognizer`, `Match`, `Region`, `Scan`)
│   ├── sandbox.go          Bounded M68000 (`m68kemu`) scratch-RAM probe for self-executing drivers
│   ├── protracker.go       ProTracker / NoiseTracker / StarTrekker (M.K., M!K!, FLT4/8 + AM, N.T., mask/title)
│   ├── soundtracker26.go   SoundTracker 2.6 (`MTN\0`) & IceTracker (`IT10`)
│   ├── old_soundtracker.go 15-sample SoundTracker
│   ├── future_composer.go  Future Composer 1.0–1.3 (`SMOD`) & 1.4 (`FC14`)
│   ├── delta_music.go      Delta Music 1.0 (`ALL `)
│   ├── final_music.go      Final Music System (`FNL`, `m68kemu` sandbox)
│   ├── whittaker.go        David Whittaker (`m68kemu` sandbox)
│   └── ...                 19 additional ExoticRipper format recognizers (ThePlayer, TFMX, OctaMED, Hippel, ...)
└── tui/
    ├── types.go            Enums, structs (`Modal`, `ListingRow`, `SubRowKind`, `UndoEntry`, `TextInput`)
    ├── listing.go          `BuildListingRows`: Sub-Row Code View builder, 16-byte `dc.b` coalescer, 3-tier EOL comment priority
    ├── app.go              `App` (`tea.Model`) + segment/status management
    ├── actions.go          Interactive type marking (`c`/`b`/`w`/`l`/`p`/`s`/`u`), virtual segment carve/uncarve (`K`), bitplane/music ripper actions (`B`/`M`), & transactional undo (`Ctrl-z`)
    ├── nav.go              Cursor, byte-offset (`←`/`→`), & automatic cross-hunk / jump-vector reference navigation
    ├── popups.go           XREFs (`x`), Functions (`f`), Search (`/`), Structs (`t`), and Segment/Space popups
    ├── keys.go             Keyboard/mouse event handling
    ├── bitplane.go         Interactive Amiga Bitplane Image Viewer (`B`), `BPLCON0`/modulo geometry, planar/EHB/HAM6 decoder, `FORM ILBM` encoder, `XTWINOPS` (`\x1b[14t`) pixel sizing, & block comment round-trip
    ├── pixelgfx.go         Terminal pixel graphics encoders (`Kitty`, `iTerm2`, `Sixel`, Unicode `Half-Block`)
    ├── theme.go            Configurable truecolor `Theme`, `LoadTheme`, and per-token operand/comment styling
    └── render.go           Fixed-grid 2D `screenBuffer` compositor, scrollbars, floating modals (`ModalBitplane`, `ModalMusicRipper`, etc.)
```

## Data Model

### `project.json`

```json
{
  "output": "out.s",
  "entry_points": [
    { "addr": 0, "name": "LAB_0_00000", "segment": "hunk0" }
  ],
  "memory_regions": [],
  "structs": {
    "ShipObj": { "90": "so_Type" }
  },
  "register_aliases": {
    "a0": "ShipObj"
  },
  "segments": [
    {
      "name": "hunk0",
      "hunk_index": 0,
      "hunk_type": "Code",
      "memory_type": "Public",
      "alloc_size": 116,
      "file": "hunk0.bin",
      "base": 0,
      "db": "project.db",
      "relocatable": true
    }
  ],
  "spaces": [
    { "name": "default", "segments": ["hunk0"] }
  ],
  "active_space": "default"
}
```

**Segments, spaces, split & carve.** The project owns a flat pool of all
`segments`; a `Space` is a named, ordered selection of them that forms one
self-contained address space, and addressing resolves through `active_space`
(`SegmentAtAddr` walks the active space's segments in reverse, so on overlap
the **last-listed segment wins** — the basis for overlays/patches). A hunk-exe
is the degenerate case: one `default` space holding every hunk at disjoint
synthetic bases. `Segment.Relocatable` distinguishes a `LoadSeg`-relocated hunk
(`true`) from a static-base flat/trackloaded part (`false`, caller-supplied
`base`).

### `project.db` (Shared Segment-Keyed SQLite Database)

Every segment-scoped table includes `seg TEXT NOT NULL` as the leading primary-key column so multiple flat overlay segments sharing the same runtime base address coexist in one shared SQLite database without colliding:

- **`cells`** — every analyzed byte range, keyed by `(seg, addr)`:
  `CODE`, `POINTER`, `DATA_B`, `DATA_W`, `DATA_L`, `DATA_ZERO`, `STRING`, `INCBIN`
- **`comments`** — user inline comments, multi-line block comments, and analyzer/trace auto-comments, keyed by `(seg, addr)`
- **`labels`** — symbolic names at addresses (`LAB_{hunk}_{offset:05X}` in hunk mode, `LAB_{addr:05X}` in flat mode; `seg = ''` for space-global/external RAM symbols), keyed by `(seg, addr)`
- **`relocs`** — exact 32-bit relocation table (`HUNK_RELOC32` / `HUNK_DREL32`), keyed by `(seg, site_addr)`
- **`edges`** — control-flow graph (`seg` = source segment), keyed by `(seg, source_addr, target_addr)`:
  `CALL`, `UNCOND`, `COND_TRUE`, `COND_FALSE`, `FALLTHROUGH`
- **`xrefs`** — data/code cross-references (`seg` = source segment), keyed by `(seg, source_addr, target_addr)`:
  `CODE_CALL`, `CODE_BRANCH`, `DATA_ADDR`, `DATA_READ`, `DATA_WRITE`
- **`functions`** — inferred subroutine boundaries, keyed by `(seg, entry_addr)`
- **`renames`** — segment-scoped symbol renames, keyed by `(seg, original)`
- **`operand_formats`** — per-instruction numeric base overrides (`HEX`, `DEC`, `BIN`), keyed by `(seg, addr)`
- **`base_regs`** — base-register (`a4`/`a5`/`a6`) invariants, keyed by `(scope_kind, scope_key, reg)`

## Analyzer Internals (Unified 3-Stage Pipeline)

### Stage 1: Ground-Truth Seeding & Relocation Invariant
1. **Relocation Table Authority:** In multi-hunk executables, every `HUNK_RELOC32` entry is stored in `relocs` (`site_addr -> target_addr`). All relocation targets receive a deterministic `LAB_{tgt_hunk}_{offset:05X}` label, and any cross-segment reference sets `is_exported = 1` (`XDEF`).
2. **M68000 Relocation Invariant:** Because the first 2 bytes of every M68000 instruction is the opcode word (never 32-bit relocated), no instruction can ever start inside `[site_addr .. site_addr + 4)`, and any relocation falling inside an instruction `[addr + 1 .. addr + size)` must align with a valid 32-bit immediate or `.l` extension word of that instruction.

### Stage 2: Unified Worklist Code Tracer + Sandbox-Validated Gap Sweep
1. **Worklist Recursive Descent (`ConfDefinite` / `ConfHigh`):**
   - Pops addresses from a single shared worklist spanning all `Code` segments.
   - Follows direct branches/calls (`BSR`, `JSR`, `BRA`, `JMP`, `Bcc`, `DBcc`), PC-relative word-offset jump tables (`JMP`/`JSR d8(PC,Xn)`), and contiguous trampoline/vector tables (`JMP target.L`, `BRA.W target`).
   - Pushes code-segment addresses referenced via `HUNK_RELOC32` or `LEA`/`PEA`/`#imm` into `candidateCode`.
2. **Monotonic Sandbox-Validated Gap Sweep (`ConfMedium`):**
   - Evaluates `candidateCode` and walks unmapped `Code` gaps using per-segment monotonic cursors.
   - Trial-decodes candidate sequences in a sandbox (`validateCandidate`), enforcing M68000 hardware invariants:
     - Brief extension word bits `10..8 == 0` (`(ext_word & 0x0700) == 0`) on indexed memory modes (`d8(An,Xn)` and `d8(PC,Xn)`).
     - Byte-immediate extension word high-byte zero (`bytes[2] == 0`) on `.b` immediate instructions and static bit ops (`btst`/`bchg`/`bclr`/`bset`).
     - No interior label or relocation overlap, and clean termination at `RTS`/`RTE`/`RTR`/`BRA`/`JMP` or verified `CODE`.

### Stage 3: Label/Relocation-Bounded Data Classification & Operand Formatting
1. **Data Gap Classification:**
   - Walks all unmapped intervals in `Code` and `Data` segments, strictly splitting at any address in `labels` or `relocs`.
   - Emits `POINTER` (`dc.l LAB_x_xxxxx` for addresses in `relocs`), `STRING` (`dc.b '...',0`), `DATA_ZERO` (`dc.l 0,...`), and `DATA_L`/`DATA_W`/`DATA_B`.
2. **Relocation-Exact Operand Formatting:**
   - Re-decodes every `CODE` cell from `raw_bytes`.
   - In **Hunk Mode**, formats `.l` immediate/absolute operands as `LAB_{hunk}_{offset:05X}` **if and only if** the operand's extension-word address is in `relocs`.
   - In **Flat Mode**, in-segment `.l` operands matching valid segment labels are formatted symbolically at analysis time, while out-of-segment `.l` targets stay numeric in `cells.op_str` and are resolved dynamically against the active `Space`'s `all_labels` at view/emit time (`ResolveFlatCrossSegOperands` + external `equ` directives).

## Trace-Driven Analysis (`analyze --trace`)

An opt-in pass for **flat self-booting binaries** (games/demos) that runs the
program from its entry point in a sandboxed M68000 interpreter (`m68kemu`)
over a flat RAM window, then **resolves indirect control flow and
hardware-register accesses by observation** and seeds them into the normal
recursive descent. Default `analyze` is unaffected; all facts produced are
non-byte-affecting (labels / edges / xrefs / comments) so load-image parity is
preserved.

- **Recorder (`internal/analyzer/trace.go`):** the analysis bus loads the image
  at its base; custom (`$DFFxxx`) / CIA (`$BFxxxx`) MMIO is routed to the
  chipset, other MMIO is absorbed, out-of-window accesses fault, and an 8 MiB
  window bounds wild pointers. It steps one instruction at a time under a hard
  budget, recording a single-valued **register-context map** (`addr -> [D0-D7,A0-A7]`)
  and every indirect-dispatch site's observed targets. Interrupts are serviced
  strictly **between** steps. Self-installed TRAP/A-line/F-line exceptions are
  vectored into the program's own handler when installed, else the trace stops.
- **Chipset (`internal/analyzer/chipset.go`):** a minimal, deterministic state
  machine modeling only the **digital state the CPU observes**: Paula
  INTENA/INTREQ + the 7-level `DeliverableIPL` priority encoder, Agnus beam
  (VPOSR/VHPOSR/VERTB), disk DSKLEN→DSKBLK/DSKSYNC handshake, serial TBE/RBF,
  audio timers, both 8520 CIAs (timers/TOD/ICR/ports, level-sensitive
  PORTS/EXTER), a **synchronous blitter** (16-bit barrel shifter + 256 LF
  minterms + area fill + line draw), and a bounded frame-end Copper MOVE walk.
- **Resolution & hand-off (`internal/analyzer/analyzer.go`):** observed
  trampoline / base-register / indexed-dispatch targets and installed
  interrupt-handler vectors become code seeds for recursive descent, plus
  call-graph edges and `; -> LAB_x (observed)` annotations;
  register-context-resolved `d16(An)` hardware accesses are named
  (`INTREQR+1` etc.).

## Music Module Recognizer Engine (`internal/modules/`, Experimental)

A self-contained experimental recognizer subsystem (reverse-engineered from ExoticRipper
V2.31) that operates directly on `[]byte` buffers without SQLite, `Project`, or
I/O dependencies:

1. **Interface & Cascade Ordering (`internal/modules/modules.go`):**
   - Each recognizer implements `Recognizer.Detect(data []byte, offset int) *Match`, returning one or more `Region`s (`RegionPrimary` and optional companion `RegionSamples`, e.g. StarTrekker `AM` waveform blocks or TFMX `smpl`).
   - Recognizers are evaluated in ExoticRipper's master discriminator cascade order with even-aligned two-byte stepping and primary-region auto-skip on match.
2. **Self-Executing Driver Probe (`internal/modules/sandbox.go`):**
   - Formats whose bounds can only be computed by running the module's own M68000 replay/init header (`FinalMusic` / `FNL`, `DavidWhittaker`) execute inside a bounded `m68kemu` scratch-RAM sandbox (hard instruction budget, inert MMIO, fault on out-of-window or OS/trap vector access).
