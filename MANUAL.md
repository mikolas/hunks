# `hunks` — Amiga M68k Disassembler & Reverse-Engineering Manual

## Overview

`hunks` is a Motorola 68000 disassembler, static call-graph analyzer, trace-seeded chipset analyzer, and interactive TUI reverse-engineering system for Amiga 500 games and multi-hunk AmigaOS executables. Written in pure Go (zero CGo), it operates on a **unified virtual address space** backed by a single shared SQLite database (`project.db`) and produces modular, 100% bit-for-bit re-assemblable `vasmm68k_mot` assembly output.

---

## Quick Start

### A. Multi-Hunk AmigaOS Executable (e.g. *Frontier: Elite II*)

```bash
# Build/install the binary once
go install ./cmd/hunks

# 1. Initialize multi-hunk module in workspace (module 'frontier' deduced from binary name -> work/frontier/)
hunks init --hunk-file assets/frontier

# 2. Run unified 3-stage analysis across all hunks
hunks -m frontier analyze

# 3. Emit modular assembly (src/frontier/hunk0.asm .. src/frontier/hunkN.asm, src/equates.i, disasm/frontier.asm)
hunks -m frontier emit --amiga

# 4. Assemble & verify with vasmm68k_mot
vasmm68k_mot -Fhunkexe -kick1hunks -nosym -no-opt -I . -I src -o build/frontier disasm/frontier.asm
python3 scripts/verify_parity.py build/frontier assets/frontier
```

### B. Flat Binary Image (e.g. *Virus* / raw Chip RAM dump)

```bash
# 1. Initialize flat binary module at fixed load address (module 'disk_1' deduced -> work/disk_1/)
hunks init --binary assets/disk.1 --base 0x3B800

# 2. Add entry point
hunks -m disk_1 entry 0x63EC8 --name main

# 3. Run analysis & emit assembly (writes disasm/disk_1.asm)
hunks -m disk_1 analyze
hunks -m disk_1 emit

# 4. Verify 100% bit-for-bit parity
vasmm68k_mot -m68000 -no-opt -Fbin -o build/disk_1.bin disasm/disk_1.asm
cmp -l assets/disk.1 build/disk_1.bin   # 0 differences
```

---

## CLI Commands & Workspace Model

`hunks` organizes repositories around two global flags:
- **`-p, --path <DIR>`** (alias `--project`, default `.`): Workspace root directory (either CWD by default or an explicit path). Anchors `work/<module>/`, `src/<module>/`, `src/equates.i`, and `disasm/<module>.asm`.
- **`-m, --module <NAME>`**: Module namespace inside the workspace. On `init`, `<module>` is deduced automatically from the binary filename (e.g. `assets/frontier` $\rightarrow$ `frontier`, `assets/intro.exe` $\rightarrow$ `intro`, `assets/Disk.1` $\rightarrow$ `Disk_1`) unless overridden with `-m <name>`. On all other commands, `-m <name>` is **required** so multi-binary workspaces never collide.

| Command | Description |
|---------|-------------|
| `init --hunk-file PATH [--force]` | Initialize multi-hunk AmigaOS module in `<root>/work/<module>/` (auto-extracts `hunk*.bin`, relocations, and `XDEF`s into `project.db`) |
| `init --binary PATH --base HEX [--output FILE] [--force]` | Initialize flat binary module in `<root>/work/<module>/` loaded at `base` |
| `-m <module> entry [SEG:]ADDR --name NAME` | Add a segment-qualified code entry point (resolved to owning segment in active space, or explicit `SEG:ADDR`) |
| `-m <module> analyze [--all \| -s, --segment NAME]` | Run unified 3-stage analysis across all module segments (whole hunk set for relocatable executables; standalone per-segment for flat binaries), or analyze a single segment with `-s/--segment NAME` |
| `-m <module> analyze --trace [--budget N]` | Trace-driven analysis: run the binary from its entry point in the built-in sandboxed M68000 interpreter (`m68kemu`) + minimal Amiga chipset, then resolve indirect dispatch (trampolines, `d16(An)`/indexed computed calls), self-installed interrupt/trap handlers, and hardware-register accesses **by observation** and seed them into recursive descent. Opt-in, for **flat self-booting binaries** (games/demos); default `analyze` is unchanged. `--budget` caps the instruction count (default 20,000,000). All facts are non-byte-affecting (labels/edges/comments) — parity is preserved. |
| `-m <module> emit [--amiga] [--all] [--relocatable] [--force]` | Emit modular Amiga assembly (`--amiga`: `src/<module>/hunk*.asm` + `disasm/<module>.asm` + shared `src/equates.i`) or single-file assembly (`disasm/<module>.asm`). Refuses to overwrite existing files unless `--force` is passed. |
| `-m <module> callgraph` / `cg [TARGET] [FLAGS]` | Inspect multi-hunk call graphs, bottom-up worklists, string/HW anchors, and function disassembly |
| `-m <module> hint code TARGET` | Mark target as code entry (`confidence = 100`) and run incremental analysis |
| `-m <module> hint data TARGET [COUNT] [--string] [--comment TEXT]` | Mark byte/data range or null-terminated string (`--string`) at `confidence = 100` |
| `-m <module> hint pointer TARGET [COUNT] [--follow] [--comment TEXT]` | Mark 32-bit pointer(s) (`confidence = 100`), optionally tracing pointed-to code (`--follow`) |
| `-m <module> hint base-reg REG BASE_HEX [--segment NAME] [--function LABEL]` | Declare a base-register invariant (`REG` = `a4`/`a5`/`a6`, e.g. `hint base-reg a6 0xDFF000`) so `d16(An)` accesses resolve to hardware names / global `DATA`/`BSS` xrefs. Scope is global, or limited to one `--segment` or `--function`; re-runs analysis |
| `-m <module> rename OLD_NAME NEW_NAME` | Rename a symbol (or multiple `OLD=NEW` pairs, or `--file <path>` batch file) across all segments in a single transaction |
| `-m <module> comment TARGET [TEXT] [--block]` | Set or clear inline comment or function/block header comment (`--block` / `-b`) |
| `-m <module> operand TARGET FORMAT` | Set operand numeric format (`HEX`, `DEC`, `BIN`) and reformat the instruction |
| `-m <module> segment add --file F --base HEX --name N` | Add a binary segment to the module |
| `-m <module> segment split PARENT --at OFF (--len N \| --to OFF) --base HEX --name N` | Slice an extent out of a segment into a new static-base part (`<name>.bin` + shared DB), filed into the active space |
| `-m <module> segment remove NAME` | Remove a segment from the module |
| `-m <module> segment list` | List all segments with `HunkType`, `MemoryType`, and sizes |
| `-m <module> space create NAME --segments a,b,c` | Create an address-space execution context |
| `-m <module> space switch NAME` | Switch active execution space |
| `-m <module> space list` | List defined spaces |
| `-m <module> carve START (--len N \| --end HEX) [--file PATH] [--name LABEL]` | Mark a range as an opaque `incbin` block (bytes written to a sidecar on emit). Refuses interior relocations in relocatable segments |
| `-m <module> uncarve START` | Remove a carve; run `analyze` afterwards to reclassify the range |
| `-m <module> map region NAME START END` | Define a memory region (e.g. BSS / low-RAM variables) |
| `-m <module> map load FILE` | Bulk-load `<addr> <name> [type]` label mappings from a text file |
| `-m <module> status` | Show module byte coverage statistics |
| `-m <module> tui` | Launch the interactive terminal UI |
| `rip FILE` | *(Experimental)* Scan a raw binary/memory dump for embedded Amiga music/tracker modules (26 ExoticRipper recognizers) and report detected formats, offsets, and region bounds |

---

## Target Address & Label Resolution Syntax

Every CLI command that takes a `TARGET` (`callgraph`, `hint`, `comment`, `operand`) as well as the TUI `Goto` (`g`) prompt accepts any of the following human- and LLM-friendly formats:

| Format | Example | Meaning |
|--------|---------|---------|
| `<segment>:<label>` | `hunk5:LAB_5_24BE8` or `hunk3:RenderSprite` | Exact label (original or renamed) within a specific segment |
| `<label>` | `LAB_5_24BE8` or `RenderSprite` | Unqualified label name (auto-generated or renamed) |
| `<segment>:+<hex>` | `hunk5:+24BE8` or `hunk3:+$10` | Hex byte offset relative to the start of `<segment>` |
| `<label>+<hex>` | `LAB_5_24BE8+2C` or `hunk5:LAB_5_24BE8+2C` | Hex byte offset relative to a label (ideal for targeting individual instructions inside a function) |
| `+<hex>` / `+$<hex>` | `+24BE8` | Hex byte offset relative to the currently active segment |
| `0x<hex>` / `$<hex>` | `0x72580` / `$72580` | Internal virtual address |

---

## Call Graph & Bottom-Up Symbolication (`callgraph` / `cg`)

`hunks -m <module> callgraph` (alias `hunks -m <module> cg`) infers subroutines across all segments from control-flow edges, `HUNK_RELOC32` code pointers, entry points, and `rts`/`rte`/`rtr` boundaries. It automatically resolves indirect calls through register-based jump vector tables (such as `lea.l LAB_6_0001A.l,a5` followed by `jsr d16(a5)` trampolines), compiler `switch` branch tables (`bra.b`, `bra.w`, and sparse `dc.l + bra.w`), and formats all functions using `<segment>:<label>` and hunk-relative offsets (`[+2A71A]`).

### `callgraph` Options

| Flag | Description |
|------|-------------|
| `[TARGET]` | Function/label name (`hunk5:LAB_5_2A71A`, `LAB_5_2A71A`), segment offset (`hunk5:+2A71A`), or address. Omit for project/segment overview. |
| `-s, --segment <NAME>` / `--hunk <N>` | Filter to a single segment/hunk (accepts `hunk149` or bare number `149`). When used without `--leaves`/`--anchors`/`--ready`/`--suspect`, renders a complete **Module Overview** of all functions in that hunk in offset order with incoming callers and outgoing callees. |
| `-d, --depth <N>` | Outgoing callee tree depth when inspecting a `TARGET` (default: `2`) |
| `--up-depth <N>` | Incoming caller tree depth when inspecting a `TARGET` (default: `2`) |
| `-c, --code` | Include full disassembly of `TARGET` (with `+offset` on every line) plus 7-line caller context snippets |
| `--leaves` | List leaf functions (0 outgoing calls), sorted by incoming caller count descending |
| `--anchors` | List functions that reference ASCII `STRING` cells or Amiga hardware registers (`$DFFxxx` / CIA) |
| `--ready` | List **bottom-up ready** unrenamed functions (`LAB_*`) whose outgoing callees are 100% renamed |
| `--suspect` | List functions that fall through into `DATA_*` / `STRING` cells without a terminator (`rts`/`jmp`/`bra`) |
| `-u, --unrenamed` | Filter worklists to show only unrenamed (`LAB_*`) functions |
| `-n, --limit <N>` | Maximum functions to display in worklist modes (`0` = unlimited, default: `50`) |
| `-f, --format <FMT>` | Output format: `text` (default), `json`, `dot` (Graphviz), or `mermaid` |

---

## Comprehensive Usage Examples & Walkthroughs

### Walkthrough 1: Bootstrapping a Multi-Hunk Game (*Frontier: Elite II*)

#### Step 1: Initialize and Inspect Segments
```bash
hunks init --hunk-file assets/frontier
```
Output:
```text
Initialized multi-hunk module 'frontier' (work/frontier/) from 'assets/frontier':
  Hunks: 13 (10 code, 1 data, 2 bss)
  Relocations seeded: 2882
  Cross-hunk symbols exported: 371
```

Inspect the extracted hunks and memory types (`CHIP`, `FAST`, `PUBLIC`):
```bash
hunks -m frontier segment list
```
Output:
```text
  hunk0 : hunk0.bin @ $10000 (db: project.db)
  hunk1 : hunk1.bin @ $20000 (db: project.db)
  hunk2 : <bss> @ $30000 (db: project.db)
  hunk3 : hunk3.bin @ $40000 (db: project.db)
  ...
```

#### Step 2: Run 3-Stage Analysis & Check Coverage
```bash
hunks -m frontier analyze
hunks -m frontier status
```

#### Step 3: Audit Suspect Functions & Fix Boundaries Before Emitting
Before emitting `.asm` files, check if any functions fell through into `DATA` or `STRING` cells without a return/jump terminator:
```bash
hunks -m frontier cg --suspect -n 10
```
Sample output:
```text
=== Suspect Cutoff Functions (fallthrough into DATA/STRING) (showing 10) ===
  hunk9:LAB_9_03E44            [+03E44] in:22  out:10    44 insts (  156 B) | SUSPECT:DATA_L@+03EF4
  hunk5:LAB_5_1AA92            [+1AA92] in:20  out:7    159 insts (  470 B) | SUSPECT:DATA_W@+1ABB2
```

Inspect a suspect function with `--code`:
```bash
hunks -m frontier cg hunk9:LAB_9_03E44 --code
```
If `+03EF4` is valid code that was not reached, mark it as `code`; if it is a pointer table or string, mark it explicitly:
```bash
# Mark unreached instructions at hunk9:+03EF4 as code and re-trace:
hunks -m frontier hint code hunk9:+03EF4

# Or mark 8 longword pointers at hunk5:+1ABB2 and follow their code targets:
hunks -m frontier hint pointer hunk5:+1ABB2 8 --follow

# Or mark a null-terminated string at hunk5:+1AC00:
hunks -m frontier hint data hunk5:+1AC00 --string
```

#### Step 4: Emit Modular Assembly & Verify 100% Parity
```bash
hunks -m frontier emit --amiga
vasmm68k_mot -Fhunkexe -kick1hunks -nosym -no-opt -I . -I src -o build/frontier disasm/frontier.asm
python3 scripts/verify_parity.py build/frontier assets/frontier
```
This generates `disasm/frontier.asm`, `src/equates.i`, and `src/frontier/hunk0.asm` .. `src/frontier/hunk12.asm`.

> **Important Workflow Rule:** Once `hunks -m <target> emit --amiga` has generated `src/<target>/*.asm` and you (or a coding agent) start editing `src/<target>/*.asm` directly to add docblocks, inline comments, `equ` constants, local labels, `INCBIN` assets, or module splits, **`src/<target>/*.asm` becomes the sole source of truth**. `hunks emit` enforces a hard overwrite guard and will refuse to overwrite existing `.asm` files unless `--force` is explicitly passed.

---

### Walkthrough 2: Reverse Engineering a Large Codebase with `hunks cg`

Even after `src/<target>/*.asm` becomes the source of truth for editing, `hunks -m <target> cg` remains a fast, read-only structural oracle for navigating a 159,000-line codebase without loading huge `.asm` files into context.

#### 1. Find Hardware & String Anchors (`--anchors`)
Start with routines that touch Amiga custom chips (`$DFFxxx` / CIA) or ASCII strings:
```bash
hunks -m frontier cg --anchors --unrenamed -n 10
```
Output:
```text
=== Hardware & String Anchored Functions (showing 10) ===
  hunk5:LAB_5_2718C            [+2718C] in:66  out:0     13 insts (   72 B) | leaf | HW:COP1LCH
  hunk5:LAB_5_275C2            [+275C2] in:13  out:0     12 insts (   54 B) | HW:INTENA,INTREQ
  hunk5:LAB_5_270DC            [+270DC] in:9   out:0     15 insts (   76 B) | leaf | HW:BLTAFWM,BLTCON0,BLTDPTH,BLTDPTL,BLTSIZE
  hunk3:LAB_3_0005E            [+0005E] in:6   out:0    253 insts ( 1140 B) | leaf | HW:AUD0LCH,AUD1LCH,AUD2LCH,AUD3LCH
```

#### 2. Find High-Impact Leaf Functions (`--leaves`)
Find leaf subroutines (0 outgoing calls) called from many places:
```bash
hunks -m frontier cg -s hunk5 --leaves --unrenamed -n 10
```
Output:
```text
=== Leaf Functions (0 outgoing calls) (showing 10) ===
  hunk5:LAB_5_2A56A            [+2A56A] in:69  out:0      1 insts (    4 B) | leaf
  hunk5:LAB_5_2718C            [+2718C] in:66  out:0     13 insts (   72 B) | leaf | HW:COP1LCH
  hunk5:LAB_5_27DAC            [+27DAC] in:46  out:0     12 insts (   36 B) | leaf
  hunk5:LAB_5_27DA2            [+27DA2] in:45  out:0      2 insts (   10 B) | leaf
  hunk5:LAB_5_2732A            [+2732A] in:27  out:0     16 insts (   50 B) | leaf
```

#### 3. Surgical Inspection of a Function & Its Callers (`cg <TARGET> --code`)
Inspect `hunk3:LAB_3_2649E` (which is called across hunks via the `a5` jump-vector table in `hunk6`):
```bash
hunks -m frontier cg hunk3:LAB_3_2649E --code
```
Output:
```text
=== Incoming Callers (up to depth 2) ===
  ◄── hunk5:LAB_5_2A71A (+2A79E, via jsr 402(a5))
    ◄── hunk5:LAB_5_24BE8 (+24EB8, via jsr 498(a5))
    ◄── hunk6:LAB_6_0020C (+0020C, via jmp)
  ◄── hunk6:LAB_6_001AC (+001AC, via jmp)
  ◄── hunk9:LAB_9_068F8 (+069A2, via jsr 402(a5))

=== Target Function ===
  hunk3:LAB_3_2649E [UNRENAMED] [+2649E] — 15 insts, 56 bytes [XDEF]

=== Outgoing Callees (up to depth 2) ===
  ├──► hunk3:LAB_3_0005E (via jsr | 253 insts, leaf | HW: AUD0LCH,AUD1LCH,AUD2LCH,AUD3LCH)

=== Target Function Disassembly (hunk3:LAB_3_2649E) ===
LAB_3_2649E:
  +2649E  tst.b    10447(a6)
  +264A2  beq.b    LAB_3_264D4
  +264A4  cmpi.b   #$F,d1
  +264A8  bcc.b    LAB_3_264D4
  ...
  +264CC  jsr      LAB_3_0005E.l
  +264D2  rts      

=== Caller Site Snippets ===
  From hunk5:LAB_5_2A71A (+2A79E, via jsr 402(a5)):
     +2A792: move.w   12(a2),d0
     +2A796: moveq    #4,d1
     +2A798: moveq    #64,d2
  >> +2A79E: jsr      402(a5) ; -> hunk3:LAB_3_2649E
     +2A7A2: movem.l  (a7)+,d7/a0-a4
```
Notice how `--code` reveals:
1. `LAB_3_2649E` calls the Paula audio routine `LAB_3_0005E` (`HW: AUD0LCH..AUD3LCH`).
2. Every caller across `hunk5`, `hunk6`, and `hunk9` invokes it via `jsr 402(a5)`.
3. The caller snippet at `+2A79E` shows the exact register arguments (`d0` = pitch/period, `d1` = sound effect ID `< $0F`, `d2` = volume `64`).

#### 4. Edit `src/<target>/*.asm` Directly & Track Bottom-Up Progress
1. Find all references to `LAB_3_2649E` in `src/frontier/`:
   ```bash
   rg -n -w "LAB_3_2649E" src/frontier/
   ```
2. Edit `src/frontier/hunk3.asm` and `src/frontier/hunk6.asm` to rename `LAB_3_2649E` → `Audio_PlaySfx` and add a header docblock preserving `; (orig: LAB_3_2649E)`:
   ```asm
   ; ============================================================================
   ; Audio_PlaySfx (orig: LAB_3_2649E)
   ; Plays sound effect d1.b (0..14) with period d0.w and volume d2.w.
   ; XREF: hunk5:LAB_5_2A740 (jsr 402(a5)), hunk6:LAB_6_0001A (jmp), ...
   ; ============================================================================
   Audio_PlaySfx:	tst.b	10447(a6)
   ```
3. *(Optional)* Mirror the rename in `project.db` so `hunks -m frontier cg` and `hunks -m frontier cg --ready` display `Audio_PlaySfx` in subsequent graph queries:
   ```bash
   hunks -m frontier rename LAB_3_2649E Audio_PlaySfx
   hunks -m frontier cg --ready -n 20
   ```
4. Re-assemble `disasm/frontier.asm` with `vasmm68k_mot` to verify 100% binary parity.

---

### Walkthrough 3: Flat Binary Disassembly & Annotation (*Virus*)

```bash
# 1. Initialize flat binary loaded at $3B800 (target 'disk_1' deduced -> work/disk_1/)
hunks init --binary assets/disk.1 --base 0x3B800

# 2. Seed known entry point and low-RAM BSS region
hunks -m disk_1 entry 0x63EC8 --name main
hunks -m disk_1 map region low_ram 0x0400 0x1000

# 3. Run 3-stage analysis (or `analyze --trace` for self-booting binaries)
hunks -m disk_1 analyze

# 4. Pre-emission annotations in project.db (optional before initial emit)
hunks -m disk_1 rename LAB_606B8 InitInterrupts
hunks -m disk_1 comment main --block "Main game entry point at $63EC8"
hunks -m disk_1 operand main+10 DEC

# 5. Emit disasm/disk_1.asm and verify 100% byte-for-byte identity
hunks -m disk_1 emit
vasmm68k_mot -m68000 -no-opt -Fbin -o build/disk_1.bin disasm/disk_1.asm
cmp -l assets/disk.1 build/disk_1.bin   # 0 differences
```

---

### Walkthrough 4: Bisecting a Blob with `split` and Isolating Assets with `carve`

A trackloaded disk or raw dump arrives as one monolithic blob. As you reverse
the loader and learn where each chunk runs, **`segment split`** cuts named
static-base parts out of it; **`carve`** then isolates embedded assets (music,
gfx, tables) as `incbin` blocks so the disassembly stays readable. See
[ARCHITECTURE.md](ARCHITECTURE.md) (Data Model) for the segment/space model.

```bash
# 1. One flat blob at base 0 (module 'disk' deduced -> work/disk/)
hunks init --binary assets/disk.adf --base 0
hunks -m disk analyze                      # reverse the trackloader first

# 2. Learned: blob[0x1600..0x3200] is copied/decompressed to RAM $40000.
#    Split it into its own static part at its true base; it is filed into the
#    active space and gets its own tl_main.bin in the shared DB.
hunks -m disk segment split main --at 0x1600 --len 0x1C00 --base 0x40000 --name tl_main
hunks -m disk analyze                      # tl_main now disassembles at $40000;
                                           # cross-part jsr/lea resolve via the unified DB

# 3. Isolate an embedded music module as an incbin block (emit policy only;
#    the bytes stay in place, label + xrefs are preserved).
hunks -m disk carve 0x40120 --len 0x1B00 --name MusicModule
#   -> on emit, writes assets/MusicModule.bin and emits `incbin "assets/MusicModule.bin"`

# 4. Changed your mind? Reversible; reclassify afterwards.
hunks -m disk uncarve 0x40120
hunks -m disk analyze
```

**Parity guard.** In a *relocatable* hunk-exe segment, `carve` refuses a range
that contains a relocation site (freezing a relocatable pointer to raw bytes
would break the rebuild) and requires even start/length — so load-image parity
is preserved by construction. In a *flat/static* part (never reassembled) the
guard does not apply and you may carve freely.

---

### Walkthrough 5: Interactive TUI Recipes (`hunks tui`)

Launch the TUI on a target:
```bash
hunks -m frontier tui
```

#### Recipe A: Tracing Cross-Hunk & Jump-Vector Calls
1. Press `S` to open the **Segments** popup, select `hunk5`, and press `Enter`.
2. Press `g`, type `+2503E` (or `hunk5:LAB_5_25036`), and press `Enter`.
3. Cursor lands on:
   ```text
   +2503E                  jsr   498(a5)  ; → hunk5:LAB_5_2A71A
   ```
4. Press `Enter` on that line: the TUI resolves `498(a5)` through the `hunk6` vector table and jumps directly to `LAB_5_2A71A` (`+2A71A`).
5. Press `x` on `LAB_5_2A71A`: the **XREFs** popup opens listing every direct and `jsr 498(a5)` caller across `hunk5`, `hunk6`, `hunk8`, and `hunk9`:
   ```text
   hunk5 +24EB8 VEC_CALL     (in LAB_5_24E84)  jsr 498(a5)
   hunk5 +2503E VEC_CALL     (in LAB_5_25036)  jsr 498(a5)
   hunk6 +0020C CODE_BRANCH  (in LAB_6_0001A)  jmp LAB_5_2A71A.l
   hunk8 +007EE VEC_CALL     (in LAB_8_007EA)  jsr 498(a5)
   ```
6. Select any caller and press `Enter` to jump to it (automatically switching segments if in another hunk), or press `Backspace` / `-` to return.

#### Recipe B: Splitting a Mid-Row String or Table on a Data Row
1. Move the cursor to any `DATA` (`dc.b` / `dc.w` / `dc.l`) row in the full-width Sub-Row Code View.
2. Use `←` and `→` (`left` / `right`) to move the highlighted `[XX]` / `[c]` byte cursor to the exact starting byte inside the row.
3. Press `s` to mark a null-terminated `STRING` starting at that exact byte (or `v` to start a range selection, move with `j`/`k`/`→`, and press `w` to mark a word table). The analyzer automatically splits the preceding bytes into clean `DATA_B` cells so alignment is preserved.

#### Recipe C: Defining a Struct & Register Alias
1. Press `t` to open the **Structs** modal.
2. Press `n`, type `ShipObj`, and press `Enter`.
3. Select `ShipObj` and press `Enter` to edit its fields.
4. Press `a`, enter offset `90`, press `Enter`, type `so_Type`, and press `Enter`.
5. Press `Esc` twice to return to the disassembly view.
6. Press `a` to open **Register Aliases** (`d` deletes an alias) or configure `"register_aliases": {"a0": "ShipObj"}` in `project.json` so `90(a0)` renders symbolically as `so_Type(a0)`.

---

## Emitted Assembly Format & Conventions

### 1. Compilable Hunk-Offset Labels (`LAB_<hunk>_<offset>`)
In multi-hunk mode, every auto-generated label embeds its hunk index and 5-digit hex hunk-relative offset:
- `LAB_0_00000` (`src/hunk0.asm`, offset `+$00000`)
- `LAB_3_2649E` (`src/hunk3.asm`, offset `+$2649E`)
- `LAB_5_24BE8` (`src/hunk5.asm`, offset `+$24BE8`)

This guarantees zero symbol collisions across hunks (even when two hunks have labels at the exact same local offset `+$00000`) while remaining 100% valid `vasmm68k_mot` identifiers. In flat-binary mode, labels use `LAB_{addr:05X}`.

### 2. Source-Linkable `; XREF:` Comments
Emitted `; XREF:` comments above labels list the **enclosing caller label** and **instruction mnemonic** (deduplicated and wrapped at 4 callers per line), never synthetic memory addresses:
- **Same-hunk reference:** `; XREF: LAB_0_00000 (beq.b), LAB_0_00046 (bsr.b)`
- **Cross-hunk reference:** `; XREF: hunk5:LAB_5_27772 (addi.l)`
- **Jump-vector reference:** `; XREF: hunk5:LAB_5_24E84 (jsr 498(a5)), hunk6:LAB_6_0001A (jmp)`

Every caller listed in `; XREF:` can be jumped to immediately in `src/hunk*.asm` via `rg "^<label>:"`.

### 3. Cross-Hunk & Jump-Vector Target Hints
Instructions that jump/call across hunks or through a register jump-vector table automatically receive a trailing target comment:
```asm
	jmp	LAB_5_2810E.l	; -> hunk5
	jsr	414(a5)	; -> hunk3:LAB_3_26432
```

---

## Interactive TUI Reference (`hunks tui`)

### Layout

```
┌─ Space: default │ Segment: hunk5 (CODE, 184.2 KB) ───────────────────────────┐
│ [?]Help  [S]Segments  [f]Funcs  [x]XRefs  [/]Search  [m]MemMap  ...          │
├──────────────────────────────────────────────────────────────────────────────┤
│  +2503E  4EAD 01F2               jsr     498(a5)       ; -> hunk5:LAB_5_2A71A↑│
│  +25042  301F                    move.w  (a7)+,d0                            █│
│  +25044  1E29 005D               move.b  93(a1),d7                           ║│
│  +25048  ; XREF: LAB_5_24E84+1C(J), LAB_5_25010+08(J)                        ║│
│  +25048  LAB_5_25048:                                                        ║│
│  +25048  2F09                    move.l  a1,-(a7)                            ║│
│  +25050  dc.b [46] 72 6F 6E 74 69 65 72 00 00 ...  │[F]rontier..│            ↓│
├──────────────────────────────────────────────────────────────────────────────┤
│ +2503E │ CODE (4B) │ -- cyc │ fn: LAB_5_25036+08 │ XREFs: 2 │ 99%            │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Navigation Keys

| Key | Action |
|-----|--------|
| `j` / `↓` | Move cursor down |
| `k` / `↑` | Move cursor up |
| `←` / `→` | Move byte cursor on `DATA` rows (`[XX]` / `[c]`) or cycle caller badges on `; XREF:` sub-rows |
| `Ctrl-d` / `Ctrl-u` | Half-page down / up |
| `PageDown` / `PageUp` | Full-page down / up |
| `Home` / `End` | Jump to top / bottom of segment |
| `Enter` | Follow reference under cursor (local branch, cross-hunk relocation, `→ <seg>:<label>` vector target, or selected `; XREF:` badge) |
| `Backspace` / `-` | Navigate back in history stack (up to 100 entries across segments) |
| `g` | Goto (`<seg>:<label>`, `<seg>:+<offset>`, `<label>`, `+offset`, or hex address) |
| `/` | Prefix-scoped search (`[seg:]addr` / `[seg:]label` navigation, or `m:`/`o:`/`s:`/`c:`/`b:`/`l:`/`cluster:` with optional `seg/` or `all/` scope, e.g. `m:jsr`, `s:hunk3/disk`, `cluster:blitter`) |
| `f` | Function list popup (shows `<seg> +<offset>  <name>`, type to filter, `Enter` to jump) |
| `x` | XREFs popup to current address (shows `<seg> +<offset>  <type>  (in <caller_label>)  <mnem> <ops>`, `Enter` to jump) |

### Type Marking & Selection Keys

| Key | Action |
|-----|--------|
| `v` | Toggle range selection (`Esc` cancels active selection) |
| `c` | Mark cursor (or selection) as `CODE` (`confidence = 100`) and run incremental analysis |
| `b` | Mark as `DATA_B` (1 byte) |
| `w` | Mark as `DATA_W` (2 bytes) |
| `l` | Mark as `DATA_L` (4 bytes) |
| `p` | Mark as `POINTER` (4-byte address, resolves target label) |
| `P` | Mark pointer table (prompts for entry count) |
| `s` | Mark as null-terminated ASCII `STRING` |
| `K` | Carve v-selection into an `incbin` block (prompts for a label name and jumps cursor to the carve start); with no selection, uncarve the carved range at the cursor (undoable via `Ctrl-z`). Refuses interior relocations in relocatable segments |
| `u` | Undefine cell(s) (revert to raw unmapped bytes) |

### Annotation Keys

| Key | Action |
|-----|--------|
| `n` | Rename label at cursor (propagates across all segments) |
| `;` | Edit inline comment at cursor (on `STRING` rows, opens the block comment editor so comments appear cleanly above `dc.b "...",0`) |
| `:` | Edit block comment (emitted on its own `; ...` line(s) above the instruction/label/string) |
| `#` | Cycle operand format (`HEX` → `DEC` → `BIN`) |

### Project & Tool Keys

| Key | Action |
|-----|--------|
| `e` | Export assembly file (`src/<target>/hunk*.asm` for relocatable hunks, or `disasm/<target>.asm` for flat binaries) |
| `r` | Re-run full 3-stage analysis across the project |
| `S` | Segment manager (`Enter` to switch segment, `I` to add segment, `d` to delete) |
| `I` | Add segment (interactive file browser → segment metadata form) |
| `Ctrl-s` | Space switcher (`Enter` to switch active space, `d` to delete) |
| `m` | Memory map region editor (`d` to delete region) |
| `t` | Struct editor (`n` = new struct, `Enter` = edit struct fields, `a` = add field, `d` = delete, `Esc` = back) |
| `a` | Register alias editor (maps a base register to a struct for automatic `d16(An)` field substitution) |
| `Ctrl-z` | Undo last edit (type-marking, carve/uncarve, rename, inline/block comment) |
| `B` | Open interactive Bitplane Image Viewer at cursor address |
| `M` | *(Experimental)* Open interactive Music Module Ripper (scan, browse, jump, rip, carve) |
| `?` | Help popup |
| `q` | Quit |

### Interactive Bitplane Image Viewer (`B`)

Pressing `B` in the Disassembly view opens the integrated, keyboard-driven Bitplane Image Viewer directly inside the terminal. It renders true high-resolution Amiga bitmaps using modern terminal pixel graphics (Kitty Graphics Protocol, iTerm2 inline images, or Sixel) with zero-dependency Unicode Half-Block (`▀`) fallback.

The viewer manages a single image at a time with up to 7 bitplanes (including AGA / special test mode). The status panel displays the exact Amiga custom chipset registers and human-readable geometry:
- **Top Border**: Base cursor address, display window (`DIW: 320×200`), data fetch/buffer stride (`DDF: 384 px (48 B)`), integer zoom factor, and pixel graphics protocol. If the buffer in RAM is wider than the native visible window (320 in Lores, 640 in Hires), the viewer automatically cuts the extra margin so the visible window displays distortion-free.
- **Register Statusline**: `BPLCON0` raw hex word, `BPL1MOD` & `BPL2MOD` line modulos (accounting for contiguous buffer cuts and interleaved multi-plane strides), and active bitplane starting pointers (`BPLxPT: 1:$04000 2:$05F40 ...`).
- **Indicators Statusline**:
  1. **`BPU:        1  2  3  4  5  6  7`**: Sequential active bitplane count in `BPLCON0` (bits 14–12). Digits $1..BPU$ are highlighted in bright cyan (`#7AA2F7 bold`); inactive digits in legible slate gray (`#65728A`).
  2. **`Synced:     1  2  3  4  5  6  7`**: Independent pointer adjustment group (`BPL1PT`–`BPL7PT`). Armed numbers are rendered in bright warm gold (`#E0AF68 bold`); unarmed numbers in legible slate gray (`#65728A`).
  3. **`Pal`**: Active color mode and live truecolor RGB swatches.

The viewer queries the terminal text area pixel dimensions at startup via the cross-platform `XTWINOPS` escape sequence (`\x1b[14t` $\rightarrow$ `\x1b[4;<height>;<width>t`) to automatically select the optimal integer scaling factor ($1\times..8\times$) and clip oversized bitmaps to the canvas, ensuring native Amiga bitmaps (320×200, 320×256, 640×512) fit cleanly with crisp, square device pixels on Linux, macOS, and Windows.

| Key | Action |
|-----|--------|
| `←` / `→` | Adjust bitmap width by $\mp 1$ word ($\mp 16$ px / $\mp 2$ bytes) |
| `a` / `d` | Adjust bitmap width by $\mp 1$ byte ($\mp 8$ px) |
| `A` / `D` | Adjust bitmap width by $\mp 16$ bytes ($\mp 128$ px) |
| `s` / `S` | Adjust scanline height by $\mp 1$ line |
| `h` / `H` | Adjust scanline height by $\mp 8$ lines |
| `g` | Direct geometry input dialog (e.g. `320x200` or `320x200x4`) |
| `+` / `-` | Increase / decrease active bitplane depth ($BPU = 1..7$) |
| `1`–`7` | Toggle bitplane $N$ in **Synced Selection** (arm/disarm pointer for stepping) |
| `0` / `Space` | Toggle all active planes armed vs. plane 1 soloed in Synced Selection |
| `!` / `"` / `#` / `¤` (`$`) / `%` / `&` / `/` | Direct depth jump to $BPU$ 1..7 (international/Nordic/US layout friendly; `Shift+1`..`Shift+7`) |
| `)` / `=` / `Shift+0` | Toggle 1 plane ($BPU=1$) vs. full 6 planes ($BPU=6$) |
| `m` / `M` | Adjust scanline row modulo by $\mp 2$ bytes |
| `Tab` | Toggle layout: Contiguous vs. Interleaved scanlines |
| `,` / `.` | Step starting pointers of armed Synced planes by $\mp 1$ word ($\mp 2$ bytes / $\mp 16$ px horizontally) |
| `↑` / `↓` or `l` / `L` | Step starting pointers of armed Synced planes by $\mp 1$ scanline row stride (vertical line scroll) |
| `z` / `x` | Coarse step starting pointers by $\mp 1$ KB ($\mp 1024$ bytes) |
| `u` / `J` | Large step starting pointers by $\mp 32$ KB ($\mp 32768$ bytes) |
| `r` / `R` | Rotate plane assignments cyclically forward / backward |
| `c` | Cycle palette mode: Grayscale $\rightarrow$ High-Contrast $\rightarrow$ Custom |
| `i` | Invert palette colors |
| `b` / `B` | Adjust palette brightness bias ($-4..+4$) |
| `e` | Toggle Hold-And-Modify 6 (HAM6) decoding (when $BPU = 6$) |
| `p` | Prompt for Copper list or raw $\$0RGB$ palette address or `+$offset` in binary |
| `o` / `O` | Zoom out / Zoom in nearest-neighbor integer scaling ($1\times..8\times$) |
| `v` | Cycle terminal graphics protocol (`Kitty` $\rightarrow$ `iTerm2` $\rightarrow$ `Sixel` $\rightarrow$ `Half-Block`) |
| `w` | Export unscaled bitmap as standard PNG to `assets/<seg>_<addr>_<WxHxD>.png` |
| `W` | Export bitmap as standard Commodore Amiga `FORM ILBM` file to `assets/<seg>_<addr>_<WxHxD>.ilbm` |
| `K` | Carve bitplane byte range as `incbin` Virtual Segment (prompts for `gfx_<W>x<H>x<BPU>[i][h][ham]` label, writes `; Bitmap:` / `; Span:` / `; Regs:` / `; Planes:` / `; Pal:` block comment above the label; round-trips geometry, modulo, `VIS`/`SYNC` masks, plane pointers, and palette/invert/bias on `B`; flat binaries only; undoable via `Ctrl-z`) |
| `Esc` / `q` | Close viewer and return immediately to disassembly listing |

### Interactive Music Module Ripper (`M`) — Experimental

> **Note:** The Music Module Ripper (`M` in TUI and `hunks rip`) is currently **experimental**.

Pressing `M` in the Disassembly view scans the active segment using the zero-dependency recognizer engine (`modules.Scan`) for embedded tracker and sound driver modules across 26 ExoticRipper-derived formats (including ProTracker, SoundTracker 2.6, Old SoundTracker, Future Composer, David Whittaker, Delta Music 1.0, Final Music System, ThePlayer, TFMX, OctaMED, and Jochen Hippel).

If modules are detected, `ModalMusicRipper` displays all found songs and companion regions (e.g. StarTrekker sample banks) with format, variant, offset, and size:

| Key | Action |
|-----|--------|
| `j` / `k` or `↓` / `↑` | Select detected module region |
| `PgUp` / `PgDn` / `Home` / `End` | Page / jump through detected module regions |
| `Enter` | Jump disassembly cursor directly to the module's start address |
| `w` | Rip / export the selected module directly to `assets/<slug>_<offset>.mod` (or `.bin`, keyed on format ID) |
| `K` | Carve module byte range as `incbin` Virtual Segment (prompts for `mod_<slug>_<offset>` label, writes `; Music:` / `; Span:` block comment above the label; flat binaries only; undoable via `Ctrl-z`) |
| `Esc` / `q` | Close ripper and return to disassembly listing |

### Theme Customization (`~/.config/hunks/theme.json`)

The TUI uses a built-in dark truecolor palette out of the box. You can override any subset of token styles in `~/.config/hunks/theme.json` (or via `$HUNKS_THEME`) using `"<fg> [bg:<bg>] [bold] [italic] [reverse]"` specifications:

```json
{
  "bg":     "bg:#16191B",
  "cursor": "#111314 bg:#C8B58A bold",
  "op":     "#D8DEE9 bold",
  "flow":   "#E0AF68 bold",
  "dreg":   "#A3B8CC",
  "areg":   "#88C0D0",
  "imm":    "#D19A66",
  "sub":    "#7FB4CA bold",
  "loc":    "#6A9E7E bold",
  "hw":     "#F7768E bold"
}
```

---

## Project Files & Workspace Layout

| File | Purpose |
|------|---------|
| `work/<target>/project.json` | Target metadata (`target_name`, segments, entry points, spaces, structs, register aliases, memory regions) |
| `work/<target>/project.db` | Target SQLite database (`cells`, `labels`, `relocs`, `xrefs`, `edges`, `renames`, `operand_formats`) |
| `work/<target>/hunk*.bin` | Extracted binary payloads for each `CODE`/`DATA` hunk of `<target>` |
| `disasm/<target>.asm` | Master assembly file (`opt o-,a-` + `include "src/equates.i"` + `include "src/<target>/hunk*.asm"`, or flat binary output) |
| `src/<target>/hunk*.asm` | Modular per-hunk assembly files (`SECTION S_N,code/data/bss[,chip/fast]` + `XDEF` exports) |
| `src/equates.i` | Shared Amiga custom chip (`$DFFxxx`) and CIA (`$BFExxx`/`$BFDxxx`) equates |

### 3-Stage Analysis Pipeline

1. **Stage 1 — Ground-Truth Seeding (`init` / `internal/hunk/parser.go`)**:
   - Extracts all `HUNK_CODE`, `HUNK_DATA`, and `HUNK_BSS` segments along with `CHIP`/`FAST`/`PUBLIC` memory flags.
   - Seeds every `HUNK_RELOC32` entry into `relocs` (`site_addr -> target_addr`) and creates `LAB_<hunk>_<offset>` labels.
   - Marks cross-hunk relocation targets with `is_exported = 1` (`XDEF`).
2. **Stage 2 — Unified Worklist Code Tracer & Sandbox Gap Sweep (`internal/analyzer/stage2_code.go`, `classify.go`)**:
   - Traces control flow across all `CODE` segments from entry points, relocation targets, and vector tables (`BSR`, `JSR`, `BRA`, `JMP`, `Bcc`, `DBcc`, and PC-relative jump tables).
   - Evaluates unmapped gaps in `CODE` segments using strict M68000 hardware invariants (valid 68000 opcode, valid brief extension word `(ext & $0700) == 0`, high-byte zero on `.b` immediates, no interior relocation overlap, valid control-flow termination).
3. **Stage 3 — Label/Relocation-Bounded Data Classification & Formatting (`internal/analyzer/stage3_data.go`, `format.go`, `internal/emitter/emitter.go`)**:
   - Classifies remaining intervals into `POINTER`, `STRING`, `DATA_ZERO`, and `DATA_L`/`DATA_W`/`DATA_B` without crossing label or relocation boundaries.
   - Formats operands as symbolic labels in Hunk Mode **if and only if** the operand's extension-word address is recorded in `relocs`.
   - Generates source-linkable `; XREF:` caller comments and `; -> <segment>` / `; -> <segment>:<label>` target hints.
