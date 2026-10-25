# Testing Procedure

`hunks` ships **no game binaries** — commercial Amiga software is copyrighted and
is not distributed with this project. The **unit tests are fully self-contained**
(they use in-memory SQLite and synthetic byte buffers, no external files). The
**integration, parity, and TUI procedures below require a binary you supply
yourself** from software you legally own (a dumped AmigaOS hunk executable or a
raw/flat binary).

Throughout, set these to point at *your own* files:

```bash
export HUNK_EXE=/path/to/your/amiga-hunk-executable   # an AmigaOS LoadSeg() exe
export FLAT_BIN=/path/to/your/flat-binary             # a raw/ROM/disk image dump
export FLAT_BASE=0x0                                   # load/run base of FLAT_BIN
```

`vasmm68k_mot` (vasm, Motorola syntax) must be on `PATH` for the parity checks.

---

## 1. Build & Unit Tests (self-contained — no assets needed)

```bash
go build ./...
go vet ./...                    # expect 0 warnings
go test -v ./...                # expect all synthetic unit tests to pass
```

Expected: 0 compiler warnings, 0 `go vet` warnings, and all unit tests across
`internal/{amiga,analyzer,callgraph,db,emitter,hunk,modules,project,tui}` pass
(hunk parser, exported labels, call-graph inference/modes, 3-stage analyzer,
chipset & trace-seeded analysis, synthetic multi-hunk reassembly parity, module
recognizers + sandbox probes, and 2D screenBuffer TUI rendering/actions/undo).
These run with no network and no external binaries.

---

## 2. Multi-Hunk Executable round-trip (user-supplied `$HUNK_EXE`)

```bash
rm -rf /tmp/test_hunk && mkdir -p /tmp/test_hunk/assets
cp "$HUNK_EXE" /tmp/test_hunk/assets/prog
cd /tmp/test_hunk
hunks init --hunk-file assets/prog
hunks -m prog analyze
hunks -m prog emit --amiga
vasmm68k_mot -Fhunkexe -kick1hunks -nosym -no-opt -I . -I src -o build/prog disasm/prog.asm
```

Expected:
- All hunks initialized; relocations seeded; cross-hunk `XDEF` symbols exported.
- `emit --amiga` generates `src/prog/hunk0.asm`.. with `LAB_<hunk>_<offset>`
  labels, source-linkable `; XREF:` caller comments, and `; ->` target hints.
- `vasmm68k_mot` assembles with 0 errors, producing **load-image parity**
  (code+data payload byte-identical; `HUNK_RELOC32` set order-independent).

> Because vasm sorts `HUNK_RELOC32` offsets differently from the original
> linker, a raw `cmp` of two hunk executables reports a spurious difference in
> the reloc table even when the loaded image is identical. Verify semantic
> load-image parity with the bundled tool instead:
>
> ```bash
> python3 scripts/verify_parity.py <built> <reference>
> # e.g. vasmm68k_mot -Fhunkexe -kick1hunks -nosym -no-opt -I . -I src \
> #        -o build_frontier disasm/frontier.asm
> #      python3 scripts/verify_parity.py build_frontier assets/frontier
> ```
>
> It compares the hunk table, per-hunk payload bytes, and the relocation **set**
> (order-independent), exiting 0 only on true load-image parity. For flat
> binaries, a plain `cmp` suffices.

---

## 3. Call Graph CLI (`hunks cg`, uses the project from §2)

```bash
cd /tmp/test_hunk
hunks -m prog cg
hunks -m prog cg --anchors --unrenamed -n 10
hunks -m prog cg --leaves --unrenamed -n 10
hunks -m prog cg --suspect -n 10
hunks -m prog cg <seg>:<label> --code
```

Expected: functions/callers formatted as `<segment>:<label>` with hunk-relative
offsets (`[+2649E]`); `--code` resolves indirect `jsr d16(a5)` jump-vector
callers across segments with context snippets.

---

## 4. Flat Binary round-trip (user-supplied `$FLAT_BIN`)

```bash
rm -rf /tmp/test_flat && mkdir -p /tmp/test_flat/assets
cp "$FLAT_BIN" /tmp/test_flat/assets/blob
cd /tmp/test_flat
hunks init --binary assets/blob --base "$FLAT_BASE" --output out.s
hunks -m blob entry <entry_hex> --name main      # a known code entry in your blob
hunks -m blob analyze
hunks -m blob emit
vasmm68k_mot -m68000 -no-opt -Fbin -o out.bin out.s
cmp -l assets/blob out.bin
```

Expected: `cmp -l` exits `0` (0 byte differences) once code/data boundaries are
resolved.

---

## 5. Interactive TUI (`hunks tui`, uses the project from §2)

```bash
cd /tmp/test_hunk
hunks -m prog tui
```

Verify:
- Full-width Sub-Row Code View scrolls smoothly (`j`/`k`, `Ctrl-d`/`Ctrl-u`) with
  a vertical scrollbar (`↑`/`█`/`║`/`↓`) on the right border of Disassembly.
- `S` Segments popup; `Enter` switches segment. `Ctrl-s` Spaces.
- `g` jumps to `<seg>:<label>`, `<seg>:+<offset>`, `LAB_<hunk>_<offset>`, `+offset`.
- `/` search; `f` Functions; `x` XREFs (`Enter` jumps to caller).
- `Enter` follows branches, cross-hunk refs (`⇢`), and jump-vector hints; `-`/`Bksp` returns.
- `←`/`→` moves the byte cursor on `DATA` rows or cycles caller badges on `; XREF` rows; `s`/`b`/`w`/`l`/`p`/`c`/`u` mark cells; `K` carve/uncarve; `Ctrl-z` undo.
- `B` opens the Bitplane Image Viewer (`K` carves as `incbin` with metadata block comment and round-trips on `B`); `M` opens the Music Module Ripper (`Enter` jumps, `w` rips to `assets/`, `K` carves as `incbin`).
- `?` Help; `q` quit.

---

## 6. `segment split` + `carve` / `uncarve` (parity-preserving; uses `$HUNK_EXE` project)

Exercises topology (`split`) and emit policy (`carve`) plus the relocatable
parity guard (see [ARCHITECTURE.md](ARCHITECTURE.md) Data Model).

```bash
cd /tmp/test_hunk      # project from §2

# (a) split: slice a static part out of hunk0 at a fresh base
hunks -m prog segment split hunk0 --at 0x100 --len 0x40 --base 0x80000 --name flatpart
hunks -m prog segment list          # flatpart : flatpart.bin @ $80000

# (b) carve REFUSED: a range containing a relocation site in a relocatable hunk
RELOC=$(python3 -c "import sqlite3; \
  print(hex(sorted(r[0] for r in sqlite3.connect('work/prog/project.db') \
  .execute('SELECT site_addr FROM relocs').fetchall())[0]))")
hunks -m prog carve $RELOC --len 0x8     # EXPECT: non-zero exit, 'refusing to carve: ... relocation site(s)'

# (c) carve ALLOWED: the flat static part carves freely (guard skipped)
hunks -m prog carve 0x80000 --len 0x20 --name FlatCarve

# (d) uncarve is reversible
hunks -m prog uncarve 0x80000
```

Expected:
- (a) `flatpart` listed at `$80000` with its own `flatpart.bin`.
- (b) carve over an interior reloc in a relocatable hunk **exits non-zero** with
  a clean refusal (no panic).
- (c) carve on the flat part succeeds (guard does not apply to non-relocatable parts).
- (d) `uncarve` removes the `INCBIN` cell, label, and block comment from `project.db`.

### Carve byte-neutrality on relocatable hunks
Carve a **reloc-free DATA range**, emit, re-assemble, confirm load-image parity:

```bash
hunks -m prog carve <reloc_free_data_addr> --len 0x10 --name DataBlob
hunks -m prog emit --amiga --force
vasmm68k_mot -Fhunkexe -kick1hunks -nosym -no-opt -I . -I src -o build/prog disasm/prog.asm
# load-image parity (code+data payload + reloc SET) must remain identical
```

Expected: the emitted hunk shows `incbin "assets/DataBlob.bin"` in place of the
inline `dc.b` dump, the sidecar holds the verbatim bytes, and load-image parity
is **PASS** (incbin reassembles byte-for-byte by construction).
