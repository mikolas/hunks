# AGENTS.md — hunks development guidelines

Context and working rules for anyone (human or agent) developing `hunks`. Keep
this neutral and current; it describes how the codebase is built and the
invariants that must hold.

## What hunks is

A terminal-native Motorola 68000 disassembler, static call-graph analyzer,
trace-seeded Amiga chipset analyzer, music module scanner, and interactive TUI
for Amiga executables and flat binaries, producing modular, byte-for-byte
re-assemblable `vasmm68k_mot` output. Pure Go (`go 1.27`, zero CGo), module
`github.com/mikolas/hunks` at the repo root. See [README.md](README.md),
[MANUAL.md](MANUAL.md), [ARCHITECTURE.md](ARCHITECTURE.md),
[TESTING.md](TESTING.md).

## Layout

```
cmd/
  hunks/main.go        CLI (cobra) dispatch
internal/
  project/             Project / Segment / Space model, project.json
  hunk/                AmigaOS HUNK_* parsing + synthetic base assignment
  m68k/                zero-allocation M68000 decoder, formatter & cycle timing
  analyzer/            analyzer.go (pipeline), stage2_code.go, stage3_data.go,
                       stage4_funcmeta.go, classify.go, format.go, baseregs.go,
                       trace.go, chipset.go
  emitter/             modular .asm emission + source-linkable XREFs
  callgraph/           static call graph (cg)
  modules/             26 ExoticRipper music recognizers + m68kemu sandbox
  db/                  controller.go (Controller + DTOs), types.go (domain enums)
  amiga/               hardware equates / vectors
  tui/                 Bubble Tea + 2D screenBuffer TUI (app, listing, keys,
                       actions, nav, render, theme, popups, types)
```

Core model: a project owns a flat pool of `Segment`s; a `Space` is a named,
ordered selection forming one address space (`SegmentAtAddr` resolves overlap
last-listed-wins). Analysis facts live in SQLite (`project.db`); structural
config lives in `project.json`.

## Build, test, verify

```bash
go build ./...
go vet ./...                # must be 0 warnings
go test -v ./...            # all synthetic unit tests pass
go install ./cmd/hunks      # install the CLI
```

Unit tests are self-contained (in-memory SQLite + synthetic bytes) — no external
assets, no network. `hunks` ships **no game binaries**; integration/parity
procedures in [TESTING.md](TESTING.md) use user-supplied binaries.

## Hard invariants (do not violate)

1. **Load-image parity.** Emitted `.asm` must reassemble byte-for-byte: code+data
   payload identical and the relocation SET order-independent (on-disk
   `HUNK_RELOC32` offset *ordering* is a vasm artifact, not a failure). Verify
   with `vasmm68k_mot` + `scripts/verify_parity.py` before claiming a change is
   safe. Any change touching analysis or emission must preserve parity on the
   reference targets.
2. **SQL lives only in `internal/db/`.** All SQL is behind typed `db.Controller`
   methods. Engine packages (`internal/analyzer`, `internal/emitter`,
   `internal/callgraph`, `internal/project`, `cmd/hunks`) must contain **no raw
   SQL** (`db.Query` / `db.Exec`) outside tests. Add a typed method on
   `db.Controller` instead of inlining SQL.
3. **Kind strings are typed enums.** `CellType` / `EdgeKind` / `XrefKind` /
   `LabelKind` live in `internal/db/types.go`; the string↔enum mapping (`AsStr` /
   `Parse*`) exists **only there**. Never compare or construct kind strings by
   hand elsewhere — use the typed enum. The TEXT values are a schema contract;
   changing one is a migration, not an edit.
4. **`emit` is one-way and never clobbers edited `.asm`.** After initial
   emission, `src/<module>/*.asm` (and flat `.s`/`.asm` outputs) is the source
   of truth. Both CLI `emit` and TUI `ExportASM` refuse to overwrite existing
   `.asm` files without `--force`. Never run `emit --force` over hand-edited asm.
5. **Every edit is reversible, atomic, and recorded.** Operations (hints,
   carve/uncarve, split, rename) do not destroy source bytes and provide an
   inverse where the user can expect one. Multi-step DB mutations must use
   `ctrl.WithTransaction` so errors roll back cleanly, and `project.json` must
   only be saved after the DB transaction succeeds.
6. **No copyrighted binaries in the repo.** `assets/`, `work/`, and `testdata/*`
   (except `testdata/README.md`) are gitignored. Do not commit game/commercial
   binaries; `*_test.go` files must never reference local copyrighted assets.
7. **Do not modify `jenska`'s upstream repository** (`github.com/jenska/m68kemu`).
   Wrap or post-process in `internal/` if custom bus behavior is needed.

## Coding standards

- **Zero warnings.** `go build ./...` and `go vet ./...` must be completely
  clean before any change is considered done.
- **Errors, not panics, in production paths.** Return `error` with clean
  messages for user-facing failures (e.g. unknown module, segment-less project).
  Cobra `RunE` handlers must return a non-nil `error` on failure (never print an
  error to stdout and `return nil`, and never silently ignore `analyzer.New`
  errors in `hint`/`rename`/`operand`).
- **DB lifecycle and transactions.** Always `defer ctrl.Close()` immediately
  after `db.New(...)` in CLI handlers, and close any owned per-segment DB handle
  when switching segments in the TUI. Use `ctrl.WithTransaction(func() error)`
  instead of raw `Begin`/`Commit` so error paths always `ROLLBACK`.
- **Fallible row mapping.** Nullable columns scan via `sql.NullString` /
  `sql.NullInt64` and map cleanly to pointer or value fields.
- **Modern Go (`go 1.27`) and shared helpers.** Use stdlib `slices`, `maps`
  (`slices.Sorted(maps.Keys(m))`), `cmp.Compare`, and `encoding/binary.BigEndian`
  rather than ad-hoc sort/search loops. Reuse canonical helpers
  (`project.ParseHex` / `project.ParseUint32`, `analyzer.ApplyCodeHint`,
  `ctrl.DetectJumpVectorBases`, `db.ParseVectoredOperand`) instead of
  duplicating logic across `cmd/hunks`, `internal/tui`, `internal/callgraph`,
  and `internal/analyzer`.
- **Match the surrounding style.** Read neighbouring code first; follow existing
  naming, package boundaries, and patterns rather than introducing new ones.
- **Keep the pipeline unified.** `Analyze` / `AnalyzeIncremental` share one
  `runPipeline`; don't fork analysis logic.
- **Dependencies:** minimal, pure Go (zero CGo). Current direct set:
  `github.com/jenska/m68kemu`, `modernc.org/sqlite`, `github.com/spf13/cobra`,
  `github.com/charmbracelet/bubbletea`, `github.com/mattn/go-runewidth`.

## Labels, addresses, parity-sensitive details

- Auto-labels: `LAB_<hunk>_<offset:05X>` (relocatable) / `LAB_<addr:05X>` (flat).
- A `.l`/immediate operand is symbolic **iff** its extension-word offset is in
  `relocs` — this is how relocation-exact emission stays correct.
- **Base-register `CustomEA` substitution (`internal/analyzer/baseregs.go`):**
  Replacing `disp(aN)` with `<HW_EQUATE>(aN)` (where `<HW_EQUATE>` is
  `target - $DFF000`) is valid **only** when `rv.val == 0xDFF000`. If a program
  loads a sub-offset base (e.g. `lea $DFF002,a4`), the operand must remain
  `disp(aN)` (annotated via comment only) or the assembled displacement will
  drift by `rv.val - $DFF000`.
- **Trace sandbox (`internal/analyzer/trace.go`):** Reset `dev.fault = nil`
  immediately before `cpu.Step()` so pre-step inspection reads cannot poison
  execution, and include Amiga Ranger RAM (`$00C00000`–`$00D7FFFF`) alongside
  custom/CIA/autoconfig ranges in `isTraceMMIO` so startup memory-sizing probes
  do not prematurely abort trace-seeded analysis.
- The analyzer sandbox validates candidate code against M68000 encoding rules
  and reloc non-overlap; instruction *size* must be exact or the recursive
  descent desyncs.

## Documentation discipline

- Docs describe **current reality**. When a feature ships, remove its
  design/plan doc — completed-work docs are dropped, not archived.
- Keep CLI/TUI reference in [MANUAL.md](MANUAL.md) in sync with the real
  Cobra commands/flags and TUI keys.
- Use repo-relative links; never absolute `file:///…` paths in repo markdown.
- The repo contains **only hunks itself** — code plus the docs that describe it
  (README, MANUAL, ARCHITECTURE, TESTING, AGENTS, CODE_OF_CONDUCT). Reverse-engineering
  reference material (Amiga hardware docs, tool manuals, agent skills) is **local
  only** and lives outside the repo.

## Git

- Never work directly on `master`/`main`; use feature branches.
- Never merge directly to `master`/`main`; always open a Pull Request (PR) for review and integration.
- Small, focused commits with a clear subject + rationale body. Conventional
  prefixes in use (`feat`, `fix`, `refactor`, `docs`, `chore`, `style`).
- Do not commit over hand-edited `.asm`, secrets, or copyrighted binaries.
- Confirm before history-rewriting or force-pushing shared branches.

## Workflow for a change

1. Read the relevant code and this file's invariants.
2. Make the change following the standards above.
3. `go build ./...` → `go vet ./...` → `go test ./...`.
4. If analysis/emission was touched: rebuild a reference target and confirm
   load-image parity (`scripts/verify_parity.py`) before declaring done.
5. Commit with a descriptive message; update MANUAL.md if behavior changed.
6. Push feature branch and open a Pull Request against `master` (never merge directly).
