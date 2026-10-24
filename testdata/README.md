# Module recognizer test corpus (LOCAL ONLY — never committed)

This directory holds **real Amiga music modules** used to validate the
recognizers in `internal/modules/`. Real modules are composers' copyrighted works, so
**`testdata/` is gitignored and must never be committed** (same rule as game
binaries and SDK material). Only this `README.md` and the manifest *format* are
tracked — not the module files.

Unit tests in `internal/modules/` stay synthetic (they test bounds arithmetic, the
region model, and rejects, with no external data). The corpus harness here is an
**integration layer**: it runs only when `testdata/` is populated and **skips
cleanly when it is absent**, so a fresh clone and CI still pass.

## Layout

```
testdata/
  README.md                     (tracked)
  expected.tsv                  (your ground-truth manifest — local)
  modules/
    protracker/   *.mod         (M.K. / M!K! / 4CHN)
    noisetracker/ *.mod
    soundtracker/ *.mod         (15-instrument)
    startrekker/  *.mod  *.nt   (FLT4/EXO4; AM companion files alongside)
    futurecomposer/ ...
    hippel/ ...
    tfmx/  mdat.*  smpl.*
    ...
```

## Ground truth: `expected.tsv`

Each line:

```
<relpath>\t<format>\t<start_hex>\t<len_dec>\t<regions>
```

- `relpath`   — path under `testdata/` (e.g. `modules/protracker/song.mod`)
- `format`    — expected `Match.Name` (e.g. `ProTracker`)
- `start_hex` — expected primary-region start offset in the file (e.g. `0`)
- `len_dec`   — expected primary-region length in bytes
- `regions`   — expected region count (1 for single-part; 2 for StarTrekker AM, …)

Lines starting with `#` are comments; blank lines ignored.

## Running

```bash
# with testdata present:
go test -v ./internal/modules/... -run TestCorpusMatchesManifest
# without testdata: the same test logs a skip note and passes.
```
