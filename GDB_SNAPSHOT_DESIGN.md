# Amiberry GDB Snapshot & Trace-Seeded Analysis (`feat/gdb-snapshot`)

## 1. Overview & Motivation

Many Amiga targets (trackloaded games, RNC/ByteKiller/StoneCracker crunched executables, bootblock intros, and multi-stage loaders) only exist in their final, unpacked form in RAM after execution has begun and custom interrupt/Copper handlers are installed.

By connecting to Amiberry's built-in GDB Remote Serial Protocol (RSP) server, `hunks` can:
1. **Snapshot a living Amiga system (`hunks init --gdb [host:port] -m <module>`):**
   - Automatically query Amiberry's physical memory map (`monitor memory-map`), dump all active `"type": "ram"` regions (`CHIP` and `FAST`/`Slow` RAM), capture all 18 CPU registers (`D0–D7`, `A0–A7`, `SR`, `PC`), and read Amiberry's 512-byte saved Custom Chip register snapshot (`$DFF000–$DFF1FF`).
   - Optionally arm a one-shot AmigaDOS process entry trap (`monitor process-break name <name>`) before taking the snapshot.
2. **Seed static & trace-driven analysis with exact runtime state:**
   - Seed `project.json` entry points and labels from live `PC`, active interrupt/trap vectors (`$000064..$0000BC`), stack return addresses (`A7`), base registers (`A0–A6`), and hardware DMA pointers (`COP1LC`, `COP2LC`, `BPL1PT..BPL6PT`, `SPR0PT..SPR7PT`).
   - Preload `RunTrace` (`hunks -m <module> analyze --trace`) and `Chipset` with the exact captured CPU registers, zero-page vectors, and custom chip state (`DMACON`, `INTENA`, `COP1LC`, etc.) instead of cold-booting with zeroed registers.

---

## 2. Amiberry GDB Server Contract

Verified directly against Amiberry's GDB stub implementation (`src/gdb_server.cpp`, `src/gdb_protocol.cpp`, `src/gdb_target.cpp`, `src/gdb_monitor.cpp`, and `src/custom.cpp`):

| Capability | Wire Packet / Command | Amiberry Implementation Details |
|---|---|---|
| **Transport & Attach** | TCP `127.0.0.1:2345` (default) | Loopback only, single client. Accepting a socket calls `debug_gdb_target().interrupt()`, which halts the CPU at the next debugger boundary (`gdb_server.cpp:177`). |
| **Handshake & Halt Wait** | `$QStartNoAckMode#b0` -> `$?#3f` | Commands (`g`, `m`, `qRcmd`) return `E16` while `halted == false` (`gdb_protocol.cpp:165,216`). Sending `?` sets `await_stop = true` and replies `S05` as soon as the CPU reaches the stop boundary (`gdb_protocol.cpp:72-78,147-150`). |
| **Packet Size Limits** | `Session::packet_size = 65536` | Max `m` read length is `packet_size / 2 = 32768` bytes (`0x8000`) because each byte is hex-encoded (`gdb_protocol.cpp:253`). Using `0x4000` (16 KiB) read chunks stays safely within limits. |
| **CPU Registers (`g`)** | `$g#67` | Returns 18 big-endian 32-bit hex values (144 hex chars): `D0..D7` (`0..7`), `A0..A7` (`8..15`), `SR` (`16`), `PC` (`17`) (`gdb_target.cpp:15-24`). |
| **Memory Map (`qRcmd`)** | `qRcmd,` + hex(`"memory-map"`) | Returns hex-encoded JSON (`gdb_monitor.cpp:245-266`): `{"addressing":"physical","truncated":false,"regions":[{"address":0,"size":524288,"type":"ram","chip":true,"name":"Chip memory"}, ...]}`. |
| **AmigaDOS Segments (`qRcmd`)** | `qRcmd,` + hex(`"segments"`) | Returns hex-encoded JSON for the current Exec process (`gdb_monitor.cpp:297-316`): `{"process":...,"name":"...","command":"...","segments":[{"index":0,"address":...,"size":...}]}`. |
| **Process Entry Break (`qRcmd`)** | `qRcmd,` + hex(`"process-break name <NAME>"`) followed by `$c#63` | Arms a one-shot stop at the first instruction of an AmigaDOS process (`gdb_monitor.cpp:328-340`). When the program launches, Amiberry halts at entry and replies `S05`. |
| **Custom Chip Snapshot (`$DFF000–$DFF1FF`)** | `$mdff000,200#5a` | Calls `save_custom(&snapshot_size, snapshot, 1)` (`gdb_target.cpp:57-65`, `custom.cpp:8102-8260`) and returns `snapshot[4 + (addr & 511)]`. Every register offset `$000..$1FF` contains the live saved state, including write-only registers: `DMACON` (`$096`), `INTENA` (`$09A`), `INTREQ` (`$09C`), `ADKCON` (`$09E`), `COP1LC` (`$080`), `COP2LC` (`$084`), `DIWSTRT` (`$08E`), `DIWSTOP` (`$090`), `DDFSTRT` (`$092`), `DDFSTOP` (`$094`), `BPL1PT..BPL8PT` (`$0E0..$0FE`), `BPLCON0` (`$100`), `BPL1MOD`/`BPL2MOD` (`$108`/`$10A`), `SPR0PT..SPR7PT` (`$120..$13E`), and `COLOR00..COLOR31` (`$180..$1BE`, 12-bit `$0RGB`). |
| **Detach & Resume** | `$D#44` | Clears temporary GDB breakpoints/watches and resumes emulation (`gdb_protocol.cpp:152-154`, `gdb_target.cpp:250-273`). |

---

## 3. Architecture & Package Layout

```
cmd/
  hunks/main.go               `init --gdb [host:port] [--process-break <name>] -m <module>`
internal/
  gdb/
    client.go                 Pure-Go GDB RSP client (QStartNoAckMode, ?, g, m, qRcmd, D)
    client_test.go            Loopback mock-Amiberry unit tests covering handshake, chunked RAM reads, qRcmd JSON, and custom chip snapshot
  project/
    project.go                `SnapshotState` in `ProjectData` (`project.json`)
  analyzer/
    analyzer.go               Static entry-point / vector / stack / base-reg / custom-pointer seeding from `SnapshotState`
    trace.go                  Preloading `RunTrace` with live CPU registers, all RAM segments, and `custom.bin` chipset state
    chipset.go                `LoadCustomSnapshot([512]byte)` helper
  tui/
    bitplane.go               Default screen address, geometry, and 32-color palette from `custom.bin` when present
```

### 3.1 `internal/gdb` Client API
Pure Go (`net.Conn`, zero external dependencies):
- `Dial(addr string, timeout time.Duration) (*Client, error)`:
  - Defaults `addr` to `127.0.0.1:2345` if empty or `"default"`.
  - Connects over TCP, sends `$QStartNoAckMode#b0`, sends `$?#3f`, and waits for the `Sxx` stop packet so `halted == true` is guaranteed.
- `(*Client) Detach() error`: sends `$D#44` and closes the connection.
- `(*Client) ReadRegisters() (Registers, error)`:
  - Parses 18 big-endian 32-bit hex words (`D[0..7]`, `A[0..7]`, `SR`, `PC`).
- `(*Client) ReadMemory(addr uint32, length uint32) ([]byte, error)`:
  - Automatically chunks reads into `0x4000` (16 KiB) `m<addr>,<len>` requests.
- `(*Client) ReadCustomSnapshot() ([512]byte, error)`:
  - Reads `$00DFF000..$00DFF1FF` (`mdff000,200`).
- `(*Client) MemoryMap() ([]MemoryRegion, error)`:
  - Sends `qRcmd` `memory-map` and parses the JSON region array (`address`, `size`, `type`, `chip`, `name`), with XML fallback via `qXfer:memory-map:read::`.
- `(*Client) Segments() (*ProcessSegments, error)`:
  - Sends `qRcmd` `segments` (best-effort; returns `nil, nil` if no AmigaDOS process is active).
- `(*Client) WaitProcessBreak(procName string, timeout time.Duration) error`:
  - Sends `qRcmd` `process-break name <procName>`, sends `$c#63`, and waits for `S05` (sending `\x03` + `process-break clear` on timeout/cancellation).

---

## 4. `project.json` Data Model Extensions (`internal/project/project.go`)

Add an optional `Snapshot *SnapshotState` field to `ProjectData` (`"snapshot,omitempty"` in `project.json`, zero impact on existing projects and zero SQLite schema changes):

```go
type SnapshotState struct {
	PC         uint32            `json:"pc"`
	SR         uint16            `json:"sr"`
	D          [8]uint32         `json:"d"`
	A          [8]uint32         `json:"a"`
	CustomFile string            `json:"custom_file,omitempty"` // "custom.bin" (512B $DFF000..$DFF1FF)
	CustomInfo map[string]string `json:"custom_info,omitempty"` // Summary (DMACON, INTENA, COP1LC, BPLCON0, ...)
}
```

### All-RAM Segment Creation on `hunks init --gdb`
1. Queries `monitor memory-map` and selects all regions with `type == "ram"` and `size > 0`:
   - Each RAM region is dumped to `work/<module>/<seg_name>.bin` (e.g. `chip.bin` at `0x0`, `slow.bin` at `0xC00000`, `fast.bin` at `0x200000`).
   - Each region becomes a `project.Segment` (`Kind: SegCode`, `MemType: CHIP` if `region.Chip` else `FAST`, `Relocatable: false`, `Base: region.Address`, `Size: region.Size`) and is added to the `"default"` `Space`.
   - `proj.ActiveSegmentName` is set to the segment containing `Snapshot.PC` (falling back to the first RAM segment).
2. Saves the 512-byte `$DFF000–$DFF1FF` snapshot to `work/<module>/custom.bin` and populates `proj.Data.Snapshot`.

---

## 5. Static & Trace-Seeded Analyzer Integration

### 5.1 Static Seeding on Snapshot (`init --gdb` & `analyze`)
When `proj.Data.Snapshot` is present:
1. **Live `PC` Entry Point:**
   - Seeds an entry point (`Entry_PC`) at `Snapshot.PC & 0x00FFFFFF` (if even and inside a loaded RAM segment).
2. **Active M68k Autovectors & Traps (`$000064..$0000BC`):**
   - Inspects the dumped Chip RAM zero-page at `$000064..$00007C` (`Level1_IRQ`..`Level6_IRQ`) and `$000080..$0000BC` (`Trap0`..`Trap15`).
   - Any vector pointing to a non-zero, even address inside a loaded RAM segment (excluding ROM addresses like `$F8xxxx`/`$FCxxxx`) is added as a named entry point (`Level3_IRQ_Handler`, etc.).
3. **Active Stack Return-Address Discovery (`A7`):**
   - Scans up to 64 words starting at `Snapshot.A[7]` (if inside a loaded RAM segment). If a 32-bit even value `retAddr` lands inside a RAM segment and the 2, 4, or 6 bytes immediately preceding `retAddr` decode as a valid `BSR` or `JSR` instruction, seeds the call target and `retAddr` as code entry points.
4. **Live Base-Register Seeding (`A0–A6`):**
   - Pre-populates `Snapshot.D` and `Snapshot.A` into the entry register context so `Stage2` / `baseregs.go` knows immediately if e.g. `A5 == $00DFF000` or `A4`/`A6` points to a RAM globals block.
5. **Custom Chip DMA Pointers (`custom.bin`):**
   - Extracts `COP1LC` (`+$080`), `COP2LC` (`+$084`), active `BPL1PT..BPL6PT` (`+$0E0..+$0F7`, gated by `BPLCON0` BPU count), and `SPR0PT..SPR7PT` (`+$120..+$13F`).
   - Creates informative labels (`CopperList_1`, `CopperList_2`, `Bitplane_1..N`) when they point to valid even Chip RAM addresses.

### 5.2 Exact Resume State in `RunTrace` (`internal/analyzer/trace.go`)
When `hunks -m <module> analyze --trace` runs on a project with `proj.Data.Snapshot`:
- Instead of synthesizing `stackTop`, zeroing `D0–D7`/`A0–A6`, and overwriting `$0`/`$4` (`trace.go:340-356`):
  1. Loads **all** RAM segments from the space into `traceDevice.mem` (including zero-page `$000000..$0000FF` intact).
  2. Hydrates `traceDevice.chipset` (`LoadCustomSnapshot`) from `custom.bin` (`DMACON`, `INTENA`, `INTREQ`, `COP1LC`, `COP2LC`).
  3. Initializes `m68kemu.CPU` registers directly from `Snapshot.D`, `Snapshot.A`, `Snapshot.SR`, and `Snapshot.PC`.

### 5.3 TUI Bitplane Viewer (`B`) Pre-Population (`internal/tui/bitplane.go`)
When `custom.bin` is present in `work/<module>/`, opening the Bitplane Viewer (`B`) defaults its initial state (`BPL1PT` address, `BPLCON0` plane count / hires / HAM / EHB flags, `BPL1MOD` modulo, and the 32-color `COLOR00..31` palette) from the captured custom chip snapshot.

---

## 6. CLI Surface

```bash
# Connect to Amiberry (defaults to 127.0.0.1:2345), dump all RAM regions + CPU regs + $DFF000..$DFF1FF:
hunks init --gdb -m <module>

# Connect to an explicit host:port:
hunks init --gdb 127.0.0.1:2345 -m <module>

# Arm a one-shot AmigaDOS process entry break, wait until hit, then snapshot:
hunks init --gdb --process-break <process-name> -m <module>
```
