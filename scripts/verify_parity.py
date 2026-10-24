#!/usr/bin/env python3
"""
Load-image parity verifier for AmigaDOS Hunk executables.

Rationale: vasmm68k_mot emits HUNK_RELOC32 offsets sorted ascending, while the
original linker (SAS/C blink / alink) used a different order. The in-memory loaded
image is byte-identical; only the on-disk reloc-table byte ORDER differs. This tool
compares the two files SEMANTICALLY:

  1. Hunk table (count, types, memory flags, advertised alloc sizes)
  2. Per-hunk initialized data payload (HUNK_CODE / HUNK_DATA bytes)
  3. Relocation SET per hunk (as sets of (target_hunk, site_offset, stored_value)),
     order-independent

Exit code 0 => load-image identical (true functional parity).
Exit code 1 => a real difference (code/data/alloc/reloc-set mismatch).

Usage: verify_parity.py <built> <reference>
"""
import struct
import sys

HUNK_HEADER = 0x3F3
HUNK_CODE = 0x3E9
HUNK_DATA = 0x3EA
HUNK_BSS = 0x3EB
HUNK_RELOC32 = 0x3EC
HUNK_DREL32 = 0x3F7
HUNK_SYMBOL = 0x3F0
HUNK_DEBUG = 0x3F1
HUNK_END = 0x3F2
HUNK_NAME = 0x3E8
MASK = 0x3FFFFFFF


class Hunk:
    def __init__(self):
        self.htype = None
        self.mem_flag = 0
        self.alloc_size = 0          # advertised bytes (from header table)
        self.data = b""              # on-disk initialized payload
        self.relocs = []             # list of (target_hunk, [offsets])


def parse(path):
    data = open(path, "rb").read()
    off = [0]

    def rd():
        v = struct.unpack_from(">I", data, off[0])[0]
        off[0] += 4
        return v

    magic = rd()
    if (magic & MASK) != HUNK_HEADER:
        raise ValueError(f"{path}: not a hunk executable (magic {magic:#x})")
    # resident library names
    while True:
        l = rd()
        if l == 0:
            break
        off[0] += l * 4
    table_size = rd()
    first = rd()
    last = rd()
    nhunks = last - first + 1
    hunks = [Hunk() for _ in range(nhunks)]
    for i in range(nhunks):
        raw = rd()
        hunks[i].mem_flag = raw & ~MASK
        hunks[i].alloc_size = (raw & MASK) * 4

    hi = 0
    while off[0] <= len(data) - 4 and hi < nhunks:
        tag = rd() & MASK
        if tag in (HUNK_CODE, HUNK_DATA):
            n = rd() & MASK
            blen = n * 4
            hunks[hi].htype = "CODE" if tag == HUNK_CODE else "DATA"
            hunks[hi].data = data[off[0]:off[0] + blen]
            off[0] += blen
        elif tag == HUNK_BSS:
            rd()
            hunks[hi].htype = "BSS"
            hunks[hi].data = b""
        elif tag in (HUNK_RELOC32, HUNK_DREL32):
            while True:
                cnt = rd()
                if cnt == 0:
                    break
                tgt = rd()
                offs = [rd() for _ in range(cnt)]
                hunks[hi].relocs.append((tgt, offs))
        elif tag == HUNK_SYMBOL:
            while True:
                slen = rd()
                if slen == 0:
                    break
                off[0] += slen * 4
                rd()
        elif tag == HUNK_DEBUG:
            dlen = rd()
            off[0] += dlen * 4
        elif tag == HUNK_NAME:
            slen = rd()
            off[0] += slen * 4
        elif tag == HUNK_END:
            hi += 1
        else:
            raise ValueError(f"{path}: unexpected tag {tag:#x} at {off[0]-4:#x}")
    return hunks


def reloc_set(hunk):
    """Order-independent reloc set: {(target_hunk, offset, stored_longword_value)}."""
    s = set()
    for tgt, offs in hunk.relocs:
        for o in offs:
            val = None
            if o + 4 <= len(hunk.data):
                val = struct.unpack_from(">I", hunk.data, o)[0]
            s.add((tgt, o, val))
    return s


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <built> <reference>")
        return 2
    built_path, ref_path = sys.argv[1], sys.argv[2]
    built = parse(built_path)
    ref = parse(ref_path)

    ok = True
    if len(built) != len(ref):
        print(f"[FAIL] hunk count: built={len(built)} ref={len(ref)}")
        return 1

    for i, (b, r) in enumerate(zip(built, ref)):
        tag = f"hunk{i}"
        if b.htype != r.htype:
            print(f"[FAIL] {tag} type: built={b.htype} ref={r.htype}")
            ok = False
        if b.alloc_size != r.alloc_size:
            print(f"[FAIL] {tag} alloc_size: built={b.alloc_size} ref={r.alloc_size}")
            ok = False
        if b.mem_flag != r.mem_flag:
            print(f"[FAIL] {tag} mem_flag: built={b.mem_flag:#x} ref={r.mem_flag:#x}")
            ok = False
        # Initialized payload must be byte-identical
        if b.data != r.data:
            # locate first differing byte within payload
            n = min(len(b.data), len(r.data))
            first_diff = next((k for k in range(n) if b.data[k] != r.data[k]), n)
            print(f"[FAIL] {tag} payload differs: len built={len(b.data)} ref={len(r.data)} "
                  f"first diff at offset 0x{first_diff:X}")
            ok = False
        # Relocation SET must match (order-independent)
        bs, rs = reloc_set(b), reloc_set(r)
        if bs != rs:
            only_b = bs - rs
            only_r = rs - bs
            print(f"[FAIL] {tag} reloc SET mismatch: built_only={len(only_b)} ref_only={len(only_r)}")
            for x in list(sorted(only_b))[:5]:
                print(f"         built-only: tgt_hunk={x[0]} off=0x{x[1]:X} val={x[2]}")
            for x in list(sorted(only_r))[:5]:
                print(f"         ref-only:   tgt_hunk={x[0]} off=0x{x[1]:X} val={x[2]}")
            ok = False
        else:
            payload_ok = (b.data == r.data)
            print(f"[ OK ] {tag} {b.htype}: payload {'identical' if payload_ok else 'DIFF'}, "
                  f"alloc={b.alloc_size}, relocs={len(bs)} (set-equal)")

    if ok:
        print("=== LOAD-IMAGE PARITY: PASS (code+data+reloc-set identical; "
              "on-disk reloc order may differ, which is a vasm artifact) ===")
        return 0
    print("=== LOAD-IMAGE PARITY: FAIL ===")
    return 1


if __name__ == "__main__":
    sys.exit(main())
