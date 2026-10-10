#!/usr/bin/env python3
"""Quickly find candidate direct ARM BL callers in an uncompressed BOZ XE3U.

Candidates need ISA disassembly confirmation: scanning all aligned 32-bit
words can accidentally interpret data or Thumb byte pairs as ARM BLs.
Never treats matches as established runtime paths without validation.
"""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path


def arm_bl_candidates(image: bytes, target: int) -> list[int]:
    if image[:4] != b"XE3U" or len(image) < 68:
        raise ValueError("Not an uncompressed XE3U image")
    code_start, code_length, code_mem = struct.unpack_from("<III", image, 20)
    if code_start < 68 or code_length > code_mem or code_start + code_length > len(image):
        raise ValueError("Malformed XE3U code section")
    if target < 0 or target >= code_length or target & 3:
        raise ValueError("ARM branch target must be 4-byte aligned in the code section")

    callers = []
    code = memoryview(image)[code_start:code_start + code_length]
    for offset in range(0, code_length - 3, 4):
        word, = struct.unpack_from("<I", code, offset)
        # Standard ARM unconditional? Here cond=AL (1110), B/BL opcode=101,
        # and link bit=1. BLX immediate and indirect calls are separate.
        if (word & 0xff000000) != 0xeb000000:
            continue
        displacement = word & 0xffffff
        if displacement & 0x800000:
            displacement -= 0x1000000
        destination = offset + 8 + 4 * displacement
        if destination == target:
            callers.append(offset)
    return callers


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("s3e", type=Path)
    parser.add_argument("target", type=lambda x: int(x, 0), help="BOZ offset, e.g. 0x301ecc")
    args = parser.parse_args()
    print(json.dumps({
        "target": hex(args.target),
        "candidate_arm_bl_callers": [
            hex(i) for i in arm_bl_candidates(args.s3e.read_bytes(), args.target)
        ],
        "caution": "Confirm each caller is actually ARM code, not Thumb/data",
    }, indent=2))


if __name__ == "__main__":
    main()
