#!/usr/bin/env python3
"""Disassemble a verified window from an unpacked Marmalade XE3U/S3E image.

No game assets are included. Requirements for actual disassembly:
clang (ARM backend) and llvm-objdump. Extraction itself uses Python stdlib.
Example:
    python3 tools/boz_s3e_disasm.py /path/to/boz.s3e.unpacked 0xdb264 0xdb340 --mode thumb
"""
from __future__ import annotations

import argparse
import pathlib
import shutil
import struct
import subprocess
import sys
import tempfile

MAGIC = b"XE3U"
HEADER_SIZE = 68


def read_window(image: bytes, start: int, end: int) -> tuple[bytes, dict]:
    if len(image) < HEADER_SIZE or image[:4] != MAGIC:
        raise ValueError("Expected an uncompressed XE3U/S3E image")
    code_offset, code_length, code_memory = struct.unpack_from("<III", image, 20)
    if code_offset < HEADER_SIZE or code_length > code_memory:
        raise ValueError("Invalid S3E code header")
    if code_length > len(image) - code_offset:
        raise ValueError("S3E code extends beyond file")
    if start < 0 or end <= start or end > code_length:
        raise ValueError("Requested window is outside S3E code range")
    return image[code_offset + start:code_offset + end], {
        "file_offset": code_offset + start,
        "code_offset": code_offset,
        "code_length": code_length,
        "start": start,
        "end": end,
    }


def disassemble(image: bytes, start: int, end: int, mode: str) -> str:
    if mode not in {"arm", "thumb"}:
        raise ValueError("Mode must be arm or thumb")
    if start % (4 if mode == "arm" else 2):
        raise ValueError("Code window must start on an instruction boundary")
    window, _ = read_window(image, start, end)
    clang = shutil.which("clang")
    objdump = shutil.which("llvm-objdump")
    if not clang or not objdump:
        raise RuntimeError("clang and llvm-objdump are required")
    with tempfile.TemporaryDirectory(prefix="boz_disasm_") as temp:
        root = pathlib.Path(temp)
        bin_path = root / "code.bin"
        asm_path = root / "code.s"
        obj_path = root / "code.o"
        bin_path.write_bytes(window)
        asm_path.write_text(
            '.syntax unified\n.' + mode +
            '\n.section .text,"ax",%progbits\n.global block\n'
            '.type block,%function\nblock:\n.incbin "' +
            str(bin_path) + '"\n',
            encoding="utf-8",
        )
        subprocess.run(
            [clang, "-target", "armv7-none-eabi", "-c",
             str(asm_path), "-o", str(obj_path)],
            check=True, capture_output=True, text=True, timeout=30,
        )
        triple = "thumbv7a-none-eabi" if mode == "thumb" else "armv7a-none-eabi"
        result = subprocess.run(
            [objdump, "-d", "--triple=" + triple,
             "--adjust-vma=" + hex(start), str(obj_path)],
            check=True, capture_output=True, text=True, timeout=30,
        )
        return result.stdout


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=pathlib.Path)
    parser.add_argument("start", type=lambda x: int(x, 0))
    parser.add_argument("end", type=lambda x: int(x, 0))
    parser.add_argument("--mode", choices=("thumb", "arm"), default="thumb")
    args = parser.parse_args()
    try:
        sys.stdout.write(disassemble(
            args.image.read_bytes(), args.start, args.end, args.mode
        ))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        parser.exit(1, f"Disassembly failed: {exc}\n")


if __name__ == "__main__":
    main()
