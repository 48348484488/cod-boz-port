#!/usr/bin/env python3
"""Resolve ARM PLT thunk symbols directly from an uncompressed Marmalade S3E.

Uses the XE3U fixup/symbol records; never guesses a function name based on
machine code. No game data is embedded in this public tool.
"""
from __future__ import annotations

import argparse
import pathlib
import struct


def u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def read_symbols_and_relocs(data: bytes) -> tuple[list[str], dict[int, int], int, int]:
    if len(data) < 68 or data[:4] != b"XE3U":
        raise ValueError("Expected an unpacked XE3U S3E")
    start, size, code, code_size = (
        u32(data, 12), u32(data, 16), u32(data, 20), u32(data, 24)
    )
    if start > len(data) or size > len(data)-start:
        raise ValueError("Invalid fixup table bounds")
    if code > len(data) or code_size > len(data)-code:
        raise ValueError("Invalid code-section bounds")
    symbols: list[str] = []
    relocs: dict[int, int] = {}
    pos = start
    while pos < start+size:
        if start+size-pos < 8:
            raise ValueError("Truncated fixup record")
        kind, record_size = struct.unpack_from("<II", data, pos)
        if record_size < 8 or record_size > start+size-pos:
            raise ValueError("Invalid fixup record size")
        body = pos+8
        if kind == 0:
            if record_size < 10:
                raise ValueError("Truncated symbol table")
            count = u16(data,body)
            cursor = body+2
            values = []
            for _ in range(count):
                end = data.find(b"\0", cursor, pos+record_size)
                if end < 0:
                    raise ValueError("Unterminated symbol name")
                values.append(data[cursor:end].decode("utf-8", "replace"))
                cursor = end+1
            symbols = values
        elif kind in (2,3,4):
            if record_size < 12:
                raise ValueError("Truncated external relocation")
            count = u32(data,body)
            if 6*count > record_size-12:
                raise ValueError("Invalid relocation count")
            for index in range(count):
                high,low,symbol_index = struct.unpack_from(
                    "<HHH",data,body+4+6*index
                )
                relocs[(high<<16)|low] = symbol_index
        pos += record_size
    return symbols,relocs,code,code_size


def arm_immediate(instr: int) -> int:
    raw=instr & 255
    rotation=((instr>>8)&15)*2
    return ((raw>>rotation)|(raw<<(32-rotation))) & 0xffffffff if rotation else raw


def resolve_plt(data: bytes, plt_offset: int) -> dict:
    symbols, relocs, code, size = read_symbols_and_relocs(data)
    if plt_offset < 0 or plt_offset+12 > size or plt_offset%4:
        raise ValueError("Invalid ARM PLT offset")
    a,b,c=struct.unpack_from("<III",data,code+plt_offset)
    if ((a & 0xfffff000) != 0xe28fc000 or
        (b & 0xfffff000) != 0xe28cc000 or
        (c & 0xfffff000) != 0xe5bcf000):
        raise ValueError("Expected three-instruction ARM PLT thunk")
    slot=plt_offset+8+arm_immediate(a)+arm_immediate(b)+(c&0xfff)
    idx=relocs.get(slot)
    if idx is None or idx >= len(symbols):
        raise ValueError("Missing or invalid external relocation for PLT slot")
    return {"plt_offset":hex(plt_offset),"got_slot":hex(slot),
            "symbol":symbols[idx],"symbol_index":idx}


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image",type=pathlib.Path)
    parser.add_argument("--plt",type=lambda s:int(s,0),required=True)
    args=parser.parse_args()
    data=args.image.read_bytes()
    try:
        result=resolve_plt(data,args.plt)
    except (ValueError,struct.error) as exc:
        parser.exit(1,f"PLT resolution failed: {exc}\n")
    print(f"{result['plt_offset']} -> {result['symbol']} "
          f"(GOT {result['got_slot']})")


if __name__ == "__main__":
    main()
