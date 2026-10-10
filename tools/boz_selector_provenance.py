#!/usr/bin/env python3
"""Correlate BOZ's stack selector from DB2FA to D8F0E.

Only verified chronological trace observations are reported. Pointer identity
within one run is not proof of semantic type or of earlier registration.
"""
from __future__ import annotations

import json
import re
import sys

PROBE = re.compile(r"\[TREE_PROBE\].*?\boff=0*([0-9a-fA-F]+)\b", re.I)
VALUE = re.compile(r"\b(r0|r2|sp0|sp28)=([0-9a-fA-F]{8})\b", re.I)
IO_EVENT = re.compile(
    r"\[S3E_FILE_RW\]\s+op=(read|write)\s+buffer=([0-9a-fA-F]{8})"
    r"\s+file=([0-9a-fA-F]{8})\s+elem=(\d+)\s+count=(\d+)"
    r"\s+result=(\d+)\s+before=(-?\d+)\s+after=(-?\d+)"
    r"\s+(?:eof=(\d+)\s+)?error=(\d+)"
)
TARGETS = {
    0xDB2FA: "key_helper_before_blx",
    0xDB2FE: "key_helper_after_blx",
    0xDB306: "stack_key_before_load",
    0xDB31C: "dispatch_with_fifth_arg",
    0xDA728: "owner_fallback_call",
    0xD8F0E: "registry_lookup_entry",
    0xD8F36: "registry_lookup_candidate",
    0xD8F44: "registry_not_found",
}


def parse_trace(raw: str) -> list[dict]:
    out = []
    for index, line in enumerate(raw.splitlines()):
        off_match = PROBE.search(line)
        if not off_match:
            continue
        off = int(off_match.group(1), 16)
        if off not in TARGETS:
            continue
        fields = {key: int(value, 16) for key, value in VALUE.findall(line)}
        out.append({"index": index, "off": off, "label": TARGETS[off], **fields})
    return out


def summarize(raw: str) -> dict:
    events = parse_trace(raw)
    def site(off: int) -> list[dict]:
        return [e for e in events if e["off"] == off]

    def last(off: int) -> dict | None:
        samples = site(off)
        return samples[-1] if samples else None

    before = last(0xDB2FA)
    after = last(0xDB2FE)
    loaded = last(0xDB306)
    dispatch = last(0xDB31C)
    fallback = last(0xDA728)
    lookup = last(0xD8F0E)

    observations = {}
    for name, event, reg in [
        ("helper_stack_before", before, "sp28"),
        ("helper_stack_after", after, "sp28"),
        ("key_in_stack_local", loaded, "sp28"),
        ("fifth_arg_at_dispatch", dispatch, "sp0"),
        ("key_at_owner_fallback", fallback, "r2"),
        ("key_at_registry_lookup", lookup, "r2"),
    ]:
        value = None if event is None else event.get(reg)
        observations[name] = None if value is None else f"0x{value:08x}"

    chain = [
        observations["key_in_stack_local"],
        observations["fifth_arg_at_dispatch"],
        observations["key_at_owner_fallback"],
        observations["key_at_registry_lookup"],
    ]
    observed = [v for v in chain if v is not None]
    in_order = (
        loaded is not None and dispatch is not None
        and fallback is not None and lookup is not None
        and loaded["index"] < dispatch["index"] < fallback["index"] < lookup["index"]
    )
    helper_dest = None if before is None else before.get("r0")
    stream_io = []
    for match in IO_EVENT.finditer(raw):
        (operation, buffer, file_handle, elem_size, count, result,
         position_before, position_after, eof, error) = match.groups()
        buffer_addr = int(buffer, 16)
        if helper_dest is not None and buffer_addr == helper_dest:
            stream_io.append({
                "op": operation, "buffer": f"0x{buffer_addr:08x}",
                "file": f"0x{int(file_handle,16):08x}",
                "element_size": int(elem_size), "count": int(count),
                "result": int(result), "before": int(position_before),
                "after": int(position_after),
                "eof": None if eof is None else int(eof),
                "error": int(error),
            })

    return {
        "events": events,
        "observations": observations,
        "helper_destination": None if helper_dest is None else f"0x{helper_dest:08x}",
        "matching_io_calls": stream_io,
        "matching_failed_io_calls": sum(
            item["result"] < item["count"] for item in stream_io
        ),
        "chronological_chain_complete": in_order and len(observed) == 4,
        "key_value_preserved_across_observed_chain": (
            in_order and len(observed) == 4 and len(set(observed)) == 1
        ),
        "registry_lookup_miss_observed": bool(site(0xD8F44)),
        "key_helper_return_r0": (
            None if after is None or "r0" not in after
            else f"0x{after['r0']:08x}"
        ),
        "note": "Pre-instruction registers and stack values only; no mutation, "
                "no inferred source-level identity, and no claim about registration.",
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: boz_selector_provenance.py TRACE_LOG")
    from pathlib import Path
    print(json.dumps(summarize(
        Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
    ), indent=2))
