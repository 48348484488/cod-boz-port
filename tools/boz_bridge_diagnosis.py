#!/usr/bin/env python3
"""Analyze BOZ crash-bridge register samples with pre/post-instruction semantics.

Each breakpoint captures registers before the instruction at its offset.
DA79A contains MOV r0,r4; DA79C can confirm that instruction's effect.
Single-shot probes need not capture the invocation responsible for a crash.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

PROBE = re.compile(r"\[TREE_PROBE\].*?\boff=0*([0-9a-fA-F]+)\b", re.I)
REG = re.compile(r"\b(r0|r2|r3|r4|r5|r6|r8)=([0-9a-fA-F]{8})\b", re.I)
SITES = {
    0xDA70E: "primary_result_before_mov",
    0xDA72C: "fallback_result_before_mov",
    0xDA702: "primary_dispatch_after_type_check",
    0xDA71C: "type_selector_comparison",
    0xDA792: "insert_call_before_bl",
    0xDA79A: "owner_before_mov_r0_r4",
    0xDA79C: "owner_after_mov_r0_r4",
    0xD8F0E: "second_registry_entry",
    0xD8F14: "second_registry_loaded",
    0xD8F16: "second_registry_search",
    0xD8F2A: "second_registry_search_done",
    0xD8F36: "second_registry_compare",
    0xD8F38: "second_registry_missing_branch",
    0xD8F3A: "second_registry_handler_found",
    0xD8F40: "second_registry_handler_call",
    0xD8F42: "second_registry_handler_return",
    0xD8F44: "second_registry_not_found",
    0xD8F46: "second_registry_return_zero",
    0xD94E4: "primary_factory_entry",
    0xD94F2: "primary_factory_null_compare",
    0xD94F4: "primary_factory_null_branch",
    0xD95BE: "primary_factory_return_after_mov",
    0xDB31C: "dispatch_before_blx",
    0xDB31E: "null_deref_before_instruction",
}



def is_owner_after_mov_safe(disassembly_rows: list[tuple[int, str]]) -> bool:
    """Accept DA79C only if the preceding DA79A instruction is MOV r0,r4."""
    for index, (off, instruction) in enumerate(disassembly_rows):
        if off != 0xDA79A:
            continue
        return (
            index + 1 < len(disassembly_rows)
            and disassembly_rows[index + 1][0] == 0xDA79C
            and re.search(r"\bmov(?:\.n)?\s+r0,\s*r4\b", instruction.lower()) is not None
        )
    return False



def verify_primary_factory_null_path(disassembly_rows: list[tuple[int, str]]) -> dict:
    """Proof only for the r2==0 branch of D94E4; not full function recovery."""
    rows = {off: instruction.lower() for off, instruction in disassembly_rows}
    requirements = {
        0xD94EE: r"\bmov\s+r4,\s*r2\b",
        0xD94F2: r"\bcmp\s+r2,\s*#0\b",
        0xD94F4: r"\bbeq(?:\.n)?\s+(?:0x)?d95bc\b",
        0xD95BC: r"\bmov\s+r0,\s*r4\b",
        0xD95BE: r"\b(?:pop|ldmia(?:\.w)?)\b.*\bpc\b",
    }
    matches = {
        hex(off): re.search(pattern, rows.get(off, "")) is not None
        for off, pattern in requirements.items()
    }
    return {
        "entry": "0xd94e4",
        "r2_zero_short_circuit_verified": all(matches.values()),
        "instruction_checks": matches,
        "cxx_equivalent_for_this_path_only": "if (arg_r2 == nullptr) return nullptr;",
    }


def parse_trace(text: str) -> list[dict]:
    events = []
    for line_number, line in enumerate(text.splitlines(), 1):
        match = PROBE.search(line)
        if not match:
            continue
        offset = int(match.group(1), 16)
        if offset not in SITES:
            continue
        regs = {name.lower(): int(value, 16) for name, value in REG.findall(line)}
        events.append({"line": line_number, "off": hex(offset),
                       "label": SITES[offset], **regs})
    return events


def _number(value):
    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(value, 16) if isinstance(value, str) else int(value)
    except (ValueError, TypeError):
        return None


def analyze(events: list[dict]) -> dict:
    ordered = []
    for index, event in enumerate(events):
        off = _number(event.get("off"))
        if off not in SITES or event.get("type", "probe") != "probe":
            continue
        registers = {k: v for k in ("r0", "r2", "r3", "r4", "r5", "r6", "r8") if (v := _number(event.get(k))) is not None}
        ordered.append({"index": index, "off": hex(off), "label": SITES[off], **registers})

    def at(offset):
        return [e for e in ordered if e["off"] == hex(offset)]

    pre = at(0xDA79A)
    post = at(0xDA79C)
    verified = []
    for p in post:
        earlier = [q for q in pre if q["index"] < p["index"] and "r4" in q]
        if not earlier or "r0" not in p:
            continue
        q = earlier[-1]
        verified.append({"pre_mov_r4": hex(q["r4"]), "post_mov_r0": hex(p["r0"]),
                         "matches": q["r4"] == p["r0"]})

    nulls = at(0xDB31E)
    return {
        "probe_count": len(ordered),
        "owner_pre_mov_samples": len(pre),
        "owner_pre_mov_r0_zero_count": sum(e.get("r0") == 0 for e in pre),
        "owner_pre_mov_r4_nonzero_count": sum(e.get("r4", 0) != 0 for e in pre),
        "owner_after_mov_samples": len(post),
        "post_mov_checks": verified,
        "post_mov_matches": sum(e["matches"] for e in verified),
        "post_mov_nonzero_r0_count": sum(e.get("r0", 0) != 0 for e in post),
        "post_mov_zero_r0_count": sum(e.get("r0") == 0 for e in post),
        "crash_site_zero_r0_count": sum(e.get("r0") == 0 for e in nulls),
        "special_type_selector_match_count": sum(
            e.get("r8", 0) != 0 and e.get("r8") == e.get("r3")
            for e in at(0xDA702)
        ),
        "primary_factory_null_arg_count": sum(e.get("r2") == 0 for e in at(0xD94E4)),
        "primary_factory_null_exit_count": sum(e.get("r0") == 0 for e in at(0xD95BE)),
        "second_selector_probe_count": len(at(0xDA71C)),
        "second_selector_equal_count": sum(
            e.get("r8") is not None and e.get("r8") == e.get("r3")
            for e in at(0xDA71C)
        ),
        "second_selector_unequal_count": sum(
            e.get("r8") is not None and e.get("r3") is not None
            and e.get("r8") != e.get("r3")
            for e in at(0xDA71C)
        ),
        "second_fallback_return_count": len(at(0xDA72C)),
        "second_fallback_null_count": sum(e.get("r0") == 0 for e in at(0xDA72C)),
        "second_registry_root_null_count": sum(e.get("r5") == 0 for e in at(0xD8F14)),
        "second_registry_no_handler_count": len(at(0xD8F44)),
        "second_registry_handler_call_count": len(at(0xD8F40)),
        "second_registry_handler_null_return_count": sum(
            e.get("r0") == 0 for e in at(0xD8F42)
        ),
        "second_registry_sentinel_selected_count": sum(
            e.get("r4") is not None and e.get("r6") is not None
            and e.get("r4") == e.get("r6")
            for e in at(0xD8F36)
        ),
        "fallback_nonzero_r0_count": sum(e.get("r0", 0) != 0 for e in at(0xDA72C)),
        "interpretation": (
            "DA79A probes observe registers BEFORE mov r0,r4, not a function "
            "return. DA79C probes observe its effect. Breakpoints are one-shot; "
            "temporal proximity alone does not establish that the sampled owner "
            "invocation is the one that later faults at DB31E."
        ),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path, help="raw [TREE_PROBE] log or crash-bridge JSON")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    data = args.trace.read_text(encoding="utf-8", errors="replace")
    if args.trace.suffix.lower() == ".json":
        source = json.loads(data)
        events = source.get("events", []) if isinstance(source, dict) else source
    else:
        events = parse_trace(data)
    result = analyze(events)
    formatted = json.dumps(result, indent=2) + "\n"
    if args.out:
        args.out.write_text(formatted, encoding="utf-8")
    print(formatted, end="")


if __name__ == "__main__":
    main()
