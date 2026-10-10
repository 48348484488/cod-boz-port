#!/usr/bin/env python3
"""Reconstruct the observed BOZ owner/null-dispatch path from crash-bridge probes.

No game bytes or offsets are patched. A result is evidence about one trace,
not a claim of full C++ decompilation or proof of correctness on other paths.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

PROBE = re.compile(r"\[TREE_PROBE\].*?\boff=0*([0-9a-fA-F]+)\b")
REG = re.compile(r"\b(r0|r4)=([0-9a-fA-F]{8})\b")
SITES = {
    0xDA70E: "primary_return",
    0xDA72C: "fallback_return",
    0xDA79A: "owner_return",
    0xDB31C: "dispatch",
    0xDB31E: "null_deref",
}


def parse_trace(text: str) -> list[dict]:
    """Return only execution probes; unrelated messages never become evidence."""
    result = []
    for line_number, line in enumerate(text.splitlines(), 1):
        match = PROBE.search(line)
        if not match:
            continue
        offset = int(match.group(1), 16)
        if offset not in SITES:
            continue
        regs = {name: int(value, 16) for name, value in REG.findall(line)}
        result.append({"line": line_number, "off": hex(offset), "label": SITES[offset], **regs})
    return result


def analyze(events: list[dict]) -> dict:
    """Correlate only chronological probes; distinguish missing from zero."""
    normalized = []
    for index, event in enumerate(events):
        try:
            offset = int(str(event.get("off", "")), 16)
        except ValueError:
            continue
        if offset not in SITES:
            continue
        registers = {}
        for name in ("r0", "r4"):
            value = event.get(name)
            if value is not None:
                try:
                    registers[name] = int(str(value), 16) if isinstance(value, str) else int(value)
                except ValueError:
                    pass
        normalized.append({"index": index, "off": hex(offset), "label": SITES[offset], **registers})

    by_label = {label: [e for e in normalized if e["label"] == label]
                for label in SITES.values()}
    zero_returns = [e for e in by_label["owner_return"] if e.get("r0") == 0]
    false_negatives_r4 = [e for e in zero_returns if e.get("r4", 0) != 0]
    # This is a temporal correlation, not proof that an allocation was lost.
    chains = []
    for owner in zero_returns:
        preceding = [e for e in by_label["fallback_return"]
                     if e["index"] < owner["index"] and e.get("r0", 0) != 0]
        later = [e for e in by_label["null_deref"]
                 if e["index"] > owner["index"] and e.get("r0") == 0]
        if preceding and later:
            chains.append({"fallback": preceding[-1], "owner": owner,
                           "null_deref": later[0]})
    return {
        "probe_count": len(normalized),
        "owner_return_count": len(by_label["owner_return"]),
        "owner_r0_zero_count": len(zero_returns),
        "r4_based_detection_missed": len(false_negatives_r4),
        "observed_null_dispatch_chains": len(chains),
        "chains": chains,
        "interpretation": (
            "A non-null fallback return preceded a zero owner result and "
            "a zero r0 at the null-dereference probe; correlation is not "
            "proof of a missing memory write."
            if chains else "Insufficient chronological probe evidence for this chain."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path, help="raw [TREE_PROBE] trace or crash-bridge JSON")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    payload = args.trace.read_text(encoding="utf-8", errors="replace")
    if args.trace.suffix.lower() == ".json":
        source = json.loads(payload)
        events = source.get("events", source) if isinstance(source, dict) else source
    else:
        events = parse_trace(payload)
    result = analyze(events)
    formatted = json.dumps(result, indent=2) + "\n"
    if args.out:
        args.out.write_text(formatted, encoding="utf-8")
    print(formatted, end="")


if __name__ == "__main__":
    main()
