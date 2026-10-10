#!/usr/bin/env python3
"""Summarize BOZ ARM r4 at new crash without conflating one-shot probes.

Traps capture registers BEFORE their instruction. The crash handler captures
the actual fault-time registers. Sampling separate invocations is not proof
of a register change within a single call.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

PROBE = re.compile(r"\[TREE_PROBE\]\s+mode=arm32\s+off=0*([0-9a-f]{1,8})\b", re.I)
R4 = re.compile(r"\br4=(?:0x)?([0-9a-f]{8})\b", re.I)
SIGNAL = re.compile(r"\bsignal\s+(\d+)\s+addr=(0x[0-9a-f]+|\(nil\))\b", re.I)
PC = re.compile(r"\bpc_off=0x([0-9a-f]{1,8})\b", re.I)

OFFSETS = {
    0x2FFA30: "array_caller",
    0x300444: "list_caller",
    0x2FE088: "function_entry",
    0x2FE098: "post_initializer",
    0x2FE0A4: "before_second_helper",
    0x2FE0A8: "before_faulting_load",
}


def summarize_crash_registers(output: str) -> dict:
    samples = []
    faults = []
    for line_no, line in enumerate(output.splitlines(), 1):
        m = PROBE.search(line)
        if m:
            off = int(m.group(1), 16)
            if off in OFFSETS:
                r4 = R4.search(line)
                samples.append({
                    "line": line_no, "offset": f"0x{off:08x}", "site": OFFSETS[off],
                    "r4": None if r4 is None else f"0x{int(r4.group(1),16):08x}",
                })
            continue
        pc = PC.search(line)
        if pc and "signal 11 " in line:
            off = int(pc.group(1), 16)
            r4 = R4.search(line)
            faults.append({
                "line": line_no, "offset": f"0x{off:08x}",
                "r4": None if r4 is None else f"0x{int(r4.group(1),16):08x}",
                "at_expected_site": off == 0x2FE0A8,
            })
    return {
        "probe_samples": samples,
        "faults": faults,
        "crash_at_2fe0a8_count": sum(x["at_expected_site"] for x in faults),
        "r4_null_at_crash_count": sum(
            x["at_expected_site"] and x["r4"] == "0x00000000" for x in faults
        ),
        "r4_at_crash_unknown_count": sum(
            x["at_expected_site"] and x["r4"] is None for x in faults
        ),
        "note": "Fault-time r4 is definitive for the observed fault. "
                "Pre-instruction probes may belong to separate calls; "
                "do not infer register corruption from ordering alone.",
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: boz_new_crash_regs.py TRACE_LOG")
    data = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
    print(json.dumps(summarize_crash_registers(data), indent=2))
