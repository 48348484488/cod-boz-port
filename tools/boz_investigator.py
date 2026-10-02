#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path

ADDR = re.compile(r"^\s*([0-9a-fA-F]+):")
CALL = re.compile(r"\bblx?\s+(?:0x)?([0-9a-fA-F]+)\b", re.I)

def addr(line):
    m = ADDR.match(line)
    return int(m.group(1), 16) if m else None

def main():
    p = argparse.ArgumentParser()
    p.add_argument("disassembly")
    p.add_argument("--target", action="append", default=[])
    p.add_argument("--json-out")
    p.add_argument("--text-out")
    p.add_argument("--probe-plan")
    p.add_argument("--probe-limit", type=int, default=128)
    a = p.parse_args()

    lines = Path(a.disassembly).read_text(errors="replace").splitlines()
    targets = [int(x, 0) for x in a.target]
    starts = [i for i, x in enumerate(lines) if ADDR.match(x) and "push" in x.lower() and "lr" in x.lower()]
    funcs = []
    for n, start in enumerate(starts):
        end = starts[n + 1] - 1 if n + 1 < len(starts) else len(lines) - 1
        funcs.append({"entry": addr(lines[start]), "start": start, "end": end})

    calls = []
    stores = []
    for i, line in enumerate(lines):
        m = CALL.search(line)
        if m:
            calls.append({"site": addr(line), "target": int(m.group(1), 16), "line": line.strip()})
        low = line.lower()
        if "str" in low and "#4]" in low and "[sp," not in low:
            owner = next((f for f in reversed(funcs) if f["start"] <= i <= f["end"]), None)
            stores.append({"site": addr(line), "function": owner["entry"] if owner else None, "line": line.strip()})

    xrefs = {f"{t:x}": [c for c in calls if c["target"] == t] for t in targets}
    ranked = []
    seen = set()
    for store in stores:
        off = store["site"]
        if off is None or off & 1 or off in seen or not confirmed_thumb(off):
            continue
        seen.add(off)
        ranked.append({"off": off, "mode": "thumb16",
                       "mode_source": "runtime_confirmed_thumb_window",
                       "reason": "store_plus4",
                       "function": store["function"], "line": store["line"]})

    # Also probe the instruction immediately after calls in the manager
    # initializer around DAA84. This captures return/register state after
    # each initialization step without instrumenting every instruction.
    instruction_sites = [addr(line) for line in lines]
    for i, line in enumerate(lines):
        site = addr(line)
        if site is None or not (0xDA9B6 <= site <= 0xDAE84):
            continue
        if not CALL.search(line):
            continue
        next_site = None
        next_line = None
        for j in range(i + 1, min(len(lines), i + 4)):
            candidate = addr(lines[j])
            if candidate is not None:
                next_site = candidate
                next_line = lines[j].strip()
                break
        if (next_site is None or next_site & 1 or next_site in seen
                or not confirmed_thumb(next_site)):
            continue
        seen.add(next_site)
        ranked.append({"off": next_site, "mode": "thumb16",
                       "mode_source": "runtime_confirmed_thumb_window",
                       "reason": "post_call_manager_init",
                       "function": 0xDA9B6, "line": next_line})
    ranked = ranked[:max(0, min(a.probe_limit, 512))]

    result = {"functions": len(funcs), "calls": len(calls),
              "confirmed_thumb_ranges": [[hex(lo), hex(hi)] for lo, hi in CONFIRMED_THUMB_RANGES],
              "store_plus4_sites": stores, "probe_candidates": ranked,
              "target_xrefs": xrefs}
    if a.probe_plan:
        Path(a.probe_plan).write_text(json.dumps(
            {"version": 3, "capacity": 512,\n             "confirmed_thumb_ranges": [[hex(lo), hex(hi)] for lo, hi in CONFIRMED_THUMB_RANGES],\n             "count": len(ranked), "probes": ranked}, indent=2) + "\n")
    data = json.dumps(result, indent=2)
    if a.json_out:
        Path(a.json_out).write_text(data + "\n")
    else:
        print(data)
    if a.text_out:
        out = ["BOZ Auto Investigator",
               f"functions={len(funcs)} calls={len(calls)} stores+4={len(stores)} probes={len(ranked)}"]
        for t, xs in xrefs.items():
            out.append(f"target=0x{t} callers={len(xs)}")
            out.extend("  " + x["line"] for x in xs)
        Path(a.text_out).write_text("\n".join(out) + "\n")

if __name__ == "__main__":
    main()
