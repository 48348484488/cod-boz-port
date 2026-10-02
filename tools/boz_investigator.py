#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path

ADDR = re.compile(r"^\s*([0-9a-fA-F]+):")
CALL = re.compile(r"\bblx?\s+(?:0x)?([0-9a-fA-F]+)\b", re.I)

def address(line):
    m = ADDR.match(line)
    return int(m.group(1), 16) if m else None

def main():
    p = argparse.ArgumentParser()
    p.add_argument("disassembly")
    p.add_argument("--target", action="append", default=[])
    p.add_argument("--json-out")
    p.add_argument("--text-out")
    p.add_argument("--probe-plan")
    p.add_argument("--probe-limit", type=int, default=64)
    a = p.parse_args()

    lines = Path(a.disassembly).read_text(errors="replace").splitlines()
    targets = [int(x, 0) for x in a.target]
    starts = [i for i, x in enumerate(lines)
              if ADDR.match(x) and "push" in x.lower() and "lr" in x.lower()]
    functions = []
    for n, start in enumerate(starts):
        end = starts[n + 1] - 1 if n + 1 < len(starts) else len(lines) - 1
        functions.append({"entry": address(lines[start]), "start": start, "end": end})

    calls = []
    for line in lines:
        m = CALL.search(line)
        if m:
            calls.append({"site": address(line), "target": int(m.group(1), 16), "line": line.strip()})

    stores = []
    for i, line in enumerate(lines):
        low = line.lower()
        if "str" not in low or "#4]" not in low or "[sp," in low:
            continue
        owner = next((f for f in reversed(functions) if f["start"] <= i <= f["end"]), None)
        stores.append({"site": address(line), "function": owner["entry"] if owner else None,
                       "line": line.strip()})

    xrefs = {f"{t:x}": [c for c in calls if c["target"] == t] for t in targets}
    ranked = []
    for store in stores:
        site = store["site"]
        if site is None or site & 1:
            continue
        ranked.append({"off": site, "mode": "thumb16", "reason": "store_plus4",
                       "function": store["function"], "line": store["line"]})
    ranked = ranked[:max(0, min(a.probe_limit, 64))]

    result = {"functions": len(functions), "calls": len(calls),
              "store_plus4_sites": stores, "probe_candidates": ranked,
              "target_xrefs": xrefs}
    if a.probe_plan:
        Path(a.probe_plan).write_text(json.dumps({
            "version": 2, "capacity": 64, "count": len(ranked), "probes": ranked
        }, indent=2) + "\n")

    data = json.dumps(result, indent=2)
    if a.json_out:
        Path(a.json_out).write_text(data + "\n")
    else:
        print(data)
    if a.text_out:
        out = ["BOZ Auto Investigator",
               f"functions={len(functions)} calls={len(calls)} stores+4={len(stores)}",
               f"mass_probes={len(ranked)}"]
        for target, refs in xrefs.items():
            out.append(f"target=0x{target} callers={len(refs)}")
            out.extend("  " + c["line"] for c in refs)
        Path(a.text_out).write_text("\n".join(out) + "\n")

if __name__ == "__main__":
    main()
