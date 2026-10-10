#!/usr/bin/env python3
"""Parse BOZ callback BLX/return pairs that were armed sequentially.

A pair is accepted only when a matching CALL and RET with the same sequence
number appear in order; unrelated one-shot TREE_PROBE samples are ignored.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

CALL = re.compile(
    r"\[HANDLER_PAIR_CALL\]\s+seq=(\d+)\s+target=([0-9a-fA-F]{8})\s+"
    r"r0=([0-9a-fA-F]{8})\s+r1=([0-9a-fA-F]{8})\s+"
    r"r2=([0-9a-fA-F]{8})\s+armed_return=([01])"
)
RET = re.compile(
    r"\[HANDLER_PAIR_RET\]\s+seq=(\d+)\s+target=([0-9a-fA-F]{8})\s+"
    r"result=([0-9a-fA-F]{8})"
)


def summarize_handler_pairs(trace: str) -> dict:
    pending: dict[int, dict] = {}
    pairs: list[dict] = []
    ignored = 0
    orphan_returns = 0
    for line in trace.splitlines():
        call = CALL.search(line)
        if call:
            seq, target, r0, r1, r2, armed = call.groups()
            num = int(seq)
            if int(armed) != 1 or num in pending:
                ignored += 1
                continue
            pending[num] = {
                "seq": num,
                "target": f"0x{target.lower()}",
                "input_r0": f"0x{r0.lower()}",
                "input_r1": f"0x{r1.lower()}",
                "input_r2": f"0x{r2.lower()}",
            }
            continue
        ret = RET.search(line)
        if ret:
            seq, target, result = ret.groups()
            num = int(seq)
            previous = pending.get(num)
            if previous is None or previous["target"] != f"0x{target.lower()}":
                orphan_returns += 1
                continue
            del pending[num]
            pairs.append({**previous, "return_r0": f"0x{result.lower()}",
                          "returned_null": int(result, 16) == 0})
    return {
        "verified_pair_count": len(pairs),
        "returned_null_count": sum(p["returned_null"] for p in pairs),
        "returned_nonnull_count": sum(not p["returned_null"] for p in pairs),
        "incomplete_call_count": len(pending),
        "orphan_return_count": orphan_returns,
        "ignored_unarmed_or_duplicate_calls": ignored,
        "pairs": pairs,
        "note": "Each pair uses one BLX trap and its immediately following return trap; "
                "no game return values are modified.",
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: boz_handler_pairs.py TRACE_LOG")
    trace_path = Path(sys.argv[1])
    print(json.dumps(summarize_handler_pairs(
        trace_path.read_text(encoding="utf-8", errors="replace")), indent=2))
