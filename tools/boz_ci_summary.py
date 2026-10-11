#!/usr/bin/env python3
"""Create a bounded, game-data-free summary of one genuine BOZ QEMU CI run.

The original resource packs and framebuffer binary data must never enter Git.
This script saves only counters, hashes, public runner IDs, and diagnostic lines.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sys


def swap_from_name(filename: str) -> int | None:
    match = re.search(r"boz-swap-(\d+)\.png$", filename)
    return int(match.group(1)) if match else None


def draw_dimensions(line: str) -> tuple[int, int] | None:
    match = re.search(r"\bimage=(\d+)x(\d+)\b", line)
    if not match:
        return None
    return int(match.group(1)), int(match.group(2))


def color_counts(frame: dict) -> tuple[tuple[str, int], ...]:
    return tuple(sorted(
        (str(item.get("rgb")), int(item.get("pixels", 0)))
        for item in (frame.get("top_rgb") or [])
    ))


def parse_draw_census(line: str) -> dict[str, int]:
    """Return integer-only counters from a BOZ_GL_DRAW_CENSUS diagnostic."""
    if not line.startswith("[BOZ_GL_DRAW_CENSUS] "):
        return {}
    return {name: int(value) for name, value in
            re.findall(r"\b([a-z_0-9]+)=(\d+)\b", line)}


def summarize(report: dict) -> dict:
    runtime = report.get("fast_property") or {}
    resource_lines = report.get("fast_resource_consumption") or []
    progress_lines = report.get("fast_resource_progress") or []
    frontend_closes = [
        line for line in resource_lines
        if line.startswith("[BOZ_RESOURCE_CLOSE]")
        and "frontend.group.bin" in line
    ]
    frontend_progress = [
        line for line in progress_lines if "frontend.group.bin" in line
    ]
    texture = report.get("fast_texture_evidence") or {}
    texture_draws = texture.get("draws") or []
    sampled_dimensions = [draw_dimensions(line) for line in texture_draws]
    census_lines = (texture.get("draw_census") or [])[-16:]
    census = [parse_draw_census(line) for line in census_lines]
    census = [item for item in census if item]
    images = runtime.get("captured_pngs") or []
    frames = []
    for img in images:
        frame_number = swap_from_name(str(img.get("file", "")))
        if frame_number is None:
            continue
        frames.append({
            "swap": frame_number,
            "sha256": img.get("sha256"),
            "distinct_rgb_colors": img.get("distinct_rgb_colors"),
            "top_rgb": (img.get("top_rgb") or [])[:3],
        })
    frames.sort(key=lambda item: item["swap"])
    frame_lookup = {f["swap"]: f for f in frames}
    return {
        "schema": "boz-ci-summary-v1",
        "provenance": {
            "run_id": os.getenv("GITHUB_RUN_ID"),
            "run_attempt": os.getenv("GITHUB_RUN_ATTEMPT"),
            "commit": os.getenv("GITHUB_SHA"),
            "workflow": os.getenv("GITHUB_WORKFLOW"),
        },
        "gameplay_verified": False,
        "visual_frontend_verified": False,
        "diagnostic_deadline_reached": runtime.get("timed_out"),
        "qemu_return_code": runtime.get("rc"),
        "guest_sigsegv_count": runtime.get("signal_11_count"),
        "swaps": (runtime.get("swap_progress_events") or [])[-12:],
        "frame_hashes": frames,
        "late_tap_events": (runtime.get("diagnostic_tap_events") or [])[:8],
        "after_tap_frame_changed": (
            frame_lookup[100]["sha256"] != frame_lookup[140]["sha256"]
            if 100 in frame_lookup and 140 in frame_lookup else None
        ),
        # Hash changes alone include diagnostic cursor movement. Unchanged
        # color counts help avoid mistaking that movement for a menu transition.
        "after_tap_color_counts_identical": (
            color_counts(frame_lookup[100]) == color_counts(frame_lookup[140])
            if 100 in frame_lookup and 140 in frame_lookup else None
        ),
        "sampled_draws_total": len(texture_draws),
        "per_frame_draw_census": census,
        "last_draw_census": census[-1] if census else None,
        "unit0_binding_transitions": (texture.get("unit0_binds") or [])[-24:],
        "sampled_draws_with_2x2_texture": sum(
            size == (2, 2) for size in sampled_dimensions
        ),
        "sampled_draws_with_larger_texture": sum(
            size is not None and (size[0] > 2 or size[1] > 2)
            for size in sampled_dimensions
        ),
        "frontend_close": frontend_closes[-1] if frontend_closes else None,
        "frontend_last_read_progress": (
            frontend_progress[-1] if frontend_progress else None
        ),
        "texture_size_totals": (texture.get("size_totals") or [])[-8:],
        "late_texture_draws": (texture.get("draws") or [])[-12:],
        "compressed_texture_uploads": (
            texture.get("compressed_events") or []
        )[:16],
    }


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: boz_ci_summary.py REPORT_JSON OUTPUT_JSON", file=sys.stderr)
        return 2
    source, output = map(Path, sys.argv[1:])
    report = json.loads(source.read_text(encoding="utf-8"))
    summary = summarize(report)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        f"[BOZ_CI_SUMMARY] run={summary['provenance']['run_id']} "
        f"frames={len(summary['frame_hashes'])} "
        f"frontend_closed={summary['frontend_close'] is not None} "
        f"tap_events={len(summary['late_tap_events'])} "
        f"census_samples={len(summary['per_frame_draw_census'])}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
