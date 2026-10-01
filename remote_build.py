#!/usr/bin/env python3
"""Render-side diagnostic/build runner for COD BOZ."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent
PUBLIC = ROOT / "public"
PUBLIC.mkdir(exist_ok=True)


def run(cmd: list[str], timeout: int = 900) -> int:
    print("[RUNNER]", " ".join(cmd), flush=True)

    try:
        p = subprocess.run(
            cmd,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
        )
    except Exception as exc:
        print(
            f"[RUNNER] command failed to start: {exc!r}",
            flush=True,
        )
        return 125

    if p.stdout:
        print(
            p.stdout,
            end="" if p.stdout.endswith("\n") else "\n",
            flush=True,
        )

    print(f"[RUNNER] rc={p.returncode}", flush=True)
    return p.returncode


def main() -> int:
    started = time.time()

    print("[RUNNER] starting", flush=True)
    print(f"[RUNNER] root={ROOT}", flush=True)
    print(
        f"[RUNNER] python={sys.version.split()[0]}",
        flush=True,
    )

    if hasattr(os, "getuid"):
        print(f"[RUNNER] uid={os.getuid()}", flush=True)

    expected = [
        "Makefile",
        "CMakeLists.txt",
        "Dockerfile",
        "src",
        "tests",
        "scripts",
        "packaging",
    ]

    files = {}

    for name in expected:
        present = (ROOT / name).exists()
        files[name] = present

        print(
            f"[RUNNER] {name}: "
            f"{'present' if present else 'missing'}",
            flush=True,
        )

    report = {
        "runner": "remote_build.py",
        "cwd": str(ROOT),
        "python": sys.version,
        "files": files,
        "make_check_rc": None,
        "duration_seconds": None,
    }

    port = int(os.environ.get("PORT", "10000"))
    server = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "http.server",
            str(port),
            "--bind",
            "0.0.0.0",
            "--directory",
            str(PUBLIC),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )
    print(f"[RUNNER] HTTP server started pid={server.pid} port={port}", flush=True)

    rc = 0

    if (ROOT / "Makefile").exists():
        rc = run(["make", "test-host"], timeout=900)
        report["make_test_host_rc"] = rc
    else:
        print(
            "[RUNNER] no Makefile; nothing to build",
            flush=True,
        )

    report["duration_seconds"] = round(
        time.time() - started,
        3,
    )

    report["exit_code"] = rc
    report["status"] = "passed" if rc == 0 else "failed"

    out = PUBLIC / "runner-report.json"

    out.write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8",
    )

    print(
        f"[RUNNER] wrote {out}",
        flush=True,
    )

    return rc


if __name__ == "__main__":
    raise SystemExit(main())
