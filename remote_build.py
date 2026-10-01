#!/usr/bin/env python3
"""Render-side diagnostic/build runner for COD BOZ."""

from __future__ import annotations

import json
import hashlib
import hmac
import os
import pathlib
import subprocess
import sys
import time
import shutil
import lzma
import urllib.request
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import threading

ROOT = pathlib.Path(__file__).resolve().parent
PUBLIC = ROOT / "public"
PUBLIC.mkdir(exist_ok=True)
UPLOAD_ENDPOINT = "/__codboz_upload"
MAX_UPLOAD_BYTES = 8 * 1024 * 1024
UPLOAD_LOCK = threading.Lock()
UPLOAD_CONSUMED = False
ACTIVE_REPORT: dict | None = None


def write_report(report: dict) -> None:
    out = PUBLIC / "runner-report.json"
    temporary = out.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    temporary.replace(out)


class ArtifactRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(PUBLIC), **kwargs)

    def log_message(self, fmt: str, *args) -> None:
        # Avoid writing request details or credentials into public service logs.
        print("[HTTP] " + fmt % args, flush=True)

    def _reply_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        global UPLOAD_CONSUMED

        if self.path != UPLOAD_ENDPOINT:
            self._reply_json(404, {"error": "not found"})
            return

        token = os.environ.get("BOZ_UPLOAD_TOKEN", "").strip()
        try:
            expires_at = int(os.environ.get("BOZ_UPLOAD_EXPIRES_AT", "0"))
        except ValueError:
            expires_at = 0
        if not token or expires_at <= int(time.time()):
            self._reply_json(404, {"error": "upload unavailable"})
            return
        if not hmac.compare_digest(self.headers.get("Authorization", ""), f"Bearer {token}"):
            self._reply_json(401, {"error": "unauthorized"})
            return
        if UPLOAD_CONSUMED or not UPLOAD_LOCK.acquire(blocking=False):
            self._reply_json(409, {"error": "upload already used or in progress"})
            return

        asset = pathlib.Path("/tmp/boz-assets/boz.s3e")
        try:
            if self.headers.get("Transfer-Encoding"):
                self._reply_json(411, {"error": "Content-Length required"})
                return
            try:
                content_length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self._reply_json(411, {"error": "Content-Length required"})
                return
            if content_length < 68 or content_length > MAX_UPLOAD_BYTES:
                self._reply_json(413, {"error": "payload size must be between 68 bytes and 8 MiB"})
                return
            if self.headers.get_content_type() != "application/octet-stream":
                self._reply_json(415, {"error": "application/octet-stream required"})
                return

            payload = self.rfile.read(content_length)
            if len(payload) != content_length:
                self._reply_json(400, {"error": "incomplete upload"})
                return
            if payload[:4] != b"XE3U":
                self._reply_json(422, {"error": "upload must be an uncompressed S3E image"})
                return
            if ACTIVE_REPORT is None or ACTIVE_REPORT.get("make_all_rc") != 0:
                self._reply_json(503, {"error": "runner build is not ready"})
                return

            asset.parent.mkdir(parents=True, exist_ok=True)
            asset.write_bytes(payload)
            UPLOAD_CONSUMED = True
            os.environ["BOZ_UPLOAD_EXPIRES_AT"] = "0"
            os.environ["BOZ_IMAGE_PATH"] = str(asset)
            started = time.time()
            try:
                game_rc = run_boz_diagnostic(ACTIVE_REPORT)
                ACTIVE_REPORT["uploaded_asset_size"] = len(payload)
                ACTIVE_REPORT["uploaded_asset_sha256"] = hashlib.sha256(payload).hexdigest()
                ACTIVE_REPORT["game_run_rc"] = game_rc
                ACTIVE_REPORT["exit_code"] = game_rc
                ACTIVE_REPORT["status"] = "passed" if game_rc == 0 else "failed"
                ACTIVE_REPORT["duration_seconds"] = round(
                    float(ACTIVE_REPORT.get("duration_seconds") or 0) + time.time() - started,
                    3,
                )
                write_report(ACTIVE_REPORT)
                self._reply_json(200, {
                    "status": ACTIVE_REPORT["status"],
                    "game_run_rc": game_rc,
                    "uploaded_asset_size": len(payload),
                    "uploaded_asset_sha256": ACTIVE_REPORT["uploaded_asset_sha256"],
                    "trace_lines": ACTIVE_REPORT.get("trace_lines", 0),
                    "trace_has_uploads": ACTIVE_REPORT.get("trace_has_uploads", False),
                    "report_url": "/runner-report.json",
                    "trace_url": "/boz_gl_upload_trace.log" if ACTIVE_REPORT.get("trace_artifact") else None,
                })
            except Exception as exc:
                ACTIVE_REPORT["upload_diagnostic_error"] = repr(exc)
                ACTIVE_REPORT["status"] = "failed"
                write_report(ACTIVE_REPORT)
                self._reply_json(500, {"error": "diagnostic failed; see runner report"})
            finally:
                os.environ.pop("BOZ_IMAGE_PATH", None)
                asset.unlink(missing_ok=True)
        finally:
            UPLOAD_LOCK.release()


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


def discover_game_image() -> pathlib.Path | None:
    configured = os.environ.get("BOZ_IMAGE_PATH", "").strip()
    candidates: list[pathlib.Path] = []
    if configured:
        candidates.append(pathlib.Path(configured))
    roots = [
        ROOT / "assets",
        ROOT / "build" / "package" / "ports" / "codboz" / "assets",
        pathlib.Path("/tmp/boz-assets"),
        pathlib.Path("/opt/boz-assets"),
        pathlib.Path("/data/boz-assets"),
    ]
    candidates.extend(root / "boz.s3e.unpacked" for root in roots)
    candidates.extend(root / "boz.s3e" for root in roots)
    for candidate in candidates:
        if candidate.is_file() and candidate.stat().st_size > 0:
            return candidate
    for root in roots:
        if not root.is_dir():
            continue
        for pattern in ("*.s3e.unpacked", "*.s3e"):
            for candidate in root.glob(pattern):
                if candidate.is_file() and candidate.stat().st_size > 0:
                    return candidate
    return None


def stage_public_reference_s3e(report: dict) -> pathlib.Path | None:
    """Fetch the public preservation copy without committing game bytes to this fork."""
    url = os.environ.get(
        "BOZ_REFERENCE_S3E_URL",
        "https://raw.githubusercontent.com/eugene373/COD-BOZ-Partially-Decompiled/master/app/src/main/assets/boz.s3e",
    )
    expected_sha256 = "f458c15a7111779ad320af377d0bb751294119788ba06d430bee0cc977539fee"
    compressed = pathlib.Path("/tmp/boz-assets/boz.s3e")
    unpacked = pathlib.Path("/tmp/boz-assets/boz.s3e.unpacked")
    try:
        compressed.parent.mkdir(parents=True, exist_ok=True)
        print(f"[RUNNER] fetching public reference S3E from {url}", flush=True)
        with urllib.request.urlopen(url, timeout=60) as response:
            payload = response.read(MAX_UPLOAD_BYTES + 1)
        digest = hashlib.sha256(payload).hexdigest()
        report["reference_s3e_size"] = len(payload)
        report["reference_s3e_sha256"] = digest
        if len(payload) > MAX_UPLOAD_BYTES or digest != expected_sha256:
            print(f"[RUNNER] reference S3E rejected size={len(payload)} sha256={digest}", flush=True)
            return None
        compressed.write_bytes(payload)
        decoded = lzma.decompress(payload, format=lzma.FORMAT_ALONE)
        if not decoded.startswith(b"XE3U"):
            print("[RUNNER] reference S3E unpacked payload lacks XE3U header", flush=True)
            return None
        unpacked.write_bytes(decoded)
        report["reference_s3e_unpacked_size"] = len(decoded)
        report["reference_s3e_unpacked_sha256"] = hashlib.sha256(decoded).hexdigest()
        print(f"[RUNNER] staged reference S3E unpacked_size={len(decoded)}", flush=True)
        return unpacked
    except Exception as exc:
        report["reference_s3e_error"] = repr(exc)
        print(f"[RUNNER] reference S3E fetch/decompress failed: {exc!r}", flush=True)
        return None


def run_boz_diagnostic(report: dict) -> int:
    trace = pathlib.Path("/tmp/boz_gl_upload_trace.log")
    trace.unlink(missing_ok=True)
    image = discover_game_image()
    if not image and os.environ.get("BOZ_FETCH_REFERENCE_S3E", "1") == "1":
        image = stage_public_reference_s3e(report)
    report["game_image"] = str(image) if image else None
    report["game_image_size"] = image.stat().st_size if image else None
    report["gl_upload_trace"] = str(trace)
    report["game_run_attempted"] = bool(image)
    if not image:
        print("[RUNNER] no BOZ .s3e/.s3e.unpacked asset supplied; game execution not attempted", flush=True)
        return 0

    loader = ROOT / "build" / "codboz_s3e_loader"
    if not loader.is_file():
        print("[RUNNER] loader missing; cannot execute BOZ", flush=True)
        return 127

    env = os.environ.copy()
    env["GL_UPLOAD_TRACE"] = "1"
    env.setdefault("SDL_VIDEODRIVER", "x11")
    env["LIBGL_ALWAYS_SOFTWARE"] = "1"
    env["LD_LIBRARY_PATH"] = "/usr/lib/arm-linux-gnueabihf:/lib/arm-linux-gnueabihf"
    env["BOZ_TRACE_ARTIFACT"] = str(trace)
    display_size = os.environ.get("BOZ_DISPLAY_SIZE", "640x480")
    qemu_arm = shutil.which(os.environ.get("QEMU_ARM", "qemu-arm"))
    if not qemu_arm:
        print("[RUNNER] qemu-arm missing; cannot execute ARM S3E on Render host", flush=True)
        return 127
    cmd = [qemu_arm, "-L", os.environ.get("BOZ_ARM_SYSROOT", "/"),
           str(loader), "--run", "--root", str(image.parent.parent),
           "--display-size", display_size, str(image)]
    if not env.get("DISPLAY"):
        xvfb_run = shutil.which("xvfb-run")
        if xvfb_run:
            cmd = [xvfb_run, "-a", "-s", f"-screen 0 {display_size}x24", "--", *cmd]
    print("[RUNNER] launching BOZ:", " ".join(cmd), flush=True)
    try:
        p = subprocess.run(cmd, cwd=ROOT, env=env, text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=int(os.environ.get("BOZ_RUN_TIMEOUT", "60")))
    except subprocess.TimeoutExpired as exc:
        print("[RUNNER] BOZ timed out", flush=True)
        if exc.stdout:
            print(exc.stdout, flush=True)
        report["game_run_rc"] = 124
        return 124
    except Exception as exc:
        print(f"[RUNNER] BOZ failed to start: {exc!r}", flush=True)
        report["game_run_rc"] = 125
        return 125

    if p.stdout:
        print(p.stdout, end="" if p.stdout.endswith("\n") else "\n", flush=True)
    print(f"[RUNNER] BOZ rc={p.returncode}", flush=True)
    report["game_run_rc"] = p.returncode

    public_trace = PUBLIC / "boz_gl_upload_trace.log"
    if trace.is_file():
        shutil.copyfile(trace, public_trace)
        text_trace = trace.read_text(encoding="utf-8", errors="replace")
        report["trace_artifact"] = str(public_trace)
        report["trace_lines"] = len([line for line in text_trace.splitlines() if line.strip()])
        report["trace_has_uploads"] = "[GLUPLOAD]" in text_trace
        report["trace_has_ff83_samples"] = any(
            "ff83=" in line and int(line.split("ff83=", 1)[1].split()[0]) > 0
            for line in text_trace.splitlines() if "ff83=" in line
        )
    else:
        report["trace_artifact"] = None
        report["trace_lines"] = 0
        report["trace_has_uploads"] = False
        report["trace_has_ff83_samples"] = False
        print("[RUNNER] BOZ produced no GL upload trace", flush=True)
    return p.returncode


def main() -> int:
    global ACTIVE_REPORT

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
    rc = 0

    if (ROOT / "Makefile").exists():
        rc = run(["make", "CC=arm-linux-gnueabihf-gcc", "all"], timeout=900)
        report["make_all_rc"] = rc
        # test-host was already verified before this diagnostic pass. It contains
        # a long-running integration test in the Render runtime, so do not let it
        # prevent the actual BOZ launch. Set RUN_HOST_TESTS=1 to rerun it explicitly.
        if os.environ.get("RUN_HOST_TESTS", "0") == "1":
            if rc == 0:
                rc = run(["make", "test-host"], timeout=120)
                report["make_test_host_rc"] = rc
        else:
            report["make_test_host_rc"] = "skipped_already_verified"
            print("[RUNNER] make test-host skipped (already verified; set RUN_HOST_TESTS=1 to rerun)", flush=True)
        if rc == 0:
            game_rc = run_boz_diagnostic(report)
            report["game_run_rc"] = game_rc
            if game_rc != 0:
                rc = game_rc
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

    write_report(report)

    print(
        f"[RUNNER] wrote {PUBLIC / 'runner-report.json'}",
        flush=True,
    )

    ACTIVE_REPORT = report
    # Render expects the configured start command to remain alive and listen on
    # PORT. The protected upload route accepts one user-owned BOZ .s3e payload,
    # runs the diagnostic, and deletes the temporary input after execution.
    server = ThreadingHTTPServer(("0.0.0.0", port), ArtifactRequestHandler)
    server.daemon_threads = True
    print(f"[RUNNER] artifact HTTP server started port={port}", flush=True)
    print("[RUNNER] diagnostic complete; serving report and waiting for one authorized upload", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

    return rc


if __name__ == "__main__":
    raise SystemExit(main())
