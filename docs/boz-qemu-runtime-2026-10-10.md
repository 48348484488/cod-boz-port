# BOZ / ReviveOS — QEMU ARM runtime evidence (2026-10-10)

Repository: `48348484488/cod-boz-port`. Do not modify the upstream `Producdevity/cod-boz-port`.

## Reproducible environment
- Render service `srv-daqv1a0473hc73978pv0`, Docker ARMHF cross-build, `qemu-arm` with ARM Mesa/SDL/Xvfb, public reference `boz.s3e` and verified `blackops_loader.dz` archive (DTRZ).
- `remote_build.py` executes `make CC=arm-linux-gnueabihf-gcc all` and opt-in `BOZ_FAST_NULL_PROPERTY=1` diagnostic lane. `RUN_HOST_TESTS=0` skips already-completed host integration tests; it does NOT mean tests were rerun in each deployment.
- Diagnostic branches are controlled by environment variables and do not constitute a production fix.

## Root cause / temporary guards
- Observed null-object chain: `0x2FD518 -> 0x30204C -> 0x20FE6E -> 0x32326C -> 0x3064D8 -> 0x301ECC -> 0x2FE7D0`, where an absent child is passed along and dereferenced.
- Experimental opt-in `BOZ_COMPAT_NULL_CHILD_SKIP=1` intercepts at `0x2FE0A8`, and `BOZ_COMPAT_SKIP_NULL_REGISTRATION=1` skips a `r1 == 0` registration at Thumb `0x20FE6E`. Both triggered once in baseline tests. No SIGSEGV observed during later 50–110s QEMU diagnostic runs.
- These are **bounded bypasses**, not recreated object implementations or confirmed game fixes.

## Rendering verification
- SDL/X11 window creation confirmed at 640x480. `eglSwapBuffers` reports `ok=1`.
- `GL_UPLOAD_TRACE` observed **59 texture uploads** during QEMU boot, including RGBA4444 (`type=0x8033`) 512x512 and 1024x512 uploads.
- For 110-second run on commit `ef8b5d927c2c6ff879cdf9e9f7bfd4b498354dea`:
  - At least **25 successful swaps**, with milestones at frames 1, 2, 3, 4, 5, 10, 15, 20, 25.
  - Through frame 25: **26 calls to glClear**, **0 glDrawArrays**, **0 glDrawElements**, **0 glDrawTexfOES**. These are counters of the instrumented API wrappers, not a claim about every imaginable rendering path.
  - Captured framebuffer: frame 1 is nearly black plus cursor; frames 5, 10, and 15 all have exactly the same PNG SHA256 `13a2b8269bffc40d6d2ecc8c04c60bd0e7982f0a2841983e5d11fda78a40af26`. They are almost uniform `#8080FF` with the cursor, **no menu, HUD, world, or visible sprites**.
  - Output URLs: `/boz-swap-00001.png`, `/boz-swap-00005.png`, `/boz-swap-00010.png`, `/boz-swap-00015.png`, and `/runner-report.json` on the Render service. Artifacts are recreated per deployment; do not assume they persist after redeploy.
- QEMU guest PC samples consistently observed `0x3F6E4656` inside ARM `libc.so.6`, instruction at ELF `0x1E656` following `svc 0`. Return sites include `__clock_nanosleep_time64` paths, consistent with game pacing; not by itself proof of a deadlock.
- Typical frame latency in emulated software GL after first two slow swaps: ~2.2–2.7 seconds/frame; first two swaps each took ~15–20 seconds.

## What remains unproven
- No successful frontend or correct background rendering. Gameplay and Single Player navigation remain unverified.
- Need determine why game doesn't issue geometry draw calls: waiting for touch input, missing resources, or another game logic path.
- `src/s3e_input.c::input_pump` returns without controller when no SDL gamepad is found. QEMU/Xvfb has no gamepad, so a touchscreen gate may never be activated.
- **Next A/B**: diagnostic-only synthetic press (using actual S3E pointer callbacks, not fake game objects) at frame 5 and release at frame 6; compare resulting callback registrations, GL geometry counters and captured frames 10/15 with untapped baseline.
- If tap is ineffective, inspect failed `s3eFileOpen`/`s3eFileCheckExists` requests with `BOZ_FILE_RW_TRACE`, and investigate missing frontend resources.

## Relevant commits
- `93ce0bc`: null-registration guard.
- `8ff534b`: ARM build signedness fix.
- `afc0e31`: preserve partial QEMU traces on timeout.
- `b3a710a`, `e818f8a`, `1b2cdff`, `d3c434f`: PC sampling, ARM memory maps and ELF analysis.
- `4687486`, `ec23436`, `5685f19`: actual framebuffer captures and PNG/palette evidence.
- `039599a`, `e208376`, `ef8b5d9`: GL geometry draw counters and longer frame capture milestones.
- `2d2f089`: isolated A/B auto tap experiment (pending runtime validation at the time of this note).
