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

## 2026-10-10 follow-up: original CDN and boot resource restoration

Evidence source: Render service `srv-daqv1a0473hc73978pv0`; logs at approximately
2026-10-11T00:34Z through 00:43Z.

1. **Input experiment (commit `2d2f089`)**: one S3E pointer-button callback
   did receive synthetic press at (320,240) on frame 5 and release on frame 6;
   no touch callback was registered; the background remained blank through at
   least 30 swaps. In this test all three geometry draw counters stayed zero.
2. **Resource resolution (commit `bf51957`)**: observed missing existence
   checks for `data-gles1/splash/splash.group.bin`,
   `data-gles1/fixed/fixed.group.bin`, and
   `data-gles1/frontend/frontend.group.bin`. The loader bundle contained
   `console.bin`, `bootstrap.group.bin`, and `style.group.bin` and opened
   them successfully. Only one ordinary file-open failed: `__ng__.dat` on
   initial read; it was then created, so that failure is not the frontend cause.
3. **Checked original CDN**: the verified S3E advertises
   `http://cdn-boz-android.callofduty.com/PROD/CODBOZ/1_0_9`.
   HEAD returned 200: `blackops_gles1.dz` length **337,594,086**;
   `blackops_etc.dz` length **487,603,915**.
   The public `blackops_loader.dz` contained 12 index entries, and
   **does not** contain splash/fixed/frontend group files.
4. **Partial exact-byte recovery (commit `e5ae89c`)**: HTTP 206 Range
   reads of the original `blackops_gles1.dz` DTRZ index (189 entries)
   recovered seven real group files, totaling **49,495,971 bytes**:
   - `frontend.group.bin` 39,214,526 bytes, SHA256 `016dd7ef792cad328d276c526cf934a3c520e9f2de0138d56e269b996d4306fa`
   - `fixed.group.bin` 1,334,029 bytes, SHA256 `d168ec622886f24054567f6ba45b4553a9dfeb81bf45ce06bbde6b296e88aa9a`
   - `splash.group.bin` 788,036 bytes, SHA256 `8c6ebf2c6a45d65b021d6e0187106e9c5ba80438cfca2f3709fb37b5c810c3af`
   - `splash_droid.group.bin`, `loading.group.bin`,
     `loading_droid.group.bin`, and `shared.group.bin` also recovered.
   These are staged to temporary `/tmp/assets/data-gles1` in the runtime.
   **No copyrighted game data was committed to GitHub.**
5. **QEMU A/B result with recovered groups**: all three previously missing
   group resources were opened successfully. GL texture upload records
   increased from **59 to 83** and `glDrawElements` from **0 to 4**
   by the fifth swap. Neither experimental null-object bypass was triggered
   (0 skip events; 0 SIGSEGVs observed). The fifth frame was still almost
   solid `#C0C0FF` plus cursor; no menu confirmed. Decode/render under QEMU
   became much slower (~97 seconds until fifth swap); 110-second timeout
   still applied.
6. **Full authentic archive experiment**: `stage_official_game_archive`
   opt-in support was committed separately to the fork; commit `33df707`
   pins SHA-256 for `blackops_gles1.dz` and `blackops_etc.dz` from the
   existing `codboz_setup`. This should be tested against the game-provided
   official CDN, rather than trusting file size alone. Download/playability
   is **not confirmed** in this note.

Next test: stage and verify complete `blackops_gles1.dz` before entering
the BOZ QEMU runtime, then inspect `S3E_FILE_OPEN`, `GL_UPLOAD_TRACE`,
`glDrawElements`, and real framebuffer snapshots. If still blank, inspect
render context/viewport/GL errors and additional missing asset requests.


## Resource recovery and first geometry draws — 2026-10-11 (confirmed)

- Tested original APK and Library archives: the 49–50 MB APK contains `blackops_loader.dz` but not the full resource packs or OBB payload. Its download database declares `main.1031105.com.atv.blackops.obb`, expected 494,902,736 bytes, with zero downloaded bytes.
- The verified BOZ `boz.s3e` binary includes a ResDownloadLink at the **original Activision CDN**: `http://cdn-boz-android.callofduty.com/PROD/CODBOZ/1_0_9`. Render verified HTTP HEAD 200 for `blackops_gles1.dz` (337,594,086 bytes) and `blackops_etc.dz` (487,603,915 bytes).
- Public reference `blackops_loader.dz` contains 12 DTRZ entries; it has bootstrap, style, console and localization, but **no** `splash.group.bin`, `fixed.group.bin` or `frontend.group.bin`. Diagnostic `BOZ_FILE_RW_TRACE` proved corresponding `s3eFileCheckExists` failures.
- Opt-in Range staging (`BOZ_STAGE_REMOTE_FRONTEND=1`, commit `e5ae89c`) downloaded and verified **seven genuine first-launch groups** (49,495,971 bytes) from `blackops_gles1.dz`: splash, splash_droid, fixed, frontend, loading, loading_droid and shared. The original frontend group is 39,214,526 bytes, SHA-256 `016dd7ef792cad328d276c526cf934a3c520e9f2de0138d56e269b996d4306fa`. This stage does not persist game data into Git.
- Subsequent opt-in full-download test (`BOZ_FETCH_OFFICIAL_GAME_ARCHIVE=1`, commit `eb3116a`) fetched all **337,594,086 bytes** of `blackops_gles1.dz` in Render, SHA-256 **`60846cf7a121ebaa200be82bd6811adcec44c607414b41086a6ffa1bd339b12c`**, validated 189 DTRZ entries and installed it under `/tmp/assets/`. The official legacy HTTPS endpoint has a certificate name mismatch, so this diagnostic used HTTP to the exact original official host after strict domain/size validation; a later commit `33df707` pins expected SHA before install.
- First runtime with seven groups, without the full archive: 83 GL texture-upload trace lines versus earlier 59; frame 5 background changed from `#8080FF` to `#C0C0FF`. Still no visible menu.
- **Full DTRZ runtime** (deploy `dep-db5dlu59mjac738edceg`): 132 GL texture-upload lines, five successful frame swaps, and **four real `glDrawElements` calls** in the first five frames versus **zero** before full resource recovery. Frame 5 remains nearly uniform `#C0C0FF` with cursor, with no visible menu. The test stopped at 135-second timeout, not SIGSEGV. No null-pointer protection hits or memory faults were logged in that limited run.
- Historical user-owned `BOZ_RENDER_TRACE_300.json` from September shows ~300 swaps and repeated pairs of `glDrawElements` (`count=6` and `count=792`) per frame. This is a different execution and useful only as a comparison, not a direct proof of equivalence.
- New diagnostic opt-in `BOZ_GL_DRAW_DIAGNOSTIC=1` (`cd425f6` and `13fdd61`) records up to 12 draw calls with GLES program, framebuffer, element buffer, viewport, scissor state and GL error. Its QEMU result was pending when this update was authored.

### Next bottleneck
Identify the precise render state and GL error for geometry drawn against a flat `#C0C0FF` framebuffer; determine whether the larger (`count=792`) draw seen in the historical trace is missing. Do **not** assert the frontend is fixed or game is playable until captured frames contain recognisable menu content.


## Texture provenance and actual zlib contract — 2026-10-11 10:20 UTC

The last QEMU diagnostic (deploy `dep-db5m480473hc73bl43og`, commit `578311de`) built ARM and passed all host tests, including the zlib ABI regression tests. It staged the official SHA-256-pinned `blackops_gles1.dz`, and loaded the signature-verified experimental PNG fix. QEMU ran for 115 seconds and captured five swaps without SIGSEGV, with frame 5 still nearly solid `#c0c0ff`.

**Confirmed from direct OpenGL state:** the full-screen geometry (`glDrawElements`, count 6, program 6, sampler 0) has `GL_TEXTURE_2D` object **58** bound in texture unit zero. That object was uploaded once as a **2 × 2 RGBA** image, first pixel `ff ff ff 80`, first-512-byte FNV hash `7eea891d3aca0693`. The exact same minuscule upload appears for dozens of texture IDs. Every one of the first five draws still samples texture 58, with no real-size update. This confirms a placeholder texture is bound where an actual frontend image should eventually appear; it does not yet prove whether the cause is failed resource resolution, failed decoder, or an incomplete frontend transition.

`s3eCompressionDecomp` was corrected from its failing stub to the five-argument ARM Marmalade interface using zlib (commits `55d26d5`, `9bf8418`) and tested. However, this BOZ execution logged **zero calls** to the decompressor, so that fix is not yet proven to affect the frontend. Similarly, program 9 and the 792-index draw in the older 300-frame trace have not appeared.

**Next:** enable resource open/check trace while the full DTRZ is present and run a controlled smaller viewport to reach more frames; compare when (or whether) `frontend.group.bin` is accessed, then trace the actual texture source. Avoid artificially substituting a non-game background.


## 2026-10-11: bottleneck measured at the Render container CPU quota

- Real, ARMHF QEMU execution with SHA-256-verified full original `blackops_gles1.dz` and `BOZ_FAST_MINIMAL_TRACE=1` still reached only five frame swaps in 145 s. At that cutoff, `frontend.group.bin` had processed **913,088 / 39,214,526 bytes** (2.33%), with no read errors and no SIGSEGV. Captured frame five remains a flat `#c0c0ff` field and cursor. Disabling GL upload pixel scans did not measurably improve this run.
- GitHub commit `a4d9c00` added opt-in `BOZ_QEMU_HOST_PROFILING=1` using Linux procfs. Its first run inadvertently measured the `xvfb-run` shell (blocked in `do_wait`), not the actual QEMU child. **The early 0.0 CPU reading was invalid**.
- Corrected collector commit `6616507` profiles the entire subprocess descendant tree, with cgroup CPU statistics. Render deploy `dep-db5msgdckfvc73aojlhg` confirmed actual QEMU PID 142 (19 threads) running, using ~256 MiB RAM and **0.14 CPU cores on average** (peak measured 0.152). The Linux cgroup `cpu.max` value was **`15000 100000`**: a limit of 0.15 CPU cores. The cgroup reported throttling in **1452/1452 scheduling periods**, and total CPU use of ~21.77 seconds over the 145-second diagnostic. Therefore this Render instance is **heavily CPU quota-bound**. This does not prove the BOZ frontend decoder is correct; it establishes a confounding limit on runtime progress.
- Commit `ba70e01` adds a diagnostic-only, opt-in `BOZ_PC_SAMPLE_UNGUARDED=1` flag. Previously `BOZ_PC_SAMPLE_INTERVAL` emitted samples only after the experimental null-registration guard actually triggered; since recent boots did not hit it, `pc_samples` stayed empty. This flag makes periodic guest PC samples possible without changing game control flow. It was deployed separately and must be assessed from its own logs.
- Added `.github/workflows/boz-qemu-accelerated.yml` (commit `040b56a`) with Ubuntu GitHub-hosted ARMHF/QEMU plus SDL2/GL software rendering dependencies, a longer 260-second timeout, real original-asset SHA checks, and diagnostic artifact uploads **excluding copyrighted game binaries**. The workflow is an alternative to upgrading the paid Render plan. **A completed GitHub Actions job and faster execution have not yet been verified**.

**Next gating evidence**: assess the runtime guest PC sample distribution and verify the GitHub Actions job can install ARMHF dependencies and actually execute QEMU. Only then compare wall time to `frontend.group.bin` byte progress and frame count. Never call the game playable until rendered frames show recognizable BOZ frontend and input works.


## 2026-10-11 single-thread Mesa comparison (verified)

The controlled A/B under the **same Render 0.15-core quota**, the same original
SHA-pinned `blackops_gles1.dz`, 640x480 viewport and 145-second timeout:

| Metric | Mesa default | `LP_NUM_THREADS=1`, `GALLIUM_NUM_THREADS=1`, `MESA_GLTHREAD=false` |
| --- | ---: | ---: |
| QEMU total thread count (late sampling) | 19 | 5 |
| Fifth swap since guest start | 101.1 s | 87.6 s |
| `frontend.group.bin` bytes processed at timeout | 913,088 | 1,175,440 |
| Frontend file read errors | 0 | 0 |
| Captured framebuffer at swap 5 | `#c0c0ff` with blue cursor | unchanged |
| CPU quota | 0.15 core | 0.15 core |

Deploy `dep-db5n2a4s728c738cfu40` finished `live`. The fifth swap
was **~13.4% faster**, and guest frontend resource consumption increased
**~28.7%**, but five swaps still completed within the test window. The
resource progress is measured *up to the test deadline*, not bytes used
to draw a visible background. The game menu remains **unverified**.

Guest PC sampling commit `ba70e01` yielded 35 samples: 24 consecutive late
samples at ARM guest PC `0x3f6e4656` within ARM libc mapping, with null guard
count still zero and no SIGSEGV. The most-frequent-address-first
symbolication improvement is commit `4aa3c36`; it has not yet been
measured in a new Render run.

The updated GitHub Actions workflow `0440a8f` uses Debian bookworm
multiarch and single-thread Mesa, and `remote_build.py` commit `08e214f`
adds `BOZ_EXIT_AFTER_DIAGNOSTIC=1` to complete without idling an HTTP server.
**GitHub Actions execution results are still unverified**; do not conflate
a committed workflow with a successfully executed job.


## 2026-10-11 first successful CPU-unthrottled BOZ runtime (confirmed)

- GitHub Actions workflow run [38136212818](https://github.com/48348484488/cod-boz-port/actions/runs/38136212818), commit `c266e32`, **completed successfully** and uploaded real diagnostic artifacts. Linux runner via Debian bookworm multiarch and ARMHF `qemu-arm`, SDL2, GLES1, GLX/EGL/Mesa software rendering. The unthrottled runner had cgroup `cpu.max = max 100000`, in contrast to Render's 0.15-core cap.
- The binary was the SHA-256-pinned S3E reference, and original full `blackops_gles1.dz` (337,594,086 bytes) downloaded from the original Activision CDN with **known SHA-256 validation**, and a strict single-host HTTP compatibility fallback due to a stale TLS hostname. No game data was committed.
- **`frontend.group.bin` was read completely and closed**: 39,214,526 / 39,214,526 bytes, 12,836 calls, 0 reported read errors, 0 seeks. Download and file availability are therefore no longer blocking this run's file parser.
- QEMU successfully presented **150 swaps** during a 260-second diagnostic deadline; swap 150 was at **253,432 ms** from the first swap, cumulative `glClear=151`, `glDrawElements=149`, `glDrawArrays=0`. **No signal 11 / SIGSEGV**. This is a real executed ARM game under a software GL stack, not a synthetic renderer.
- Actual 640x480 screenshots at swaps **5, 10, 15 and 60 are byte-identical** (PNG SHA-256 `ceb6fc52bfcc775ce8b07a503f4b5e5879efb3064c6583fd3ec244b47495d997`), containing only a nearly uniform `#c0c0ff` framebuffer and blue cursor. Thus **NO visible frontend and NO proven gameplay**, despite the game executing 150 swaps. The older Render trace had sampled a 2x2 placeholder texture with program 6/count 6, but it remained unproven that the same texture was bound at late frames.
- Action failures preceding success were resolved incrementally: native `libc6-dev`, ARM GLES1, ARM `libGL.so.1` (Mesa GLX/EGL), and strict SHA-pinned HTTP fallback on the original official host. The one-shot runtime and real PNG/swap assertions are implemented without changing the game binaries.
- Late draw / texture investigation: commits `1144bf4`, `0680092`, `2f2a98e` record first 12 and every 25th `glDrawElements` (GL program, geometry, FBO, texture ID/size/hash) without per-pixel GL_UPLOAD_TRACE. Workflow run [38136783823](https://github.com/48348484488/cod-boz-port/actions/runs/38136783823) was **in progress** when this note was updated; do not infer its result from the earlier 150-swap success.
- Commit `e085118` additionally captures actual framebuffer screenshots at swaps 100 and 150 in future runs. The first successful archive contained images only through swap 60.

**Next acceptance gate:** confirm whether late draws still bind the 2x2 placeholder and whether geometry grows beyond six indices/program 6. If yes, investigate frontend scene transition / texture source and decoder; otherwise inspect late GL state and shader program. The main CI `make format-check` failures on seven edited C/test files are a separate pending style issue, not a BOZ runtime regression.


## 2026-10-11: confirmed late GL placeholder plateau (run 38136783823)

- [GitHub Actions run 38136783823](https://github.com/48348484488/cod-boz-port/actions/runs/38136783823) finished successfully. ARM QEMU execution downloaded the original verified `blackops_gles1.dz`; its `frontend.group.bin` was **read completely and closed** with zero I/O errors.
- Sparse GL state sampling logged **17** real `glDrawElements` records, each accompanied by `glGetError() == GL_NO_ERROR`. Samples through calls **1, 50, 75, 100 and 125** were all exactly `mode=GL_TRIANGLES count=6, program=6, fbo=0` and viewport `640x480`. The documented older 300-swap trace's `program=9 / count=792` transition did **not** appear.
- Draws **1–75** sampled texture ID **58**, and draws **100–125** texture ID **59**; **both** were only `2x2 RGBA`, with a single upload and the exact same hash `7eea891d3aca0693` / first RGBA pixel `ff ff ff 80`. Texture 59 appearing is NOT evidence of real frontend background. Program 6 had 3 active attributes and 4 uniforms.
- Actual framebuffer PNGs through swap 60 remained byte-identical `#c0c0ff` with the debug cursor, and no segmentation fault was reported. The diagnostic exited at the 260-second deadline without verified menu or gameplay.
- **Conclusion limited to observations:** fully reading the frontend asset group is not sufficient for real GL images or larger frontend geometry to become active; investigate actual texture allocation/decompression and scene transition independently.
- Commit `8809eb2` adds size distribution accounting and read-only `glCompressedTexImage2D`/`glCompressedTexSubImage2D` forwarding diagnostics, emitting `[BOZ_GL_TEX_SIZE_TOTAL]` at swaps 5/60/100/150. Commit `8a94495` collects these counters; workflow update `2b427e8` adds a CI assertion for real texture-size snapshots. **These new counters have not yet been verified by a completed run**.
- A separate Render profiler experiment `220f7c3` initially failed from `NameError: thread_cpu_totals` and a legacy HTTPS certificate mismatch. Commit `e92566b` fixes the scope bug, and the strict SHA-pinned official-host HTTP option was restored for its next deploy. Do not cite the failed test as a valid thread profile.


## 2026-10-11 late frontend pointer test (implementation committed; outcome pending)

The accelerated QEMU trace loaded all 39,214,526 bytes of
`frontend.group.bin` and closed it **between guest swaps 100 and 125**.
Previous `BOZ_DIAGNOSTIC_AUTO_TAP=1` used frames 5/6, before the
frontend was ready, so it could not conclusively test the expected
"touch screen to continue" transition. Do not claim it disproved input gating.

Commit `67a4290` adds a strictly opt-in `BOZ_DIAGNOSTIC_LATE_TAP=1`
experiment: call the existing S3E pointer dispatch **press at swap 125**
and **release at 126**; capture actual original framebuffer at swaps
125, 130 and 140 (plus previous 100 and 150 milestones).
It leaves normal game runs unchanged. Commit `fed756a` enables the
experiment in the accelerated GitHub Actions workflow and verifies that
both callback attempts and post-tap frame swaps occurred. Commit
`5eea07d` prints before/after framebuffer hashes and palette sizes
so differences can be compared with the zero-tap historical run.
A different image hash alone is **not** proof of the actual menu; actual
visible content and associated input transitions are required.

**Awaiting actual run evidence:** callback registration and consumption,
frame-100 versus frame-140 screenshot hashes and GL texture/geometry
post-tap changes. A committed workflow is not an executed or successful
experiment until logs and artifacts confirm the result.
