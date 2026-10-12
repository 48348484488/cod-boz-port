# BOZ frontend visibility — verified ARM/QEMU evidence (2026-10-12)

Scope: the fork `48348484488/cod-boz-port` only. No original game assets or frame pixels are committed.

## Verified real-runtime evidence

- [Run 38151413957](https://github.com/48348484488/cod-boz-port/actions/runs/38151413957), commit `3a0aec6`, completed successfully, without SIGSEGV.
- The guest consumed 39,214,526 bytes from `frontend.group.bin` and subsequently drew many indexed GL elements.
- Vertex shader program 6 was linked. First captured fullscreen quad indices: `0,1,2,3,0,2`; logical vertex coordinates: (0,0), (0,3840), (5120,3840), (5120,0).
- Real sampler `inSampler0` uses texture unit 0 in sampled programs 6, 9 and 18. Examples: program 9 uses texture 56 (512×512); program 18 uses texture 62 (1024×512).
- 5-region byte sampling found actual nonzero data in large textures. RGBA4444 alpha of texture 56: 44/160 sampled pixels nonzero; texture 62: 14/160 nonzero. Do not infer complete texture opacity from these samples.
- Program 6/9 calls sampled GL_BLEND=on, SRC_ALPHA/ONE_MINUS_SRC_ALPHA and GL_CULL_FACE=on. Program 12/18: GL_BLEND=off, GL_CULL_FACE=on. The latter may be intentional; do not patch without a controlled comparison.
- The captured frame 300, before diagnostic cursor overlay, consists of precisely 3 horizontal uniform regions: RGB(28,26,25) rows 0–144 and 336–479; RGB(131,121,120) rows 145–335. This is **not** the recognizable menu.
- Before/after overlay frame captures show identical content apart from 185 pixels of diagnostic cursor. The cursor does not occlude an existing menu.
- All sampled glDrawElements returned GL error 0. Absence of a GL error does not guarantee visible triangles.

## Current experiment

Commit `4e4999c46e7b2380f8027386c301695a0849e1b8` adds opt-in `BOZ_GL_VISUAL_AB_PROBE=1`:

- Frame 300: ordinary draw (control).
- Frames 325–349: disable culling around guest draw, then restore.
- Frames 350–374: enable blending around guest draw, then restore.
- Frames 375–399: both changes, then restore.
- Frame 400 onward: ordinary state again.

This is **diagnostic-only** and deliberately restores GL state after each draw. Compare actual PNG hashes, color populations and pixel differences for swaps 300/325/350/375 (and 400 when captured). Do not infer success from hash alone: changing the cursor affects hash.

Workflow [38209655310](https://github.com/48348484488/cod-boz-port/actions/runs/38209655310) executes the probe under real ARM/QEMU. If the framebuffer does not change, investigate geometry winding, vertex attributes, UV scale/offset, render-target content, or missing frontend transitions rather than forcing a permanent culling/blend override.

## Acceptance

Visible and recognizable original frontend is required before claiming the menu works. A shader link, successful asset read, nonzero texture payload, 400 swaps, or an opaque two-tone background alone is insufficient.
