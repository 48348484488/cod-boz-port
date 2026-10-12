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

## Completed reversible framebuffer-state experiment

- [Run 38210750883](https://github.com/48348484488/cod-boz-port/actions/runs/38210750883), commit `456a5dd`, **success**, without SIGSEGV.
- Controlled per-frame treatments: swap 300 original; 305 culling disabled; 310 blending enabled; 315 both; 320 original again. Experimental state was restored after every indexed draw.
- `BOZ_GL_VISUAL_AB` records confirm the requested state changes were made: `changed_cull=1` at 305, `changed_blend=1` at 310, both at 315.
- All five post-overlay PNG SHA-256 hashes match **exactly** (`81a9cd49fe4a5c13893b452d8d5e73d4ae9a547361a2712930969e72ed59b7c7`); pre-overlay hashes likewise match. Therefore neither disabled face culling nor forced alpha blending rendered additional frontend elements in this scene. **Do not ship either change** as a purported fix.

## Current texture sampling and clear provenance experiment

- Commit [5422ddd](https://github.com/48348484488/cod-boz-port/commit/5422ddd29ed1fa1a7a8ac797ba047924ded44f7f) adds read-only diagnostics for each sampled guest draw:
  - `BOZ_GL_UV_STATE` records the *actual* `inUVScale` and `inUVOffset` values of the active shader.
  - `BOZ_GL_TEXTURE_PARAMS` records texture unit 0's actual min/mag filtering and wrap modes, without changing sampling state.
  - `BOZ_GL_CLEAR_CAUSE` records guest `glClear` mask, color, scissor, framebuffer and caller for frames 275/300/305/310/315/320.
- [Run 38213011265](https://github.com/48348484488/cod-boz-port/actions/runs/38213011265) is the actual ARM/QEMU execution for this commit. Inspect the report in `boz-diagnostics/docs/boz-latest-ci.json` **only after** its provenance `run_id` becomes `38213011265`.
- Interpret this evidence before deciding on a fix: incomplete mipmap texture, incorrect UV transform, screen-clearing overwrite, or a separate scene-transition issue. These are hypotheses, not confirmed defects.

## Acceptance

Visible and recognizable original frontend is required before claiming the menu works. A shader link, successful asset read, nonzero texture payload, 400 swaps, or an opaque two-tone background alone is insufficient.
