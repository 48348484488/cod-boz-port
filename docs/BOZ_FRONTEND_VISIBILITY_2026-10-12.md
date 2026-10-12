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

## Completed texture and clear state investigation

- [Run 38213011265](https://github.com/48348484488/cod-boz-port/actions/runs/38213011265), commit `5422ddd`, **success**, without SIGSEGV.
- Programs 6, 9 and 18 report `inUVScale=(0.000244141,0.000244141)` and `inUVOffset=(0,0)`. This matches a 1/4096 scaling convention, but does **not** prove each incoming UV attribute is valid.
- Sampled texture 56 (512×512) and 62 (1024×512) have `GL_TEXTURE_MIN_FILTER=GL_LINEAR (0x2601)` and `GL_TEXTURE_MAG_FILTER=GL_LINEAR`; neither requires mipmaps. Wrap mode is `GL_REPEAT (0x2901)`.
- Program 12 has no `inUVScale` or `inUVOffset`; its sampled texture unit 0 is texture 0 with the default min filter. Do **not** attribute its draw to a missing mipmapped texture unless it actually samples a texture.
- Guest `glClear` at swaps 275 and 300/305/310/315/320 uses `mask=0x4100` (color+depth), framebuffer 0, no scissor and `rgba=(0.501961,0.501961,1,1)`, return address `0x4A2D9DEC`.
- Captured framebuffer after swaps 300–350 instead consists of dark RGB(28,26,25) regions and center RGB(131,121,120). Thus **drawing after the guest clear changes the framebuffer**, despite the missing recognizable menu.
- The remaining task is to identify which draw produces these stripes, distinguish intended flat-color geometry from missing textured geometry, and verify input UV attributes.

## Current framebuffer attribution experiment

- Commit [b0662c8](https://github.com/48348484488/cod-boz-port/commit/b0662c8f2ef19aacf35bd956900e0b5f563774d6) adds opt-in `BOZ_GL_PIXEL_TRAIL`.
- On swap 300, after each actual guest `glDrawElements`, it reads a single 1×321 RGBA strip to sample x=320 at GL y=80 (bottom), y=240 (middle) and y=400 (top), and logs the current program, texture ID, draw index count and three RGB values. This is read-only.
- [Run 38214365049](https://github.com/48348484488/cod-boz-port/actions/runs/38214365049) executes the test in real ARM/QEMU. The resulting asset-free `boz-diagnostics/docs/boz-latest-ci.json` should contain `pixel_trail` only after its provenance `run_id` becomes `38214365049`.
- Locate the first draw whose sampled colors transition from the clear color to the final dark/gray stripes; trace its program, bound texture, and vertex geometry before modifying renderer behavior.

## Draw coverage correction (verified)

The full `boz-fast-property.log` from [run 38213011265](https://github.com/48348484488/cod-boz-port/actions/runs/38213011265) shows:

| Counter | Swap 295 | Swap 300 | Added |
|---|---:|---:|---:|
| `glDrawArrays` | 351 | 441 | **90** |
| `glDrawElements` | 404 | 414 | **10** |

Therefore the late scene has roughly **18 array draws + 2 indexed draws per swap**. The initial `BOZ_GL_PIXEL_TRAIL` in commit `b0662c8` sampled only indexed draws and could miss the source of the frame's dark/gray stripes.

Commit [3aa034a](https://github.com/48348484488/cod-boz-port/commit/3aa034a1c6a35809dbf1575d9062a7198a0a47e4) addresses this by sampling the framebuffer **after both real GL draw entry points** with a combined chronological `order` counter, tagged `kind=arrays` or `kind=elements`. It retains the existing asset-free three-pixel summary and changes no game pixels. Verify it in [actual QEMU run 38215180010](https://github.com/48348484488/cod-boz-port/actions/runs/38215180010).

Do not interpret the original indexed-only trace as proof that an indexed draw created a stripe if an intervening array draw could have overwritten the framebuffer.

## Acceptance

Visible and recognizable original frontend is required before claiming the menu works. A shader link, successful asset read, nonzero texture payload, 400 swaps, or an opaque two-tone background alone is insufficient.
