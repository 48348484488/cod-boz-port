# BOZ Recovery State

Updated 2026-10-01.

## Verified recovered payload

- `assets/boz.s3e`
  - size: 1,902,539 bytes
  - SHA-256: `f458c15a7111779ad320af377d0bb751294119788ba06d430bee0cc977539fee`
- `assets/blackops_loader.dz`
  - size: 5,289,707 bytes
  - SHA-256: `41f00e3418ca2833e2bc5cb936c7600083b7c757500e0646912d92fda899a597`

These were recovered from historical BOZ APKs and are not redistributable game data.

## Main resource status

The frontend/main resource archives are still missing from the recovered APKs:

- `blackops_dxt.dz`
- `blackops_etc.dz`
- `blackops_atitc.dz`
- `blackops_gles1.dz`

Historical verification records identify a previously verified-cache copy of `blackops_dxt.dz`:

- source: `proof/cache/blackops_dxt.dz`
- expected size: 5,289,743 bytes
- SHA-256: `9ce68bd76c1c65f409952d5c71607e68f3e97ab05193c075248af20e00cbe408`
- DTRZ validation: true

The actual bytes of that cache file have not been recovered into the current working filesystem, so this record must not be treated as possession of the archive.

## Runtime evidence

The preserved BIGTEX v2 trace reached:

- 360 swaps
- 6 `glTexImage2D` uploads
- 3,669 verified ARM copies
- loader-only execution
- frontend not validated

The trace also records `blackops_dxt.dz` lookup failures. Therefore the checkerboard/frontend issue has not been falsely attributed to the GL upload path.

## Reproduction rule

Do not commit proprietary game-resource bytes to this public repository. Keep only source code, hashes, diagnostics, manifests, and reproducible tooling here. When the user supplies an authorized resource archive, run the real frontend/GL trace against those bytes.
