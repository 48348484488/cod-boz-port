# BOZ / ReviveOS Recovery

This directory stores reproducible recovery metadata and checkpoints for the BOZ/ReviveOS work.

## Current checkpoint

- ARMHF cross-build on Render: PASS (make rc=0)
- QEMU ARM execution: waiting for diagnostic input
- GL trace flag: GL_UPLOAD_TRACE=1
- Expected trace: /tmp/boz_gl_upload_trace.log
- Render service: srv-daqv1a0473hc73978pv0
- ARMHF libc fix commit: 299182d8a109d0d247d5bc643235e793b14d0bd6

## Diagnostic input identity

The game binary itself is not committed here. Recover it from the user's owned BOZ package and verify before use.

- filename: boz.s3e
- expected size in APK: 1902539 bytes
- SHA-256: f458c15a7111779ad320af377d0bb751294119788ba06d430bee0cc977539fee
- unpacked size: 4550559 bytes
- unpacked magic: XE3U
- known package: COD_BOZ_OpenBOZ_v0.2.4_first_open_method_signed.apk
- known package size: 49791447 bytes
- APK path: assets/boz.s3e

Never substitute a different binary without recording its hash.

## Resume sequence

1. Recover the known APK/S3E.
2. Verify SHA-256.
3. Supply the S3E to the Render diagnostic runner.
4. Run the ARMHF loader under qemu-arm with GL_UPLOAD_TRACE=1.
5. Preserve runner report and boz_gl_upload_trace.log.
6. Determine whether checkerboard pixels originate in BOZ or in the ReviveOS upload/conversion path.
7. Commit code fixes plus non-proprietary traces/reports/checkpoints here.
