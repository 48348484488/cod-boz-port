# BOZ / ReviveOS external artifact recovery index

Generated 2026-10-02. This file records important artifacts that exist in the ChatGPT Library but are not necessarily stored in this Git repository.

## Current canonical development
Repository: 48348484488/cod-boz-port
Branch: master
Current diagnostic line: BOZ runtime under qemu-arm; investigating NULL returned by BOZ+0xDA6AC before crash at +0xDB31E.

## Library artifacts
| Name | Size | Library file id |
|---|---:|---|
| BOZ_PNG_INPUT_LENGTH_FIX_v2.zip | 3743073 | file_000000005eac820e9743dc8c9e2a1f7c |
| ReviveOS_BOZ_v1.2_png_integrado.zip | 56859988 | file_000000000548820ea4a438111887456c |
| BOZ_RESOURCE_MOUNT_FIX_v1.zip | 6843508 | file_000000005c90820e896dd054070f8790 |
| ReviveOS_BOZ_v1.2_resource_mount.zip | 59972655 | file_000000007b3c820ea5c4fcd9085d2c82 |
| BOZ_S3E_COMPRESSION_FIX_v1.zip | 27609 | file_000000000a08820ea9e9045916ba38cc |
| ReviveOS_BOZ_v1.1_pixel_guard.zip | 53123439 | file_00000000bbd8820e83ba5568f80bfca5 |
| BOZ_BIGTEX_ORIGIN_TRACE_v2.zip | 6541671 | file_000000000068820eac10bf413b95ab4b |
| BOZ_FRONTEND_SWF_TRACE_v2.zip | 21412 | file_00000000b4c4820e85279861e7266cb1 |
| BOZ_PIXEL_CONVERTER_FIX_v2.zip | 42566 | file_00000000212c820eb4841ecad4900d72 |
| BOZ_BIGTEX_ORIGIN_TRACE_v1.zip | 143476 | file_000000000214820ea6668dceb2ecfe08 |
| BOZ_RENDER_TRACE_300.json | 276935 | file_00000000fbec820ea539b3f62e852003 |
| FIRST_REAL_BOZ_FRAME.png | 690852 | file_0000000000ec820e8e8eeb62a423d4e7 |
| OpenBOZ-Recompiler-v0.2.4-source.zip | 44970 | file_000000002af8820ea4ba0a980592511b |
| OpenBOZ-Recompiler-v0.2.3-source.zip | 43080 | file_00000000b97c820e9105309e35dfee98 |
| OpenBOZ-Recompiler-v0.2.2-audiofix-source.zip | 31856 | file_000000007538820e91d0bc2c80e0668c |
| boz_level12_crash.txt | 26096710 | file_000000009198820e95b60fba61887c09 |

## Game/APK references retained in Library
These are intentionally indexed rather than redistributed from this public source repository.

| Name | Size | Library file id |
|---|---:|---|
| COD_BOZ_OpenBOZ_v0.2.4_first_open_method_signed.apk | 49791447 | file_00000000c2a4820e9383205084c56dd0 |
| COD_BOZ_OpenBOZ_v0.2.4_first_open_method_signed(1).apk | 49791447 | file_0000000057e0820e8d0511e49844aff4 |
| COD_BOZ_ReviveOS_v0.2.5_ASLR_FIX.apk | 49793924 | file_00000000f9ec8210a0047d02106fd876 |
| COD_BOZ_OpenBOZ_v0.2.3_audiofix_mainmenu_hook_signed.apk | 49791222 | file_000000003464820e92e9784840e4769c |
| COD_BOZ_OpenBOZ_v0.2.2_audio_race_fix_signed.apk | 49787774 | file_00000000d71c820eaec23c3decfcef87 |
| COD_BOZ_OpenBOZ_v0.2.1_mainmenu_slot8_hook_signed.apk | 49791193 | file_00000000a57c820eabc646366182f31a |

Known original compressed boz.s3e SHA-256 from the v0.2.4 APK:
f458c15a7111779ad320af377d0bb751294119788ba06d430bee0cc977539fee

Public diagnostic reference compressed boz.s3e SHA-256:
d50e4bf0b86a26a8ccef604b5edddb962684289f16004f7066d9671a0acc7f01

## Recovery rule
Do not delete Library artifacts until their useful source/patch/report content has been merged into the canonical repository. Large APK/game data should be restored from a legitimately held copy and verified by hash rather than committed to the public repository.
