# BOZ: crash bridge and pre-instruction register correction (2026-10-10)

## Confirmed behavior from real BOZ runtime

Observed in Render `srv-daqv1a0473hc73978pv0` on 2026-10-05
and reproduced 2026-10-10 with the BOZ public reference S3E under qemu-arm.
Both runs reached the NULL dereference at 0xDB31E (exit status 139).

| Offset | Instruction | Observed state | Meaning |
| --- | --- | --- | --- |
| 0xDA70E | mov r4,r0 | r0=0 | Primary creation returned null |
| 0xDA72C | mov r4,r0 | r0=0x40B34A28 | Fallback creation returned a pointer |
| 0xDA792 | bl 0xDA5A4 | earlier probe | Calls tree-insertion helper in one path |
| 0xDA79A | mov r0,r4 | r0=0, r4=0x40B34A28 | **Before MOV**, not owner function return |
| 0xDA79C | instruction after MOV | new breakpoint | Will test whether r0 now equals r4 |
| 0xDB31E | crash site | r0=0 | NULL dereference at a later call |

**Important correction:** The former `null_owner_returns=1` metric is
wrongly named because breakpoints trap **before** executing the target
instruction. At DA79A the routine executes `mov r0,r4`. A zero
pre-instruction r0 with a nonzero r4 is entirely compatible with a
nonzero return after the instruction. The prior report's assertion that
the owner itself returned null was unsupported. We have removed that
claim from the active analyzer.

The runtime probe is a **one-shot trap**. Even a post-MOV capture at
DA79C may belong to a different invocation from the later fault at
DB31E. To prove provenance requires per-call correlation or a more
specific caller trace.

## Follow-up implementation

- `tools/boz_bridge_diagnosis.py` now reports both pre- and post-MOV
  observations. It does not present temporal correlation as a causal
  proof.
- `remote_build.py` adds DA79C only when the disassembly shows a
  16-bit `mov r0,r4` at DA79A and the next instruction begins at DA79C.
- `tests/test_boz_bridge_diagnosis.py` covers real register samples,
  misordered probes, missing fields, and instruction-boundary validation.

## Remaining work

1. Read actual DA79C r0 and compare with previous DA79A r4.
2. Determine whether the later zero at DB31E came from the **same**
   call. Do not infer this from single-shot traps.
3. Investigate whether the manager lookup, fallback allocation or
   registration path produces null on a different invocation.
4. Re-test the game. This diagnostic change is not yet a crash fix.

No copyrighted BOZ resources are stored in the public repository.

## Subsequent confirmed factory path (2026-10-10)

Live QEMU/Render probes proved that the first fallback pointer survives
DA79A MOV: before the instruction, r4=0x40B34B50 and r0=0;
at DA79C, *after* MOV, r0=0x40B34B50. The apparent null owner
return was an instrumentation interpretation error, now fixed.

The next call at DB31C entered the DA6AC path with r2=0.
At DA70A, r2 was still 0. D94E4 (the primary factory) returned zero
and the caller later crashed at DB31E.

The following instructions prove the primary factory's null-argument
short-circuit, for this observed binary/version only:

| Address | Thumb instruction | Effect |
| --- | --- | --- |
| D94EE | mov r4,r2 | Preserve argument r2 |
| D94F2 | cmp r2,#0 | Test argument for null |
| D94F4 | beq 0xD95BC | Jump directly to return on null |
| D95BC | mov r0,r4 | Place null into return register |
| D95BE | ldmia.w sp!,{...,pc} | Return to caller |

C++-style **partial** behavioral reconstruction, with no claim of
recovering source variable names or entire function:

    if (arg_r2 == nullptr) return nullptr;

The remaining unknown is why the caller provides a null r2 for the
second invocation. The immediate null factory result is by design;
the crash occurs when subsequent code assumes the return is non-null.

Current investigation inspects the Thumb instructions around DB31C
and preserves their disassembly as a separate artifact. Do not patch
the factory to invent a non-null object without identifying the
required argument and initialization path.


## Deferred probes: second invocation conclusively isolated

2026-10-10 Render deployment dep-db529it9fdbs73bbvntg used
BOZ_DEFER_OWNER_SECOND=1, arming 9 Thumb probes when hitting the
0xDB31C dispatch breakpoint. The ARMHF loader built successfully,
14 Python diagnosis regression tests passed and the QEMU run
reproduced the crash at 0xDB31E (RC 139).

The *second* owner invocation (rather than an earlier first-shot
observation) hit:
- 0xDA71C: r8=0x40B34AC0, r3=0x7C955BF1 -> NOT equal.
- 0xDA728: fallback call with r2=0x40B34AC0.
- 0xDA72C: **fallback returned r0=0**.
- 0xDA72E/0xDA730: zero result detected, taken branch back to
  0xDA702 according to confirmed disassembly.
- 0xD94E4: primary factory called with r2=0.
- 0xD95BE: primary factory returned r0=0 as specified by the
  0xD94F2 null short-circuit.
- 0xDB31E: caller dereferenced null; exit status 139.

The exact fallback rejection reason inside BOZ+0xD8F0E is
NOT YET KNOWN. The factory might reject the provided selector,
a missing resource, or an unsupported host service; do not
assign a cause without probing. The next investigation targets
D8F0E and its return paths on the **second** invocation. No
memory patch or non-null fabricated object was introduced.
