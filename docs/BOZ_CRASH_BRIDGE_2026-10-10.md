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
