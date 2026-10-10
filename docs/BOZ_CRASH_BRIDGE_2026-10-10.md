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


## D8F0E fallback is a registered-handler lookup, not an allocator

The runtime-linked Thumb disassembly emitted on 2026-10-10 shows:

- 0xD8F10: LDR r6, [r0, #44] — obtain registry/sentinel pointer.
- 0xD8F12: LDR r5, [r6, #4] — load the tree root.
- 0xD8F16..0xD8F28: walk the ordered search tree comparing key
  from the node at offset +16 against input r2.
- 0xD8F2A..0xD8F38: compare the candidate to the sentinel and
  check its key. If no match, branch to D8F44.
- 0xD8F3A: LDR r2, [r4,#20] — load callback from the node.
- 0xD8F40: BLX r2 — invoke registered callback. Callback may
  itself return NULL.
- 0xD8F44: MOVS r0, #0 — explicit no-handler result.
- 0xD8F46: return.

This makes two possible and distinguishable failure conditions:
(1) the selector provided by the second owner call was absent in
the registry, or (2) a callback was found and returned null. Both
cause DA72C r0=0. Neither outcome should be assumed in advance.

To settle this, we added deferred runtime probes in D8F0E on the
SECOND owner invocation, recording the root, sentinel comparison,
handler call, and absent-entry branch. Regression tests check both.


## 2026-10-10 sparse second-call trace: missing selector identified

The targeted Render run dep-db543pnavr4c73fd24bg
(commit 147863fea7339c7bbbc9a7ca721c94d58f204840)
passed 16 existing regression tests and reproduced RC=139.

During the second owner's factory path D8F0E, the first registry lookup
used key 0xE2E16F9C. It reached the BLX handler at 0xD8F40, which
returned a nonzero object pointer (0x40B34A40 at D8F42).

A later D8F0E lookup used a different key, 0x40B34AC0, and selected
the registry sentinel at 0xD8F36 (r4==r6==0x40A28A68).
This traversal executed D8F44 (MOVS r0,#0), then D8F46 (r0==0):
**no matching callback was registered for that key in this registry
at lookup time**. That is the directly observed reason for the
fallback factory's zero return in the sparse trace.

This does **not** establish why that key is missing: wrong key,
unregistered class, initialization order, incomplete runtime service,
or a missing asset are distinct hypotheses.

## Callback call/return-pair improvement

The earlier 42-probe capture was ambiguous because D8F40 and D8F42
were both armed as independent one-shot BKPTs and could be confused
with adjacent instruction addresses or unrelated invocations.

New commit series adds optional BOZ_TRACE_HANDLER_PAIRS=1:
- Wait for second owner dispatch at DB31C.
- Arm D8F40 only.
- On D8F40, preserve target in r2 and arm D8F42.
- On D8F42, record actual r0 result for the same BLX invocation.
- Repeat, capped at 48 correlated pairs.
- tools/boz_handler_pairs.py rejects incomplete/unmatched pairs.
- The crash-bridge run disables default mass probes and selects a
  minimal focus set to avoid unrelated/adjacent breakpoint confusion.

The new instrumentation is diagnostic; **no fake callbacks or game
objects are inserted**. Functional recovery remains blocked until the
registration path or wrong selector provenance is confirmed.


## 2026-10-10 focused 9-probe runtime — final evidence

Render deployment dep-db546gid0e5s73e50qh0 (commit
e2c5a0936262fc4b99d557511089744282058432) was LIVE.
ARMHF build and make test-host passed with **20 regression tests**.

To disambiguate callback paths, the runner used only 9 Thumb probes
and BOZ_TRACE_HANDLER_PAIRS=1. The run reached the fault at DB31E,
exit status 139, and recorded:

- DB31C: second owner call triggered deferred probe arming.
- DA728: selector r2=0x40B34B20 passed to D8F0E.
- D8F0E: manager=0x4065CF68, requested selector r2=0x40B34B20.
- D8F14: loaded registry sentinel r6=0x40A28AC8 and **nonzero**
  root r5=0x40B34940.
- D8F36: candidate r4=0x40A28AC8 equals sentinel r6.
  The lookup thus has no matching node for this requested selector.
- DA72C: fallback returned r0=0.
- DB31E: null-object fault repeated, RC=139.
- HANDLER_PAIR summary: count=0, null=0, incomplete=0,
  orphan=0. This is expected for a lookup that does not invoke
  a handler, not evidence that a registered callback returned null.

In an earlier independent run, the missing selector was 0x40B34AC0
instead; these addresses vary across executions and must not be
hardcoded as the faulting selector. We have confirmed a missing
registered entry at the instant of lookup, NOT whether the selector
is wrong or a registration step was skipped.

Next investigation must trace the owner-call fifth argument, loaded
into r8 from [sp,#56] at DA6BA. The caller at DB306 loads this value
from [sp,#28] and stores it to its fifth argument slot at DB30E.
The preceding call to 0x257B98 and registration writes to the
manager's tree at +0x2c are the next static/runtime investigation
targets. Do not invent a callback pointer or bypass the null check.


## 2026-10-10 selector provenance and S3E file-I/O

The recovered, unpacked S3E (SHA-256 of unpacked image:
dbf342663fcd8c7f8fcedced1693eb532cbea8053ef472c0cb837323f3b57d95)
has a header-defined code offset 0x39483. No proprietary bytes are
included in this repository. Offline ARM/Thumb disassembly was verified
against the runtime-emitted instructions using clang and llvm-objdump;
tools/boz_s3e_disasm.py reproduces it for locally supplied S3E images.

The actual S3E fixup/symbol relocation table resolves these ARM PLT stubs:
- BOZ+0x6B4 -> s3eFileWrite (GOT 0x411214)
- BOZ+0x77C -> s3eFileRead (GOT 0x411254)

The S3E ARM routines 0x257B98 and 0x257CA4 use these imported
serialization operations according to mode flags. The meaning of the
mode **must be measured at runtime**, not guessed. The new
tools/boz_s3e_imports.py computes the symbol names from fixups.

A real Render run (dep-db54iu7lk1mc738nlnag, 2026-10-10)
recorded before/after 0x257CA4 (DB294 -> DB298), before/after 0x257B98
(DB2FA -> DB2FE), before DB306 and at DB31C. The selector's
stack word [sp,#28] stayed 0x40B35AC0 throughout; the fifth
argument at DB31C and D8F0E key were also 0x40B35AC0.
The new analyzer confirmed a complete preserved chain.

Crucially, that run logged
[SELECTOR_FILE_IO] matched=1 incomplete=1:
an emulated S3E read/write call targeting the precise input buffer
at DB2FA transferred fewer elements than requested.
This is an **observation** and does not yet prove a missing game file,
because the operation kind, handle and EOF/error details were
not included in that run's summary. The next deployment logs
the exact operation, return count, EOF/error and file open path,
without modifying in-game behavior.

A nonzero stale pointer in a serializer destination is not proof
that that pointer is a valid registered type. Work must first identify
which file/stream call was incomplete and whether the real game
resource was available. Do not fabricate a registry entry.
