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


## Byte-level confirmation from locally recovered APKs

On 2026-10-10 we read actual `assets/boz.s3e` from three recovered APKs:
- `COD_BOZ 1.0.12.apk`
- `COD_BOZ_ReviveOS_v0.2.5_ASLR_FIX.apk`
- `COD_BOZ_OpenBOZ_v0.2.4_first_open_method_signed(1).apk`

All three embed the **same compressed S3E bytes**:
- Size: 1,902,539 bytes
- SHA-256: `f458c15a7111779ad320af377d0bb751294119788ba06d430bee0cc977539fee`

LZMA FORMAT_ALONE decompression of each produced identical XE3U images:
- Size: 4,550,559 bytes
- SHA-256: `dbf342663fcd8c7f8fcedced1693eb532cbea8053ef472c0cb837323f3b57d95`

The restored `boz.s3e.unpacked` file matches all three decompressed
images byte-for-byte. Thus, the function offsets discussed in this
document refer to the same uncompressed executable across these
recovered builds. APK runtime wrappers, resource bundles, and original
game assets may still differ; this verification does not prove that
complete BOZ gameplay has been restored.


## ARM 2FE0A8 proof from restored XE3U (2026-10-10)

Static disassembly was performed on the locally restored
`boz.s3e.unpacked` with verified XE3U code offset 0x39483,
using clang's ARM backend and llvm-objdump. This is from the
same 4,550,559-byte game image whose SHA-256 is recorded above.

Selected real instructions:

| BOZ offset | ARM instruction | Effect |
| --- | --- | --- |
| 2FE088 | push {r0,r1,r4,r5,r6,lr} | Save caller registers |
| 2FE08C | mov r4,r0 | Copy input object into r4 |
| 2FE090 | mov r5,r1 | Copy second argument |
| 2FE094 | bl 30CB4C | Call initializer/global supplier |
| 2FE098 | add r6,sp,#4 | Prepare stack result buffer |
| 2FE0A4 | blx 20F26C | Call Thumb helper |
| 2FE0A8 | ldrh r3,[r4,#44] | Read 16-bit field from object |
| 2FE0AC | tst r3,#64 | Check object flag |

The QEMU failure had PC=BOZ+0x2FE0A8, fault address
0x0000002C (44), and SIGSEGV. On this exact LDRH this
proves the effective base r4 was 0 for the crashing
invocation. The first-shot probes in an earlier run did not
capture that invocation reliably: a pre-instruction sample at
2FE0A8 had nonzero r4, so it must not be treated as the
same failing call.

The Thumb helper at 0x20F26C performs
PUSH {r3,r4,r5,lr} and returns with POP {r3,r4,r5,pc};
therefore it appears to preserve r4 as required by the ARM
calling convention. This does **not** rule out other
implementation or runtime corruption; it narrows the
question to the caller-supplied object pointer and the
remaining nested calls.

The updated crash handler now logs full fault-time ARM
registers; tools/boz_new_crash_regs.py and its regressions
separate definitive SIGSEGV state from unrelated one-shot
probes. Next step is correlate the object argument to its
caller at BOZ+2FFA30 or BOZ+300444, without patching
a fake non-null pointer or claiming the gameplay works.


## Actual Thumb caller and upstream null lookup (2026-10-10)

The full register crash trace in Render (dep-db557134a5bs73dciamg,
2026-10-10 15:07 UTC) conclusively reports
PC=BOZ+0x2FE0A8 and **r4=0x00000000**. Test suite and five
new crash-regs regressions passed.

The preserved stack from the same crashing invocation contains:
- [sp+0]=0x00000000: initial r0 pushed by 2FE088.
- [sp+20]=0x4A20FE53: saved LR, identifying Thumb caller at
  BOZ+0x20FE4E (return address 0x20FE52, Thumb bit set).

This is not the earlier assumed ARM caller at 2FFA30 or
300444. The relevant Thumb function starts at BOZ+0x20FE1C:

| Offset | Instruction | Evidence |
| --- | --- | --- |
| 20FE1E | ADD.W r4,r0,#0x24 | Prepare pointer holder |
| 20FE2E | BLX 302028 | Test holder before proceeding |
| 20FE38 | BLX 2FD518 | Lookup/construct pointer |
| 20FE3C | MOV r1,r0 | Use lookup return as stored value |
| 20FE40 | BLX 302010 | Store value; 302010 is STR r1,[r0] |
| 20FE46 | MOV r0,r4 | Pass pointer holder |
| 20FE48 | BLX 302020 | Load pointer; 302020 is LDR r0,[r0] |
| 20FE4E | BLX 2FE088 | Use the pointer without null guard |

At the crashing invocation, the stored pointer and the loaded
argument are null. This strongly implicates the result of
2FD518; exact per-call probes are now added at 2FD518,
2FD568, 20FE3C and 20FE4E to verify it dynamically.

The ARM function 2FD518 has a **real zero return path**:
- When argument r1 is zero (as provided at 20FE34),
  it calls Thumb 2352F8.
- At 2FD568, it tests r0 and returns immediately on zero.
- Otherwise it branches to 2FD4E0 to create an object.
- 2352F8 calls 24BA2C and continues to 235220 for
  lookup/dispatch. Do not claim which resource or registry
  entry is missing until the runtime path is measured.

These disassemblies are from restored, verified
boz.s3e.unpacked; no game bytes have been checked into GitHub.
No fake pointer or unconditional bypass has been applied.


### Static lookup logic at 235220

Direct Thumb disassembly of the restored S3E shows a further
failure path in BOZ+0x235220, reached through 0x2352F8:

- 0x235246 loads the entry-array pointer from manager+0x44;
- 0x235248 loads the entry count from manager+0x48;
- 0x235250/0x235252 compare the cursor to the end;
- 0x235258 loads an entry key from node+0x4;
- 0x23525A compares the entry key with the requested type;
- 0x235272 sets r0=0 if traversal finishes with no accepted entry;
- 0x235298 returns that result.

This **proves that an absent matching type can propagate a
null pointer through 2FD518 to the 20FE4E call**. It does not
yet prove the missing type at runtime; the new typed
ARM/Thumb probes will check the path.


## Experimental non-fabricating null-child A/B (2026-10-10)

The baseline crash is PC=BOZ+0x2FE0A8, ARM LDRH r3,[r4,#44]
with r4=0 and fault address 0x2C. The unmodified primary QEMU run
still returns RC=139 at the same location.

Commit 9d83284e89ed34dfc8f02d139e6f664d0e966d6e added an
**opt-in, bounded, diagnostic-only** SIGSEGV continuation gated by
BOZ_COMPAT_NULL_CHILD_SKIP=1. For this exact ARM PC and r4=0,
it skips the invalid child copy and resumes at BOZ+0x2FE0F8,
the routine's original temporary-object cleanup path
(MOV r0,r6, BL destructor, stack epilogue). It does not create a fake
object. At most 128 such continuations are allowed; defaults are OFF.

Commit a4ef9c3241931880d374dba063ed885c19247ec7 enables this
flag **only in the crash-bridge A/B run**, not in the primary run.

The Render deployment dep-db55iqrbc2fs73edjurg compiled successfully,
passed make test-host and reproduced the baseline fault. The
experimental crash bridge (also RC=139) advanced past 2FE0A8 and
recorded a *different* fault:

- PC=BOZ+0x2FE7D0; ARM instruction STR r1,[r0,#0x90]
- r0=0, effective fault address 0x90
- LR=BOZ+0x301F04, identifying the BL call site at 0x301F00.
- Static disassembly at 0x301EE0/0x301F00 shows:
  MOV r0,r5 and then BL 0x2FE7D0. Thus the caller provided a
  null target pointer to this store.
- Missing group resources (frontend/fixed/splash) were still
  reported by the file layer.

The A/B result validates that the guarded change of control flow
can pass the earlier failure, NOT that gameplay or initialization is
correct. The exact optional/required semantics of missing child
objects remain unknown. Do not enable this compatibility flag by
default or replace it with a synthetic object before validating
complete asset initialization.

Public source mirror eugene373/COD-BOZ-Partially-Decompiled has
the loader DTRZ but no frontend.group.bin, fixed.group.bin or
splash.group.bin in its tracked tree (checked 2026-10-10).
The original data packages still must be provided or downloaded
through the authorized game resource pipeline.


## Offline ARM call graph for new null-property crash

Static disassembly from the recovered XE3U image
(SHA-256: dbf342663fcd8c7f8fcedced1693eb532cbea8053ef472c0cb837323f3b57d95)
shows:

- 2FE7D0: STR r1,[r0,#0x90]. A zero r0 faults at address 0x90.
- 301ECC: PUSH {r3,r4,r5,lr}; MOV r5,r1 (301ED4).
  301EE0: MOV r0,r5; 301F00: BL 2FE7D0. Thus its input
  argument r1 is carried directly into the faulting setter.
- Exactly two direct ARM BL candidates target 301ECC:
  - 3064FC (function 3064D8): calls with r1 copied from
    the function input r1 at 3064EC, without a null guard here.
    It was called by ARM BLs at 30A598,30C6C0,31AC44,
    31DE20,323280.
  - 30AE10 (function 30ADC8): calls with r1=r4, the
    r4 input had already been dereferenced at 30ADF4
    in the relevant path; this source seems less likely
    but is not ruled out by static analysis alone.

The QEMU crash confirms LR=BOZ+301F04, r0=0, r5=0, and
fault address 0x90, but the previously exposed log alone
did not distinguish the two parents.

New diagnostic code inspects 301ECC's saved LR at
the fatal stack [sp+12] to determine whether the actual
caller was 3064FC or 30AE10. If 3064FC is confirmed,
the fast stack parser also inspects the saved grandparent
at [sp+44] to distinguish its five known callers.
This analysis only reads crash state and does not patch
or allocate game objects.

For repeated offline investigations, tools/boz_arm_callgraph.py
searches candidate ARM BL instructions directly in the
uncompressed XE3U code in one pass. Its results require
instruction-mode verification because raw 32-bit pairs in
Thumb regions/data can resemble ARM instructions.

A short experimental QEMU runner mode, BOZ_FAST_NULL_PROPERTY=1,
reduces repeated diagnostic passes and emits
public/boz-fast-property.log and the report field fast_property.
The original game loader's null-child skip stays **OFF by
default** outside this explicit diagnostic A/B test.


## Live fast-path ancestry proof for 2FE7D0 (2026-10-10)

Render deployment dep-db55rmbbc2fs73eeeomg at commit
2dd8152bf5b4074b2928e65430442edbdd872cb7:
ARMHF build, make test-host and 47 Python tests PASS.
The fast path completed a single QEMU execution with RC=139.

Actual crash-time evidence:
- BOZ_NULL_CHILD_SKIP n=1 advanced past the earlier 2FE0A8 fault
  in a diagnostic-only opt-in A/B run.
- At 2FE7D0, the original ARM STR r1,[r0,#0x90] faulted
  with r0=0, address 0x90 and LR=BOZ+301F04.
- Saved return LR from the fatal 301ECC frame was BOZ+306500,
  proving it was called from 3064FC inside function 3064D8.
- Saved next LR was BOZ+323284, proving 3064D8's
  caller was function 32326C (BL at 323280).
- Saved next LR was 0x4A20FE73, i.e. Thumb return 20FE72
  after the BLX to 32326C at 20FE6E.

Byte-verified ARM/Thumb instructions show this common source:

    20FE38  BLX 2FD518       ; child/type lookup
    20FE40  BLX 302010       ; store returned object in holder
    20FE48  BLX 302020       ; load it for the first copy
    20FE4E  BLX 2FE088       ; first null-child crash
    20FE54  MOV r0,r4        ; same holder
    20FE5A  BLX 30204C       ; ARM LDR r0,[r0], reload holder
    20FE64  MOV r1,r0
    20FE6E  BLX 32326C
    323280  BL  3064D8
    3064FC  BL  301ECC
    301ED4  MOV r5,r1
    301EE0  MOV r0,r5
    301F00  BL  2FE7D0
    2FE7D0  STR r1,[r0,#0x90] ; second null-child crash

The two downstream crashes use the same pointer holder
written from 2FD518. The root cause of NULL *inside* that
lookup remains unproven: missing/unregistered type or
incomplete game assets could account for it.

The full-game assets frontend.group.bin, fixed.group.bin,
and splash.group.bin remain missing from the Render runner.
The available blackops_loader.dz carries bootstrap resources
but not those three groups. Do not default to fabricating
objects or skipping either null pointer use.
