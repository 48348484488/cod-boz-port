# BOZ crash bridge: null owner return, 2026-10-10

## Evidence (existing Render run)

Service: `srv-daqv1a0473hc73978pv0`, observed 2026-10-05
14:17:03Z. The existing trace reached a fatal null-object path, RC 139.

| Offset | Probe | r0 | r4 | Interpretation |
| --- | --- | --- | --- | --- |
| 0xDA6C6 | lookup_return | 0x00000000 | 0x4065DF78 | Lookup returned zero |
| 0xDA70E | create_primary_return | 0x00000000 | 0x00000000 | Primary creation returned zero |
| 0xDA72C | create_fallback_return | 0x40B34A28 | 0x4A45EF00 | Fallback creation returned a nonzero pointer |
| 0xDA79A | owner_return_value | 0x00000000 | 0x40B34A28 | Owner returns zero, even though r4 is nonzero |
| 0xDB31C | owner_dispatch | 0x4065DF78 | 0x4065DF78 | Dispatch entered with manager/object pointer |
| 0xDB31E | null_deref | 0x00000000 | 0x4065DF78 | r0 is zero at the failing instruction |

The runtime log explicitly emits `[NULL_OBJECT] BOZ+0x0db31e after BLX r12`
and `[NULL_FLOW] r0=00000000`.

The original `null_owner_returns` analysis used `r4==0`, producing a
**false negative** even though `r0==0` at `0xDA79A`. The code now
checks `r0`, and `tools/boz_bridge_diagnosis.py` records the temporal
sequence and the mistaken r4-based result. Host regression tests cover the
real register values and missing/reordered probe data.

### Limits of the evidence

The fallback allocation returned a nonzero pointer. We **have not
demonstrated** that a memory write was dropped or that the fallback instance
is the same object as the null dispatch target. The trace contains
chronological correlation only, not a complete C++ reconstruction.

### Next runtime verification

Run the updated service against the authorized BOZ S3E and inspect
`public/boz-crash-bridge.json`:
- `null_owner_returns` should contain the observed event with r0 zero.
- `causal_summary.owner_r0_zero_count` should be nonzero if the path recurs.
- `causal_summary.observed_null_dispatch_chains` should reflect the same
  chronological sequence (not claim full identity/causation).
- Then instrument the return/dispatch behavior around `0xDA792` with
  instruction-width-aware probes confirmed from disassembly; do not add
  Thumb probes into arbitrary halfwords or ARM-mode instructions.

Game binary/resources are **not** stored in this public repo; runtime
executions must identify the exact S3E hash used to reproduce results.
