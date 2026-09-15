# ObjSeq_ExecuteActionCommand matching

`ObjSeq_ExecuteActionCommand` improves from **99.741554% to 99.960236%**
in EN `GSAE01`, EN rev1, JP, PAL, and PAL rev1. Each input DOL was verified
against its configured hash before comparison. The function remains 2,012
bytes / 503 instructions; four instructions still differ.

## Source changes

The pending-condition queue now uses indexed `ObjSeqPendingCmd0B` records at
runtime-buffer offset `0x2b34`. The deferred environment-command queue uses
indexed `ObjSeqBgCmd` records at `0x3ca4`. Both retain the retail field-store
order and increment their counters once per insertion.

An explicit signed-byte pointer preserves the deferred opcode's store/reload
address calculation. The timed-sound path indexes the timer array and uses a
narrow `s16` view at `offsetof(ObjSeqState, sfxId)` for the existing sound ID.
This reproduces the retail address-register lifetimes. Command opcode and
frame-delta accesses now use the existing `ObjSeqCommand` fields.

These changes fully match the deferred-command and timed-sound regions. The
pending-condition queue's index and entry-base registers also match; its
payload-address and stride temporaries remain swapped.

## Remaining difference

At function offsets `0x2dc` through `0x2e8`:

```text
retail                         source
addi r0,r26,4                  addi r3,r26,4
slwi r3,r5,3                   slwi r0,r5,3
add  r4,r31,r3                 add  r4,r31,r0
stw  r0,11060(r4)              stw  r3,11060(r4)
```

Both sequences store the next command's address in the same queue entry.
Subsequent halfword loads overwrite r0 and r3 before either temporary can be
observed again. Resolving source data and call relocations at EN retail
addresses confirms that these are the only four differing instructions in
the complete function.

LLDB captures and register-graph replay identify an allocation-order issue:
the generated stride temporary receives r0 before the payload-address
temporary is coloured. Indexed records fix the longer-lived queue registers,
but the tested pointer forms, explicit cached indices, local lifetimes,
integer/address views, and inline accessors do not resolve this last swap
without introducing other differences. Those experiments are not retained.
Ordinary and instrumented compiler outputs are checked for identical raw
object hashes.

## Verification

Every other function retains its previous machine code, including the exact
`ObjSeq_start` and `ObjSeq_onMapSetup`. Named symbol layouts and all non-text
section bytes, sizes, alignments, and relocation targets remain unchanged.
The complete DLL improves from 99.77284% to **99.78571%** and remains
`NonMatching`. Compiler settings and TU boundaries are unchanged.

The five regional comparisons agree on the result. The reset probe passes
with `--require-exact`; `ninja all_source` and the strict EN checksum target
pass. `clang-format --dry-run --Werror` passes, and formatting preserves the
complete source object's SHA-256.
