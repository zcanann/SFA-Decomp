# Sequencer Speed Source Recovery

`seqSpeed` and the immediate-speed branch of `seqCrossFade` both store a
16-bit speed at sixteen addresses separated by `0x38`. Relative to `seqNote`,
the first address is `0x291A + slot * 0x1868`. These are the existing
`SynthVoiceRuntime.voices[slot].section[index].speed` fields, not anonymous
runtime words. The deferred branch's `0x22D8` and `0x22DA` accesses are
`syncCrossInfo.speed2` and `syncCrossInfo.flags`. Layout assertions beside the
canonical types cover those offsets, the voice stride, and the section size.

Both manually expanded sixteen-store blocks are replaced with ordinary
unsigned-index loops. GC/1.2.5n fully unrolls them into the retail stores.
In `seqCrossFade`, introducing the loop initially grows the frame by eight
bytes; removing the existing unused `deadSlot0` and `deadSlot1` locals
recovers the exact frame and every instruction. The remaining `deadSlot2`
is still unexplained: deleting it changes the frame, so this is partial
source recovery, not a claim that every local in the function is original.

The three raw-offset speed macros have no remaining consumers and are
removed. `synth_queue.c` also uses the shared runtime definition instead of
its two duplicate callback-prefix overlays. In `seqStop`, the intermediate
slot address stays a byte cursor with `sizeof(SynthVoice)` and canonical
`offsetof` dereferences. A direct indexed voice pointer introduces one
extra instruction; preserving that intermediate lifetime reproduces the
existing code without pretending it is a different runtime struct.

## Verification

`synth_queue.o` remains byte-identical (SHA256
`1335e559821a9139bba7773e2ebe3c68a3e778b73eb32314eb3e250b5a58106b`).
All allocated section bytes, named symbol positions, and relocation targets
in `synth_handle.o` remain unchanged; only one anonymous exception-table
symbol's generated name changes. All three assigned handle functions remain
100% exact. The queue retains six exact functions; `seqStop` still has its
28 register-operand differences. No compiler profile or TU boundary changes.
Both `ninja all_source` and the strict retail DOL checksum pass.
