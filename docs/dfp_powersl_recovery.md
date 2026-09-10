# DFP_PowerSl sequence and effect controls

Slot 572 owns six functions and its final descriptor. Its canonical header is
`include/dlls/objects/572_DFP_PowerSl.h`; the generated source path and neighboring
slots 571 and 573 remain intact. The registry includes the canonical declaration
and casts the actual `ObjectDescriptor` at its generic resource entry.

The retail extra-size function returns 12 bytes. The three signed words are a
sequence starting frame, a Partfx effect ID and a game bit that disables the
render effect. Init reads them from signed placement halfwords at `0x1A`, `0x1C`
and `0x20`. Nonpositive frame/effect values are replaced with one in the placement
itself. The signed byte at `0x18` becomes the high byte of `anim.rotX`. The mutable
placement type is a reader prefix, with assertions for every accessed offset;
its full allocation size is unproven. EN revision 1 and JP both identify object
definition `0x344` as `DFP_PowerSl`, DLL `0x23C`, class `0x30`, but neither contains
a placement for it in the available romlists.

The old `activateObjectId` label was incorrect. Update queues the value through
`ObjSeq_preempt` and requests the object's sequence with index zero. `ObjSeq_start`
uses the queued value to suppress the ordinary audio-start path when nonzero and
stores its low halfword in the background command at runtime-buffer offset
`0x2A82`. `ObjSeq_runBgCmds` reads that command word into `pendingStartFrame`
(state offset `0x5E`) before updating the sequence. This is a starting frame,
not an object ID.

The old spawn-object labels also hid Partfx dispatch. While the configured game
bit is clear, render calls the configured effect with flags 4 and then 1. Their
existing canonical flag names are retained without claiming that flag 4 means
preload. The animation callback checks both the returned priority-hit result and
its object pointer, then emits effect `0x39E` twenty times with flag 1. Its shared
hit-result/loop local and postincrement test are preserved. The callback is now
`dfppowersl_spawnHitEffects`, consistently named in all five symbol configs.
Partfx routes that ID to resource `0x1A`; its effect handler chooses randomized
velocity and scale, texture `0x17C` and a 100-frame lifetime. Init sets hit-volume
priority `0x13`, volume ID one and source slot zero. Free releases the object's
Expgfx source.

Checksum-verified EN, EN revision 1, JP and PAL revision 1 agree on the six
normalized object functions, signed placement accesses, allocation return,
20-iteration loop and descriptor callback layout. EN text is
`0x80209F34..0x8020A1C8` (660 bytes); its descriptor is 56 bytes at `0x80329E08`.
The neighboring lightning descriptor ends exactly at that address, and slot 573
retains its independent eight-byte null record. No split or compiler change is
needed. PAL revision 0 receives the helper name only; its local DOL fails the
configured checksum and supplies no binary-match claim.

All four complete objdiff reports retain the same scores: six exact functions,
660 code bytes and 56 data bytes for this object. Only its callback symbol and
relocations change; function bytes, allocated sections, named storage offsets
and physical relocation destinations are unchanged. Every other source object,
including the registry, retains its raw hash. All four `all_source` builds and
the strict EN checksum pass within 30-second limits. This recovers the source
contract without claiming additional matched bytes.
