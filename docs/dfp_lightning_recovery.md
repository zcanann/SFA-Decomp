# DFP lightning controls and shared effect layout

Slot 571 owns its public API and 28-byte state in
`include/dlls/objects/571_DFP_Lightni.h`. The generated source path, complete
five-function TU, final descriptor and literal pool remain intact. The registry
includes the canonical header and casts its actual `ObjectDescriptor` only at
the generic resource entry. Slot 572 retains its independent source and descriptor.

The old angular and radius labels did not describe the consumers:

| Recovered control | Placement | State | Consumer |
| --- | --- | --- | --- |
| Width steps | signed byte `18` | signed halfword `14` | Multiply by 12, retain the low byte, pass as lightning line width |
| Lifetime in tens of frames | signed byte `19` | signed halfword `16` | Multiply by 10; used for ordinary effect lifetime and one reset threshold |
| Bolt segment-density parameter | signed halfword `1A` | float `0C` | Normalize by 32767 and scale by 5 |
| Strand segment-density parameter | signed halfword `1C` | float `10` | Same normalization |
| Player-target game bit | signed halfword `20` | signed word `18` | Select player-relative endpoint and force the trigger timer |

Init repairs each nonpositive density parameter to one in the placement itself.
The placement type is therefore mutable. It models only the evidenced reader
prefix through `0x21`, including two opaque bytes at `0x1E`. EN revision 1 and
JP each contain fifteen nine-word (`0x24`-byte) `DFP_Lightni` placements in
`dfptop.romlist.zlb`; the full EN allocation is unproven and must not be sized
from this reader prefix. State size comes from the retail extra-size return,
and every state field and placement access has a canonical offset assertion.

The shared `lightningCreate` allocates 40 bytes, stores the densities at `0x18`
and `0x1C`, the lifetime at `0x22`, and width at `0x26`. `lightningRender` forwards
these fields to `lightningDrawBolt`. Bolt density multiplies bolt length to
select its segment count; strand density does the same in `lightningDrawStrand`.
Both counts are capped at ten. Width reaches `GXSetLineWidth` and is halved for
recursive branches. It does not control an angle, and the densities do not
represent X/Y radii.

The owning `LightningEffect` type and its size/offset assertions, creation API,
renderer parameter names and movement-helper density globals now express that
same contract. The two movement globals retain their values 2.0 and 0.2 and
their adjacent four-byte small-data slots. Their declarations and all five
symbol configs use the recovered density names. The three slot-owned density
literal anchors are also renamed without moving them. Shared consumer edits
are limited to those names, declarations and registry typing.

The object retains its original timing behavior. A set player-target bit forces
a sub-1000 timer to 999 and selects the player-relative endpoint; that path
creates a ten-frame effect. Ordinary effects use the configured lifetime.
Render separately checks the canonical floor-zap bit to choose its reset
threshold. The puzzle-complete bit suppresses creation after the previous effect
has been freed, and the timer still moves to 1000. Signed width/lifetime
conversions, low-byte/halfword truncation, random-call order and density clamps
are preserved. Sound `0x4C3` remains a local numeric ID because no canonical
name was established. The unused conversion helper remains as its proven
literal-pool and anonymous-symbol anchor.

EN owns five functions at `0x80209958..0x80209F34` (1,500 bytes), a 56-byte
descriptor at `0x80329DD0`, and 48 literal-pool bytes at `0x803E64E0`.
Checksum-verified EN, EN revision 1, JP and PAL revision 1 agree on the normalized
five object functions and five shared lightning consumers, allocation returns,
placement conversions, width multiplication, descriptor callbacks and pool bytes.
PAL revision 0 receives consistent symbol names only; its local DOL fails the
configured checksum and supplies no matching claim.

All four complete objdiff reports remain unchanged. The object, engine renderer,
registry and every other source object remain byte-identical except
`obj_movelib.o`, whose only changes rename the two density symbols and their
relocations. Function bytes, allocated data, named storage positions and physical
relocation destinations remain unchanged. The other 1,003 EN objects and 987
objects per verified secondary target retain their raw hashes. All four
`all_source` builds and the strict EN checksum pass within 30-second bounds.
This is source and contract recovery, with no additional matched-byte claim.
