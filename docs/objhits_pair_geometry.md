# Object-pair geometry

`ObjHits_DetectObjectPair` now exposes two native vectors: `toOther` is the
other object's current position relative to A's stored collision position;
`storedSeparation` is B's stored position minus A's. The collision pass
refreshes these stored positions after processing pairs, and dirty-position
synchronization can refresh them earlier. They are collision snapshots, not
necessarily an untouched previous animation frame.

The first vector projects the other object onto A's movement segment. The
second supplies the separation-response direction. Component variables now
name the movement, offset, span heights, combined radius and integer distance.
The movement and output offsets retain their scalar storage: grouping them
into vectors changes the generated registers. `sweepValue` retains its two
lifetimes, first squared movement length and then the closest-point fraction.

A vertical-span pair first rejects disjoint height ranges, then discards Y
for the initial distance and movement direction. Swept testing is attempted
only for movement length squared above one and a projected fraction inside
[0, 1]. The swept-distance helper retains its three-dimensional distance
calculation, including Y; that asymmetry is not normalized. Coincident centers
are excluded by the positive-distance test. The nearest-distance bookkeeping
also retains its codegen-significant integer/float/integer conversion.

All 54 compiled function bodies, allocated sections, named symbol layouts and
resolved relocation destinations are unchanged. Anonymous literal symbols
renumber. `ObjHits_DetectObjectPair` retains its 1,232-byte size and 99.902596%
match, with six register-operand differences and identical mnemonics. This
is a source-structure recovery, not an additional exact match.

The inspected alternatives did not improve matching: scalar projection-axis
assignment order was flat; native movement changed six operand differences
to 29, and a native response offset changed them to 38. Passing a cached
position vector by value to the inline swept-distance helper added twelve
instructions. In the adjacent hit-volume routines, direct state access,
joined fallback definitions and indexed mask-definition walks also failed to
improve the baseline. Those experiments were restored.

Formatting is checked separately for object identity. The full source build
and strict retail checksum gate publication with a 30-second timeout for
each Ninja invocation. The unit remains `NonMatching`; the separate object
comparison verifies this source recovery while the matching link uses retail.
