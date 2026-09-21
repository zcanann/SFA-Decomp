# Track-contact sphere selection

`ObjHits_CheckTrackContact` matches **100%** in EN, JP, PAL, EN revision 1 and
PAL revision 1: 267 instructions / 1,068 bytes. This completes the earlier
98.764046% to 99.625465% improvement. The final change removes the remaining
18 differing instruction words, all register-allocation differences.

The complete EN ObjHits TU improves from 99.96229% to 99.977684%, with 53 of
54 functions exact. `ObjHits_CheckObjectHitVolumes` and data still differ,
so the unit remains `NonMatching`.

## Retained source

The function indexes the model's sphere definitions and both runtime sphere
buffers directly. In the linked-sphere path, this removes the explicit byte
offset and current/previous element pointers. The definition lookup likewise
uses the volume index instead of retaining an element pointer. MWCC shares
the repeated address expressions and emits the retail 24-byte definition and
16-byte sphere strides, without additional loads or arithmetic.

The active-model lookup, buffer selection, traversal order, capacity limit,
per-iteration definition-table load and collision response are preserved.
No compiler flags, pragmas, assembly, layouts or TU boundaries change.

## Behavior and selector coverage

The selector uses the high mask nibble for a self query and the low nibble
for a query against another object. Model definitions supply an owning sphere
index, mask bit, and four packed relative-index nibbles. Nonzero packed links
are consumed most-significant nibble first until the shifted word becomes
zero, so leading/interior zero nibbles select the owning sphere; trailing
zero nibbles are not visited. A zero link word selects just the owning sphere.
The query retains at most `TRACK_HIT_MAX_POINTS` points in traversal order.

Current and previous runtime spheres receive the map X/Z offsets. Without
model hit volumes, the query instead uses the source object's current and
previous world positions with its fallback radius, clamped to 0.1. The first
set bit of the returned contact mask selects the reported position and
surface type; a contact object distinguishes the two contact-kind flags.

`python3 tools/test_objhits_track_contact.py` extracts the production function
and canonical sphere/result records. An independent Python selector checks
240 deterministic scenarios at O0 and O2: self/cross masks, suppression,
packed links, ownership filtering, capacity, both sphere buffers, fallback
radii and contact-mask handling. The host fixture mocks geometry and the
minimal surrounding object fields; it does not validate retail object offsets
or actual triangle intersections. A current/previous-buffer swap is rejected
in 22 subcases across the two optimization levels.

## Compiler evidence

Existing `../mwcc` register-allocation reconstructions guided the LLDB
investigation; no additional compiler source was needed for this match.
The baseline's named-variable ordering alone cannot reproduce the complete
retail color vector in its captured fixed interference graph. Separating
the buffer selector from the packed links also changes the instruction
sequence. Direct indexing instead lets the compiler generate the element
address temporaries and reproduces every retail register operand. This
establishes the resulting code, not the original source spelling.

The final LLDB trace records 19 stages and 267 aligned instructions with zero
retail differences. Its 132-node GPR graph replays simplification and all
99 physical color choices exactly, with no high-degree removals or spill
retries. The traced object is byte-identical to an ordinary build, SHA-256
`d393b21028035679c7b88da19636503ab2e5ee5addfa58bd389a2ddfec7e9219`.

Reproduce the capture with:

```sh
python3 tools/tricky_backend_trace.py --unit main/main/objhits \
  --function ObjHits_CheckTrackContact --graph \
  --output build/objhits_track/exact_trace
```

## Validation

- Original DOL hashes verified before all five regional comparisons. Each
  improves from 99.625465% to 100%; no other function score changes.
- All 53 sibling EN function bodies, allocated non-text sections, named symbol
  layouts and resolved relocation targets are unchanged.
- Formatting preserves the complete object byte for byte. The TU and
  `include/main/objhits.h` pass `clang-format --dry-run --Werror`.
- The existing contact-selection test passes at both optimization levels.
- `ninja all_source build/GSAE01/ok` passes with the unchanged strict retail
  checksum. The retail-backed link gates build integrity; it does not claim
  a complete ObjHits source link.
