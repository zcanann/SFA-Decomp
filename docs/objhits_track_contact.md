# Track-contact sphere selection

`ObjHits_CheckTrackContact` now walks the model's sphere definitions and both
runtime sphere buffers with one native index. The compiler derives the
24-byte definition and 16-byte sphere strides. This removes the separately
maintained byte offset and two pointer cursors without changing iteration
order or the per-iteration definition-table load. The active-model lookup
uses the object's bank directly; the shared getter remains for other callers.

Under the unchanged GC/1.3 profile, the function improves from 98.764046% to
99.625465%. All 267 instruction mnemonics match retail, with 18 operand
differences remaining (previously one mnemonic and 43 operand differences).
The object unit improves from 99.81037% to 99.84577%; its exact-function count
remains 49 of 54. This is a partial match, not a completed unit.

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

All 53 sibling function bodies, allocated data, named symbol layouts and
resolved relocation targets are unchanged. Formatting is verified separately
for object identity. The full source build and strict retail checksum gate
publication, each with a 30-second timeout. This unit remains `NonMatching`,
so the source-object audit is required in addition to the retail-backed link.
