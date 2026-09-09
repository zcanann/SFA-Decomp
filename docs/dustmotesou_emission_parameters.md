# DustMoteSou emission parameters

DLL 690 requests no extra state. Its nine EN functions occupy
`80237574..80237808`; the terminal 56-byte descriptor is at
`8032BDE8..8032BE20`. Its sole constant is the eight-byte unsigned-integer
conversion double at `803E73C8..803E73D0`. The four-byte gap after DLL 689's
pool remains unclaimed, and the generated source path is preserved.

The update at `802375C4` selects behavior by object ID: `0x807` is TailLightSo,
`0x80E` is FireWorkSou, and other IDs use ordinary bursts. Initialization applies
rotation bytes and disables hit detection. A signed placement game bit at
`+0x24` gates emission, with `-1` bypassing the gate.

The five shared helpers establish these placement meanings:

| Offset | Meaning |
| --- | --- |
| `0x1B` | Spawn-type table index, also selecting two parameter tables for ordinary bursts |
| `0x1C` | Effect-parameter table index |
| `0x1D` | Ordinary distribution mode, TailLightSo frame mask, or FireWorkSou particle count |
| `0x20` | Particle scale |
| `0x26..0x28` | Box extents, arced radius endpoints and height, or directional distance multiplier at `0x26` |
| `0x29` | Ordinary spawn-probability threshold |
| `0x2A` | Ordinary burst selector: zero box, one arced, otherwise directional |

Each ordinary helper makes four independent trials, drawing an integer from
0 through 99 and emitting when it is below the threshold byte. Values of 100
or more always pass. This byte is not a flag mask. TailLightSo instead ANDs
`+0x1D` with the integer effect timer's low 16 bits and emits for a nonzero
result. FireWorkSou uses the byte as its loop count. Canonical union views
record these distinct contracts without changing loads or call arguments.

The arced helper at `80097734` scales its radial shape by
`heightT * (radiusEnd - radiusStart) + radiusStart`, rotates it into the XZ
plane, and sets Y to `(heightT - 0.5) * height`. Its three dimensions are radial
endpoints and a full height span; they are not angles. The endpoint names do
not assume ascending order. The shared declaration and implementation now use
these meanings while preserving expressions, types and local lifetimes.

The canonical placement type is a reader prefix through `+0x2A`, with each
recovered field and union view offset asserted. No active EN producer or
serialized record width was established. EN rev1 and JP each contain 167
records resolving to this DLL: 153 DustMoteSou, eight TailLightSo and six
FireWorkSou, all 48 bytes. Those secondary records corroborate the family but
do not establish a full EN allocation size. No extra-state type or speculative
placement tail is retained.

The nine owner functions, five emission helpers, rotation helper and random
range helper have equal normalized instruction signatures across the verified
EN, EN rev1, JP and PAL rev1 DOLs. The owner's complete constant pool is
byte-identical. Full source builds and objdiff reports cover all four versions;
the strict EN retail checksum remains the link gate. This is source recovery
within an already exact unit, not a new match-percentage gain.
