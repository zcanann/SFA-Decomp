# Animation frame headers and sampling

The EN v1.0 readers `modelAnimUpdateChannels` (`80024524`),
`modelAnimResetState` (`80024EC8`), and `ObjModel_SampleJointTransform`
(`80027E00`) establish the move prefix and frame-header fields now named in
`include/main/objanim_internal.h`.

| Offset from move start | Representation | Meaning |
| --- | --- | --- |
| `0x00` | `u8` | Uninterpreted prefix byte |
| `0x01` | `s8 frameControl` | Existing frame-type and step control bits |
| `0x02` | `s16 frameStreamOffset` | Offset to the packed per-frame stream; EN readers use `lha` |
| `0x04` | `s16 rootCurveOffset` | Existing root-curve offset |
| `0x06` | `u8 jointCount` | Number of joints consumed by the joint decoder |
| `0x07` | `u8 frameCount` | Frame count; clamped playback subtracts one for its playable length |
| `0x08` | `u8 frameStride` | Byte distance between packed frames |
| `0x09` | `u8` | Uninterpreted frame-header byte |
| `0x0a` | `u16 trackDescriptors[]` | Variable-length packed track descriptors |

`ObjAnimFrameHeader` replaces the misleading two-byte `ObjAnimFrameCommand`
type. Its old `opcode` is a joint count. The frame header is four bytes before
its flexible descriptor array. `ObjAnimMoveData` describes the six-byte move
prefix before its flexible frame payload; its former size of eight included
an artificial one-byte array and alignment padding. No runtime allocation or
array traversal uses `sizeof(ObjAnimMoveData)`. The corresponding assertions
now describe the prefix rather than a complete variable-length record.

The joint decoder starts directly at `trackDescriptors`. The root-transform
decoder uses the same canonical offset while retaining its existing packed
address arithmetic. Move setup reads `frameCount` rather than calling the
stored count a playable frame length. Existing disc-format notes in
`docs/wiki/Animation.md` corroborate this layout using EN rev1 records; the
signed stream-offset type here follows the active EN v1.0 instructions.

## Sampler state

The sampler now uses the existing four-element `ObjAnimState.frameData` and
`cacheSlots` arrays rather than indexing beyond the first named scalar member.
Slots select current/previous move and current/previous blend data. Cached
blend slots use the blend cache; other cached slots use the move cache. Both
apply the canonical `OBJANIM_CACHED_MOVE_DATA_OFFSET` before interpreting the
move prefix. Uncached slots use the model's animation pointer table.

The sampler temporarily installs the selected frame header, computes the
stream cursor and interpolation stride, calls the root-transform decoder, then
restores the original frame-header pointer. Its other state writes remain.
Decoded translation samples are scaled by `1/512`, offset by the first bone's
head, and multiplied by root-motion scale. The zero-animation branch retains
the retail fall-through after clearing outputs; it is not an early return.

## Validation

The complete `model.o`, `objanim.o`, and `render.o` objects are byte-identical
to their pre-change versions under their configured game compiler. This
includes code, data, symbol layouts, and relocations. The sampler remains an
exact 692-byte function, with no match-score changes in the affected units.
The full strict checksum and `all_source` builds check the shared declaration
across consumers. The active model TU is formatted separately; shared
animation and rendering edits are limited to the recovered type and fields.
