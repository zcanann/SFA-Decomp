# ROM font decoder recovery

`OSFont.c` now describes its compressed input with a private
`OSFontCompressedHeader` and names the decoder's stream cursors. This removes
the three header-offset casts and the imported `r7`/`r25` register names while
preserving the SDK algorithm and its declaration order.

The retail `Decode` loads the decoded size from offset 4, the link-stream
offset from 8, and the chunk-stream offset from 12. Mask words begin at offset
16. The new type asserts all three field offsets and its 16-byte size. Its
32-bit signed fields preserve the decoder's existing signed locals and output
size comparison. `GetFontSize` reads the same header and still checks only
the first three magic bytes, `Yay`; its unsigned return type is unchanged.

Each mask bit selects either one literal byte from the chunk stream or a
two-byte link from the link stream. The link's low twelve bits encode distance
minus one. The high nibble encodes length minus two; a zero nibble instead
consumes a chunk-stream byte and adds eighteen. The copy advances through the
destination, permitting overlapping back-references. The recovered names keep
the existing biased copy index rather than changing this loop's arithmetic.

The Sunshine and Pikmin 2 SDK implementations independently have this same
three-stream algorithm. Pikmin 2 also names the stream roles. The private
header type and SFA's descriptive local names are a reconstruction, not a
claim that these exact declarations survive in the original source. The loader
reads font payloads through `__OSReadROM`; validation here concerns the retained
decoder instructions, not a newly obtained font image.

All five source objects are byte-identical to their pre-change counterparts,
including symbol and relocation tables. Each retains all seven exact
functions (2,924 bytes), including the 372-byte decoder, and all 2,852 data
bytes in objdiff with completion annotations disabled. Every other source
object is unchanged. All five `all_source` and native strict-checksum builds
pass against the hash-verified retail inputs. Formatting introduces no changes.

Donor files inspected without modification:
`reference_projects/super_mario_sunshine/src/dolphin/os/OSFont.c` and
`reference_projects/pikmin2/src/Dolphin/os/OSFont.c`.
