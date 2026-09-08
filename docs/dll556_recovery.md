# Slot 556 moving-object storage

The numbered slot owns its public API, verified 16-byte state and recovered
placement prefix in `include/dlls/objects/556.h`. Its object identity remains
unproven. The canonical header replaces two legacy headers; unrelated sibling
state imports and duplicate size assertions are removed from this TU.

## EN evidence

The ten functions occupy `80204B54..802050C4` (1392 bytes). The 56-byte
descriptor occupies `803298D0..80329908` and ends the source. The existing
32-byte constant pool at `803E6398..803E63B8` is preserved. Neighboring slots,
source paths, splits, symbols and compiler profiles are unchanged.

`dll_22C_getExtraSize_ret_16` at `80204B5C` returns 0x10. Initialization at
`80205024` establishes these placement accesses:

| Offset | Storage | Use |
| --- | --- | --- |
| `18` | signed byte | shifted eight bits into object X rotation |
| `1A` | signed halfword | converted to float at state offset zero |
| `1C` | signed halfword | truncated into the activation byte at state `0C` |
| `1E` | signed halfword | copied to state `08` |
| `20` | signed halfword | activation game bit at state `06` |

The former `raiseHeight` name implied a motion parameter, but no TU reader
uses that initialized float. Motion uses fixed offsets of -1228 and +60 from
placement Y, so the field is now `placementValue1A`. Activation mode 1 bypasses
the initial gamebit gate while retaining the proximity test. The second game
bit is also only initialized in this TU. Neither observation establishes how
external consumers might use those fields.

The placement type is explicitly a prefix through the halfword at 0x20.
EN extracted assets are unavailable here, and no direct full-size allocation
contract is established. Field offsets are asserted without inventing a total
record size. The complete state size and all recovered state offsets are
asserted against retail accesses and the extra-size callback.

The update retains its alias locals, signed timer conversion and distance
calls whose return values are ignored. Free retains both resource cleanup
calls. The registry includes the canonical header and casts the actual
`ObjectDescriptor` at its generic `ResourceDescriptor` boundary.

## Validation

EN, EN rev1, JP and PAL rev1 retain identical source objects and complete
objdiff reports. All ten functions and both data sections remain exact. Full
source builds pass for those four versions, and EN passes its strict retail
checksum. Formatting is committed separately and checked for unchanged object
bytes. This is storage and source recovery; it claims no new matching bytes.
