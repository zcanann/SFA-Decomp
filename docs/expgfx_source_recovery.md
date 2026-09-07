# Expgfx Source Recovery

## Spawn and Slot Contract (2026-09-06)

The EN `expgfx_addremove` entry at `8009F2CC` consumes the same 0x64-byte
`EffectSpawnConfig` produced by partfx and Effect1 through Effect20. The duplicate
`ExpgfxSpawnConfig`, byte-pair color overlay, and texture-word overlay are removed.
The consumer now uses the canonical scalar fields, including the unsigned
halfword loads for the color words at 0x58, 0x5A, and 0x5C.

The spawn word at +0x04 is narrowed into the slot halfword at +0x36. The update
function passes that halfword to the partfx spawn callback when triggering an
impact effect. It is not vertex padding: `quadVertex3Pad06` is now
`impactEffectId` in the canonical config and all 21 producer TUs that used that
name. The unrelated legacy `unk04` view is not reinterpreted in this pass.

Each 0xA0-byte slot begins with four 0x10-byte vertices. The recovered union
exposes that array and its metadata view without casting the entire slot to an
unrelated vertex type:

| Slot Offset | Metadata | Vertex Storage |
| --- | --- | --- |
| 0x06 | remaining lifetime | vertex 0 unused halfword |
| 0x0F | initial alpha | vertex 0 alpha |
| 0x16 | initial lifetime | vertex 1 unused halfword |
| 0x1F | start red | vertex 1 alpha |
| 0x26 | sequence ID | vertex 2 unused halfword |
| 0x2F | start green | vertex 2 alpha |
| 0x36 | impact effect ID | vertex 3 unused halfword |
| 0x3F | start blue | vertex 3 alpha |

The RGB bytes at 0x8C-0x8E are the end color. Remaining lifetime starts at the
configured duration and decreases; the update computes
`end + (start - end) * remaining / duration`. `drawGlow` takes color from vertex
0 for all four vertices, so the other three alpha bytes are available for these
endpoints. Geometry initialization writes only XYZ and ST, preserving metadata.

The update's local rotation/scale/translation record is the existing 0x18-byte
`MatrixTransform`, not a separate Expgfx-specific transform type.

### Verification

- Expgfx raw object SHA-256 remains
  `093414280ff1e5dc993b4b79c1d75520073cf817778c6da6fb4706e4312d090e`.
- All 21 producer object hashes are unchanged by the shared field rename.
- Expgfx remains 44/46 exact functions, 99.83384 fuzzy overall; no new matched
  bytes are claimed for this source recovery.
- `python -m unittest discover -s tools -p test_expgfx_slot_layout.py` checks the
  metadata aliases and runs the production quad-write sequence over 100 random
  slots, verifying every byte outside XYZ/ST is preserved.
- `ninja all_source` and the strict EN retail DOL checksum both pass. Expgfx
  remains NonMatching; the checksum uses its retail object, not reconstructed C.

## Runtime Storage Remains Unresolved

The existing runtime overlay spans six separately defined BSS objects. Native
arrays declared before the functions reorder BSS by first use: resource entries
are followed by masks rather than bounds. Definitions after all uses preserve
the retail offsets but lose shared-base addressing and regress codegen. A single
typed aggregate preserves byte offsets but also regresses several exact functions.
None of those storage probes is retained. Zero-filled section equality alone
misses the first-use layout problem; compare named symbol offsets as well.
