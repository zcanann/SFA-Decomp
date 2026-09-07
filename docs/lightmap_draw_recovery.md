# Lightmap draw source recovery (2026-09-07)

All 29 functions in the current `main/lightmap_draw.c` carve now match EN
GSAE01: 4,664 code bytes and the assigned 40-byte jump table are exact in
objdiff. The fuzzy score improves from 99.92710% to 100%.

The carve remains `NonMatching`. Its generated constant pool cannot yet replace
the retail pool shared with the surrounding map-rendering source fragments.
The matching build therefore continues to link this carve's retail object.

## Shadow bounds conversion

`lightmapQueueShadowRow` converts the six signed, packed bounds to world
coordinates, takes their midpoint, and transforms that point into camera space
for the transparent draw queue's depth key. Six scalar coordinates replace
the two partially converted vectors and the mixed coordinate temporaries.
Each axis uses the same conversion:

```c
OSs16tof32(&bounds->maxX, &worldMaxX);
worldMaxX = worldMaxX / 8.0f + block->transform[0][3];
```

The retail scale word at `0x803DEC20` is `0x3e000000`, or `0.125f`.
Multiplication by the guessed external `gTrackPackedCoordScale` gave that value
a different compiler lifetime. A literal multiplication recovers the register
assignments but reverses the multiplication operands in six fused operations.
Division by `8.0f` produces the reciprocal literal and the exact operand order.
The ordinary GC/1.3 compiler with the existing TU flags emits all 78 retail
instructions exactly. All other functions preserve their raw instruction bytes.

Queue flushing, signed fast casts, translation offsets, midpoint arithmetic,
depth clamping, and selector packing retain the retail behavior. The queue API
header is included first; its declarations require no changes.

## Constant-pool boundary

The recovered expression emits an ordinary eight-byte `.sdata2` pool containing
`0.125f` followed by `0.5f`. Retail loads instead address `0x803DEC20` and
`0x803DEBFC`, respectively; these are not one contiguous eight-byte allocation.
`tex_dolphin` also reads both addresses, and `lightmap` reads the half constant.
These references agree with the broader shared-pool evidence recorded in
[dll_naming_manifest.md](dll_naming_manifest.md#yield) for `shader`, `lightmap`,
`lightmap_initmapblocks`, `lightmap_draw`, and `tex_dolphin`.

Temporarily linking the recovered carve from source confirmed the boundary
problem: the extra pool shifts following `.sdata2` data by eight bytes, and the
strict retail checksum fails. Objdiff's 100% for the currently assigned sections
does not account for that unassigned pool. No pool bytes were claimed, no
compiler profile was changed, and the carve was returned to `NonMatching`.
The next structural step is recovering the surrounding original TU and its
complete pool; further register permutations in this function are unnecessary.
The historical compiler-profile regressions in the manifest do not disprove
the retail shared-pool evidence.

## Validation

- Objdiff: all 29 functions and the assigned 40 data bytes exact.
- The other 28 functions and the jump table's bytes, size, alignment, and
  relocations are unchanged.
- `ninja all_source` and the strict matching build pass with 30-second timeouts.
  The final matching DOL is byte-identical to the preceding retail build, with
  this carve still using its retail object.
- The active source and queue API header pass `clang-format --dry-run --Werror`.
  Running the formatter leaves both files unchanged and preserves the complete
  object, so no separate formatting commit is needed.
