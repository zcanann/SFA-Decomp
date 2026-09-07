# Expgfx Source Recovery

## Native storage and current EN match (2026-09-07)

Expgfx now reaches **99.99813% fuzzy match**, with **45 of 46 functions exact**.
The allocator is complete. The remaining update difference is 18 instruction
bytes: stack displacements for eight spilled values. The unit stays
`NonMatching` until its source-linked DOL passes the retail checksum.

| Measure | Previous | Current |
| --- | ---: | ---: |
| Unit fuzzy match | 99.88683% | 99.99813% |
| Exact functions | 44 / 46 | 45 / 46 |
| `expgfxGetSlot` | 95.89899% | 100% |
| `expgfx_updateActivePools` | 99.88024% | 99.99222% |
| Update instructions | 2,311 | 2,313 |
| Exact data bytes | 6,660 | 6,660 |

### Emission and ownership

The Dinosaur Planet reference's `src/dlls/engine/13_expgfx/expgfx.c` uses
independent pool arrays and puts its constructor before its gameplay functions.
That source lineage, the reverse retail function order, and the successful
save-game recovery support GC/1.3 deferred emission here. The unit uses the
existing `cflags_dll_noopt_noautoinline_deferred` profile: the compiler remains
GC/1.3, with `nopeephole,noschedule` and `noauto`. There is no TU split or
per-function compiler setting.

Ordinary function definitions and tentative BSS definitions are ordered for
MWCC's reverse deferred emission. Complete definitions are available at code
generation, allowing MWCC to synthesize its shared BSS base. The two synthetic
`ExpgfxRuntimeDataLayout` and `ExpgfxStaticDataLayout` overlays and their offset
macros are removed.

The 0x1340-byte BSS span now has these independent definitions:

| Offset | Definition | Size |
| --- | --- | ---: |
| 0x0000 | resource entries | 0x200 |
| 0x0200 | pool bounds | 0x780 |
| 0x0980 | effect table entries | 0x500 |
| 0x0E80 | pool source modes | 0x50 |
| 0x0ED0 | tracked source pointers | 0x140 |
| 0x1010 | two source-frame masks | 0x10 |
| 0x1020 | plane-offset set IDs | 0x50 |
| 0x1070 | active counts | 0x50 |
| 0x10C0 | active-slot masks | 0x140 |
| 0x1200 | slot-pool bases | 0x140 |

The old crystal-burst struct incorrectly combined four amplitude scalars with
independent quad templates. Separate amplitude and template arrays recover
MWCC's shared data base in the quad initializer and update. Each used template
has four vertices, as established by its consumers. The unreferenced repeated
template bytes remain opaque. Likewise, the frame-flag array has 80 entries;
the following 32 unused bytes are retained separately. The predecessor's two
triangle records explain that latter byte pattern without inventing an EN
consumer.

Diagnostic strings are literals at their call sites. Deferred generation and
string reuse reproduce their retail order and preserve all initialized bytes.
The active symbol config records the recovered array boundaries; source paths
and TU section boundaries remain unchanged.

### Functions

`expgfxGetSlot` uses ordinary indexed searches over the native arrays. MWCC
performs the retail unrolling and emits all 198 instructions exactly. The
manual five-way search, cached mask snapshots, and extra pointer cursors are
gone. Both free-slot searches share their loop counter.

`expgfx_resetAllPools` also uses indexed arrays. Its inline resource cleanup
indexes entries instead of incrementing the entry argument. That distinction
preserves the retail register allocation and all 116 instructions.

The update keeps the active pool index separate from the texture/resource
address. It uses that index for both the active-mask lookup and final pool
writeback, allowing the compiler to share the byte-offset calculation. The
byte-buffer local retains its two nonoverlapping roles in the next-pool scan
and cache writeback. Splitting those roles currently creates an extra store.
All arithmetic, branches, instruction counts, and register operands now agree.

The earlier trail-vector recovery, narrowed ambient-color products, and direct
`s16` rotation-speed conversions are retained. The three rotation products
still require the direct floating-point-to-halfword spelling; an intermediate
`int` cast introduces sign-extension instructions.

A full source-link audit exposed a pre-existing false exact report in
`objfx_spawnFrameTimedHitPulse`: objdiff normalized two reversed SDA load
relocations. A direct truth test of the floating-point frame timer recovers
retail's timer-first, zero-second load order. The linked-byte comparison
verifies this correction.

### Remaining stack layout

Only these eight stack locations differ in `expgfx_updateActivePools`:

| Value | Retail offset | Current offset |
| --- | ---: | ---: |
| pool byte offset | 316 | 344 |
| cache writeback buffer | 320 | 340 |
| maximum-X pointer | 324 | 336 |
| current pool index | 328 | 332 |
| ambient blue plus one | 332 | 316 |
| ambient green plus one | 336 | 320 |
| ambient red plus one | 340 | 324 |
| active-mask pointer | 344 | 328 |

The 18 affected loads/stores differ only in their displacement byte. Native
array access was the structural breakthrough; changing declaration scopes,
scan helpers, or merging the pool index back into the resource address has not
resolved the final layout without other regressions. No forced stack record,
volatile storage, or compiler override is retained.

### Validation

- `ninja all_source` and the normal matching build pass, including the strict
  retail checksum. Expgfx's normal matching link still uses its retail object.
- A diagnostic source link produces a DOL of the same size as retail and differs
  at exactly the 18 displacement bytes listed above, all inside the update.
  Every other linked byte agrees, verifying the new BSS offsets, initialized
  data, anonymous literals, relocations, and the other 45 functions. Its strict
  checksum fails as expected; the unit is restored to `NonMatching` afterward.
- All allocated non-text section bytes, sizes, and alignments are preserved.
  Named array offsets and sizes are checked independently of zero-filled BSS
  section equality. Objdiff reports all 6,660 data bytes exact.
- The two slot-layout tests pass. They exercise the production quad-write
  sequence over 100 random slots and verify metadata and simulation bytes are
  preserved. The harness now stops at the native global declarations instead
  of the removed overlay macro.
- Formatting is a separate change, verified to preserve the complete object.
  TU and owning-header `clang-format --dry-run --Werror` checks pass.

Useful commands:

```sh
python3 configure.py --matching
# Each Ninja invocation must have a 30-second timeout.
ninja all_source
ninja
python3 tools/unitfuzzy.py dlls/engine/10_expgfx/expgfx.c
python3 -m unittest discover -s tools -p test_expgfx_slot_layout.py
```

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
