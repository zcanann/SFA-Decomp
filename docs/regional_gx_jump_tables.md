# Regional GX jump-table recovery

PAL rev1's GXLight and GXTexture functions were already exact, but their data
claims began 48 bytes too late. GXFrameBuf's preceding claim included GXLight's
switch table and part of GXTexture's first table. An eight-word context that
normalizes every pointer to the same marker cannot identify a switch table.

## Retail evidence

The five tables contain only aligned interior addresses in independently matched
functions. Translating each case offset into the corresponding regional function
produces one unique complete byte sequence in the target DOL's data section.

| Table | EN start | PAL rev1 start | Bytes |
| --- | --- | --- | --- |
| GXLight `@54` | `8032E750` | `803300A8` | 28 |
| GXTexture `@47` | `8032E770` | `803300C8` | 244 |
| GXTexture `@105` | `8032E864` | `803301BC` | 244 |
| GXTexture `@146` | `8032E958` | `803302B0` | 244 |
| GXTexture `@179` | `8032EA4C` | `803303A4` | 60 |

The compiled code independently materializes these table starts. Resolving its
relocations against the corrected split bases reproduces all 7,032 retail code
bytes, including those materializations. The 205 table entries resolve to the
exact retail switch-case addresses. GXLight's four trailing zero bytes preserve
its existing eight-byte section alignment; no source padding object is invented.
Anonymous names here are extraction annotations matching compiler output, not
historical symbol names.

PAL's GXFrameBuf data consists of four 60-byte mode records at `8032FFB8`,
`8032FFF4`, `80330030`, and `8033006C`. Their complete bytes uniquely identify
`GXNtsc480IntDf`, `GXMpal480IntDf`, `GXPal528IntDf`, and `GXEurgb60Hz480IntDf`.
The EN `GXNtsc480Prog` record has no identical occurrence in PAL's data section.
EN rev1 and JP retain all five records. This explains a real layout transition;
it does not support interpolating the following table boundary inside a table.
The shared SDK source can retain its fifth mode: the linker discards the unused
`GXNtsc480Prog` record in PAL. The retail PAL `setDisplayCopyFilter` has no
progressive-mode pointer comparison and unconditionally selects the custom
filter weights. Its game-source counterpart still needs regional recovery, but
this does not prevent the SDK unit itself from matching.

The corrected PAL ranges are:

- GXFrameBuf `.data`: `8032FFB8..803300A8` (240 bytes).
- GXLight `.data`: `803300A8..803300C8` (28 table bytes plus four alignment bytes).
- GXTexture `.data`: `803300C8..803303E0` (792 bytes).

## Regeneration and validation

`recover_jump_table_layout` in `tools/version_progress.py` restores table symbols
using the exact translated entries. It rejects repeated target sequences,
unmatched functions, entry addresses that could be callbacks, mixed-function
entries, and overlapping table projections. A complete table-only TU range is
projected only when all table offsets agree and all intervening/trailing bytes
are short, identical zero alignment gaps. It does not assign arbitrary neighboring
data or infer an entire mixed-data TU from one table.

All three secondary split files regenerate identically after the correction.
EN rev1 and JP need no split changes. The PAL GX symbols and table boundaries
survive repeated projection. Unrelated pre-existing symbol normalization output
was excluded from this change.

PAL gains three completely exact units and **1,064 matched data bytes**. Matched code
and total code/data denominators remain unchanged. The matching manifest now
credits GXFrameBuf's 2,708, GXLight's 2,584 and GXTexture's 4,448 code bytes
as complete (9,740 total).
GXLight and GXTexture source `.text` resolves exactly through 116 relocations,
and their initialized sections reproduce 1,006 retail bytes through 205 data
relocations.
The latter excludes linker padding and includes the constant/register-ID pools.

A full PAL link using extracted retail objects reproduces the configured retail
SHA-1, `c1a6ccdc61c7e719e20ea7cc59c8de09fd183e66`. Substituting the three GX source
objects, retaining their existing compiler profiles and the generated PAL linker
script, produces the identical DOL. This independently verifies both discarded
source data and retained table offsets; it is not a claim that a complete PAL
source link is recovered. The same substitution check also passes in EN and EN
rev1. The initial JP audit stopped on duplicate global names; the subsequent
[JP symbol repair](jp_link_symbol_recovery.md) removes those collisions and
verifies the same three GX substitutions against the JP retail checksum.

All four source builds pass with source objects unchanged. EN passes its strict
retail checksum. Eight new tests cover case order, uniqueness, independent
function evidence, callback rejection, repeated anonymous names and padding bounds; the existing 54
projection/SDA tests also pass. No compiler settings or SDK C source changed.
PAL rev0 was excluded because its local artifact fails the configured retail hash.

`tools/verify_source_link.py` preserves the response files, ELF/DOL outputs and
linker logs in a temporary directory (or a directory selected with `--output`).
It uses the existing built objects and generated linker script.

```sh
python3 tools/verify_source_link.py GSAP01_rev1 dolphin/gx/GXFrameBuf.c dolphin/gx/GXLight.c dolphin/gx/GXTexture.c
python3 -m unittest discover -s tools -p test_jump_table_projection.py
python3 -m unittest discover -s tools -p test_version_progress.py
python3 -m unittest discover -s tools -p test_sda_symbol_audit.py
```
