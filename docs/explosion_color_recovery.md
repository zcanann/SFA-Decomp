# Explosion renderer color recovery

Slot 458's `explosion_render` uses two `GXColor` values: a texture tint, initially
opaque white, and an additive color, initially zero. Both colors and their
argument copies now use the actual GX color type. Named RGBA fields replace
byte-indexed writes through integer locals. `flickerIntensity` supplies all four
channels of the additive color; `explosion_computeColor` supplies the tint RGB
while the current flame supplies its alpha.

The white initializer `sExplosionQuadColorA` is a four-byte `const GXColor`
instead of a single-element integer array. Its existing `.sdata2` bytes and
symbol layout are unchanged. The zero local initializer naturally emits the
previously external four-byte `.sbss2` template. Initializing both locals in
retail order preserves every instruction; assigning scalar zero or initializing
only the second aggregate did not. Named zero-array probes also disturbed the
existing constant pool and were discarded.

The shared `setupAdditiveTintedTexture` API still takes packed-word pointers;
its implementation immediately interprets them as `GXColor` values for
`GXSetTevKColor` and `GXSetTevColor`. Explicit casts remain at that call boundary.
Its source, public declarations, and other callers are unchanged. The existing
RGB output API likewise retains its byte-pointer boundary.

## Ownership and regional splits

The sole active EN relocation to `lbl_803E8468` is the word load at
`explosion_render+0x3C`. In each verified DOL, decoding that instruction against
the startup r2 base independently establishes the template address. A full
direct r2 load/store scan of each eight-byte neighborhood finds only that load.
There are no references to its following four bytes in that scan; the active
extracted-object scan also finds no reference to EN's old `sSynthFadeTimeScale`
label there. That unsupported math name is removed rather than given a new
semantic role. The four bytes remain outside the claimed color record.

| Version | Retail load | Claimed `.sbss2` range |
| --- | --- | --- |
| EN | `801B436C` | `803E8468..803E846C` |
| EN rev1 | `801B4920` | `803E90E8..803E90EC` |
| JP | `801B445C` | `803E8588..803E858C` |
| PAL rev1 | `801B4B70` | `803E9E48..803E9E4C` |

The config symbol is now `sExplosionAdditiveColorInit` in all four versions.
Secondary symbols previously included the following four alignment bytes in an
eight-byte object; their size is corrected to four. The repaired
`version_progress.py --write` independently reproduces all three new regional
splits without dropping existing BSS claims. Unrelated regenerated symbol
normalization is not part of this recovery.

## Validation

All four versions retain 11 exact functions and 6,616 code bytes. All six
previous allocated sections and all 35 named symbol layouts are unchanged.
The only new source section is a four-byte, eight-aligned `SHT_NOBITS` `.sbss2`.
Its sole load relocation replaces the old external reference at the same
instruction and target offset. Anonymous compiler symbol numbers change, but
all other relocation sites, kinds, addends, sections and offsets are identical.

Each version gains four matched and completed data bytes, taking slot 458 from
336 to 340 exact data bytes. The data denominator decreases by four bytes as
DTK recognizes the alignment gap between the preceding sky index record and
the newly claimed explosion template. Code scores and denominators are
unchanged. Every other compiled source object is byte-identical in all four
builds. The descriptor remains at the end of the TU, the canonical header and
shared consumers are untouched, and the generated-path audit passes.

All four full-source builds and the strict EN checksum pass with slot 458
linked from compiled source. Formatting is checked separately for unchanged
object bytes before landing.
