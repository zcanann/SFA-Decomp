# Shader zero-color templates

The shader TU owns three four-byte zero `GXColor` initializer templates. They
are read by glow rendering, material setup and lightmap setup, in that storage
order. The old `sSynthFadeUnit` name at the first address is misleading: its
only active retail reference is the initial fog color in `renderGlows`. The
config now names that record `sGlowFogColor`.

## Ownership and order

EN's complete direct r2 load/store scan of `803E8440..803E8450` finds three
word loads and no stores. The active extracted-object relocation scan finds
the same three references, all in `main/shader.c`. A stale extracted
`tex_dolphin.o` duplicates those functions from before their merge; it is
absent from the current build configuration and is not a second consumer.

| Consumer | Function-relative load | Template offset |
| --- | --- | --- |
| `renderGlows` | 0x1C | 0 |
| `mapBlockRender_setShader` | 0x10 | 4 |
| `mapBlockRender_setLightmapShader` | 0x10 | 8 |

Three direct local initializers preserve instruction bytes but emit the records
in the wrong order. Two private inline initialization helpers establish the
glow and material templates before the lightmap function's ordinary local
initializer. Each helper initializes the caller's existing color from its
own const zero template. No helper body or additional call is emitted.

These helper boundaries are a source-layout hypothesis supported by their
live initialization uses and the exact emitted order, not recovered original
helper names. The caller retains its local color: extracting the entire glow
setup instead swaps its local and by-value argument stack slots, changing four
operands in an already-exact function. That broader extraction is not retained.

## Regional claims

Decoding the three retail load instructions against each verified DOL's startup
r2 base establishes these spans without assuming one global region delta:

| Version | Claimed `.sbss2` range |
| --- | --- |
| EN | `803E8440..803E844C` |
| EN rev1 | `803E90C0..803E90CC` |
| JP | `803E8560..803E856C` |
| PAL rev1 | `803E9E20..803E9E2C` |

The following four unreferenced alignment bytes remain unclaimed. The secondary configs
had included them in an eight-byte lightmap symbol; that symbol now describes
the four-byte color, consistent with its load and `GXColor` contract. The three
template names agree across versions. Once the 12-byte span is claimed, DTK
recognizes the following four bytes as alignment and omits them from the data
denominator, even with an explicit symbol entry. This accounting change is
separate from the 12 newly matched bytes; no padding definition or artificial
padding unit is added to preserve the old count.

The required `version_progress.py --write` refreshes initially could not map these BSS
boundaries conservatively and dropped the shader and previously verified renderer
claims. Existing claims were preserved, and only the independently established
12-byte spans and color symbols were added. The subsequent
[zero-tail projector fix](version_progress.md#zero-initialized-tail-projection-2026-09-08)
now preserves both claims automatically. BSS has no file-backed DOL payload;
the checks use section kind, zero contents, size, alignment and retail load
addresses rather than reading purported constant bytes from the DOL file.

## Validation

All 145 source function bodies, all previous allocated sections, and all
defined named-symbol layouts remain unchanged. The only new section is a
12-byte `SHT_NOBITS` `.sbss2`, aligned to eight bytes. The three source load
relocations select offsets zero, four and eight exactly as retail does.
All other relocation destinations remain unchanged, including anonymous
symbol offsets despite compiler renumbering.

Each of EN, EN rev1, JP and PAL rev1 gains **12 matched data bytes**, bringing
the shader unit to 40,668 exact data bytes. Code scores and the code denominator
are unchanged; the data denominator decreases by the four alignment bytes
described above. All other compiled source objects are identical.
Full source builds and the strict EN checksum pass, and formatting is verified
separately for unchanged objects. Shader remains `NonMatching`; the strict
link uses its retail object, so source placement is established by the object
and relocation comparisons above rather than that integration check alone.
