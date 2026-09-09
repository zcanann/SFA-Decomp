# Effect flag relocation blocks and MagicPlant

The target-address relocation block `80180100..80180218` treated every reference
into that range as an effect flag. In PAL rev1, the range includes two real
MagicPlant entry points: `MagicPlant_render` at `8018013C` and
`MagicPlant_update` at `801801B8`. It suppressed their descriptor relocations at
`.data + 0x28` and `.data + 0x20`, leaving raw addresses where the source emits
callback references.

## Literal instruction evidence

Removing that block in a PAL diagnostic build adds 36 relocations: the two real
callbacks and 17 spurious `lis` / `addi` pairs in 11 effect TUs. The seven literal
values are `80180100`, `80180104`, `80180108`, `80180200`, `80180208`, `80180210`
and `80180214`. Source assigns these to effect behavior flags, combining scale,
billboarding, jitter, alpha and optional velocity/depth behavior.

Each pair was checked against the same offset in an independently unique
normalized retail function in EN, EN rev1, JP and PAL rev1. The complete eight
instruction bytes agree across all four originals and the corresponding source
objects; source has no relocation at either instruction. Names or a global
address displacement were not used to establish the correspondence.

All four configs replace the broad target block with 17 eight-byte source ranges.
The config comments identify the owning function and literal at each range.
Re-extraction preserves the raw integer pairs and restores the PAL descriptor's
real `ADDR32` relocations. Other legacy target blocks remain separate work.

## Constant identities

After recovering the callback relocations, PAL MagicPlant scored 100% in objdiff
but its source link still differed at four `lfs` instructions. Three external
legacy labels resolved to unrelated PAL constants at the same numeric EN address:
`lbl_803E3870`, `lbl_803E3878`, and `lbl_803E3880`.

All eight legacy constant references now use semantic external names. The roles
were already recovered in the TU's macros. Direct retail r2 operands and identical
four-byte values establish each regional address; the unrelated regional address
labels remain intact.

| Symbol | Bytes | EN | EN rev1 | JP | PAL rev1 |
| --- | --- | --- | --- | --- | --- |
| `gMagicPlantOne` | `3f800000` | `803E3858` | `803E44F0` | `803E3978` | `803E5238` |
| `gMagicPlantZero` | `00000000` | `803E385C` | `803E44F4` | `803E397C` | `803E523C` |
| `gMagicPlantDropProgressThreshold` | `3f4ccccd` | `803E3870` | `803E4508` | `803E3990` | `803E5250` |
| `gMagicPlantLaunchSpeedDivisor` | `42c80000` | `803E3874` | `803E450C` | `803E3994` | `803E5254` |
| `gMagicPlantPi` | `40490fdb` | `803E3878` | `803E4510` | `803E3998` | `803E5258` |
| `gMagicPlantHalfCircleBinaryAngle` | `47000000` | `803E387C` | `803E4514` | `803E399C` | `803E525C` |
| `gMagicPlantFadeOutAnimStep` | `3b83126f` | `803E3880` | `803E4518` | `803E39A0` | `803E5260` |
| `gMagicPlantRandomProgressScale` | `3c23d70a` | `803E3890` | `803E4528` | `803E39B0` | `803E5270` |

The TU's declaration order, types, macros, function bodies and compiler profile
are preserved. Formatting is isolated in a following commit and must leave the
compiled object bytes unchanged.

## Result and validation

PAL MagicPlant now matches all 10 functions, 3,032 code bytes and 80 data bytes,
adding 56 matched data bytes and one completed unit. Its all-retail link and
source-substitution link reproduce the original PAL DOL. The same source
substitution also reproduces the EN, EN rev1 and JP originals. This is a selected
unit check, not a claim that every regional source unit links correctly.

All four source builds pass and EN's strict checksum passes. EN, EN rev1 and JP
report measures remain unchanged. Only MagicPlant's renamed external symbol
references change source object identity; every other source object, including
the 11 affected effect TUs, remains byte-identical. The eight constant identities
survive regional symbol regeneration.

```sh
python3 tools/verify_source_link.py GSAP01_rev1 dlls/objects/254_MagicPlant/MagicPlant.c
```

## PAL v1.0 and the second flag family (2026-09-09)

The newly verified PAL v1.0 DOL contains the same effect implementations. Its
configuration had not inherited the five instruction exclusions for `80080100`,
so DTK treated those flags as addresses. They occur once in Effect2, Effect7
and Effect8 and twice in Effect20. Correcting those five pairs completes all
four units, adding 60,196 matched code bytes. PAL v1.0 now has 914 exact source
units and 93.3901% matched code; source instructions and data are unchanged.

The neighboring legacy target block `80080108..80080120` is also replaced by
seven proven instruction pairs in every version. Their values are `80080108`,
`80080110`, `80080112` and `80080118`, in Effect1, Effect3, Effect4 and Effect5.
Together with the earlier family, all five configs now use 29 eight-byte
instruction ranges in 15 effect TUs. PAL v1.0 also receives the earlier 17
`80180100..80180214` exclusions. Other legacy target blocks are unchanged.

Correspondence comes from independently unique normalized whole retail
functions. Each complete eight-byte `lis`/`addi` pair is identical in all five
hash-verified DOLs. The compiled source has the same bytes and no relocation at
either instruction. All 15 source objects are themselves byte-identical across
the five versions. The config comments retain the owning function and integer
value at every exclusion; genuine references elsewhere remain relocatable.

| Newly exact PAL v1.0 unit | Complete code bytes | Complete data bytes |
| --- | ---: | ---: |
| `dlls/engine/27/27.c` | 15,708 | 836 |
| `dlls/engine/32/32.c` | 6,468 | 464 |
| `dlls/engine/33/33.c` | 6,228 | 336 |
| `dlls/engine/45/45.c` | 33,024 | 972 |

The 60,196-byte gain counts the four formerly unmatched spawn functions; each
TU's other four functions were already exact. Both progress denominators stay
unchanged, and no previously exact unit regresses.

Validation: `all_source` passes for all five versions, and the EN matching build
passes its strict retail checksum. Each version's all-retail link and a second
link substituting all 15 affected source objects reproduce that version's
verified original DOL exactly. Every compiled source object is byte-identical
to its pre-change baseline. The other four versions' matched code, data and
function counts are unchanged.
