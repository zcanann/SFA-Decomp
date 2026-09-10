# Subtitle-box texture data

JP's `main/textrender_drawbox.c` matched all nine functions but only 92 of its
1,460 data bytes. The two embedded RGB5A3 texture arrays contain the same bytes
in EN, EN rev1, JP and PAL rev1. The mismatch was a false relocation in the edge
texture, not a different Japanese asset.

`gameTextInitBoxTextures` allocates a 16-by-16 and a 20-by-20 RGB5A3 texture,
copies each source through halfword loads/stores, and flushes 512 and 800 bytes.
The source arrays have 256 and 400 `u16` texels respectively. Edge texels 320 and
321 are `0x8001, 0x8000`; together they resemble the word `0x80018000`.

| Version | Edge texture | Pixel pair address |
| --- | --- | --- |
| EN | `802CA100` | `802CA380` |
| EN rev1 | `802CAC80` | `802CAF00` |
| JP | `802CA200` | `802CA480` |
| PAL rev1 | `802CB8B8` | `802CBB38` |

In JP, dtk interpreted that word as `textRenderStr + 2864`, zeroing it in the
extracted object and adding a relocation at `.data + 0x498`. Both texture symbols
now carry `data:2byte noreloc` in all four verified versions. The switch table
following the arrays keeps its eight real case relocations.

EN's older global block on relocation targets `80018000..80018004` is removed.
The only aligned initialized-data occurrences are the edge texture and
`gLoadingScreenTextures`, which already has its own `noreloc` annotation. The
strict EN checksum verifies the more precise replacement.

JP's drawbox unit now matches 3,100 code bytes and all 1,460 data bytes, adding
1,368 matched data bytes and one completed unit. Both the all-retail link and a
link substituting this unit's source reproduce SHA-1
`a0646def31229c051f5143e6551840e6560b0556`. Source object bytes are unchanged.

All four source builds pass and EN's strict retail checksum passes. The texture
annotations survive regional symbol regeneration. EN rev1 and PAL retain their
existing drawbox code differences, including the later four-pixel HUD border
expansion; this metadata correction does not claim those functions as matching.
The neighboring texture-tiling function also retains its register-allocation
mismatch and is not included in the verified JP source substitution.

```sh
python3 tools/verify_source_link.py GSAJ01 main/textrender_drawbox.c
```

## Completing the later HUD border change

EN rev1, PAL v1.0, and PAL rev1 now also match the complete drawbox unit.
Their `gameTextDrawBox` expands the style-7 HUD rectangle by four pixels on
each side when the current text directory is not 3. Retail subtracts four from
the signed X/Y arguments and adds eight to width/height, narrowing each result
to `s16` before `drawHudBox`. The shared source uses a private border-width
constant: zero in EN v1.0/JP and four in the other three versions. The directory-3
solid rectangle and other box styles keep their existing geometry.

| Version | `gameTextDrawBox` | Size |
| --- | --- | --- |
| EN v1.0 / JP | `8001BE90` | 1,820 bytes |
| EN rev1 | `8001BF44` | 1,836 bytes |
| PAL v1.0 / PAL rev1 | `8001BFF4` | 1,836 bytes |

This adds four instructions. Six switch-table destinations move forward by
16 bytes, explaining the previously unmatched 1,368-byte `.data` section:
the texture bytes themselves were already equal. All five verified DOLs have
identical corner and edge textures, including the newly available PAL v1.0.
Allocated non-code bytes and symbol positions in the source object are unchanged;
the six `.data` relocation addends now identify the correct case labels.

The independent source link also exposed an unnamed PAL dependency:
`gGameTextBoxCornerInset`, owned by `gametext.c`. The small-data audit against
EN rev1 finds four corresponding loads in `gameTextDrawBox`. Manual inspection
confirms `lwz r7, -0x7D9C(r13)` at `8001C1B8`, `8001C210`, `8001C268`, and
`8001C2C0` in both PAL revisions. Retail startup initializes r13 to `803E4980`
in PAL v1.0 and `803E4B40` in PAL rev1, resolving to the existing four-byte
symbols at `803DCBE4` and `803DCDA4`. Both contain integer 2. These symbols now
use the canonical name; their addresses, sizes, and ownership are unchanged.
The EN v1.0-based audit cannot anchor this changed function; EN rev1 supplies
the identical retail body needed for the comparison.

Each later version gains one exact 1,836-byte function, 1,368 reported matching
data bytes, and one completed unit. All nine functions and all 1,460 data bytes
are exact across all five versions. EN v1.0 and JP source objects are byte-identical
to the baseline, and every other source object is unchanged in all five versions.
All five `all_source` builds, native strict checksum targets, and independent
all-retail/selected-source links reproduce the verified originals. The three
later matching manifests now include `main/textrender_drawbox.c`.
