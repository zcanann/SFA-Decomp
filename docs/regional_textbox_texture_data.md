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
