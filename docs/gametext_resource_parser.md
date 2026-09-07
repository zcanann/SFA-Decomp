# Game-text resource parser

`gameTextFinalizeLoad` occupies EN `8001AD64..8001B39C`. It installs a completed
resource, uploads font images, and retains a compact allocation containing the
glyph, message, and string tables. Its two relocation passes are distinct:
message records initially contain string-table indices, while string-table words
contain byte offsets relative to the string-data block. After the table prefix
is copied, both pointer levels and the charset's two table pointers move by the
allocation delta.

## Corrected record boundaries

The previous eight-byte `GameTextTableHeader` began four bytes before the actual
header. Its `unk0` was the final `TextGlyph`'s width, height, font, and page bytes,
not a header field. EN code stores `input + 4` as the glyph table and reads the
message count and string-data size at `input + glyphCount * 16 + 4` and `+6`.
The recovered records now express those boundaries directly:

| Record | Layout |
| --- | --- |
| `GameTextGlyphTable` | four-byte count, followed by 16-byte `TextGlyph` records |
| `GameTextTableHeader` | `u16 entryCount`, `u16 stringDataSize`; four bytes total |
| `GameTextDef` | existing 12-byte message record |
| `GameTextStringTable` | four-byte count, followed by four-byte offsets/pointers |
| `GameTextTextureHeader` | four `u16` fields: format, bits per pixel, width, height |

The texture stream follows the string-data block and a length-prefixed skipped
block. Each texture's payload follows its eight-byte header. Zero width **and**
zero height terminate the stream. The file format values 1 and 2 map to the
existing `GX_TF_RGB5A3` and `GX_TF_I4` constants. Pixel copying still follows the
retail split: four-bit images copy bytes; other images copy halfwords. The stream
advance uses the recorded bits-per-pixel value, independently of that copy branch.

The parser now indexes `TextFont.textures` instead of treating the entire font
record as an `int**` and indexing four words beyond the cursor. Image access uses
the existing texture-header helper and native `Texture.dataSize`. Named locals
distinguish string data, padding, texture data, and the compacted allocation.
The compacted prefix still ends at the first texture header, so it includes the
skipped block but excludes texture headers and image payloads.

## Asset evidence

This checkout has the EN v1.0 DOL but no extracted EN v1.0 `files/gametext` tree.
Cross-checking the available EN rev1 assets confirms all 1,216 resource extents:
764 contain one image and 452 contain two. Every file ends exactly after the
zero-dimension texture terminator. The skipped block is empty in 856 files and
contains only `0xEE` in the other 360. That filler pattern does not establish its
original purpose.

For example, the EN rev1 Link/English resource has 61 glyphs. The last glyph's
tail is `09 0F 04 00` at file offset `3D0`; the real message header starts at
`3D4` and contains count `0037` and string-data size `03B8`. Boot/English has
43 glyphs and its real header begins at `2B4`. EN instruction accesses, rather
than cross-version asset addresses, determine the source layout.

`tools/orig/source_leaks.py --orig-root orig/GSAE01_rev1 --search gametext`
also identifies the bundled generated Boot source artifacts and their
`GameTextData.h` references. No literal source/header artifact is imported here.

## Execution and matching

`tools/gametext_parser_probe.py` links the actual MWCC object into a separate
emulated address range and compares its complete parser against the EN DOL.
It runs the retail register-save helpers and mocks allocation, freeing, and cache
maintenance. The mocks clobber volatile integer registers. Comparisons cover the
call arguments/order, four charset records, load-slot state, language/directory,
mutated input, compacted tables, and texture payloads. Allocation guards, the
stack pointer, nonvolatile GPRs, SDA registers, and CR2–CR4 are checked as well.

The default 360 comparisons include empty resources; zero, short, eight-element,
and remainder string loops; zero through three textures; short image copies;
all four source selectors; and first/second texture-allocation failures. Adding
English/Japanese Boot, Link, and sequence 4 resources produces 432 passing
comparisons. A deliberate one-byte error in the initial string relocation fails
the compacted-buffer comparison. This validates the tested parser behavior;
it does not execute the real allocator, GPU, cache hardware, or the asynchronous
loader, and does not claim malformed-input or allocation-failure safety.

Run with the optional `unicorn` and `pyelftools` Python packages installed:

```sh
python3 tools/gametext_parser_probe.py \
  --audit-root orig/GSAE01_rev1/files/gametext \
  --resources orig/GSAE01_rev1/files/gametext/Boot/English.bin \
  orig/GSAE01_rev1/files/gametext/Boot/Japanese.bin \
  orig/GSAE01_rev1/files/gametext/Link/English.bin \
  orig/GSAE01_rev1/files/gametext/Link/Japanese.bin \
  orig/GSAE01_rev1/files/gametext/Sequences/4_English.bin \
  orig/GSAE01_rev1/files/gametext/Sequences/4_Japanese.bin
```

The structural correction is retained despite a codegen regression:
`gameTextFinalizeLoad` changes from 99.836685% to 97.79397% fuzzy and from 1,592
to 1,596 bytes. Most differences are register allocation; the typed glyph-table
expression adds one address calculation. Gametext changes from 96.54275% to
96.39944%, retaining 41/54 exact functions and unchanged exact-code/data credit.
All 53 other functions retain their instruction bytes. Non-text section bytes
and named storage offsets remain unchanged. The source remains `NonMatching`;
the strict retail checksum therefore does not validate this parser's C.

Both the strict checksum target and `ninja all_source` pass with 30-second
timeouts. The existing load-slot, runtime, font-resource, measurement, and color
suites also pass. Formatting is a separate commit and preserves the complete
generated object.
