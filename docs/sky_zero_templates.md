# Sky zero initializer ownership

Engine slots 5 and 6 each own a zero initializer in `.sbss2`. Ordinary C
initializers emit both templates with the existing compiler profiles and preserve
all 75 function bodies. Neither unit needs a text boundary change.

`skyRenderTimeOfDayBackdrop` initializes one four-byte `GXColor`. Its old
`lbl_803E8458` symbol incorrectly included four following alignment bytes.
`sky2_run` initializes one three-byte `SkyBestIdx` record using a halfword load
followed by a byte load. The old two-byte and six-byte symbols divided that
record and included five following bytes in its final member.

The index record contains two selected direction indices and one unused byte.
The selection loop considers eight directions, then the blending loop reads
exactly two indices. The source now expresses those accesses as a two-element
array and asserts the complete three-byte record layout. The third byte is
initialized by retail but has no subsequent consumer in this function.

The index template is a local const aggregate, copied into the existing local
at the original initialization point. Initializing the destination at its early
declaration instead changes 59 instruction bytes through scheduling; preserving
the copy's execution point retains the exact body. No compiler overrides,
forced sections, helper bodies, or synthetic padding declarations are needed.

## Retail boundaries

Each verified DOL's startup r2 value and the three consumer instructions establish
these addresses independently:

| Version | Backdrop color | Direction indices |
| --- | --- | --- |
| EN | `803E8458` | `803E8460` |
| EN rev1 | `803E90D8` | `803E90E0` |
| JP | `803E8578` | `803E8580` |
| PAL rev1 | `803E9E38` | `803E9E40` |

The color word load is at `skyRenderTimeOfDayBackdrop+0x24`; the index halfword
and byte loads are at `sky2_run+0x94` and `+0x9C`. A full direct r2 load/store
scan of each corresponding 16-byte neighborhood finds only these three accesses.
The active EN extracted-object relocation scan agrees; no other live object
references the old three symbols. Indexed or materialized-address accesses are
outside the direct instruction scan.

Config names now identify `sSkyBackdropFogColorInit` and `sSkyBestIndicesInit`
consistently across all four versions. The color claim is four bytes. The index
claim ends on the next word boundary: its symbol is three bytes, followed by one
DTK-generated alignment byte. Ending the split immediately after byte three
makes the following automatic BSS unit invalidly aligned. The source object's
index section remains exactly three bytes; its next linked section supplies
alignment naturally. No fourth record member is invented. The following four
bytes remain automatic and the four bytes after the color remain unclaimed.

The required `version_progress.py <version> --write` attempts currently fail
because its initialized-data analysis tries to read the new sky BSS range from
the DOL file. Existing regional configs are preserved; only the directly verified
sky ranges and symbols are changed. BSS ownership is checked through retail
addresses and emitted `SHT_NOBITS` layout, not nonexistent file-backed bytes.

## Validation

Both sky units remain 100% exact and complete in EN, EN rev1, JP and PAL rev1.
Slot 5 retains 57 functions and 16,924 code bytes, with 780 reported data bytes.
Slot 6 retains 18 functions and 9,236 code bytes, with 384 reported data bytes.
Each version gains eight matched and completed data bytes: seven bytes of
initializer records and the one alignment byte counted by objdiff. The total
data denominator decreases by four bytes after DTK recognizes the backdrop
color's following alignment. Code scores and denominators do not change.

Every previous allocated section and named symbol layout is unchanged. The
only new sections are eight-aligned `.sbss2` sections of four and three bytes.
All relocation sites, kinds, and destinations are preserved except the three
former external references, which now select the local templates at their exact
retail offsets. Every other compiled source object is byte-identical across all
four builds. Full source builds and the strict EN retail checksum pass. Both
sky units use their compiled source objects in the matching link.
