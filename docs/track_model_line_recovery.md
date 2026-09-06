# Track model-line ownership

## September 6: Canonical definition and range records

`intersectModLineBuild` receives the `ObjDef` loaded from `OBJECTS.bin` in
`loadObjectFile`. That caller initializes `modLines` and `modLineCount` before
the call. The former `IntersectModLineObject` overlay duplicates these fields
and the three generated pointers at 0x34, 0x38 and 0x3C. It is removed; the
builder and line-enable helper now use the canonical `ObjDef` fields.

`include/main/track_line.h` owns the existing 16-byte `IntersectLine` record
and the recovered two-byte `TrackModelLineRange`. The builder allocates
`lineCount * 16 + pointCount * 12 + 40` bytes and places the ranges after the
points. On each sorted-kind transition it writes the new first index and
the preceding range's end index. The last range ends at the total line count.
The sweep scans `first <= i < end`. This establishes twenty half-open byte
ranges, not a second object layout. The shared `ObjDef` size remains 0x9C;
pointer offsets and both record layouts have compile-time assertions.

The sweep's segment selector and vertical tolerance are consistently `s8` in
the public declaration. Segment `-1` selects all lines; otherwise it indexes
the model or map group table. Tolerance expands the vertical interval.
Retail forwards both arguments without extra narrowing, and reads the
stack-passed tolerance with `lbz`. Widening their definitions to `int` adds
conversions and changes that load to `lwz`. Their two header override macros
are removed across all consumers. `TRACK_BBOX_FLAGS_S8` remains: widening the
line mask adds conversions, while making the complete mask chain unsigned
loses the exact lower-level sweep. Caller signedness still needs recovery.

## Verification

The signature-only cleanup rebuilds 45 objects and leaves all 2,873 source
objects raw-identical. The model-ownership change rebuilds 671 objects; only
`track_dolphin.o` changes. All its data bytes, section layouts, named symbol
locations and relocation records remain identical. Only 17 instruction bytes
change, confined to register choices in the builder's range-clear loop.

The builder stays 1,352 bytes but moves from 99.82249% to 99.57101% fuzzy;
the complete TU moves from 99.7081% to 99.696%. Its 23 exact functions and
every other function byte sequence are preserved. The typed range lookup in
the sweep is byte-neutral. Ordinary two-member initialization adds six
instructions, and `memset` replaces the inline clear with a call; neither is
retained. The byte-clear loop operates on the actual allocated buffer without
the old pointer-to-pointer reinterpretation.

No flags, splits, symbol configuration or matching classifications change.
The source build and strict retail-DOL gate are both required. This is source
and type recovery with a small fuzzy regression, not a code-byte matching gain.
