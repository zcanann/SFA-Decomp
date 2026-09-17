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

## September 7: Typed sorting and range-clear addressing

The builder now sorts and marks consumed entries through `IntersectLine.kind`,
uses `sizeof(IntersectLine)` and `sizeof(Vec)` for its line/point storage, and
names the candidate, selected, and emitted line indices. The shared engine pool
retains its existing integer storage. The `sizeof` terms explicitly retain
signed arithmetic so the existing allocation-size zero test keeps its retail
`cmpwi`. The signed byte access used to toggle line flags also remains: an
unsigned compound assignment changes the retail sign-extension instruction.

A local byte pointer inside each range-clear iteration gives MWCC the retail
base-plus-index addressing. It preserves the reload of the definition's range
pointer before each byte store and removes all sixteen operand differences in
that loop. The builder improves from 99.57101% to 99.82249%; only the earlier
adjacency loop's `li` versus `mr` initialization remains different. The typed
sort and size expressions are byte-neutral.

The complete object comparison changes seventeen instruction bytes only in
`intersectModLineBuild`. All other 29 function bodies, symbol layouts, relocation
records, and non-text bytes remain identical. The TU reaches 99.67222% fuzzy,
retains 23/30 exact functions, and keeps all 2,040 data bytes exact. Formatting
is committed separately and preserves the raw object hash. Both `all_source`
and the strict retail checksum gate pass; the TU remains `NonMatching`.

## GC/1.3 zero-commoning boundary (September 17)

A fresh unchanged-object backend capture now follows the single differing
instruction through 21 stages. At the first adjacency-loop initialization,
`outputLineIndex` is virtual GPR 43 and `lineByteOffset` is GPR 44. Both zero
loads remain unchanged through late value numbering: its eligible interval is
[49, 227]. The baseline raw-object SHA-256 is
`6aa15c92ee6ae57d0b9930a7d335f8196a9761d4b3ff02755e66bab5a25cc520`.
The independently reconstructed GC/1.3 predicate at `0x005082a0` rejects these
named-register destinations. This distinguishes the difference from physical
color selection or a missed final peephole.

Replacing explicit byte-offset induction with ordinary array indexing gives
a compiler-generated offset in GPR 70, inside [48, 227], but the first zero
still targets GPR 43. No commoning occurs; indexing alone is insufficient.
Extracting the adjacency pass into an inline helper does produce the retail
copy: after late value numbering, GPR 70 copies GPR 69 and becomes `mr r4,r5`.
However, this moves the zero-commoning mismatch to the sorting loop: its named
index is GPR 41, below the helper variant's lower bound 46, and the generated
GPR 61 zero cannot share that excluded definition. Other registers also change,
so the helper is not retained.

Reusing the endpoint counter for the later adjacency/sorting index and using
ordinary array indexing produces the complete retail instruction sequence,
including the required copies. Its remaining eleven operand differences swap
only the adjacency offset and line pointer between r3 and r4. This is a useful
source-shape witness, not an accepted source change: its 99.80769% fuzzy score
is below the retained 99.82249%. Giving adjacency its own typed line pointer
rotates three registers instead. Sharing every line counter additionally
changes later strength reduction, so that broader rewrite is also rejected.

The trace validator now recognizes GC/1.3 opcode 0x199 (`PSQ_STX`), independently
checked against the verified compiler's descriptor table at `0x005bdcf0` with
18-byte stride. This permits the builder's large-stack indexed paired-single
save to pass mnemonic/register alignment; it does not add a complete paired-
single encoding validator. All 38 backend-IR tests pass, including a positive
indexed-store fixture and wrong-register/wrong-opcode rejection tests.

Reproduce the retained-source capture with:

```sh
python3 tools/tricky_backend_trace.py --unit main/main/track_dolphin \
  --function intersectModLineBuild --graph --register-class gpr \
  --output build/track_complete/model_line_trace
```

The endpoint-counter/indexed candidate's GPR graph has 230 nodes and 196
physical color choices, with no high-degree removals. Its line pointer is
virtual register 49 (r4), and its generated byte offset is virtual register 70
(r3). The retail projection exchanges those two colors and satisfies the
captured interference graph with every other color unchanged. Thus the remaining
operand differences are consistent with allocation order, rather than a need
for extra instructions. The candidate object SHA-256 is
`34fd25445b494ef8382a5c2e28ccb01ac41a6faafce526d8c5bf04214a9e26ff`.

Declaring a separate adjacency pointer anywhere among the outer locals gives
the same three-register rotation as a loop-local pointer. Reusing the import
pointer preserves the two-register exchange; sharing only with the sorting or
final adjacency-update phase does not. Naming the computed byte offset inside
or outside the loop, or reusing the dead source-count variable for it, also
preserves the exchange. While/for spelling, prefix/postfix increments and
`register` qualifiers do not resolve it. Per-line or per-endpoint inline
helpers regress the match. None of these candidates is retained.
