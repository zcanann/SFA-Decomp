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

## Static block-line range stores

The final `trackIntersect` phase writes the current sorted-line ordinal into
both the new segment's start and the previous segment's end. Its narrowed
`u16` local is now named `sortedLineIndex`, and both stores explicitly cast it
to `u16`. Either cast alone leaves the old code unchanged; together they keep
the stored value in retail's r4 while the extended previous type occupies r5.
These casts preserve the existing value and width.

LLDB captures reproduce the ordinary before/after objects and successfully
replay both GPR graphs: 286 nodes / 252 color choices before, 287 / 253 after,
with no high-degree removals. The index narrowing defines original virtual
GPR32 before the change and temporary GPR257 afterward. Physical coloring then
assigns the latter r4. This is a codegen-significant source spelling, not a
change to segment types, ordinal values, or table storage.

All five versions improve from **99.552635% to 99.61404%** for `trackIntersect`.
The 570-instruction / 2,280-byte body changes only seven instruction words:
509, 511, 513, 518, 519, 521 and 524 swap r4/r5 operands. Retail differences
fall from 32 to 26. The TU reaches **99.74085%**, still **24/30 exact functions**;
`trackGetIntersect2` remains at 99.989235% with its two differing stores.

The other 29 functions, allocated data, named-symbol layout and resolved
relocations are unchanged. All five originals' configured hashes are rechecked;
full source builds and strict retail checksum gates pass in each version.
The raw object SHA-256 is
`ea07066e0c5c0da98c2c5c270472b5ad0a71e1e577a140b5690f3a13636b660c`.
No host execution of the entire static-line rebuild is claimed.

Splitting adjacency/range-loop counters, extracting inline adjacency or range
helpers, permuting the original counter declarations and adding casts to
adjacency accesses do not improve this candidate. Removing the existing empty
loop regresses code generation substantially, so it is retained. Coordinator
pointer-walk experiments also leave its two store differences unchanged.

## Exact model-line builder through the pool accessor (September 20)

`intersectModLineBuild` now matches all **338 instructions / 1,352 bytes**.
The private `trackGetPooledLine(index)` accessor returns a typed element of the
existing integer-backed engine pool. The builder uses ordinary indexed access
through this helper and shares one neutrally named `index` across endpoint,
adjacency and output loops. These lifetimes do not overlap. No volatile access,
new storage, compiler setting or forced-inline pragma is needed.

The earlier shared-counter/indexed candidate already emitted the correct
instruction sequence but exchanged the adjacency pointer and byte-offset
registers. Comparing its LLDB capture with the accessor version aligns all
338 instructions and maps 188 registers, with no partition conflicts or mapped
interference-edge differences (four graph neighbors remain unmapped). The
pointer changes from virtual GPR49/r4 to GPR72/r3, and the generated offset
changes from GPR70/r3 to GPR69/r4. This recovers the retail colors. The accessor
is inlined; no extra function body or call is emitted.

The retained capture exactly reproduces the ordinary object, replays the
230-node GPR graph and all 196 physical color choices, and reports zero retail
differences. Against the previous retained source, only instruction 94 changes:
`li r4,0` becomes retail's `mr r4,r5`. Every other function's bytes, every named
symbol's location and every non-text byte is unchanged. Anonymous literal
labels renumber, but their relocation offsets, types, addends and resolved
destinations remain identical.

All five input DOL hashes are checked. Each regional `all_source` and strict
retail checksum gate passes, and all five track objects have SHA-256
`ca5e66b31beb372b8424aee30297da96e2707163d94f7bf8d15173f0c6268c95`.
The complete TU reaches **99.90503%**, with **26/30 exact functions**. It remains
`NonMatching`; this is an exact function, not a claim that the entire TU links
from source to retail bytes.

## Static-line adjacency uses the same accessor

`trackIntersect` now also calls `trackGetPooledLine(i)` in its adjacency pass.
This one-line change fixes eighteen register-only instruction differences,
raising the function from **99.61404% to 99.807014%**. It remains 570 instructions
/ 2,280 bytes. Its eight remaining differences are the sort-loop zero copy at
index 321 and the final segment-loop counter/offset registers at indices
489, 490, 494, 513, 526, 527 and 529.

Both LLDB captures reproduce their ordinary objects and replay 287-node GPR
graphs with 253 color choices and no high-degree removals. The register-role
comparison aligns all 570 instructions, maps 222 registers, and finds no
partition conflicts or mapped interference-edge differences; four neighbors
remain unmapped. The adjacency pointer changes from virtual GPR50/r5 to
GPR87/r3, its index from GPR65/r4 to GPR64/r5, and its offset from GPR84/r3 to
GPR83/r4. These are all the changed instruction operands.

All five regional objdiff reports now give the TU **99.92069%**, with
**26/30 exact functions**. Each region passes the original-DOL hash check,
`all_source` and strict retail checksum. All five object hashes are
`833e92e118ea39d26a25a1b3b6af59d31c89b097088f3ad53e98ac44286792f8`.
Only `trackIntersect` changes relative to the exact-model-builder commit;
other function bytes, named symbols, data and resolved relocations are
unchanged. The two builders' shared accessor has no emitted out-of-line body.

## Exact sorting opcodes and typed endpoints (September 20)

The private `trackSortLineOrder()` helper now owns the bubble-sort pass, while
its identity-table initialization stays in the caller. The helper uses typed
`IntersectLine.kind` accesses and keeps the evidenced table-base reload for
the second swap store. Its declaration order matters to MWCC's register
allocation. Inlining recovers retail's `mr r5,r10` at instruction 321 without
volatile accesses or an extra call/body. Extracting the initialization too
instead exchanges its counter and offset registers, so that broader helper
was rejected.

The final segment pass uses indexed lookup through `trackGetPooledLine` rather
than a second manually maintained byte offset. This preserves its zero copy
once the sorting offset has moved into the helper. The map-line import pass
also uses the canonical `MapHitLine.x/y/z[endpoint]` and
`IntersectLine.pt[endpoint]` arrays. The source-coordinate and destination-byte
scratch cursors are unnecessary: removing both preserves every already-exact
instruction and changes only the still-unmatched final-loop register choices.
Removing the resulting unused declarations preserves the raw object.

`trackIntersect` improves from **99.807014% to 99.91228%**. All 570 opcodes and
non-register operands match retail. Seven instruction words still differ at
indices 489, 490, 494, 513, 526, 527 and 529: the final index uses r26 instead
of r23, and its generated offset uses r25 instead of r22. No function is
promoted to exact by this change.

The final LLDB capture equals the ordinary compile, aligns all 570
instructions, and replays the 287-node graph and 253 color choices without
high-degree removals. Retail's colors for virtual GPR60 and GPR68 satisfy that
same graph with all other colors unchanged. A scratch replay of the candidate
before endpoint cleanup could recover retail colors by moving its two final
values earlier in simplification order. Actual dedicated locals at those
positions recovered the physical registers, but replaced the required zero
copy with a second `li`. The named/generated exclusion in the companion
compiler's `GC13_ValueNumbering_CanNumber` explains that tradeoff. Those
experiments are not retained. Volatile scalar casts did not fix it; volatile
objects or reads added stack storage and instructions.

All five input hashes, source builds and strict retail checksums pass. Regional
objdiff reports agree at **99.92923% for the TU**, with **26/30 exact functions**.
Each track object has SHA-256
`cf5235c552236ef4632d0aa1cc5073ef03340de58a7bb6c82c4e8950fcb66b34`.
Only `trackIntersect` changes relative to the preceding accessor commit;
other function bytes, named-symbol layouts, non-text data and resolved
relocations remain identical. The unit is still `NonMatching`.
