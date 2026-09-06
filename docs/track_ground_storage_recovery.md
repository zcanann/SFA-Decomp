# Track ground-query storage

## Retail evidence

The former `gIntersectSegmentTypeTable[0x212]` declaration hid three distinct
arrays in one 1,060-byte `u16` object. `trackIntersect` initializes forty
halfword range endpoints; the line sweep selects one of twenty ranges.
`trackGetHeight` uses the following 35 pointers to order results, then 35
24-byte `TrackGroundHit` records. Both the coordinator and triangle collector
stop at 0x23 results. These capacities come from runtime indexing and limits,
not solely from gaps between symbols.

The recovered EN layout is:

| Address | Storage | Bytes |
| --- | --- | --- |
| 8038D840 | `gIntersectSegmentTypeTable[40]` | 0x50 |
| 8038D890 | `gTrackGroundHitOrder[35]` | 0x8C |
| 8038D91C | `gTrackGroundHits[35]` | 0x348 |
| 8038DC64 | Existing `gTrackBlockDescriptors[20]` | 0x1E0 |
| 8038DE44 | Existing `gTrackGridOrigin` | 0x104 |

`trackGetHeight` now initializes native array pointers, fills the order table
by indexing complete hit records, and uses the existing `TrackQueryBounds`
fields. No raw offsets into the range array remain in the query. The result
sort still rearranges pointers only, in descending height order with stable
ties. Negative modes still skip broadphase, mapping -1 to zero and other
negative values to one.

Descriptor storage is not enlarged: the retail broadphase can advance to its
20-entry limit and write a sentinel beyond that array into the following
grid-origin storage. This change does not conceal or repair that behavior.
The unexplained remainder of the grid-origin object is left untouched.

## Verification

GC/1.3 generates the exact BSS offsets above without section directives or
compiler-profile changes. Total BSS remains 0x708. All non-text section bytes
and layouts are unchanged; all previously named objects keep their addresses.
The compiler now emits its own common BSS-base symbol. Literal names renumber,
but their payloads and resolved locations do not change.

Only `trackGetHeight` changes among all 2,873 source objects' functions. It
remains 632 bytes, with descriptor setup moved after broadphase and result
pointer initialization reordered. Its fuzzy score falls from 100% to
98.341774%; the TU moves from 99.696% to 99.65869%, retaining 22 rather than
23 exact functions. Data remains 100%. This is a deliberate source/storage
recovery regression, not a code matching improvement.

`python tools/test_track_ground_query.py` compiles the production coordinator,
record types and global declarations into a host harness. Three tests cover
35 query cases: bounds truncation, modes, object/static coordinate paths,
triangle intervals, empty/single/full result sets, capacity dispatch, stable
sorting, unchanged records and repeated-query reset. Geometry intersection
itself is mocked and is not verified by this harness. Reversing the production
sort predicate in memory produces 28 failures, confirming the ordering oracle
rejects that regression. Host pointers are native-sized; retail layout is
checked separately in the MWCC object.

`ninja all_source` and the strict retail DOL checksum both pass. The TU remains
`NonMatching`, so the strict link uses its retail object and is not proof of
the reconstructed function's instruction identity.
