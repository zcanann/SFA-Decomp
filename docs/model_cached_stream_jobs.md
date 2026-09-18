# Cached model animation jobs

Target: EN v1.0 (`GSAE01`), game compiler GC/1.3.

The two blend-stream entry points take a 0x10-byte `ModelVtxAnimJob`, embedded
at `ModelFileHeader + 0x88` for vertices and `+ 0xac` for normals. Their retail
loads select the halfword chunk count at job +0x02, GQR7 quantization scale at
+0x06, and chunk pointer at +0x0c. The renderer supplies exactly those two
header addresses. The old implementation read the count as an unrelated
`ModelFileHeader.flags` field and obtained the other fields through raw offsets.

Allocation, instance setup, relocation, and rendering now use the embedded job
records. `ObjModel_RelocateAnimData` assigns each job's chunk pointer from its
corresponding loaded entry array, then fixes up weight-stream offsets. The old
flat count and pointer aliases are removed. All other model-header offsets
remain unchanged.

Both loaded entry arrays now have the canonical `ModelVtxAnimChunk*` type.
The relocation loop at EN `0x80028ec0` also establishes two different instance
output tables: `vertexAnimOffsets` at `ObjModel + 0x40` stores each chunk's
signed 32-bit byte offset, while `normalAnimOutputs` at `+0x44` stores
`normalBuf + chunk.srcDataOffset` pointers. The vertex stream adds its selected
output-buffer base to each offset; the normal stream uses the pointers directly.
The renderer now passes these fields without the old unrelated model-header
overlay or integer-to-pointer casts. The normal entry array and weight-stream
base are named consistently with their proven normal-stream consumer.

The renderer retains its integer storage view when selecting a double-buffered
vertex pointer, using `offsetof(ObjModel, vtxBuf)` in place of the literal offset.
Native pointer-array indexing changes the addressing sequence and regresses the
otherwise exact shadow-render function; the canonical output-table accesses
preserve the complete renderer object.

A chunk occupies 0x74 bytes. Its recovered tail contains the source-data offset,
weight-stream pointer, two reordered-matrix indices, transfer counts, element
count, and byte offset within the cached data. The loaders now use native chunk
indexing, including `chunk[1]` for prefetches, and `sizeof(ROMtx)` for the matrix
stride. Unknown chunk contents remain opaque.

The transfer counts are 32-byte blocks, not four-byte words: both cache wrappers
forward their count to the locked-cache block API or multiply it by 32 in the
ordinary-memory fallback. The source retains the retail rounding expression.
Each loader primes the first data/weight pair, alternates between two pairs of
cache buffers, queues the next pair before waiting, transforms the current
chunk in place, and copies the result to its output. The last chunk is processed
after a full queue wait. The normal variant retains both its ordinary and
three-vector transform paths.

A direct `gModelCacheBuffersA[1]` access at the initial weight transfer keeps an
extra address alive and changes register allocation throughout both loaders.
The proven integer-address expression remains, with its byte offset expressed
as the size of one actual array element. The existing byte-sized cache indices
and reload order also remain.

The paired-single transform kernels retain their existing scalar C fallbacks.
This job recovery does not claim to reproduce their quantized instructions or
resolve their zero match scores.

Validation: all 85 model function bodies, allocated section contents, named
symbol positions, and relocation destinations are unchanged. Three anonymous
compiler-generated relocation names differ in `model.o`; all other 1,001 source
object hashes are identical, including `objprint_dolphin.o`. The complete objdiff
report is unchanged: the normal loader remains 880 bytes at 99.181816%, and the
vertex loader 628 bytes at 99.01274%. The strict retail checksum and `all_source`
pass. Existing matrix-preparation tests pass 144 scenarios each at O0 and O2;
those tests cover adjacent matrix behavior, not cache-DMA execution.


## Vertex stream helpers (2026-09-18)

The vertex stream now uses a private inline helper to prefetch the next data and
weight pair. It returns the current chunk captured before the transfer calls,
retaining the original chunk-table reload for the weight transfer. Its
`nextBufferIndex` selects the data buffer directly; the adjacent entry selects
the weights. The initial
prefetch remains in the caller. A second private inline helper shares the
transform-and-copy operations between the loop and final-chunk paths.

EN objdiff improves `ObjModel_BlendVertexStream` from 99.01274% to 99.20382%.
Its size remains 628 bytes; 21 instructions still differ in register operands,
down from 28. The final-chunk path is byte-exact; remaining register differences
are in the loop and its setup. This is partial progress, not a new exact function. All other 84
function bodies are unchanged. Formatting and the final helper name preserve
the tested candidate's allocated bytes and normalized relocations.

`tools/model_vertex_stream_probe.py` resolves the retail object's relocations
and verifies its complete body against the hash-verified EN DOL, then executes
both wrapper bodies in Unicorn. An independent call oracle checks 640 scenarios
with 0, 1, 2, 3, 4, 7, 8, 15, 16 or 31 chunks, signed input/output offsets,
byte-sized matrix and transfer counts, and varied quantization values. It
checks transfer, wait, transform and output-copy arguments and ordering while
clobbering volatile GPRs at dependency calls. DMA, skinning arithmetic and
save/restore helpers are stubbed; these tests do not validate hardware transfers
or callee-save behavior. All 1,280 wrapper comparisons pass. EN `all_source`,
the strict checksum target and active-source/header formatting checks pass.

Reproduce after building the source object, using Python with Unicorn installed:

```sh
python3 tools/model_vertex_stream_probe.py build/GSAE01/src/main/model.o --output /tmp/model-vertex-stream.json
```

The same source change was also compiled for EN rev1, JP and PAL rev1 after
verifying each input DOL against its configured hash. Each regional report
shows the same 99.01274% to 99.20382% improvement; only the vertex-stream body
changes. Allocated non-text bytes, normalized relocations and named symbol
positions are unchanged in each before/after pair. No regional source condition
or completion-manifest claim is added.


## Exact normal-stream wrapper (2026-09-18)

A private inline `modelConsumeNormalChunk` helper now shares the normal wrapper's
transform-and-copy sequence. Its function-pointer argument receives one of the
two fixed kernel functions; GC/1.3 resolves it during inlining, preserving direct
calls. This removes four duplicated sequences and reproduces retail register
allocation without assembly, pragmas, or compiler-profile changes.

`ObjModel_BlendNormalStream` is now exactly 880 bytes with identical normalized
relocations in EN, EN rev1, JP and PAL rev1. Each original DOL passed its configured
hash check. EN model now has 80 of 85 exact functions; the complete TU remains
`NonMatching`. The vertex wrapper retains its 99.20382% improvement. Against the
prior committed source, only these two function bodies change; allocated data,
normalized relocations and named symbol positions remain unchanged. No regional
completion manifest claims the still-incomplete object.

The final formatted normal helper preserves the tested body. The vertex call
oracle still passes 640 cases per implementation; the normal wrapper is verified
by complete byte and relocation identity. `ninja all_source`, the strict retail
checksum target, an explicit retail checksum verification, and source/header
formatting checks pass.
