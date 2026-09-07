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
