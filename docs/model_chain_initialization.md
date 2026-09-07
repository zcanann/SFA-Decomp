# Model chain initialization and momentum

The EN v1.0 model-chain cluster uses the canonical records in
`include/main/model.h`. Its initializer and damping loop previously disguised
node fields as unrelated `ObjModel` and `ModelFileHeader` members. Those accesses
now name the actual node positions, local offsets, and momentum.

## Retail layout and behavior

`ObjModelChain_Alloc` at `80026CFC` allocates a `0x1c`-byte chain owner,
`count * 0x0c` bytes of entries, and `(nodeCount + 1) * 0x54` bytes of nodes
for each entry. Its input is traversed as pointers to descriptors containing
a joint-index pointer and a node count. The existing generic public argument
remains compatible with the callers' differently declared descriptor tables;
the allocator interprets each descriptor through `ObjModelChainDesc`.

`modelChainInitNodesFromJoints` at `80026928` initializes each ordinary node
from its descriptor's joint index:

- The 28-byte bone record's `head` coordinates become `localOffset` at node
  offsets `0x18`, `0x1c`, and `0x20`.
- The active 64-byte joint matrix's translation becomes world `pos` at
  offsets `0`, `4`, and `8`. The shared lookup retains the retail upper-bound
  fallback to joint zero and is evaluated separately for each coordinate.
- The extra terminal node receives local offset `(0, 0, 100)` and a world
  position obtained by transforming that offset through the last listed joint.
  This explains the allocator's additional node. As in retail, initialization
  assumes a nonempty joint-index list; it reads `jointIndices[nodeCount - 1]`.

`modelChainApplyDampingAndJitter` at `80026790` updates `posDelta` at offsets
`0x0c`, `0x10`, and `0x14` for all `nodeCount + 1` nodes. Each component receives
damping and axis-scaled jitter; the Y component also receives gravity. The
jitter calculation uses the first selected joint matrix's third row, now
expressed through `ObjModelJointMatrix.row2`.

The initializer, damping loop, and `ObjModelChain_Update` now index native
arrays. The allocator retains an explicit byte offset with `sizeof` strides
and typed field accesses: native indexing changes its exact instruction
sequence, and retaining a local entry pointer removes the retail reloads of
the entry-array base. Layout assertions sit beside the canonical definitions.

## Code generation

With game compiler GC/1.3, all 85 model function bodies retain their previous
instruction bytes. The four affected functions remain 100% in objdiff; the
unit remains at 74/85 exact functions and 92.268425% aggregate fuzzy match.
Allocated section bytes, sizes, and named symbol layouts are unchanged.
Anonymous literal symbols are renumbered, but normalized relocation
destinations are unchanged. Separate formatting preserves complete object
bytes. The strict retail checksum and `all_source` builds validate linkage
and the canonical header across consumers.
