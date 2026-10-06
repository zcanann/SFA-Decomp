# Model matrix preparation

The EN v1.0 matrix-preparation cluster in `src/main/model.c` uses three
different array layouts: 28-byte `ModelBone` records, 64-byte
`ObjModelJointMatrix` records, and 48-byte Dolphin `ROMtx` output records.
The joint matrix's first 48 bytes are an affine `Mtx`; its final 16 bytes
are not touched by these functions. The matrix bank is selected by
`ObjModel.bufferFlags & 1`.

| EN function | Address | Behavior |
| --- | --- | --- |
| `model_multMtxs` | `80027104` | Apply the supplied world matrix to each regular joint matrix in place. |
| `modelInitBoneMtxs` | `800271BC` | Concatenate each joint matrix with the negated bone-tail translation, then reorder the result for vertex processing. |
| `modelInitBoneMtxs2` | `800272A8` | Emit the same reordered matrices before applying the world transform to each joint. With zero joints, transform the single rigid matrix and emit no reordered output. |

The retail loops advance the bone records by `0x1c`, joint matrices by
`0x40`, and reordered matrices by `0x30`. Native `ModelBone` and `ROMtx`
indexing now expresses the initializer's two output/input strides instead
of one-element scalar arrays and manual byte counters. The world-transform
wrapper now shares `modelGetBoneMtx` and declares its model argument as
`ObjModel*`; its direct rendering caller uses that canonical type.

The existing matrix lookup preserves the retail upper-bound fallback to
joint zero. The zero-joint branch in `modelInitBoneMtxs2` retains its expanded
lookup because replacing it with the helper changes an already-exact body.

## Original GC/1.3 investigation (superseded)

The percentages in this section record the initial compiler migration. Subsequent
source work restored the complete matrix and rendering units to 100%; they are
not outstanding regressions or permission to retain new ones.

Under the game GC/1.3 compiler, `model_multMtxs` remains byte-exact at 184
bytes and `modelInitBoneMtxs2` remains byte-exact at 348 bytes. The 236-byte
initializer changes only four instruction bytes relative to the previous
source: two loop increments exchange order. Its objdiff score moves from
99.28814% to 99.15254%. The cleaner array representation is retained despite
that small scheduling regression. All other 84 function bodies are unchanged;
the unit retains 74/85 exact functions, with aggregate fuzzy match moving
from 92.26969% to 92.268425%.

Named symbol layouts and allocated data are unchanged. Relocation differences
are anonymous-symbol renumbering with unchanged normalized destinations. The
direct rendering consumer's object is byte-identical. The separate formatting
pass preserves the complete model and rendering-consumer object bytes.

`python3 tools/test_model_matrix_init.py` compiles the production function
bodies with host views of pointer-bearing owner records and the actual
pointer-free bone/matrix definitions. It checks 144 scenarios each at `-O0`
and `-O2`: joint counts through 255, both matrix banks, extra joints, all
three entry points, inverse-bind translations, world-transform ordering,
output guards, inactive/unused matrices, and the trailing joint-matrix row.
Expected results use independent affine formulas.

This is source-behavior coverage, not execution of the target PPC instructions:
the test models the SDK matrix operations in C and does not validate the
32-bit layout of pointer-bearing owners or Gekko floating-point rounding.
Target code generation is checked separately with objdiff and the matching
checksum build; `ninja all_source` checks the typed API across consumers.


## Bone output index and animation slots

`ModelBone` now distinguishes the packed output-matrix index/flags at `+1`
from the two animation-matrix slots at `+2` and `+3`. The former `idx[3]`
spelling grouped different roles and suggested that every byte carried a flag.
The signed parent remains at `+0`, head translation at `+4`, and bind translation
at `+0x10`; the complete record stays 0x1C bytes. All offsets and the total size
are asserted beside the canonical definition.

EN `modelAnimUpdateChannels` copies joint-matrix-slot bytes from either a cached
move's prefix or the resident animation map into `+2 + channel`. Three callers
pass two channels; the remaining call selects one or two. This establishes a
two-element slot array independently of the gap before the head vector. The
producer keeps its existing byte cursor and uses `offsetof` on the recovered
array. Native struct-member indexing changes the already-exact code generation.

The retail matrix builder at `80006C6C` supplies the corresponding readers:

- The blended pass reads `+2` for the first pose and `+3` for the second, scaling
  each slot by 64 bytes to index the packed pose/matrix workspace.
- Reads at `+1` select output and cached-quaternion slots through the low seven
  bits. Other paths sign-extend the byte, combine it with the caller's mask,
  and skip a bone when the result is negative. The high bit is therefore kept
  with the output index; it is not described as an unconditional disable flag.
- The single-pose path reads its animation slot from `+2`; the hierarchy pass
  continues to use the parent byte and output-matrix index.

The archived C reconstruction in `docs/foreign/joint_matrices_c.c` uses the same
canonical fields. Its existing signed casts and mask operations are preserved;
the live matrix-builder assembly is unchanged. This archived reconstruction is
supporting explanation, while the EN instruction accesses establish the layout.

The archived C also compiles against the current canonical header using the
render TU's compiler command. The existing matrix-preparation test passes all
144 scenarios at both host optimization levels. All source objects remain byte-identical in EN, EN rev1,
JP, and PAL rev1, with unchanged fresh objdiff reports. All four full source
builds and the strict EN retail checksum pass under 30-second timeouts.
Formatting of the active model source/header is committed separately and checked
for unchanged generated output. This is shared structure recovery; no new match
credit is claimed.

## Matrix render commands and their data

`objprint_dolphin.c` now declares the two GX matrix-ID tables, an ordinary
48-byte `Mtx` identity, and a 48-byte diagnostic string slot. The last twelve
floats of the former `gObjJointMtxTemp[24]` were actually the bytes of
`<renderOpMatrix> ERROR CASE numMatrices = %d\n`, its terminator, and two padding
bytes. The identity and diagnostic are distinct symbols in all five retail
configs. `renderOpMatrix` directly names the texture-ID table and diagnostic
instead of reaching beyond the position-ID array.

Putting these definitions before their users lets MWCC generate its own shared
data base. With definitions after the functions, separate named accesses add
twelve instruction bytes. No invented aggregate, cross-global offset view,
section override, or compiler change is needed. The writable string slot keeps
the evidenced `.data` placement and complete byte span.

Both matrix-command helpers use `ObjModel*`; `renderOpMatrix` also uses
`ModelFileHeader*` and its canonical joint counts. Its header and cached joint
cursor have separate lifetimes. The stream readers retain a byte pointer instead
of truncating the instruction address to `u32`. A native-width address sum keeps
the exact MWCC operand order; ordinary pointer addition changes the instruction
sequence. The position-only helper retains its existing one-element cursor array:
a scalar cursor adds a register move under the common compiler profile.

The locked-cache layout is unchanged: 48-byte position matrices at `+0`, normal
matrices at `+0x12C0`, and 64-byte input joint records at `+0x2700`.
`modelInitMtxs` admits two through 100 joints, including extra joints. The cached
normal path concatenates before clearing translation; the uncached path clears
translation before concatenating. Both orders are preserved.

`python3 tools/test_model_matrix_render.py` executes 8,424 scenarios at each of
`-O0` and `-O2`, with ASan/UBSan and pointers above 4 GiB. It covers all eight bit
alignments, counts zero through twelve (including the two padding ID entries),
cached/preparation/uncached states, 2/17/100 cached joints, byte indices through
255 on the uncached path, shadow/normal/texture flags, GX call order and IDs,
matrix values, complete cache writes, and untouched input/guard bytes. Malformed
counts 13–15 still exceed the retail ID tables; this recovery does not widen
them. Four local negative controls caught pointer truncation, wrong texture IDs,
wrong normal-cache offset, and wrong stream advancement.

All five complete rendering TUs remain 100%: 32 functions, 25,004 instruction
bytes, and 12,768 data bytes each. Every instruction/data byte, relocation
destination, and other named symbol offset matches the pre-change objects.
Every other source object is unchanged. All five `all_source` builds and strict
source-linked retail DOL checks pass. The full report inventories retain only
the pre-existing TRK vector-carving and MusyX discarded-data accounting artifacts;
there are no new report regressions or retail-object substitutions. Formatting
is verified separately against the complete source-object hashes.
