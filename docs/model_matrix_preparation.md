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

## Validation

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
