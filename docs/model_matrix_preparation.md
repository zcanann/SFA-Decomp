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
