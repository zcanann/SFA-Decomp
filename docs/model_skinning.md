# Quantized model skinning

The three scalar reconstructions in `src/main/model.c` now implement the retail
quantization scales and floating-point evaluation order for the tested finite
inputs. They remain nonmatching C; this recovery adds no inline assembly or
compiler exception.

## Stream contracts

| EN kernel | Input/output | Vectors per weight pair | Matrix translation |
| --- | --- | ---: | --- |
| `ObjModel_TransformVerticesWithTranslation`, `80029E18` | signed 16-bit XYZ | 1 | Included |
| `ObjModel_TransformVerticesLinear`, `80029F9C` | signed 8-bit XYZ | 1 | Omitted |
| `ObjModel_TransformNormalTriplets`, `8002A110` | signed 8-bit XYZ | 3 | Omitted |

The last function was provisionally named `TransformQuadVerticesLinear`. Its
retail loop processes three vectors per weight pair, as does its caller's normal
stream mode. The new name describes that demonstrated contract without assigning
individual normal/binormal/tangent roles to the three vectors. The wrapper's
mode parameter is correspondingly named `normalTriplets`.

Each matrix is a reordered `ROMtx`: four consecutive XYZ columns, with translation
in the final column. The two weight bytes are loaded through GQR6 as unsigned
values scaled by `2^-7`, established by `ObjModel_InitRenderBuffers`. They are not
assumed to sum to 128. Normal and position wrappers configure GQR7 for signed
8-bit and signed 16-bit streams respectively. Scalar fast casts depend on the
SDK's initialized GQR2/GQR4/GQR5 defaults.

## Quantization and rounding corrections

GQR's load and store scale fields each encode a signed six-bit exponent. The
former C expression `1 << ((GQR7 >> 24) & 63)` used the load field for both
directions and performed an invalid signed integer shift for large encodings.
The private `modelQuantizationFactor` now constructs the corresponding normal
float power of two with an IEEE binary32 exponent. Load and store factors come
from their respective fields. The existing single-register GQR7 accessor remains
unchanged. The helper is a scalar reconstruction aid, not a claimed retail
function.

The load factor is `2^-loadScale`; the store factor is `2^storeScale`. Quantized
stores clamp to the signed output range and truncate toward zero through the
existing SDK fast casts. The scale interpretation and conversion model agree
with [Dolphin's paired-load/store implementation](https://github.com/dolphin-emu/dolphin/blob/master/Source/Core/Core/PowerPC/Interpreter/Interpreter_LoadStorePaired.cpp).

Retail position arithmetic starts with a fused `matrixX * x + translation`, then
fuses the Y and Z contributions in order. Previously the scalar expression added
translation last. A concrete counterexample uses `x=y=1`, X coefficient `2^24`,
Y coefficient 1, and translation `-2^24`: retail produces 1, whereas the former
expression rounded away the 1 and produced zero.

Retail then rounds matrix A's transformed result times weight A, and fuses matrix
B's weighted contribution into it. MWCC initially fused A instead, producing four
one-unit output differences in the expanded probe. The C sum is spelled with the
B product first so this compiler emits the evidenced sequence. All three kernels
use the same order. No volatile temporary, pragma, or assembly arithmetic is
introduced to force rounding.

## Behavioral probe and limits

`tools/model_skinning_probe.py` loads the verified EN DOL and the actual compiled
model object. Unicorn executes ordinary PPC instructions; a hook handles the
paired-single loads/stores, update addressing, fused arithmetic, and live GQR
reads. A separate scalar matrix oracle checks the output bytes. The hook uses
host single-precision fused multiply-add, so this is not a hardware conformance
suite for exceptional floating-point values.

Run with optional `unicorn` and `pyelftools` installed:

```
python3 tools/model_skinning_probe.py
```

The 2,306 scenarios per implementation cover all 64 signed scale encodings,
separate load/store scales, signed-byte and signed-halfword streams, three-vector
groups sharing weights, counts 2/3/7, saturation, in-place and separate output,
output guards, preserved general registers, and translation cancellation. Retail
and corrected C pass all cases. The former compiled object fails 1,672 cases;
`--object <old.o> --allow-source-mismatch --output <report.json>` retains that
audit mode without embedding retail instructions or test outputs.

The retail loops initialize CTR to `count - 1` and enter their pipelined loop
without a zero-trip check. These comparisons use counts of at least two. Retail
also prefetches one vector beyond the last output; the probe supplies readable
lookahead bytes. The scalar C does not reproduce those speculative reads or
invalid-count looping. Arbitrary overlap with matrices or weights, NaN/infinity,
subnormal behavior, nondefault SDK fast-cast registers, and other GQR data types
are outside the tested contract. Buffer loading and cache DMA are not emulated.

## Object and version validation

The three retail instruction sequences are byte-identical across verified EN,
EN rev1, JP, and PAL rev1. All four inputs pass their configured SHA-1. Each target
compiles the same changed model object. Only the three scalar kernel bodies
change; every other function body and every allocated data section remains
byte-identical. The triplet function has the same name in source and all four
symbol configs. Its symbol rename and the two shifted kernel offsets account
for neighboring call relocations.

The position reconstruction shrinks from 464 to 448 bytes, the single-normal
kernel grows from 412 to 420, and the triplet kernel from 428 to 436. The combined
text size is unchanged. The three functions remain nonmatching in objdiff; the
single-normal kernel improves from 0% to 9.387096% fuzzy matching. All other
function scores and the exact-function/code-byte totals are unchanged. All other compiled
source objects are unchanged in every version. No TU boundary, manifest entry,
compiler profile, or checksum expectation changes.

The existing host probes also pass 22 blend-channel cases, 144 matrix-preparation
scenarios, and 135 sparse morph scenarios at both `-O0` and `-O2`. The morph PPC
probe passes its 16 decoder cases and 135 scenarios against compiled and retail
code. All four `all_source` builds and the strict EN retail checksum pass.
