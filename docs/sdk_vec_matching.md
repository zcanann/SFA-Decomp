# SDK Vector Source Recovery

EN `dolphin/mtx/vec.c` is exact with GC/1.2.5 and `-fp_contract off`.
This is an SDK-only profile; game code remains on the common GC/1.3 compiler.

## Evidence

The function at `0x80247888` negates and normalizes its input, normalizes the
surface normal, takes their dot product, evaluates `2 * normal * dot - input`,
and normalizes the result. It is `C_VECReflect`, not `C_VECHalfAngle`.
Its sole game caller in object DLL 667 deflects a projectile's velocity during
an Arwing barrel roll, independently confirming reflection semantics.

`reference_projects/marioparty4/src/dolphin/mtx/vec.c` supplies the same C
algorithm and call topology. That project's `configure.py` assigns its matrix
library to `DolphinLibUnpatched`: GC/1.2.5 with contraction disabled. These are
source-lineage and instruction-level clues, not a compiler choice inferred
from aggregate match percentage.

| C source profile | Reflection instructions | Remaining differences |
| --- | ---: | --- |
| GC/1.2.5n, contraction on | 50 / 53 | Three fused operations; epilogue order |
| GC/1.2.5n, contraction off | 53 / 53 | Epilogue stack restore order |
| GC/1.2.5, contraction off | 53 / 53 | None |

The other ten vector functions also remain byte-exact under the recovered
profile. Their evidenced SDK paired-single assembly is retained; the former
scalar assembly implementation of reflection is replaced by ordinary C.

## Literal Ownership

Named constants with forced `.sdata2` declarations, explicit-zero pragmas, and
volatile-load macros were unnecessary. Ordinary `0.5f`, `3.0f`, and `2.0f`
expressions emit the correct twelve-byte pool. The next unit starts at an
eight-byte boundary, providing the four zero alignment bytes at `0x803E7654`.
There is no fourth source constant. The bogus zero symbol is removed without
changing the TU split or forcing any section placement.

The full text section is 672 exact bytes. The final retail DOL checksum passes
with this unit still linked from source, proving the natural literal relocations
and linker padding as well as the code. Both `ninja all_source` and the strict
matching build pass; compiler-profile tests cover the SDK exception and keep
the game-wide GC/1.3 policy intact.
