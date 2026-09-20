# Game math under MSL_C: exact compiler profile

On 2026-09-20 the user authorized an exception to the GC/1.3 game compiler
requirement for the four game-category units under `MSL_C/PPCEABI/bare/H/`.
They now use GC/1.2.5n, retaining their existing optimization and inline settings.
Other game math files continue to use GC/1.3. This exception does not establish
that these routines originated in MSL; their game category and TU boundaries
are unchanged.

| Unit | Previous EN code fuzzy | Final code/data | Functions | Code bytes |
| --- | ---: | ---: | ---: | ---: |
| `math_float_helpers.c` | 75.1358% | 100% / 100% | 8 | 648 |
| `math_802927a4.c` | 87.963684% | 100% / 100% | 7 | 1,432 |
| `math_80293da4.c` | 83.05306% | 100% / 100% | 7 | 1,960 |
| `math_8029454c.c` | 62.86885% | 100% / 100% | 2 | 244 |

The total is 24 exact functions, 4,284 code bytes and 604 data bytes. The
sine/cosine unit needs only the compiler change. The other three also need
distinct locals for integer/fractional parts, conversion results and polynomial
accumulators. Those locals reproduce retail's floating-register saves, frames
and moves; recent GC/1.3-oriented simplifications had combined their lifetimes.
The two power cores use conditional expressions for the fractional-exponent
result, reproducing the single store after the branch joins. Existing union
views, coefficients, signed exponent-bit arithmetic and constant-pool ownership
are preserved. No assembly or per-function pragmas are added.

Scratch controls with GC/1.2.5 and GC/1.2.5n produced identical code scores.
GC/1.2.5n is retained as the existing MSL library default, rather than claiming
the binary uniquely identifies that compiler revision. Switching compiler alone
gave 99.166664%, 94.48883%, 100%, and 99.016396%, respectively. Additional
optimization controls did not close the source-dependent gaps. Exact final
code includes the retail FPR save/restore calls that GC/1.3 replaced with
paired-single saves.

EN validation uses `python3 configure.py --matching`, `ninja all_source`,
strict `ninja`, the full objdiff report, and the compiler-profile unit tests.
The matching link includes all four source objects and retains retail SHA-1
`e750e8e894707a52446118a4b84f1b58b677b269`.

The same four source objects also match EN revision 1, JP, PAL, and PAL
revision 1. Every input DOL passes its configured hash. Each target passes
`all_source`, reports 100% code and data for all four units, and passes
`tools/verify_source_link.py` with all four substituted together into a full
retail-object link. The regional matching manifests include these verified units.

PAL revision 1 exposed an existing symbol collision: the source's unused
`lbl_803E79B4` pool word collided with an unrelated constant in DLL 529.
The unit-owned word now has the name `sFastFloorZeroTail` in source and all five
symbol configs. The PAL revision 1 symbol is at `803E93AC`; the unrelated
`803E79B4` label stays with DLL 529. The SDA audit verifies all 15 consumed
constants in the helper unit against actual retail operands; this unconsumed
word has no instruction anchor. Its position is retained between the proven
`sFastFloorOne` and conversion-bias constants, and the complete substituted
DOL confirms its bytes and placement without changing ownership or boundaries.
