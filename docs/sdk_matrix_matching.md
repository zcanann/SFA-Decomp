# SDK Matrix Source Recovery

EN `dolphin/mtx/mtx.c` is exact with GC/1.2.5 and `-fp_contract off`, the
same independently supported SDK profile as `vec.c`. Game code stays GC/1.3.

## Code Evidence

The matrix source in `reference_projects/marioparty4/src/dolphin/mtx/mtx.c`
provides C implementations of `PSMTXRotRad`, `C_MTXLightPerspective`, and
`C_MTXLightOrtho`, and C setup surrounding the paired-single assembly in
`PSMTXRotAxisRad`. Its matrix library uses `DolphinLibUnpatched` (GC/1.2.5)
with contraction disabled. Retail preserves separate multiply/add rounding
and the unpatched compiler's epilogue ordering.

With the recovered bodies and contraction disabled, GC/1.2.5n leaves three
functions non-exact: `PSMTXRotRad`, `PSMTXRotAxisRad`, and
`C_MTXLightPerspective`. GC/1.2.5 reproduces all twelve retail functions.
The SDK's actual paired-single implementations remain; the handwritten
scalar bodies and axis-rotation prologue/epilogue are removed.

## Literal Ownership

The retail pool at `0x803E7618` is six floats in this order:
`1.0f`, `0.0f`, `2.0f`, `-1.0f`, `0.5f`, and the degrees-to-radians factor.
Restoring only the called C bodies emits the right values in the wrong order.
The SDK's standard `C_MTXIdentity` before `PSMTXIdentity` and
`C_MTXLightFrustum` before `C_MTXLightPerspective` naturally recover the
complete 24-byte pool. Their unused function bodies are linker-stripped;
their shared literals remain. Neither function is an invented pool helper:
both APIs already exist in our SDK header and both appear in this order in
the Mario Party 4, Metroid Prime, and Wind Waker matrix sources.

The complete twelve-store identity implementation comes from Metroid Prime;
Wind Waker independently agrees. Mario Party 4's unused C identity body
omits the translation-column stores and is not copied. A wholesale import
of its matrix source also emits an extra `-2.0f` literal, so that broader
source reconstruction is not established by the current retail pool. The
retained counterparts explain the bytes but do not uniquely prove every
dead function originally present in this SDK revision.

Six forced-section constants, explicit-zero pragmas, and volatile literal
loads are removed. No split or retail symbol addresses change. Anonymous
compiler constants replace the named definitions at the same pool offsets.

## Verification

All twelve assigned functions are 100% in objdiff. The two restored unused
SDK bodies add 208 bytes before dead stripping; the retail text remains
1,600 bytes. The initialized `.sdata` and `.sdata2` sections are unchanged.
Raw instruction changes in three recovered bodies only remove the explicit
`r2` field from SDA21 relocation placeholders; the compiler emits the proper
relocations, and the linker supplies the same final register and address.
Both `ninja all_source` and the strict retail DOL checksum pass with this
unit still `Matching`. Compiler-profile tests cover the matrix exception.
