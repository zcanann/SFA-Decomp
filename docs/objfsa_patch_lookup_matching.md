# Objfsa patch lookup

`Objfsa_GetPatchGroupIdAtPoint` in `dlls/engine/20_Hcurves/Hcurves.c`
improves from 98.35616% to 99.178085% under the existing common GC/1.3
compiler and optimization profile. Both retail and reconstructed bodies are
292 bytes. The unit still has 17 of 19 exact functions.

The lookup rejects patches outside their open Y interval, then tests the four
X/Z half-planes in order. A point on a plane is accepted; a positive plane
expression rejects it. The private inline `objfsaFindRejectingPatchPlane`
returns the rejecting plane index, or four when all planes accept the point.
This is a source-structure reconstruction, not evidence of an original helper
name. Keeping the Z and X declarations in that order reproduces the retail
floating-point register assignment after inlining.

The extraction removes ten register-operand differences. The remaining
instruction is the initialization of the normal-component counter: retail
copies the zeroed plane counter with `mr r7,r8`, while the compiler emits
`li r7,0`. No compiler flags, storage layouts, or TU boundaries change.

Only this function's instruction bytes change. All other function bodies,
allocated non-text sections, named-symbol layouts, and resolved relocations
are unchanged. The existing 72-byte literal-pool ordering mismatch in this
unit is unaffected. Objdiff remains the measure of the reconstructed source;
the strict matching link uses the retail object while this unit is NonMatching.

Validation: `python3 configure.py --matching`, `ninja -j64 all_source`, and
strict `ninja -j64`, each with a 30-second timeout. The resulting matching DOL
is byte-identical to the EN v1.0 retail DOL. Formatting is committed separately
and checked for unchanged generated object bytes.
