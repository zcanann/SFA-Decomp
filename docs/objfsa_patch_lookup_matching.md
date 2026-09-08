# Objfsa patch lookup

`Objfsa_GetPatchGroupIdAtPoint` in `dlls/engine/20_Hcurves/Hcurves.c`
matches all 73 instructions (292 bytes) in EN, EN revision 1, JP, PAL, and
PAL revision 1 under the existing common GC/1.3 compiler and optimization
profile. Each unit now has 18 of 19 exact functions.

The lookup rejects patches outside their open Y interval, then tests the four
X/Z half-planes in order. A point on a plane is accepted; a positive plane
expression rejects it. The private inline `objfsaFindRejectingPatchPlane`
returns the rejecting plane index, or four when all planes accept the point.
This is a source-structure reconstruction, not evidence of an original helper
name. Keeping the Z and X declarations in that order reproduces the retail
floating-point register assignment after inlining.

The earlier extraction removed ten register-operand differences, reaching
99.178085%. Initializing `planeIndex = 0` and then copying it into
`normalComponentIndex` in a separate statement recovers the final retail
`mr r7,r8`; the chained assignment emitted `li r7,0`. The neighboring
`objfsaExitOutside` already uses this scalar initialization pattern.
No compiler flags, storage layouts, or TU boundaries change.

Only this function's instruction bytes change. All other function bodies,
allocated non-text sections, named-symbol layouts, and resolved relocations
are unchanged across all five versions. Each input DOL was checked against
its configured SHA-1, and the five retail lookup instruction bodies are
identical. The existing 72-byte literal-pool ordering mismatch and the
remaining `Objfsa_UpdateWalkGroupPatches` mismatch are unaffected.
Objdiff remains the measure of the reconstructed source;
the strict matching link uses the retail object while this unit is NonMatching.

Validation: `python3 configure.py --matching`, `ninja -j64 all_source`, and
strict `ninja -j64`, each with a 30-second timeout. The resulting matching DOL
is byte-identical to the EN v1.0 retail DOL. Formatting is committed separately
when it produces a diff, and checked for unchanged generated object bytes.
