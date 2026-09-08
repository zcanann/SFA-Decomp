# Vector-math matrix temporary lifetimes

EN GSAE01: all 25 functions, all 5,068 code bytes, and all 72 data bytes
match. The TU uses the common GC/1.3 compiler and its existing whole-TU
`-O4,p -opt nopeephole,noschedule,nostrength` profile. No compiler flags or
pragmas changed.

`mtxRotateByVec3s` builds an inverse rotation basis, then multiplies the
supplied translation vector by that basis. The older Rare `mathRpyXyzMtx`
assembly in the Diddy Kong Racing and Jet Force Gemini reference projects
provides a useful structural analogue: six trig values, two arithmetic
scratch values, and reuse of the first three trig values for translation.
The EN GameCube object remains the matching authority.

The recovered C keeps the multiply, add, subtract, and negate steps separate.
It uses two scratch values throughout the matrix calculation and lets MWCC
eliminate repeated cross products. The homogeneous zero entries use the
shared constant directly. This produces the retail floating-point register
allocation, including the zero in f0, without manually retaining the cross
products or a local zero across rows.

The first three rotation components become X, Y, and Z for the translation
calculation. Their neutral `component0..2` names reflect those successive
roles. Reusing different rotation components changes register allocation even
when the load order and arithmetic are otherwise identical.

The last function remains 200 instructions / 800 bytes, now with no differing
instructions. All other 24 functions and the constant pool remain exact.
`ninja all_source` and the strict retail-checksum build both pass with vecmath
marked matching and its compiled source object included in the final DOL.
