# Defined atan range reduction

`atanf` previously used `reduced * (reduced = 1.0 / absoluteValue)`, reading
and modifying the same scalar without sequencing. Its comment explicitly
retained undefined behavior for a prior compiler's register allocation.

One initialized double now holds the absolute input and then its reciprocal.
The reciprocal assignment precedes its square. This models the actual two
phases of range reduction without keeping an unused magnitude alive alongside
the reciprocal. The input remains float, `__fabsf` still computes float
absolute value, and the small-input `value * value` still multiplies in single
precision before promotion to double. Polynomial coefficients and evaluation
order are unchanged.

GC/1.3 emits the same absolute value, range comparison and small-input
multiplication instructions. It uses one fewer nonvolatile floating-point
register and removes four save/restore instructions. `atanf` shrinks from
412 to 396 bytes against the 380-byte target, improving fuzzy match from
79.08421% to 85.82105%. The TU improves from 63.738808% to 64.93284%.
The remaining differences include the known register-save ABI mismatch;
no compiler version or flags change.

All other seven functions retain their raw bytes and function-relative
relocation records. The three functions after `atanf` move sixteen bytes
earlier. All 248 data bytes, section layouts and data symbol addresses remain
unchanged. Among 2,873 source objects, only `acosf.o` changes.

`python tools/test_atan_reduction.py` compiles the production function and
coefficients with Clang at both O0 and O2, with unsequenced-expression warnings
treated as errors. It checks 2,580 inputs per build against mathematical atan,
including both sides of +/-1, signed zero, subnormals, infinities, NaN, a dense
[-2, 2] interval and large magnitudes. Finite results use a 2e-7 absolute error
bound; this is not a claim of bit-exact PPC floating-point emulation. The old
source fails the compiler gate, and a deliberately incorrect reciprocal square
fails the numerical oracle.

Both `ninja all_source` and the strict retail DOL gate pass. The unit remains
`NonMatching`; the strict link still uses its retail object.
