# Water effects (engine DLL 19)

EN v1.0, GC/1.3, 2026-09-07. All 15 functions (6,680 text bytes) and
all 304 assigned data bytes match. The unit is `MatchingFor("GSAE01")`
and links from C with its existing compiler profile and boundaries.

## Splash bands

`waterfx_drawSplashBurst` previously differed in seven floating-point register
operands. Grouping the particle lifetime and derived band phase in a local
record preserves the existing equations and recovers all 166 instructions.
This is transient calculation state, not a claim about an allocated game
object or an original type name. The alpha calculation still reads the
unmodified lifetime after computing the phase and fade.

## Particle traversal

The renderer indexes each pool through its existing element type. One byte
pointer carries the current particle through all four rendering phases;
casts at the accesses identify the ripple, splash, drop, or wake record.
The ripple scan has its own index. Splash, drop, and wake scans share the
second index, including its initialization before splash render-state setup.

Ripple and wake geometry use one triangle index: two triangle descriptors
and four vertices per particle. Typed array expressions replace the explicit
28-, 60-, 32-, and 64-byte induction counters. MWCC generates the retail
walkers, update order, and initial register copies from those expressions.

These lifetimes matter together. Separate typed particle locals leave the
wake pointer and counter swapped; a separate drop counter can reproduce all
register colors but replace a retail copy with a zero load. Splitting the
shared pointer or counter again therefore requires a code-generation check.
All 215 renderer instructions now match. The earlier comma-order experiment
was an incomplete reconstruction, not evidence of an unreachable allocation.

## Validation

- Objdiff: 15/15 functions, 100% code and data.
- Every retail function body is byte-identical; `.sdata2` bytes also agree.
- Common named data symbols retain their retail sections, offsets, and sizes.
  The linker supplies the final one-byte `.data` alignment gap.
- The existing unused `waterfxBandEnvelope` helper remains in the object and
  is discarded by the linker. Its 92 bytes explain the source object's larger
  raw `.text` section; it is not part of the retail function set.
- `ninja all_source` and the strict matching build pass. The source-linked DOL
  retains retail SHA1 `e750e8e894707a52446118a4b84f1b58b677b269`.
- Formatting is committed separately and checked against the complete object.
