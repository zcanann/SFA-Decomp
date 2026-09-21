# Debug-display TU completion

`errorThreadFunc` now matches all 694 retail instructions (2,776 bytes) in
GSAE01, GSAE01_rev1, GSAJ01, GSAP01 and GSAP01_rev1 under the existing GC/1.3
TU profile. That separator change initially left `debugPrintDrawRecord` with
nine differing operand words (99.90131%), thirteen of fourteen functions exact,
and unit fuzzy matching at 99.97716%. The final wrap change below completes it.

The last difference was two adjacent setup instructions: retail initialized
colour 0xc080 before `y + 76`, while the previous single-loop source emitted
those instructions in the opposite order. Declaration reordering did not help:
the compiler substituted the colour into the store and then hoisted it from
the loop body, after the explicit counter initialization.

Recovery of GC/1.3's accepted-definition mover at 0x0056e600 in the companion
`mwcc` research project established that it inserts before the selected loop
preheader's final instruction. Its derived-induction initializer at 0x0056fe40
also exposed distinct initialization anchors. They passed 288 and 1,620 bounded
original/native comparisons respectively, with explicit dependency boundaries;
these are functional reconstructions, not Win32 binary matches.

A column-then-row rectangle fill provides the relevant nesting. Initialize the
byte row offset before the column loop, initialize the row counter inside it,
and reset the offset after each column. With the separator's bounds
`(240, 59, 241, y + 76)`, the column loop disappears. The captured backend stages
show the colour moving between the offset and row-counter initializations
already at code motion. The solution therefore does not depend on the proposed
later strength-reduction initialization path.

`errorDrawFilledRect` is a reconstructed private helper name and plausible
source organization, not a recovered original symbol. The helper supports
multiple columns; the existing source-body framebuffer harness verifies its
pixel coverage, cursor reset, empty rectangles, framebuffer edges, and the
actual guarded crash-display call alongside the other three separators.

Validation on 2026-09-20:

- Ordinary and instrumented scratch objects have identical SHA-256
  `da2cdb63a59e277bda1c082ef321b8712846f61adb6624cd413959cd4d27582b`.
  The trace aligns all 694 instructions with zero retail differences.
- All five versions retain every other function's previous score and match
  `errorThreadFunc` at 100%; each passes `ninja all_source` and the strict
  retail checksum target after matching configuration.
- Raw object comparison across all five versions changes only six bytes in
  the two swapped instructions. Data bytes, named-symbol layouts and relocation
  destinations are preserved; only an anonymous data-symbol label is renumbered.
- All 13 framebuffer, rectangle-record and formatted-text behavior tests pass.
- The active TU and its header pass clang-format's strict check. Formatting
  changes are confined to the new helper; existing source formatting is unchanged.

## Final automatic-wrap match

`debugPrintDrawRecord` now matches all 456 instructions (1,824 bytes). The entire
TU is Matching in all five versions: 14 functions, 7,880 code bytes and 10,272
data bytes. The GC/1.3 compiler and existing TU optimization profile are unchanged.

The residual was a top/right coordinate register exchange in the third rectangle
expansion, at automatic wrapping. A diagnostic GC/1.3 graph capture reproduced
all 169 physical-register decisions. A temporary-factory observation traced the
scaled top coordinate back to the range splitter at caller return `0x0045d2ff`,
with the unscaled top coordinate as its original object. Thus both top-coordinate
lifetimes, plus the right coordinate, had to change allocation together.

Swapping the shared rectangle helper's top/right declaration order fixed the
wrap expansion but broke the reposition and explicit-newline expansions. The
retained reconstruction instead gives automatic wrapping its own private inline
`debugPrintWrapLine` operation, including the bounds, draw-pass guard and cursor
reset. Its local top coordinate precedes the right coordinate. Reposition,
explicit newline and final-log drawing retain the shared helper. This deliberately
keeps a small repeated bounds calculation: consolidating it changes generated
register allocation. The helper name and source organization are inferred, not
recovered original provenance; identical runtime behavior does not establish the
original abstraction.

Final validation on 2026-09-20:

- All five regional objdiff reports show every function and section at 100%.
- Relative to the separator-matched baseline, only 11 bytes in the nine operand
  words of `debugPrintDrawRecord` change. All other function bodies, data bytes,
  named-symbol layouts and resolved relocation destinations are preserved.
- Every version passes `ninja all_source` and the strict retail checksum target
  with this TU enabled as source. Independent `tools/verify_source_link.py`
  substitutions also reproduce each hash-verified original DOL exactly.
- All 13 framebuffer, rectangle-record and formatted-text tests pass. The existing
  record harness now extracts the wrap helper as well, so its wrap thresholds,
  pass guards, rectangle coordinates and cursor resets exercise production code.
- The source and canonical header pass the strict clang-format check. Only newly
  introduced code needed formatting; no separate existing-code formatting diff.
