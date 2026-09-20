# Crash-display separator matching

`errorThreadFunc` now matches all 694 retail instructions (2,776 bytes) in
GSAE01, GSAE01_rev1, GSAJ01, GSAP01 and GSAP01_rev1 under the existing GC/1.3
TU profile. The unit remains NonMatching because `debugPrintDrawRecord` still
has nine differing operand words (99.90131%). Thirteen of fourteen functions
are exact; unit fuzzy matching is 99.97716%.

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
