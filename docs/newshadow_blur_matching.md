# Shadow blur compiler trace

## Shared row and column lifetimes

The word and halfword paths now share their same-role row counter and texture
column cursor. The row buffer and output-buffer cursors remain local to their
passes. The source still gathers and scatters I8 columns in four-pixel groups,
with the same padding, window arithmetic, and in-place two-pass ordering.

Under the existing GC/1.3 profile, this raises `boxBlurTexture` from 99.45059%
to 99.57596% in EN, EN revision 1, JP, PAL, and PAL revision 1. All 1,356
instruction mnemonics remain exact; operand differences fall from 125 to 97.
Each TU reaches 98.992195%, still with 40/44 exact functions. This is a partial
matching improvement, not a new exact function or a regional exact-unit claim.

Only the blur's instruction bytes change. The other 43 function bodies,
allocated non-text bytes, named-symbol layouts, and resolved relocations are
unchanged in all five versions. Their retail blur instruction bodies are
identical. No compiler flags, data declarations, or version branches change.

The execution probe now accepts `--version`, verifies that DOL against its
configured SHA-1, and decodes its `r2`/`r13` bases from `__init_registers`.
It uses the selected version's actual register-save helpers and cache-flush
address for both retail and relocated source execution. All 360 cases pass
per version (1,800 total), including both padding widths, tiled output, guards,
flush arguments, and preserved GPR/CR fields. For example:

```sh
python3 tools/shadow_blur_probe.py --version GSAJ01
```

## Recovered fill lifetime

The halfword path now masks the original `fill` parameter with `fill &= 0xffff`
instead of introducing a separate `u16` local. This preserves the low-halfword
padding semantics while recovering retail's narrowing position and registers:
`clrlwi r30,r6,16` follows the window calculation, and the window-end address
uses `r31`. The private blur API now takes `Texture*`, matching its sole caller
and the header followed by I8 pixel storage; that type correction is object-byte
neutral relative to the masking change.

`boxBlurTexture` improves from 99.166664% to 99.45059%, with 1,356 instructions
on both sides. Mnemonic alignment differences fall from two to zero and operand
differences from 160 to 125. The TU improves from 98.86959% to 98.94111%; 40 of
44 functions remain exact. The other 43 function bodies, non-text sections,
named-symbol layouts, and relocation targets are unchanged. The remaining
column-pass register differences still prevent a complete function match.

`tools/shadow_blur_probe.py` executes both compiled and retail PPC against an
independent untiled, separable box-filter reference. Its 360 cases cover square
sizes 8 through 128, windows 4/8/12/16/20/24, three padding patterns, and zero,
white, random, and impulse images. It checks tiled pixel output, header and
image guards, cache-flush arguments, and callee-preserved registers. The game's
128-pixel, 16-wide, zero-fill call is included. The suite passes; deliberately
reducing the source mask to eight bits makes it fail. Invalid sizes or windows
are outside this probe's scope.

Run after building the source object, using Python with `unicorn` and
`pyelftools` installed:

```sh
python3 tools/shadow_blur_probe.py
```

## Baseline trace

At `8287f6d51d`, `boxBlurTexture` has 1,356 retail and source instructions and
99.166664% fuzzy similarity. The first 349 instructions match. Later column
passes have register exchanges, and the halfword path narrows the fill value
two instructions earlier than retail. Mnemonic alignment reports two rows for
that moved instruction and 160 same-mnemonic operand differences.

## Diagnostic support

The GC/1.3 trace originally stopped at instruction 9: backend opcode `0x67`
emits `rotlwi r0,r0,3` in the signed remainder calculation. This is another
alias of the rotate-and-mask family already recognized by the decoder. After
recognizing it, instruction 196 exposed opcode `0x46`, which emits the unsigned
`divwu r25,r0,r5` used by the moving average.

Both are now recognized. Validation also checks the complete emitted encoding
for `0x67`: both GPRs, shift, mask endpoints, opcode and record bit. Shift and
mask fields must lie in 0..31; wrapped masks remain valid. Unsigned division
has its own mnemonic and XO encoding, distinct from signed division. These
checks do not turn the diagnostic into a complete PowerPC emitter; unsupported
opcodes still fail closed.

The independent unit-test encodings were checked with the project's PowerPC
assembler. Tests cover rotate/shift aliases, a wrapped mask, unsigned division,
invalid shift/mask fields, and every single-bit corruption of each tested
instruction. Signed/unsigned mnemonic swaps and incorrect division registers
are rejected. The backend suite passes 72 tests, with seven optional capture
fixtures skipped.

## Baseline allocation

The completed capture contains 17 stages and a 524-node GPR graph. All 1,356
final records align with the emitted object. Simplification and 485 physical
color decisions replay without a forced high-degree removal. The instrumented
and ordinary objects share SHA-256
`37fa64d55cb5691a8f0320bb3ab8ac64a70ce5f9a772f499c919442d2cdb86b6`.

These are reconstructed-source virtual registers, not recovered retail names:

| Role in the source trace | Virtual register | Source GPR | Retail GPR |
| --- | ---: | ---: | ---: |
| Word-path column cursor | 53 | 26 | 28 |
| Word-path inlined blur output index | 70 | 28 | 26 |
| Narrowed halfword fill | 46 | 26 | 30 |
| Halfword-path window-end address | 84 | 30 | 31 |
| Halfword-path column cursor | 40 | 31 | 28 |
| Halfword-path inlined blur output index | 63 | 28 | 26 |

Moving the inline row helper before its caller leaves the result unchanged.
Reusing one texture cursor for column reads and writes adds two instructions
and worsens allocation. Splitting the row helper's initialization and output
indices retains instruction count but increases operand differences to 446.
None of these source variants is retained. Further work needs to explain the
column cursor's lifetime together with the inlined blur index; changing one
local in isolation has not recovered the retail assignment.

Reproduce the capture with:

```sh
python3 tools/tricky_backend_trace.py --unit main/main/newshadows \
  --function boxBlurTexture --graph --output build/flag_probe/newshadow_blur
```

The tool retains its ordinary-versus-instrumented whole-object hash gate.
The original diagnostic change modified no game source, compiler profile or match flag.
`ninja all_source` and the strict retail checksum pass with 30-second limits.
