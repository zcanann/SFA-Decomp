# Shadow blur compiler trace

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

## Observed allocation

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
This diagnostic change modifies no game source, compiler profile or match flag.
`ninja all_source` and the strict retail checksum pass with 30-second limits.
