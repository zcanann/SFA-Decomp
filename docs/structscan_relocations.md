# Instruction-immediate relocation diagnostics

`structscan.words` and `strucdiff.text_lines` now attach a big-endian 16-bit
immediate relocation at instruction address + 2 to its instruction. They
previously accepted only relocations at the instruction's first byte. That
worked for branch relocations and word-addressed records but silently omitted
ordinary `R_PPC_ADDR16_HA` / `R_PPC_ADDR16_LO` pairs from both comparison keys
and readable diagnostics.

The shared attachment predicate accepts the +2 position only for the existing
16-bit-immediate masks. It does not attach a branch, SDA21, unknown relocation,
or following instruction's relocation merely because it is nearby. Existing
word-addressed relocations remain supported.

The omission could report two different function pointers as identical: both
assembler objects contain zero immediate fields, but the omitted relocations
name different functions. Those two address-materialization instructions now
count as operand differences. Raw-byte mode still sees identical zero fields,
as requested by that mode.

## Retail example

The four `gameTextGetStr` diagnostic-address differences are not register
allocation differences. The repaired reader shows:

| | Retail | Reconstructed |
| --- | --- | --- |
| `lis` / `addi` target | `sJpDiscStatusGlyphs` | `...data.0` |
| Base offset within `.data` | `0x20A8` | `0` |
| First diagnostic displacement | `0xEC4` | `0x2F6C` |
| Resulting `.data` offset | `0x2F6C` | `0x2F6C` |

The first literal remains at EN `0x802C9E04`. The other three diagnostic
strings have the same base difference. This explains the observed immediates
and identifies a data-base formation question; it does not establish an
original declaration model or authorize a TU split.

The scanner deliberately retains its coarse `POOL` normalization for data
symbols. Its counts are instruction-shape diagnostics, not proof of identical
relocation destinations or literal values. Objdiff and explicit data/layout
checks remain necessary. The historical `recolour` output label includes all
same-mnemonic operand differences, including immediates and relocation targets.

## Verification

`python3 tools/test_structscan_relocations.py` assembles actual big-endian
PowerPC objects and checks halfword relocations, branch relocations, readable
targets, raw mode and the different-function-pointer regression. It also checks
rejected relocation offsets and kinds. Restoring the old instruction-only
attachment fails all three tests. The existing compiler-probe, backend-trace
and probe-runner suites pass as well (26 tests in total).

No game source, target configuration, match flag or generated data is changed.
