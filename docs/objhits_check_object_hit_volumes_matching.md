# CheckObjectHitVolumes matching

`ObjHits_CheckObjectHitVolumes` matches **100%** in EN, JP, PAL, EN revision 1
and PAL revision 1: 348 instructions / 1,392 bytes, up from 99.583336%.
All 54 ObjHits functions now match. EN has 25,988 matched code bytes; its
88-byte `.sdata2` section still differs, so the TU remains `NonMatching`.

## Retained source

The function reads priority states and active models directly through the
canonical object fields. It loads state A before state B and declares its
locals in the allocator-proven order. The shared inline getters remain for
other callers. Buffer caching, attachment handling, masks, collision calls,
and miss callbacks are unchanged. No compiler flags, pragmas, assembly,
layouts or TU boundaries change.

## Compiler evidence

LLDB showed that the inline getters introduce generated register identities
for state A and the four active-model lookups. A fixed-graph query using the
existing `../mwcc` allocator reconstruction could not reproduce the complete
retail color vector by reordering the baseline's named locals alone.

Direct field accesses retain named state and model locals. The sibling
`solve_gc13_register_order.py` then found a locals-only permutation, verified
by its independent procedural allocator replay. Compiling that declaration
order reproduces every retail instruction. This proves the reconstructed
source's output, not the original source spelling. No additional compiler
source was needed.

The final LLDB trace records nine stages and 348 aligned instructions with
zero retail differences. Its 212-node GPR graph replays simplification and
all 176 physical color choices, without high-degree removals or spill
retries. The traced and ordinary objects are byte-identical, SHA-256
`f820dbfc84359d46552f7fc4e41dadbf04228fd8a9f6d201d2b021a23168b689`.

```sh
python3 tools/tricky_backend_trace.py --unit main/main/objhits \
  --function ObjHits_CheckObjectHitVolumes --graph \
  --output build/objhits_object/exact_trace
```

## Validation

- Verified original DOL hashes before all five regional comparisons. Each
  improves from 99.583336% to 100%; all other function scores are preserved.
- Only this function's EN instruction bytes change. The other 53 bodies,
  allocated non-text sections, named symbol layouts and resolved relocation
  targets are unchanged.
- Formatting preserves the complete object byte for byte. The TU and
  `include/main/objhits.h` pass `clang-format --dry-run --Werror`.
- `ninja all_source build/GSAE01/ok` passes with the unchanged strict retail
  checksum. The retail-backed link checks build integrity; the remaining
  literal-pool mismatch prevents a complete ObjHits source-link claim.
