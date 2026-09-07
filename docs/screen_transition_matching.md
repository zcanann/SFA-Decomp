# Screen-transition matching

Engine slot 22 (`src/dlls/engine/22/22.c`) matches EN v1.0 completely as of
2026-09-07: ten functions, 2,548 code bytes, and 120 data bytes. The common
GC/1.3 compiler and the existing optimization and inlining profile are unchanged.

The only remaining function, `screenTransition_drawWhiteWipe`, already emitted
the retail sequence of 322 instructions. Forty instructions used different
registers. Its source reused the same locals for unrelated roles in the
horizontal and vertical passes, while conversions and loop-invariant expressions
created additional compiler temporaries.

The matching reconstruction gives each pass its own band extent, moving edges,
distance, strip width, widened step, and signed loop limit. The viewport halves
are `u16`; the vertical divisor explicitly widens its half-height before the
logical shift. Direct float-to-`u16` conversions recover the two band extents.
The declaration order then gives these values their retail register allocation.

Controlled compiles against the unchanged profile show the interaction:

| Source | Differing instructions | Structural differences |
| --- | ---: | ---: |
| Original reused locals | 40 | 0 |
| Separate axis values, before ordering | 57 | 0 |
| Separate axis values and matching order | 0 | 0 |

The final signed distance locals and `while` conditions preserve that match.
The fallback's `(r, b, g)` color order, scissor calls, partial edge strips, and
division behavior remain the retail behavior.

GC/1.3 backend captures validate the emitted instructions against the ordinary
object and replay register simplification and coloring. The original graph has
182 nodes; the final graph has 183 nodes and 143 coloring decisions. Neither
requires high-degree removal. Named source lifetimes and temporary ordering
explain the result without a compiler change or register-binding mechanism.

Objdiff reports every function and all data at 100%. All function bytes match
the retail object. Relative to the previous source object, only the white-wipe
function's instruction bytes change; allocated data, named-symbol offsets, and
relocation destinations are unchanged. Anonymous literal names are renumbered.
Both `ninja all_source` and the strict retail DOL checksum pass with slot 22
linked from source. Formatting is checked separately against the raw object.

Reproduce the diagnostic capture with:

```sh
python3 tools/tricky_backend_trace.py --unit main/dlls/engine/22/22 \
  --function screenTransition_drawWhiteWipe --graph \
  --output build/flag_probe/screen_transition_matching_backend
```
