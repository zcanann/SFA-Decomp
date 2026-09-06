# WORLDplanet: complete EN match

DLL 466 now links from source for GSAE01. All eleven functions (5,112
bytes) and all 344 assigned data bytes match retail, including the final
DOL checksum. The September 6, 2026 work began at `ab4b1fe26d`; the first
pass landed at `4f670f1eb5`, and the follow-up completes the match.

| Measurement | Initial | First pass | Complete |
| --- | ---: | ---: | ---: |
| Whole-TU objdiff fuzzy match | 99.47965% | 99.81221% | 100% |
| `worldplanet_update` fuzzy match | 99.15179% | 99.69388% | 100% |
| Update instruction count (retail: 784) | 783 | 784 | 784 |
| Exact functions reported by objdiff | 10 / 11 | 10 / 11 | 11 / 11 |
| Exact assigned data bytes | 344 / 344 | 344 / 344 | 344 / 344 |

The three five-entry orbit-ID, angle-offset, and flight-path-ID arrays
were incorrectly modeled as one `WorldPlanetObjectTables` struct.
Independent array definitions reproduce retail's common `.data` base,
indexed orbit-ID loads, and later angle-address computation. A common
register base alone does not establish a source-level struct. The arrays
retain their original order and 20-byte extents at `0x8032A178`,
`0x8032A18C`, and `0x8032A1A0`. The following unlock-gamebit array is
accessed by name, without walking beyond the former struct.

The follow-up resolves the remaining local-storage mistakes:

- The input X and Y bytes are separate scalar locals. The former packed
  struct introduced an extra address temporary in the compiler's graph.
- One object pointer serves the Arwing interpolation and then the
  selected-planet camera focus. Those lifetimes do not overlap. Keeping
  the latter pointer in the address-taken integer action ID caused a
  stack spill; introducing another pointer while retaining the input
  struct moved the object parameter into the wrong register.
- The orbit angle is a `u16`, with its assignment supplying the required
  wrap. The orbit object and counter retain their function-scope
  declaration order.
- The orbit loop names its shared byte offset using the array element's
  `sizeof`, then captures the angle-entry pointer at its first use.
  Both locals reuse retail's register. Direct indexing alone leaves a
  compiler-created offset in a different register; capturing the pointer
  before the expression also moves its computation before the tilt-cosine
  call.

The GC/1.3 backend trace explained the apparent register-allocation cliff.
With a separate selected-object local and the input struct, the object
parameter still had 29 neighbors after the first simplification sweep,
so it survived an extra sweep and received `r31` instead of `r24`.
Separating the input bytes and reusing the object pointer removes that
problem. The trace's ordinary and instrumented objects were required to
have identical raw SHA-256 hashes. The decoder now also recognizes the
observed `sraw` and `mfcr` opcodes used by this function.

The final link exposed two operand swaps that objdiff's 100% report did
not distinguish. The lighting-intensity multiplication and selection
zero comparison loaded the right values into opposite floating-point
registers. Their raw instructions had identical relocation placeholders,
and all data sections already matched. A local intensity-scale value
preserves the multiplication's load order; testing the selection float
directly with `!value` preserves the comparison's order and removes the
old integer negation sequence from the source. Resolved relocation
targets and the retail checksum verify both fixes. The earlier 42-byte
diagnostic difference included these twelve relocated bytes.

The TU retains the common GC/1.3 game compiler, automatic inlining, and
its existing `nopeephole,noschedule` profile. The inlined Fox-spawn helper
from the first pass remains. No generated path, TU split, global data
order, or compiler profile changes are needed. The neighboring
`../dinosaur-planet` tree provided no WORLDplanet implementation to use
as a donor.

Validation includes the slot-466 scaffold audit, `ninja all_source`, and
strict matching `ninja`, with 30-second timeouts on both builds. The
separate formatting commit preserves the raw object hash and passes
`clang-format --dry-run --Werror` on the source and canonical header.
