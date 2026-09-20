# Older math: library neighborhood and ten reference projects

Subsequent user-approved implementation: [MSL paths, names and grouping](msl_math_rehome.md).

2026-09-20, SFA baseline `fe5149e59a`, EN v1.0.

**The binary location is positive evidence for a library math block.** The
older routines sit inside the runtime/MSL neighborhood, with standard MSL
functions before them and additional MSL-related code after them. Together
with their older compiler behavior, that is a reasonable basis for treating
them as library math rather than established game-authored code. **MSL is a
plausible working hypothesis, but no matching MSL version was identified.**

The distinction matters: adjacency supports grouping and a library compiler
profile; it does not distinguish one MSL archive from a separate math archive
linked beside MSL. The previous inference that these must be Rare-authored
was too strong. This audit changes no source paths, split boundaries, compiler
options, progress categories or matching status.

## EN address order

The current `.text` claims give the following contiguous sequence. The EN DOL
passes its configured SHA-1 `e750e8e894707a52446118a4b84f1b58b677b269`.
Names are reconstruction annotations, not a recovered linker map.

| Address interval, end exclusive | Contents |
| --- | --- |
| `8028E7FC..80291948` | MSL I/O, memory, printf, strings and wide-character I/O |
| `80291948..80291CBC` | `copysign`, `frexp`, `ldexp`, `modf` |
| **`80291CBC..80294640`** | **Disputed older math family, with `rand`/`srand` inside it** |
| `80294640..8029465C` | Currently identified weak PPC helpers |
| `8029465C..8029471C` | ctype and console I/O |
| `8029471C..80295334` | Later float-math family, including the donor-supported MSL trig tables |
| `80295334..802B7298` | Player DLL TU |

This is substantially stronger than merely finding one math routine somewhere
near one C-library function. The disputed block is 10,628 bytes: the 49 matched
math functions plus 44 bytes of random-number routines. Its constant pools
also follow the surrounding math pools in address order. See the
[pool and boundary audit](math_boundary_audit.md) for actual retail load evidence.

Neither this order nor a library's usual member order proves that exactly one
archive supplied every intervening function. In particular, the statement in
the earlier rehoming history that archives must be contiguous is not an
adequate ownership test. The actual observed ordering is useful evidence
without making that absolute assumption.

## Other GameCube decomps

Inspected six existing checkouts and fetched four additional pinned snapshots.
The following are their reconstructed source/split evidence; their original
DOLs were not available for independent binary comparison in this audit.

| Project / target | Observed math neighborhood or implementation |
| --- | --- |
| Melee / GALE01 | `wchar_io` → `math_1` (`80326118`) → table-based `trigf` → `math` → MetroTRK |
| Mario Party 4 / GMPE01_00 | `modf` (`800EB814`) → double `sin`/`tan` → wrappers → `math_ppc` → MetroTRK |
| Pikmin 2 / GPVE01 | `modf` (`800CF720`) → double `sin`/`tan` → wrappers → `sqrt`/`math_ppc` → extras |
| Metroid Prime / GM8E01_00 | `modf` (`8039485C`) → `nextafter` → double `sin`/`tan` → wrappers → `math_ppc` → MusyX |
| Mario Kart: Double Dash / MarioClub_us | `modf` (`80112830`) → double `sin`/`tan` → wrappers → `sqrt`/`math_ppc` → extras → debugger |
| Wind Waker / GZLE01 | `modf` (`80330B88`) → double `sin`/`tan` → wrappers → `math_ppc` → MetroTRK |
| Sunshine / GMSJ01 | Double-math helpers → `hyperbolicsf` (`80086B44`) → `inverse_trig` → `trigf` → `exponentialsf` → MetroTRK |
| Thousand-Year Door / G8MJ01 | `modf` (`8026C2FC`) → double `sin`/`tan` → wrappers, explicitly grouped under `MSL_C.PPCEABI.bare.H.a` |
| Twilight Princess / GZ2E01 | `modf` (`8036C494`) → double `sin`/`tan` → wrappers in MSL |
| Kirby Air Ride | Much of the reference remains anonymous assembly; inspected its source and assembly constants, without asserting an MSL object grouping |

These projects support the general runtime/math clustering, but they do not
all contain the same floating-point implementation. The seven double-math
neighborhoods above use the familiar fdlibm family; Melee and Sunshine expose
the alternate single-precision MSL family. No inspected project establishes
SFA's disputed 49-function family as that project's MSL implementation.

### A concrete correction: Gekko helpers can be MSL

Sunshine's MSL
[`Single_precision/inverse_trig.c`](https://github.com/doldecomp/sms/blob/3945807148d745b1516bc4e386541e3779cfaf4f/src/PowerPC_EABI_Support/Msl/MSL_C/MSL_Common_Embedded/Math/Single_precision/inverse_trig.c)
defines a weak `_inv_sqrtf` using `__frsqrte` and Newton refinement, alongside
`acosf`, `atanf` and `atan2f`. Thus the earlier assertion that a Gekko-specific
reciprocal-square-root/Newton implementation is necessarily non-MSL is false.

It is not a matching donor for SFA's whole family: Sunshine's inverse trig uses
different range-reduction tables and polynomial coefficients. Its `rand`
also uses multiplier `0x41C64E6D`, increment 12345, and a 15-bit result, unlike
SFA's full-word generator. Those differences identify different implementations;
they do not exclude an uninspected MSL variant or a separate library.

## Coefficient search, including hexadecimal assembly data

`tools/math_lineage_probe.py` extracts 40 binary32 coefficient fingerprints
from the matched SFA inverse-trig, integer-angle trig and exp2 sources. It
searches numeric values rather than just their decimal spellings: decimal
literals round to binary32, hexadecimal words are considered as raw bits,
sign is ignored, and C comments are removed.

Across **34,428 source/header/assembly files in ten project trees**, there is
no file with two distinct fingerprints. The 12 candidate files contain only
the ordinary `0.99999f` value or one accidental raw-word match: Mario Party 4's
sound-effect ID `0x767` has the bits of SFA's tiny final cosine coefficient.
None is a matching polynomial cluster. Twilight Princess's scanned tree also
includes its non-GameCube sources, so the file count is an overinclusive source
corpus count, not a count of GameCube translation units.

This strengthens “not found in these references” beyond decimal-string grep.
It does not exclude missing source, dead-stripped routines, coefficients
expressed as arithmetic or paired double words, or other library versions.
The 40 fingerprints do not represent every constant in all 49 functions.

Run with any local source trees (downloads stay under ignored `build/`):

```sh
python3 tools/math_lineage_probe.py \
  reference_projects/melee reference_projects/marioparty4 \
  reference_projects/pikmin2 reference_projects/prime \
  reference_projects/mkdd reference_projects/tww \
  build/math-lineage-references/doldecomp_sms/sms-* \
  build/math-lineage-references/doldecomp_ttyd/ttyd-* \
  build/math-lineage-references/doldecomp_kar/kar-* \
  build/math-lineage-references/zeldaret_tp/tp-*
```

JSON records the SFA source hashes, coefficient bits, scanned file counts and
candidate paths under `build/math-lineage-references/coefficient-scan.json`.
The decimal/hex equivalence and comment-exclusion control passes; the reported
corpus totals were rechecked. EN `all_source`, strict `ninja`, and a fresh DTK
checksum check pass with the unchanged production source.

Reference revisions:

| Project | Revision |
| --- | --- |
| Melee | `df2ba482bdf6bec8b6f2feea3d0c71f5d1f78bd8` |
| Mario Party 4 | `147b165a83187ac9e6cfdc3bf52f2e73437b1ffd` |
| Pikmin 2 | `55471edf0d6d991b0cb209436557116bd33c2d06` |
| Prime | `fc935295e3f74a2c71b3a83839319166823e2649` |
| Double Dash | `a2f28da303042895ac03af5c0a98fb9ebdbd7ce8` |
| Wind Waker | `be8da688fcc755d77e2cdb7a69124297b01ff683` |
| [Sunshine](https://github.com/doldecomp/sms/tree/3945807148d745b1516bc4e386541e3779cfaf4f) | `3945807148d745b1516bc4e386541e3779cfaf4f` |
| [Thousand-Year Door](https://github.com/doldecomp/ttyd/tree/2df569d19d2251d971c518d0e53811416fc326a4) | `2df569d19d2251d971c518d0e53811416fc326a4` |
| [Kirby Air Ride](https://github.com/doldecomp/kar/tree/3ed51a1a008a05c33225cc286c046b8f90fb3d0e) | `3ed51a1a008a05c33225cc286c046b8f90fb3d0e` |
| [Twilight Princess](https://github.com/zeldaret/tp/tree/c8fa8c9e2aab72cf4e5db0e5d1c84a9ea6ee6eb0) | `c8fa8c9e2aab72cf4e5db0e5d1c84a9ea6ee6eb0` |
