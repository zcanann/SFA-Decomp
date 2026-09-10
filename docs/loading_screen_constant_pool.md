# Loading-screen constant-pool audit

The current `dlls/engine/50/50.c` matches all seven functions (1,340 bytes)
under GC/1.3, but only 72 of 104 data bytes. Its complete 32-byte retail
constant window has this layout:

| Offset | Contents | Direct load count | Consumers |
| --- | --- | ---: | --- |
| `00` | Unsigned integer-to-double conversion bias | 8 | Loading-screen fades and centered texture coordinates |
| `08` | Float zero | 1 | Texture LOD initialization |
| `0C` | Float 255 | 6 | Loading-screen alpha |
| `10` | Float 30 | 6 | Loading-screen fade duration |
| `14` | Zero word | 0 | No direct load |
| `18` | Float zero | 2 | Title-screen initialization and frame-start callbacks |
| `1C` | Zero word | 0 | No direct load |

All five hash-verified DOLs have the same bytes and the same 23 load sites
relative to the unit's text start. Each address was checked from the original
instruction's signed displacement and the retail startup value of r2. These
are actual distinct zero addresses, not merely objdiff symbol annotations.

| Version | Pool start |
| --- | --- |
| EN | `803E1CE8` |
| EN rev1 | `803E2968` |
| JP | `803E1E08` |
| PAL v1.0 | `803E34F0` |
| PAL rev1 | `803E36B0` |

The compiled pool has only twenty bytes, in the order 255, 30, conversion
bias, zero. The LOD initializer and both callbacks share that final zero.
Recovering only the order of the first four values therefore cannot complete
the unit. The extra zero words must not simply be declared as invented padding.
The two separately used zeros warrant further ownership investigation, but
their duplication alone does not establish a new TU boundary.

Three source probes tested a called coordinate-centering helper, moving the
existing texture-initialization helper before `runLoadingScreens`, and both
together. Explicit inline forms keep the original pool; extracting the
coordinate expression slightly regresses code similarity to 99.826866%.
Moving only the existing inline initializer leaves every function exact.
Ordinary static helpers can emit the desired bias/zero/255/30 prefix, but the
initializer retains a call and the combined unit drops to 81.307465%. None
recovers the second zero or improves complete data matching. All probes were
restored; compiler settings, source, splits and progress flags are unchanged.

The previous named-constant attempt and its checksum failure are recorded in
commits `8500ca17d2` and `9c2e517911`. Repeating that approach without checking
emitted sections is not a solution. Retail source-leak and cross-version source
tag searches supplied no loading/title file anchor in this pass.
