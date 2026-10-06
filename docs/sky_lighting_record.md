# Sky lighting record recovery

The sky updater no longer reads past a three-float C array into neighboring
global objects. `gSkyTimeOfDayLighting` owns both directions and the three
five-sample curves that the updater actually reads. The old
`sSkyUnusedColors` name was wrong: its fifteen floats supply moon intensity,
ambient intensity, and blend alpha throughout the day.

The working Foxhollow port supplied this lead: see its
`game/src/dlls/engine/5/5.c` at commit `6a3ba4b`. This change independently
checks the layout against retail; the descriptive type and field names are
reconstructions, not recovered original declarations. Foxhollow's separate
host texture-pointer storage is a port adaptation and is not imported here.

## Retail evidence

EN `skyUpdateLightingFromTimeOfDay` starts at `8008A04C` and loads the data
base `8030F2C8` into r28. Its day path reads three floats at offsets 0, 4, 8;
its night path reads offsets 12, 16, 20. The linear-curve calls pass that same
base plus the sample index times four and offsets `40`, `18`, `2C` (hex),
respectively. Four time intervals select indices 0 through 3, and
`Curve_EvalLinear` reads that sample and the next one. Each curve therefore
needs exactly five floats. The final read ends at offset `54`.

| Field | Offset | Size |
| --- | ---: | ---: |
| Sun direction | `00` | `0C` |
| Moon direction | `0C` | `0C` |
| Moon intensity samples | `18` | `14` |
| Ambient intensity samples | `2C` | `14` |
| Blend alpha samples | `40` | `14` |

All five input DOLs pass their configured SHA-1 before inspection. All 21
float words agree at the following regional bases:

| Version | Address |
| --- | --- |
| EN v1.0 | `8030F2C8` |
| EN v1.1 | `8030FE88` |
| JP | `8030F3E8` |
| PAL v1.0 | `80310958` |
| PAL v1.1 | `80310A98` |

All five symbol configs now describe one `54`-byte object. No split boundary
changes. The obsolete forced-retention rule for `sSkyUnusedColors` is removed;
the complete record has actual source references. A tree-wide search found
no consumers of the three old global names outside this TU.

## Code generation and behavior

This is a storage correction, with a measured matching cost. GC/1.3, its
existing TU flags, and function order are unchanged. EN retains 53 of 57
exact functions and all 780 assigned data bytes; its fuzzy score is
99.688965%. The four residuals are:

| Function | Before bytes | After bytes | Match |
| --- | ---: | ---: | ---: |
| `skyUpdateLightingFromTimeOfDay` | 1,204 | 1,196 | 99.152824% |
| `skyUpdateShadowLightDirection` | 588 | 556 | 94.18367% |
| `renderSunAndMoon` | 1,948 | 1,948 | 99.99384% |
| `skyLoadLights` | 484 | 476 | 98.32231% |

The compiler shares the record base and some indexed address calculations.
Retail instead reloads the moon-vector base or repeats intermediate additions.
Ordinary subarray locals and cursor expressions were tested but did not
recover the whole unit. No pointer laundering, compiler exception, assembly,
or artificial source split is added to restore the score. The unit is
`NonMatching` and removed from the four regional completion manifests, so
strict links use the retail object while `all_source` compiles the recovery.

Every non-text source section keeps its bytes, size and alignment. All other
named data symbols retain their offsets and sizes, and every other EN source
object is byte-identical to the baseline. The three old symbols are replaced
by the complete record; compiler-generated literal names can be renumbered.
All five versions produce the same per-function scores and pass both
`ninja all_source` and their strict retail checksum target. The checksum
proves the matching link; it does not certify the substituted sky source.

`tools/sky_lighting_probe.py` executes the compiled updater and curve
evaluators against verified EN retail in PPC emulation. It checks exact
light-slot call arguments, output color bytes, untouched state and record
storage, guard bytes, and preserved registers. Its 485 cases cover absent
state, both sides of every time/lighting boundary, all four slot-flag
combinations, zero/full/partial color blends, and randomized directions and
distinct curve channels. Only the final renderer calls are intercepted;
the Gekko save/restore instructions use the existing paired-single emulator.
This establishes behavior for those fixtures, not a gameplay or hardware
floating-point conformance test.

Reproduce after configuring EN and building its sky and curve source objects:

```sh
python3 tools/sky_lighting_probe.py
```

The optional `unicorn` and `pyelftools` packages are required. Local reports,
baseline object, source experiments, and build logs are under the ignored
`build/sky-state-recovery/` directory.

The overlapping `SkyState` / `SkyTimeBlend` texture layouts remain a separate
recovery job. Retail establishes their shared allocation and field roles,
but the capacity behind the legacy blend-texture index still needs evidence;
the gap to the next pointer alone does not establish an array length.
