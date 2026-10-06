# Sky lighting curve recovery

The sky updater uses two three-float direction arrays and three named
five-sample curves. Every access stays within its declared array, including
the moon direction and the interpolator's second sample. The former
`sSkyUnusedColors` table supplies moon intensity, ambient intensity, and blend
alpha; none of these samples are unused.

Foxhollow's native port supplied the adjacency bug lead; see its
`game/src/dlls/engine/5/5.c` at commit `6a3ba4b`. Retail code generation now
supports independent arrays rather than the initially proposed combined
`SkyTimeOfDayLighting` record. The descriptive array names are reconstructions,
not recovered original identifiers.

## Retail evidence

EN `skyUpdateLightingFromTimeOfDay` starts at `8008A04C` and loads the data
pool base `8030F2C8` into r28. Its day path reads three floats at offsets 0, 4,
8; its night path reads offsets 12, 16, 20. The linear-curve calls pass that
same base plus the sample index times four and offsets `40`, `18`, `2C` (hex),
respectively. Four quarter-day intervals select indices 0 through 3, and
`Curve_EvalLinear` reads that sample and the next one. Each curve therefore
needs exactly five floats. The final read ends at offset `54`.

| Array | Offset from pool base | Size |
| --- | ---: | ---: |
| `gSkySunDirection` | `00` | `0C` |
| `gSkyMoonDirection` | `0C` | `0C` |
| `gSkyMoonIntensityCurve` | `18` | `14` |
| `gSkyAmbientIntensityCurve` | `2C` | `14` |
| `gSkyBlendAlphaCurve` | `40` | `14` |

All five input DOLs pass their configured SHA-1. All 21 float words agree at
the following regional pool bases:

| Version | Address |
| --- | --- |
| EN v1.0 | `8030F2C8` |
| EN v1.1 | `8030FE88` |
| JP | `8030F3E8` |
| PAL v1.0 | `80310958` |
| PAL v1.1 | `80310A98` |

The five symbol configs describe each array at these offsets. No TU boundary
changes. Direct source references retain all three curves, so the old forced
retention rule for `sSkyUnusedColors` stays removed. The unused trailing
`.sbss` word `sSkyUnusedD` still needs its existing rule.

## Matching source structure

The shared register in the updater is a compiler-generated data-pool base,
not proof of a source-level aggregate. GC/1.3 groups the independent arrays
into `...data.0` when the function references them together. Ordinary indexed
accesses then reproduce retail's three independent curve-address calculations.
Other functions reference the sun and moon arrays independently, reproducing
retail's separate base loads and vector offsets.

This recovers the useful curve meanings and array bounds while restoring all
four functions that regressed under the aggregate declaration. The complete
TU matches in every version: **57/57 functions, 16,924/16,924 code bytes, and
780/780 data bytes**, with completion annotations disabled. Compiler version,
flags, function order, and the assigned section extents remain unchanged.
The unit is source-linked again in EN and all four regional manifests.

Every other EN source object is byte-identical to the pre-recovery baseline.
The full project reports were also regenerated without completion annotations
for all five versions. All scored function bodies are exact. Two existing
reporting cases require final-link evidence: the TRK vector table's padding
symbol has no source function counterpart, and MusyX's
[`sal_volume` exception sections](musyx_volume_completion.md) include helper
records that the linker discards. Every version passes `ninja all_source` and
the strict retail DOL checksum with the sky source object linked.

## Behavior probe

`tools/sky_lighting_probe.py` executes the compiled updater and curve
evaluators against verified EN retail in PPC emulation. It locates and checks
each direction and curve array through its own symbol, without assuming that
source arrays are contiguous. It checks exact light-slot call arguments,
output color bytes, untouched state and array storage, guard bytes, and
preserved registers.

The 485 cases cover absent state, both sides of every time/lighting boundary,
all four slot-flag combinations, zero/full/partial color blends, and randomized
directions and distinct curve channels. Only the final renderer calls are
intercepted; Gekko save/restore instructions use the existing paired-single
emulator. This establishes behavior for those fixtures, not a gameplay or
hardware floating-point conformance test.

Reproduce after configuring EN and building its sky and curve source objects:

```sh
python3 tools/sky_lighting_probe.py
```

The optional `unicorn` and `pyelftools` packages are required. Local reports,
object comparisons, and build logs are under the ignored
`build/sky-state-recovery/` directory.
