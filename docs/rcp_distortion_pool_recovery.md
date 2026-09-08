# Distortion-render constant pool

The distortion renderer's three named coefficients now precede the functions
and use same-type `const f32*` reads, following the declaration/access model
established by the [math pool recovery](math_literal_pool_recovery.md).

| Coefficient | Value | Retail pool offset | Consumer role |
| --- | ---: | ---: | --- |
| `sRcpDistortRadiusScale` | 2.146452f | 0 | Numerator of the radius-dependent falloff |
| `sRcpDistortFalloffPower` | 2.520326f | 4 | Power applied to the configured radius |
| `sRcpDistortStrengthScale` | 255.0f | 8 | Scale from configured strength to a channel byte |

`Rcp_InitDistortionEffects` computes the falloff as the first coefficient divided
by `powfCoreHighPrecision(radius, power)`, then stores it in the selected slot's
parameter pair. Its strength conversion uses the third coefficient. The float
values, precision, arithmetic expressions and selected slot are unchanged.

Previously, anonymous literals placed these three words at offsets 72, 76 and
80, after all the earlier functions' constants. The new ordinary scalar
objects occupy offsets 0, 4 and 8, reproducing the complete 80-byte retail
`.sdata2`. The old section was 84 bytes because its different order required
additional alignment. MWCC supplies the new pool's double alignment and its
remaining zero gap; there are no padding declarations, aggregate anchors,
section attributes or split changes.

The definitions have external linkage, with no public header API. The explicit
address view suppresses duplicate literal emission. A `static const` variant
retains the old 84-byte order and is not used. This is an observed scalar
storage model consistent with the binary, not proof of the original author's
exact declarations.

The same source produces the exact pool in four SHA-1-verified retail versions:

| Version | Pool start |
| --- | --- |
| EN v1.0 | `803DEB48` |
| EN rev1 | `803DF7C8` |
| JP | `803DEC68` |
| PAL rev1 | `803E0510` |

The three symbol names are assigned by these pool offsets in each version.
Existing symbol addresses, sizes, alignment and attributes are preserved.
PAL rev0 is excluded because its local DOL does not pass its configured hash.

All seven function bodies remain byte-identical. All non-pool allocated bytes,
existing named-symbol layouts, and non-pool relocation destinations are
unchanged. Each pool relocation retains its instruction offset, load width and
payload. The 39 ordered floating-point loads agree with retail; the complete
pool bytes are also compared directly with each DOL. The direct-r2 audit finds
no outside consumer of this pool in any of the four versions. That scan does
not cover every possible materialized pointer or indexed access.

Reproduce the value and direct-load checks with:

```sh
python tools/pool_value_sequence.py src/main/rcp_dolphin.c --version GSAE01
python tools/retail_pool_audit.py src/main/rcp_dolphin.c --version GSAE01
```

This supersedes the unresolved `rcp_dolphin` placement verdict in the historical
`priced_classes.md` sections 6b and 12: the scalar address-read form is a
working alternative to the earlier aggregate-placement experiments.

The extracted EN objects also contain exactly three relocations to these
coefficients, all in `rcp_dolphin`. No source/header consumer of the old names
remains. This supplements the direct-load audit with the current object splits'
relocation evidence.

The unit now has 100% code and data agreement in all four verified versions,
adding **80 matched data bytes per version**. It is promoted to `Matching` for
EN and added to each verified secondary matching manifest. EN's strict retail
checksum passes with the source object linked, recovering a complete unit of
3,404 code bytes and 26,494 data bytes. All four full source builds pass under
30-second limits; every unrelated source object and objdiff unit is unchanged.
Formatting is a separate commit, checked for identical generated objects.
