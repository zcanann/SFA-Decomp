# Render texture-coordinate helpers

Two private helpers now express existing texture-coordinate operations in
`track/intersect_render.c`. A third recovers a projected-shadow fog-color
initializer and its previously unclaimed storage:

- `renderTextureCenterTranslation` builds an XY translation of either -0.5 or
  +0.5, with zero Z translation. The distortion filter calls the positive case
  twice when restoring the texture center after scale/rotation. The snow-flash
  overlay calls the negative case twice when moving the texture origin to its
  center. Matrix concatenation order and scratch-matrix ownership are unchanged.
- `renderTextureFrameOffset` converts an unsigned frame index to a float and
  divides by the supplied period. The moon callback passes its byte-sized day
  index and 30.0f, preserving the existing texture offset and division.

- `projectedShadowInitChannelFogColor` copies a const zero RGBA template into
  the channel setup's local fog color. Its definition precedes depth-fade setup,
  which retains its separate local zero initializer. This recovers retail
  template order without changing the initialization instructions or stack slots.

These are ordinary called `static` functions under the existing GC/1.3 automatic
inlining profile. All six calls inline into their parents. Their definitions
also produce three standalone local bodies totaling 112 bytes. The linker
strips all three; none appears in the linked ELF, and the retail checksum
confirms that their presence does not enlarge or reorder the final text. The helper names and source boundaries are reconstructed;
there is no leaked original source establishing their exact spelling.

The helpers account for the formerly displaced constant-pool prefix. The
center operation emits -0.5 and +0.5 at offsets 0x54/0x58. The frame conversion
emits the unsigned integer-to-double bias at 0x60. The compiler supplies the
intervening alignment. Later users share those literals without named scalar
anchors, padding declarations, section attributes or synthetic unused code.
The complete 236-byte `.sdata2` now agrees with retail.

This matters independently of the match counter: all 65 existing function
bodies retain identical instruction bytes. Their 185 ordered constant loads
retain their values and widths. Every relocation is compared at its offset
within its owning function; non-pool destinations are unchanged except for the corrected zero-template
positions described below. Later function symbols move by up to 112 bytes
in the source object because the standalone helpers precede them. Non-text
allocated section bytes other than `.sdata2`, and existing named data layouts,
are unchanged. Inserting the helpers also renumbers anonymous identifiers;
validation compares section, offset and payload rather than just those names.

Explicit `inline` alone defers the conversion pool until the caller and does
not recover this ordering. Named-scalar half-value probes can recover the pool
with an ordinary frame helper, but change three already-exact functions; those
probes are not retained. The accepted helpers express the repeated matrix
operation and actual frame conversion while preserving every existing body.

The historical lost-body hypothesis in `priced_classes.md` identified the
missing early literals but supplied no known original function. This recovery
uses live call sites rather than inventing an uncalled clamp. Pool ordering
supports the reconstructed source arrangement; it does not prove that these
were the only possible original helpers.

The same pool is checked directly against each configured, SHA-1-verified DOL:

| Version | `.sdata2` start | `.sbss2` start |
| --- | --- | --- |
| GSAE01 | `803DEEA0` | `803E8450` |
| GSAE01_rev1 | `803DFB20` | `803E90D0` |
| GSAJ01 | `803DEFC0` | `803E8570` |
| GSAP01_rev1 | `803E0868` | `803E9E30` |

PAL rev0 is excluded because its local DOL fails the configured hash. The
direct-r2 pool audit finds no outside consumer in any verified target; it does
not cover every possible materialized pointer or indexed access. Reproduce the
value and direct-load checks for each `--version` with:

```sh
python tools/pool_value_sequence.py src/track/intersect_render.c --version GSAE01
python tools/retail_pool_audit.py src/track/intersect_render.c --version GSAE01
```

## Zero-color ownership and the strict link

The initial pool-only promotion failed the EN checksum despite objdiff reporting
all assigned sections exact. The unit emitted eight bytes of `.sbss2`, but its
split did not claim them. Linking source therefore duplicated the records and
increased the BSS end by eight bytes. The two local initializer templates also
had the opposite order from retail.

Retail channel setup loads the first four-byte record at `8007809C`; depth-fade
setup loads the second at `80077B10`. The claimed EN span is
`803E8450..803E8458`. Every verified version has the same order and the same
function-relative load offsets (channel +420, depth fade +56). Scanning direct
r2 loads finds only those two consumers. An EN relocation scan across all
extracted objects also finds exactly these two references, both in this TU. These records lie in zero-initialized
BSS, not in file-backed DOL data; validation checks the zero ELF section,
relocations, runtime load addresses and final checksum rather than pretending
to read BSS bytes from the DOL file.

The const initializer in the channel helper matters: a mutable template or
struct-return helper changes stack-slot allocation in the already-exact
channel setup. File-scope named colors emit in `.sdata2` or `.sbss` instead of
`.sbss2`. Those alternatives are not retained. The recovered helper is a
source-layout hypothesis supported by its live initialization call, template
order and unchanged code, not a claim to an original helper name.

The regional `version_progress.py <version> --write` refresh was run for all
three secondary targets. Its conservative mapper could not map the new
`.sbss2` boundary and dropped the entire unit. The existing claims were
preserved, and the eight-byte spans above were added using the direct retail
load evidence. Unrelated regenerated symbol changes were discarded.

No section-alignment override, forced section, linker retention directive or
compiler-profile change is needed. EN `all_source` and the strict retail SHA-1
target pass with this unit linked from source. The same source and data layout
pass in EN rev1, JP and PAL rev1, including full `all_source` builds, before
adding the unit to their matching manifests. All four reports show 65/65 exact
functions (54,200 bytes) and 628/628 exact data bytes. Other source objects and
unit reports are unchanged, apart from the divided automatic `.sbss2` gap. The change recovers 236 pool bytes plus eight previously unclaimed
zero bytes per verified version and makes the complete render unit eligible
for source linking.
