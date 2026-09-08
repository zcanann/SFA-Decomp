# Engine 0: HUD declaration and source-shape recovery

EN v1.0, 2026-09-04. The unit is `src/dlls/engine/0/0.c`, containing the
command menu, HUD, communicator, and pause menus. It remains `NonMatching`.
The September 4 pass reached 106 of 118 exact functions; the September 5
follow-up below starts with 108. All 118 have the retail instruction count.
The whole TU uses GC/1.3, `-inline noauto`, and signed `char`.

## Color declarations and the compiler fingerprint

`gameTextSetColor` is implemented with four `u8` channels in
`src/main/textrender_gettext.c`, but Game UI previously saw four `int`
parameters. Recovering that byte contract also lets `hudDrawCounter` accept
`u8 alpha` and call `drawTexture` directly, removing its incompatible
function-pointer cast. Float expressions pass directly to the narrow
parameters; the score-screen pulse locals are bytes. These changes preserve
every baseline function's instruction bytes under GC/2.0.

The two local pause-menu texture helpers similarly accept `u16 scale`.
Their implementations already consumed the low 16 bits. Removing the old
intermediate integer conversions in their callers preserves their code.
The shared color header has a Game UI opt-in, so other callers retain their
existing declarations.

The resource loader provides evidence beyond an aggregate compiler score:
retail reloads three communicator object pointers immediately after storing
them. With the same source, GC/1.3 emits those loads and matches all 896
bytes. GC/1.3.2, GC/1.3.2r, and GC/2.0 forward the stored pointers. The older
compiler's previous indirect-call regression in `hudDrawCounter` disappears
with the corrected declaration; retail's direct call is now reproduced.

GC/1.3 preserves all 105 previously exact functions and fixes the loader.
It also removes the extra instruction in `drawViewFinderHud`, improving that
function from 99.36948% to 99.4498%. Signed `char` preserves the existing
byte comparisons. Unsigned compound-assignment masks preserve the retail
operations on `gCMenuButtons`; comparison masks retain their original types.
This supports the compiler profile without claiming a recovered historical
build script or changing the confirmed TU boundary.

## Status-page call recovery

The scarab counter's format is `"%d/%d"`. Its reconstructed `sprintf` call
omitted the capacity argument. Retail's `lbz r6` supplies that argument and
also tests whether the capacity is zero. Passing `gPauseMenuScarabCapacity`
restores both instructions.

The spellstone count is one sum of four `mainGetBit` calls, in the same
source order used by the other menu logic. MWCC emits the retail call and
addition order from that expression; the manually staged count temporaries
were changing its registers. Together these fixes improve
`pauseMenuDrawStatusPage` from 99.85141% to 99.91085%. Twelve instruction words
still differ, all in the alpha registers.

## A solved residual: communicator pulse rendering

`hudDrawCommunicatorAlert` now matches all 632 bytes / 158 instructions.
The previous 99.05064% implementation carried explicit locals for fade,
horizontal offset, vertical position, alpha, and scale. Those locals
reproduced the calculations but obscured the compiler's common expressions
and loop strength reduction.

The matching source has only two signed-byte locals: pulse phase and
segment index. Both draw calls repeat their coordinate, alpha, and scale
expressions. Alpha is `255 - segment * 85`; MWCC creates the descending
170, 85, 0 induction variable itself.

The decisive declaration is the texture-drawing scale argument. Game UI's
existing narrow-alpha API view also needs **`u16 scale`**, alongside
`u8 alpha`. With an `int` scale declaration, explicit `(u16)` casts make
MWCC share the already-truncated scale across calls, introducing two extra
copies. With the narrow declaration, MWCC shares the untruncated arithmetic
and emits the retail conversion at each call.

This is supported by the renderer implementations in
`src/track/intersect_render.c`: all three texture-drawing routines consume
scale as `u16`. The reconstructed renderer definitions still use wider
parameters; the matching caller view does not by itself prove which
historical header declared those definitions. The shared header therefore
retains its default view, and the existing Game UI opt-in now describes
both narrow arguments as `INTERSECT_HUD_NARROW_ARGS`.

One other Game UI call needed its recovered conversion corrected:
`hudDrawButtons` passes the Y-button animation scale directly as a float
expression. Its old intermediate `(int)` cast adds an unwanted mask under
the narrow declaration. Removing that cast restores its previous code
exactly. Every other function preserves its baseline match, apart from the
independent grid interpolation improvement below.

## Grid interpolation and pulse

In `pauseMenuDrawGridCell`, spelling the two interpolation terms as
`pr / 512.0` instead of `pr * 0.001953125` reproduces the retail fused
multiply-add operand order. The function improves from 99.545456% to
99.624504%, with the same 253 instructions. Register differences remain.

The pulse reflection now uses a conditional expression, narrowing the reflected
value inside that expression before multiplying by the fade step. This reproduces
retail's instruction and branch sequence, improving the function to 99.68379%.
All 253 instructions remain; register differences still prevent an exact match.
The other 117 function bodies, data contents, relocations, and named symbol
offsets are unchanged. The exact-function count remains 106 / 118.

## Dinosaur Planet comparison

The substantive predecessor is
`../dinosaur-planet/src/dlls/engine/1_cmdmenu/cmdmenu.c`. Its file comment
records the debug-side name `9slcommandmenu.c`. Useful counterparts include
`cmdmenu_page_load_items`, `cmdmenu_store_loaded_item_metadata`,
`cmdmenu_draw_player_stats`, and `cmdmenu_dtor`.

The N64 implementation confirms parallel item tables, indexed loops, and
the inventory/sidekick distinction. It is an earlier implementation:
the GameCube communicator, Arwing HUD, pause-menu additions, and duplicate
item-clear passes cannot simply be copied from it. Natural indexed rewrites
of the current C-menu loader, including separate-array probes, did not
reproduce the EN pointer and register structure. No sibling files were
changed.

## Constant ownership and remaining work

Three former external constants are now emitted by their consumers:
the backdrop's `f32` scale of 435.2, the podium's `f32` base Y of -2.1,
and division by 1024.0f for the ring transforms. These preserve every
instruction byte. The float locals preserve the retail loads and conversion
precision; substituting literals directly can instead fold the conversion
or change the precision of an intermediate constant.

The source `.sdata2` grows from 936 to 948 bytes toward the retail 980.
Its fuzzy match improves from 97.28601% to 97.92531%. No duplicate named
constants or explicit section placement are needed.

- **Release:** only three instruction words differ, all using `r26` where
  retail uses `r27` for the initial texture iterator.
- **Constant ownership:** five external constants remain absent from the
  emitted pool: `gGameUiPi`, `lbl_803E1F30`, `lbl_803E1F34`,
  `lbl_803E20B8`, and `lbl_803E2128`. Their values plus pool alignment
  account for the remaining size difference. Replacing them with literals
  or float locals changes folding, conversion reuse, or register allocation.
  Appending named definitions puts them in `.sdata`. Their source ownership
  remains unresolved; do not force sections or duplicate literals.

## September 4 validation

| Measure | Before communicator fix | After communicator fix | Current |
| --- | ---: | ---: | ---: |
| Exact functions | 104 / 118 | 105 / 118 | 106 / 118 |
| Exact code bytes | 44,208 / 75,188 | 44,840 / 75,188 | 45,736 / 75,188 |
| TU fuzzy match | 99.79481% | 99.80385% | 99.82806% |
| Exact assigned data bytes | 8,972 / 9,952 | 8,972 / 9,952 | 8,972 / 9,952 |

The current pass starts at commit `2793989679`. All non-pool data sections
retain their bytes, sizes, and named symbol offsets. GC/1.3 changes five
data relocations from named arrays to section-plus-offset references; they
resolve to the same locations. Comparing 2,682 pre-existing source objects
after the builds finds only engine 0 changed.

Use the normal object build and objdiff report, plus
`python3 tools/fnbytes.py 0 hudDrawCommunicatorAlert`, to reproduce the
function comparison, or substitute `gameUiLoadResources` for the loader.
The strict EN checksum build and `ninja all_source` both pass within their
30-second limits (about 16 seconds each). Formatting checks also pass.
The strict build still uses retail code for this `NonMatching` TU and is
not proof that the remaining twelve functions match.

## September 5 follow-up

A fresh build at `4d84859649` already uses GC/1.3 and has 108 exact
functions, including the subsequently matched `GameUI_release` and
`hudDrawMagicBar`. This pass preserves that compiler profile and TU boundary.

The C-menu count-label loop now derives its row offset from `i * 50`.
MWCC generates the induction variable itself, bringing `hudDrawButtons`
from 99.666664% to 99.68513%. The head-display scanline computes and saves
its Y coordinate in the first draw call, matching retail's placement of
the calculation after loading the texture and X coordinate.
`headDisplayDraw` improves from 98.802086% to 99.21875%.

The TU code fuzzy score rises from **99.85679% to 99.86833%**. Exact code
remains 48,544 / 75,188 bytes across **108 / 118 functions**. All 118
functions retain the retail instruction count, and no function's score
regresses. Only the two edited functions change instruction bytes.

All six data sections retain their source-object bytes, sizes, alignment,
and resolved data relocations. Every named symbol retains its size and
offset. MWCC renumbers anonymous pool and switch-table symbols after the
head-display edit; their layouts and contents remain unchanged.

The TU is still `NonMatching`: ten functions have residual differences,
and `.sdata2` still emits 948 of the retail pool's 980 bytes. Direct literal
substitutions for the five missing constants change code generation; they
were not retained. Declaration and scope probes also failed to eliminate
the remaining differences. No partial compiler profile, forced section, or
additional TU split is used.

Validation: `python3 configure.py --matching`, strict default `ninja`, and
`ninja all_source` pass within the required 30-second timeout per build.
Formatting checks pass for the TU and its public API header. The strict
checksum still links retail code for this `NonMatching` TU.

## September 5 complete constant-pool recovery

The next pass starts at `0cd820cb40` and resolves the pool ownership left
open above. All eleven references to TU-owned compiler literals now use
their correctly typed values. Five values were missing from the source
pool: float pi, 80.0f, 320.0f, 256.0f, and double 1/256. Six others were
already emitted anonymously but still had external references in the C.
The source now emits the complete **980-byte `.sdata2`**, including the
retail alignment, with no duplicate named constants or forced sections.

Float locals for the status icons, hint panel, grid cursor, and carousel
retain retail's conversion precision and operand order. The timed HUD
element uses a compound alpha update. These spellings preserve the exact
functions that direct literal substitutions initially changed.

The map and head-display shimmer calculations combine their two sine
waves in one expression. This preserves the retail call order and restores
the floating-point registers. The viewfinder line helper computes its
corner offsets in the draw-call arguments, improving the grid's temporary
registers. `headDisplayDraw` rises to 99.302086%; the viewfinder remains
below its previous score at 99.36948% after the literal recovery.

| Measure | Previous | Current |
| --- | ---: | ---: |
| Exact functions | 108 / 118 | 108 / 118 |
| Exact code bytes | 48,544 / 75,188 | 48,544 / 75,188 |
| Code fuzzy match | 99.86833% | 99.865135% |
| Exact assigned data bytes | 8,972 / 9,952 | **9,952 / 9,952** |

All 118 functions retain their retail instruction counts. Existing
exports, non-pool data layouts, and resolved data relocations are
unchanged. An undefined-symbol audit of the 1,042 active target objects
finds no other TU consuming the eleven former literal symbols. Old build
objects outside the active config are excluded from this audit.

A diagnostic link replaces only engine 0's retail object with the rebuilt
GC/1.3 object. It succeeds with no missing symbols, preserves every linked
section address and size, and reproduces every linked data section byte
for byte. Only `.text` differs: 563 bytes across the ten remaining
non-exact functions. Thus the small code-fuzzy regression accompanies a
complete, independently linked data recovery.

Validation: strict checksum `ninja` and `ninja all_source` both exit 0
within their 30-second limits. Formatting checks pass for the TU and
`include/main/dll/dll_0000_gameui_api.h`. The TU remains `NonMatching`;
the diagnostic source link does not yet reproduce the retail DOL.

## September 5 button-HUD match

`hudDrawButtons` now matches all **3,684 bytes / 921 instructions** under
the same GC/1.3 profile. The count-label opacity clamp is two conditional
expressions. The lower bound remains an `int` zero, while the upper bound
is explicitly `(s16)0xFF`, preserving the signed-short result before the
highlight-fade multiplication.

The two conditional expressions resolve the register allocation across
the function, including its long-lived HUD base, selected icon, and row
offset. An untyped upper bound leaves just one reversed `mullw` operand
order; the signed-short bound resolves it. The clamped value is unchanged
for every input representable by `alpha`.

Exact functions rise from **108 to 109 / 118**, and exact code rises from
48,544 to **52,228 / 75,188 bytes**. Code fuzzy match is **99.88057%**.
The other 117 function bodies are byte-identical to the preceding source
object. All assigned data remains exact, and source exports, section
layouts, and resolved relocations are unchanged.

The staging rebase also brings in the corrected shared `fsin16Approx(u16)`
declaration. Explicitly promoting the two wrapped head-display angles to
`int` preserves the caller's previous expression types and restores the
complete pre-rebase object byte for byte. The shared narrow API is retained;
removing only the explicit angle casts does not restore the code generation.

This pass also rechecks the whole-TU optimizer controls. Enabling peephole
optimization or scheduling regresses the match substantially. Disabling
lifetimes, dead-store elimination, propagation, loop-invariant motion,
common-subexpression elimination, or strength reduction improves none of
the remaining functions. No compiler-profile change is retained.

Validation: the strict checksum build and `ninja all_source` both exit 0
within their 30-second limits. Formatting checks pass for the TU and its
public API header. Nine functions remain non-exact, so the TU remains
`NonMatching` and the full-TU goal is not complete. A diagnostic source-object
link succeeds with every linked data byte intact; 506 text bytes still
differ from the strict-build baseline.

## September 5 viewfinder heading recovery

Declaring the major-label opacity before the minor-label and heading locals
improves `drawViewFinderHud` from **99.36948% to 99.51004%**, removing 30
differing instruction words. A typed `f32 angleUnitsPerDegree` local for
the existing 182.04445f conversion fixes the heading offset's `fnmsubs`
operand order, reaching **99.518074%**. Adding `const` to that local restores
the previous operand order, so the non-const spelling is retained.
The function retains all 1,245 instructions; 105 words still differ,
predominantly in floating-point registers.

The TU reaches **99.89041%** fuzzy match, with **109 / 118** exact functions,
**52,228 / 75,188** exact code bytes, and all **9,952** assigned data bytes
exact. The other 117 function bodies, data layouts, exports, and resolved
relocations are unchanged from the button-HUD improvement.

This follows checks of declarations in nested scopes as well as the leading
function blocks. Further grouped-declaration permutations, separating
initializers from declarations, and changes to the segment helper's local
declarations do not improve the result. Nine functions remain non-exact, so
the TU stays `NonMatching`. Declaration-order sensitivity is measured here,
not evidence of the historical source spelling.

Validation: the strict checksum and `ninja all_source` builds both exit 0,
and formatting checks pass. After finishing the shared-header rebuild in
30-second-limited invocations, the final strict and all-source runs take
20.39 and 22.79 seconds. The staging rebase preserves the complete source
object byte for byte. A diagnostic source-object link leaves every data
byte intact and reduces the residual text differences from 506 to **465**
bytes.

## September 6: compiler traces on macOS

The staging resync through `e0cff4c0f6` preserves the complete `0.c` object:
109 / 118 functions remain exact, with 99.89041% code similarity and all
9,952 assigned data bytes exact. The source object SHA256 is
`5878b3855f71f6077a2ed61b222692bc49738ea00befd307a065acdc24c0db61`.

`tools/tricky_backend_trace.py` now accepts `--unit` and infers that unit's
configured source. Its new macOS provider uses LLDB with the repository's
Wibo executable; the existing Windows provider remains available. For example:

```sh
python3 tools/tricky_backend_trace.py --unit main/dlls/engine/0/0 \
  --function headDisplayDraw --function pauseMenuDrawStatusPage --graph \
  --output build/flag_probe/engine_0_backend
python3 tools/tricky_backend_trace.py \
  --read build/flag_probe/engine_0_backend/trace.json \
  --function headDisplayDraw --instruction 229 --instruction 230
```

Capture requires the supported GC/1.3 compiler hash, LLDB, Wibo's
`loadPEFromSource` symbols, and the Python dependencies used by the existing
object-inspection tools. On the tested Apple Silicon host, Wibo runs under
Rosetta. The provider verifies each intercepted instruction and emulates its
32-bit `ret` or `push ebx`; letting LLDB step these guest instructions as
host instructions can crash the compiler. Compiler files remain untouched.
Captured and ordinary objects must have identical raw hashes before a trace
is published. A timeout and a missing-function probe both fail without leaving
a running compiler or debugger. Unsupported IR still fails validation.

The live trace validates all 480 instructions and 21 snapshots for
`headDisplayDraw`, and all 673 instructions and 20 snapshots for
`pauseMenuDrawStatusPage`. GPR graph simplification and every physical color
choice replay exactly. Decoder coverage now includes these functions' floating
instructions, symbolic `li` operands, and fallthrough branches across empty
blocks. Symbolic loads retain checks of the opcode, destination, and zero base;
the relocation's low halfword remains opaque.

The head-display trace explains why merely chaining the three zero assignments
does not produce retail's two copies. Constant propagation turns the phase
locals into immediate loads, but their virtual GPRs 35 and 44 fall below the
late value-numbering range beginning at 46. Computing phases from the scanline
instead creates eligible induction temporaries. Computing all three quantities
from a row counter also produces two copies, but the current forms worsen
register allocation, so none is retained. For the status page, the remaining
three instructions concern one alpha value: virtual GPR 46 receives r24 even
though retail's r28 is free. The already-expanded register bank chooses the
lower free register. These are observations of the reconstructed source's
compiler behavior, not proof of the original local declarations.

Validation after the resync: 68 backend tests complete with seven Windows-only
skips; live capture with and without graphs and offline trace inspection pass.
The strict build exits 0 in 15.72 seconds with the expected retail SHA1, and
`ninja all_source` exits 0 in 16.26 seconds. The TU and API header pass the
formatting check.

## September 6: all residual functions traced

All 5,740 instructions in the nine remaining functions now align with captured
FINAL CODE records. Each GPR graph's simplification and physical coloring also
replays against the live compiler. The complete instrumented objects retain
the ordinary object's `5878b385...c0db61` SHA256 above.

| Function | Instructions | Differing instruction words |
| --- | ---: | ---: |
| `drawViewFinderHud` | 1,245 | 105 |
| `pauseMenuDrawStatus` | 516 | 34 |
| `cMenuSetItems` | 302 | 60 |
| `headDisplayDraw` | 480 | 40 |
| `drawArwingHud` | 266 | 22 |
| `pauseMenuDraw` | 1,141 | 8 |
| `pauseMenuDrawStatusPage` | 673 | 3 |
| `pauseMenuDrawGridCell` | 253 | 16 |
| `mapScreenDrawHud` | 864 | 47 |

This required seven additional observed instruction spellings and a register
parser correction. A branch target printed as `f150`, or even `f0`, is a hex
address rather than an FPR. Branch records still reject unexpected GPR/FPR
operands, and symbol annotations are excluded from operand parsing. Regression
tests cover both ambiguities and preserve rejection of actual register
mismatches. The backend suite completes 72 tests with seven Windows-only skips.

Every current residual GPR graph simplifies entirely through low-degree sweeps;
none invokes the weighted high-degree choice. This describes the reconstructed
source only. Register correspondences inferred from retail also need to account
for commuted additions: the apparent two-color conflicts for the C-menu base
and count come from swapped addition operands, not demonstrated value splitting.

The status-page trace also confirms that reusing one local for the three alpha
stages does not merge their backend lifetimes: later assignments already have
distinct virtual registers before GLOBAL OPTIMIZATION. An inline fade-conversion
helper, including a variant containing the repeated hologram setup, changes the
initial alpha from r24 to r26 but increases its residual from three words to five.
An opacity aggregate has the same problem. None is retained. Typed C-menu source
cursors preserve all 302 instructions but worsen the residual from 60 to 68
words. Separating the grid-cell pulse phase and changing its argument widths
also fail to improve matching. Source and compiler settings remain unchanged.


## September 8: viewfinder HUD exact

`drawViewFinderHud` now matches all **4,980 bytes / 1,245 instructions**,
up from 99.518074% and 105 differing instruction words. The same source
scores **100% in all five retail targets**: EN v1.0, EN rev1, JP, PAL, and
PAL rev1. Every input DOL was verified against its configured SHA1 before
those regional comparisons. The TU remains `NonMatching`; its other
residual functions prevent claiming an exact whole object in any manifest.

The curved compass lines and heading ticks share a float wave-offset
helper. Their endpoint expressions pass directly to the segment helper,
which derives its direction from those endpoints. This lets MWCC recover
the retail common expressions and floating-point register allocation.
The segment helper repeats the angle-to-radians expression in its sine
and cosine calls; the compiler shares the calculation. Computing the
sliding reticle coordinate in the draw call removes the last register
swap. The tick spacing follows the tick position in the declaration list,
and the tick alpha scratch is declared before the text alpha.

Only this function's instruction bytes change: 135 bytes within the same
4,980-byte extent. All other function bytes and objdiff scores, allocated
data bytes and section layouts, and named symbol offsets remain unchanged.
Anonymous symbols are renumbered. The whole TU retains its common GC/1.3
compiler profile, flags, and retail boundary.

Validation includes regional objdiff reports, the strict EN checksum build,
`ninja all_source`, and formatting checks on the TU and its API header.
Formatting is committed separately and checked for identical object bytes.

## September 8: status-update register recovery

At staging `74978326cd`, `pauseMenuDrawStatus` improves from **99.64147%
to 99.92248%** under the unchanged GC/1.3 profile. Differing instruction
words fall from **34 to 8**, with all 516 instructions retained. **The
function is not yet exact.**

The animated-update loop now indexes the local status array directly and
repeats the opacity-array access instead of carrying a named opacity pointer.
This removes the obsolete byte-offset local and reproduces the complete
retail register allocation in that loop. The inline `hudSnapshotStatus`
helper groups the displayed value, previous value, and timer initialization;
its scalar argument also restores the snapshot loop's remainder copy.
The existing byte base remains necessary for code generation, with its
field offsets now derived from `offsetof(CMenuHud, ...)`.

The remaining differences are instructions 270, 272–274, 276–277, and
279–280: the first unrolled snapshot copy uses r3 for the scaled index
and r0 for the loaded value, where retail uses r0 and r3 respectively.
A live optimizer trace validates the generated instruction stream and
register coloring. The source probes included direct and factored stores,
index and counter forms, pointer lifetimes, local declaration order, and
aggregate status layouts; none tested eliminates this last swap. This is
a description of the remaining mismatch, not proof of a compiler limitation
or the historical source spelling.

All other 117 function bodies, allocated data-section bytes and layouts,
named symbol layouts, and resolved relocations retain their baseline values.
Anonymous literal names are renumbered. Objdiff still reports all 9,960
assigned data bytes exact. The unit remains `NonMatching`.

Validation: `python3 configure.py --matching`, strict default `ninja`, and
`ninja all_source` pass, with each Ninja invocation limited to 30 seconds.
The strict retail checksum uses the retail object for this nonmatching unit
and does not establish a source match. Secondary DOLs are unavailable in
this checkout, so no regional progress manifest is promoted.

## September 8: status-update exact

`pauseMenuDrawStatus` now matches all **2,064 bytes / 516 instructions**,
closing the eight-word snapshot-copy mismatch above. The snapshot loop
reads its local status array through a signed `int snapshotIndex` copied
from the byte-sized slot counter. The destination addresses continue to
use that counter. This restores r0 for the scaled index and r3 for the
first loaded value in the unrolled copy, without adding instructions.
An unsigned index alias does not reproduce the result.

Objdiff reports **100%** for the function under the unchanged GC/1.3
profile. Exact functions rise from **109 to 110 / 118**, and exact code
rises from 55,932 to **57,996 / 75,188 bytes**. All other 117 function
bodies, data-section bytes and layouts, named symbol layouts, and resolved
relocations retain their baseline values. All 9,960 assigned data bytes
remain exact. The complete TU still has other nonmatching functions and
remains `NonMatching`; no whole-object regional manifest is promoted.

Validation: `python3 tools/fnbytes.py 0 pauseMenuDrawStatus --md5` reports
identical target/current function MD5 `ef3b8eb59db5cd73e25fa09f20ac5ecb`.
After `python3 configure.py --matching`, strict `ninja` and
`ninja all_source` both pass with 30-second timeouts.


## September 8: Arwing HUD opacity narrowing

`drawArwingHud` improves from **99.56767% to 99.94361%** against staging
`590a45c8ec`, reducing differing instruction words from **22 to 3** while
retaining all **1,064 bytes / 266 instructions**. It is not yet exact.
The opacity arguments now explicitly narrow the signed 16-bit fade value
to `u8`, consistent with the HUD draw interface. This recovers the retail
register allocation for the health-pip calculations and texture/conversion
bases without changing the unit's GC/1.3 profile.

Only the promoted bomb-slot index remains different: instructions 131,
132, and 144 use r24 where retail uses r22. The spacing multiply is already
shared exactly as in retail. A captured MWCC optimizer/register-allocation
trace reproduces the ordinary build and shows the index being colored
before r22 becomes available. Tested signedness, declaration and scope
changes, explicit index/spacing locals, shared scratch variables, texture
lookup forms, and inline loop helpers either retain the mismatch or add
other differences. These experiments do not establish a compiler limitation
or the historical source spelling; none is retained in source.

Only this function's bytes change (33 bytes). All other function bodies,
allocated data-section bytes and layouts, named symbol layouts, and resolved
relocations retain their baseline values. The unit remains `NonMatching`.

Validation: objdiff, the strict default `ninja` after
`python3 configure.py --matching`, and `ninja all_source` pass; each Ninja
invocation is limited to 30 seconds. Formatting checks cover the active TU
and its API header, with identical object bytes after formatting. Secondary
DOLs are unavailable in this checkout, so no regional manifest is promoted.


## September 8: head-display noise sampling

`headDisplayDraw` improves from **99.302086% to 99.677086%** on EN v1.0,
reducing 40 differing instruction words to **nine**. It retains the retail
**1,920 bytes / 480 instructions**; this is not a complete match.

Each noise-strip draw now obtains its two texture offsets in the call
arguments. MWCC evaluates them in the same order as the previous explicit
`noiseX` and `noiseY` assignments and passes the same samples to the same
arguments. Removing the named offset lifetimes restores retail's registers
for the model-table lookup, both opacity clamps, and most of the border.
The four random calls, their bounds, and the strip coordinates are preserved.

Only this function's instruction bytes change (41 bytes). All other
function bytes and objdiff scores, allocated data contents and layouts,
named symbol offsets, and resolved relocations are unchanged. Formatting
is committed separately and checked for an identical complete object.

Two residual words initialize the wave counters with `li` where retail
copies the zero scanline offset with `mr`. A fresh GC/1.3 backend capture
confirms that these explicit counters are outside late value numbering's
immediate-commoning range. Deriving the phases from the scanline index can
produce the copies, but the tested forms regress allocation elsewhere.
The other seven words concern the border's upper Y coordinate (`r27`
versus retail `r23`) and one cached texture-table address (`r23` versus
retail `r24`). No compiler flag, pragma, boundary, or API change is retained.

Regional source builds score 99.677086% in JP and 99.675% in EN rev1, PAL,
and PAL rev1. All five input DOL hashes are verified. The TU stays
`NonMatching`, so no whole-object progress-manifest claim is added.
Validation also includes the strict EN checksum target, `ninja all_source`,
and formatting checks on the TU and its API header.


## September 8: Arwing HUD exact

`drawArwingHud` now matches all **1,064 bytes / 266 instructions**,
closing the three-word bomb-index mismatch above. The health loop computes
`maxHealth >> 2` in its condition and `(health & 3) + 0x12` where it selects
the partial-health texture. Removing both corresponding locals reproduces
the retail register allocation; removing either alone does not. MWCC still
hoists both calculations, preserving the original instruction order and
single computations. The bomb loop itself needs no change.

The already-exact `hudDrawStatusBarsAndCounters` in this same TU provided
the useful source pattern: compute the pip limit in the loop condition and
the partial frame in its selection branch. This combined with the recovered
opacity narrowing resolves the mismatch under the unchanged GC/1.3 profile.

Objdiff reports **100%** for the function. Exact functions rise from
**110 to 111 / 118**, and exact code rises from 57,996 to
**59,060 / 75,188 bytes**. Only three bytes in `drawArwingHud` change;
all other 117 function bodies, allocated data bytes and layouts, named
symbol layouts, and resolved relocations remain unchanged. Anonymous
literal symbols are renumbered. All 9,960 assigned data bytes remain exact.
The complete TU remains `NonMatching` because other functions still differ.

Validation: `python3 tools/fnbytes.py 0 drawArwingHud --md5` reports the
identical target/current MD5 `04f2aec1ff494198dc7dcaca536305c5`.
After `python3 configure.py --matching`, strict default `ninja` and
`ninja all_source` pass with 30-second timeouts. Formatting checks cover
the active TU and its API header and preserve identical object bytes.
Secondary DOLs remain unavailable, so no regional manifest is promoted.


## September 8: pause-menu renderer residual audit

`pauseMenuDraw` remains **99.95618%**, with **8 differing instruction words
out of 1,141 / 4,564 bytes**, under the current GC/1.3 compiler and unchanged
TU flags. No source variant from this pass is retained. This rechecks the
older GC/2.0-era findings in `docs/priced_classes.md` section 34 against the
active compiler; it does not establish that a source match is impossible.

| Instruction indices | Remaining difference |
| --- | --- |
| 58, 132 | Map-page opacity uses r28 instead of r29 |
| 530, 622, 656, 727 | Confirmation-page opacity uses r31 instead of r29 |
| 1064, 1106 | Final token-prompt additions reverse the two source operands |

The live compiler trace reproduces the ordinary object and replays all 263
GPR color choices without a spill or high-degree removal. The two opacity
values are independent live ranges. Declaration order, scalar type changes,
branch-local variables, and inline hologram helpers do not recover the
retail allocation. Output-parameter helpers add stack traffic. The terminal
text updates still exhibit the documented fold: naming the measured height
or calculating the final position directly lets propagation remove the
preceding spacing update; compound assignment preserves that instruction
but retains the wrong operand order. Integer-width, cast, cursor-helper,
and measurement-helper variants did not improve the match.

The matching-object scan found related patterns in THP decoding,
`voxmaps_traceLine`, and `CameraModeStaffAnim_subdividePathAngles`, but none
has the same terminal two-term integer addition and following offset call.
Those are comparison leads, not evidence for pointer or wider coordinate
types here. The retail source-leak inventory yielded no pause-menu source.

Reproduce the current diagnostic capture with:

```sh
python3 tools/tricky_backend_trace.py --unit main/dlls/engine/0/0 \
    --function pauseMenuDraw --graph --instruction 58 --instruction 530 \
    --instruction 1064 --instruction 1106 --output build/flag_probe/pause_menu_draw
```

Target function MD5: `8a39b00d03abe18374ca86ea2726baae`.
Current function MD5: `fba550f4ccad52cdca4f9d4e713101c6`.
The entire original source object was restored byte-for-byte after probing.
Strict `ninja` and `ninja all_source` pass with 30-second timeouts, and
formatting checks pass for the active TU and its API header.


## September 8: head display exact

`headDisplayDraw` now matches all **1,920 bytes / 480 instructions** in
EN v1.0, improving from **99.677086% to 100%** and closing the nine-word
residual above. All five supported retail versions now report 100% for
this function.

The matching source derives the two shimmer phases from the four-pixel
scanline offset (`y * 3400` and `y * 2000`). MWCC emits the retail induction
counters and their initial zero copies. The fade value is captured from
its signed-halfword store expression:
`panelAlpha = gHeadDisplayFadeAlpha = clampedAlpha;`.
This preserves the desired alpha and dimension registers alongside the
derived counters.

Two shared integer temporaries retain their successive roles. `y` holds
the viewport Y selection, then the scanline offset, then the border's top
coordinate. `value` holds the clamped height and then each strip's Y
coordinate; its initial height comparison keeps the unsigned cast.
Splitting these lifetimes changes allocation. The old local `width` is
named `panelY`, reflecting its actual use as the panel's vertical origin.
No compiler setting, API declaration, or TU boundary changes.

The same-TU Arwing fix supplied the useful combined-expression approach;
the exact `ObjModel_RelocateAnimData` loop and `drawHudBox` supplied counter
and border examples. The final change preserves the sine-call order,
random samples, opacity calculations, and border geometry.

Regional comparison establishes one real viewport difference: EN v1.0
and JP load `GXRModeObj.xfbHeight` at offset 8; EN rev1 and both PAL builds
load `efbHeight` at offset 6. A version condition selects that field.
Every input DOL is verified against its configured retail SHA1. The
complete TU remains `NonMatching`, so no whole-object regional progress
manifest is promoted.

Only 20 instruction bytes change in the EN object and diagnostic source
link. The other 117 functions, allocated data bytes and layouts, named
symbol offsets, and resolved relocations are unchanged; anonymous literal
names are renumbered. Exact functions rise to **112 / 118**, exact code to
**60,980 / 75,188 bytes**, and all **9,960** assigned data bytes remain exact.
Target/current function MD5 is `5f90aa03deb9c029ec57996869a95603`.

Validation includes all five regional function comparisons, the strict
EN checksum target, and `ninja all_source` with 30-second build timeouts.
Formatting is committed separately and verified to preserve object bytes.


## September 8: pause-menu grid cell exact

`pauseMenuDrawGridCell` now matches all **1,012 bytes / 253 instructions**
in all five retail targets. Every input DOL was checked against its configured
SHA1. EN function MD5 is `76477c5a4a040f94730f162fbe0292a3`.

The remaining 16 instruction differences came from opacity types and lifetimes.
The cell opacity and faded opacity are signed shorts. Converting the fade
expression directly from double to short, reflecting the pulse with `^=`, and
multiplying it in place reproduce the retail lifetime. Computing the `/ 15`
factor at its use site and declaring the cell opacity before the faded opacity
restore the remaining register choices.

The short alpha contract extends through `pauseMenuDrawGrid` and its callers.
Their float-derived opacity locals also need direct conversion to short;
retaining an intermediate `s32` cast adds narrowing instructions. Removing the
redundant short casts in the relevant caller expressions preserves their
original conversion lifetimes. `gridAlpha` and `frontGridAlpha` now describe the
status page's two opacity stages, replacing misleading `ty1` / `ty2` names.

Across all five versions, full object comparisons show exactly **18 changed
instruction bytes**, all in `pauseMenuDrawGridCell`. Every other function,
allocated data section, named symbol offset, and relocation is unchanged.
Engine 0 now has **113 / 118 exact functions** and remains `NonMatching` as a TU;
no whole-object regional progress claim is made. Compiler profiles and confirmed
TU boundaries are unchanged.
