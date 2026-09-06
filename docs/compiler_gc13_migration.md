# Game-code migration to GC/1.3

The initial migration preserved EN v1.0's exact matched code/data/function counts
and source linkage. Changes to already-nonmatching functions' fuzzy scores are
recorded separately below. The later common-compiler experiment accepts source
regressions while retaining the strict retail checksum through NonMatching units.
The starting point is `6c4919813e`: 799 game-category units, 8,042 exact functions,
2,214,856 matched code bytes (87.85165%), and 982,099 matched data bytes.

## Compiler default migration

GC/1.3 became the main game library default. An unchanged-source comparison
migrates 699 GC/2.0 units and `main/rand.c` from GC/1.2.5n. Explicit
`-char signed` in the game flags restores another 20 units: the compiler help
and compiled `(char)-1 < 0` controls confirm that GC/2.0 defaults to signed
plain char while GC/1.3 defaults to unsigned. All previously exact GC/1.3
controls also retain their match with the explicit setting.

That initial migration left 743 game units on GC/1.3, 45 temporary GC/2.0 overrides, ten older
math overrides, and the ProDG decompressor. The remaining overrides record
unfinished migration work; their current-source regressions are not compiler
provenance. SDK and third-party compiler profiles were outside this initial
game-code migration. The ProDG unit remains in the inventory.

Eight older math candidates reject the legacy `-opt functions` setting under
GC/1.3. The two other math units compile but regress. They require separate
flag and source recovery; excluding them from the initial sweep would conceal
part of the remaining game-code work.

Every unit's report measures are unchanged after the default migration.
All 798 MWCC objects were compared against their original compiler builds.
Fifteen objects use different relocation representations: local section-base
symbols replace named data targets, or SDA21 relocation offsets select the
instruction rather than its immediate halfword. Resolving these targets gives
identical addresses; allocated bytes, named symbol locations, and literal-pool
locations are unchanged. The final linked DOL is byte-identical to retail.

Both `ninja` and `ninja all_source` pass with 30-second timeouts after
`python3 configure.py --matching`. Retail DOL SHA-1:
`e750e8e894707a52446118a4b84f1b58b677b269`.

## Source recovery and compiler discriminator

Subsequent source fixes migrate `main/gameloop.c`, `main/gameloop_main.c`, and
`main/thp/n_options.c`: unsigned mask literals restore the immediate mask/XOR
instructions for cache alignment, game-bit inversion, and audio DMA buffer
selection. The final source is exact under both compilers; formatted objects
preserve the baseline sections, symbols, and relocations. This brings the
migration to 746 GC/1.3 units and 42 temporary GC/2.0 overrides.

Slots 544 and 525 remove legacy casted calls in favor of their canonical
renderer/environment APIs. Slot 525 also corrects the shared sky flag query's
return type to `u8`, supported by the callee's one-bit return and the caller's
direct byte store. Its four adjacent consumers retain byte-identical objects.

Slot 239 (`pushable`) provides a compiler discriminator under its existing
whole-TU profile. Four casted calls become ordinary calls to
`pushable_updateCurtain`, `pushable_initMagicGem` (twice), and
`pushable_initWcPushBlock`. No types, data, or optimization flags change.

| Source/profile | Whole TU | update | init | updateMagicGem |
| --- | ---: | ---: | ---: | ---: |
| Original, GC/2.0 | 100% | 100% | 100% | 100% |
| Original, GC/1.3 | 99.4295% | 97.98883% | 96.829895% | 100% |
| Clean, GC/1.3 | 100% | 100% | 100% | 100% |
| Clean, GC/2.0 | 96.30786% | 64.13408% | 90.02577% | 100% |
| Clean, GC/2.0 with `-inline noauto` | 99.227844% | 100% | 100% | 91.78626% |

Retail and clean GC/1.3 retain the curtain and initialization calls while
inlining both `pushable_driftEyePos` operations. GC/2.0 inlines the curtain and
WC block initialization instead, expanding update from 716 to 972 bytes and
init from 1,552 to 1,704 bytes. Disabling automatic inlining restores those
calls but introduces two drift-eye helper calls that retail does not have.
GC/1.3 reproduces the complete retail call/inlining topology without the casts.
The accepted object differs from the original exact GC/2.0 object solely in
compiler metadata, with no anonymous-symbol renumbering.

This is evidence for GC/1.3 with the clean source and existing profile, not proof
of every TU's compiler or an exhaustive rejection of possible GC/2.0 settings.
The five-way control matrix, commands, identical-source hashes, full objects,
and retail call audit are in `build/gc13_migration/239/`.

Slot 429 (`SHthorntail`) independently shows the same pattern. Removing four
prototype-identical casts around its snoring and pending-event helpers gives
100% under GC/1.3 and 83.81869% under GC/2.0. GC/2.0 `-inline noauto` repairs
the four callers but introduces two `SHthorntail_stepPathControl` calls absent
from retail, leaving the TU at 96.55611%. The accepted GC/1.3 object differs
from the original exact object only in compiler metadata. Its canonical header
is unchanged; controls and call audits are in `build/gc13_migration/429/`.

Slot 468 (`WORLDAstero`) replaces eight trig function-pointer casts with direct
calls. The public sine/cosine approximation headers now declare `u16` angles,
matching their definitions and the retail parameter-home layout; three redundant
WORLDplanet argument masks disappear. Both object TUs preserve their exact
objects on GC/1.3 and GC/2.0. The shared API correction changes register
allocation in the already-nonmatching `headDisplayDraw`: GC/1.3 fuzzy matching
falls from 99.302086% to 98.6875%. Its instruction kinds/order, size, all data,
symbol offsets, and relocations remain unchanged, as do all exact match counts.
The full dependency audit is under `build/gc13_migration/468/review/`.
Subsequent independent Game UI work in `46cc0ca650` restores the earlier
99.302086% score with an explicit integer argument conversion while retaining
the corrected public prototype, and also matches `hudDrawButtons`.

## Subsequent clean-source migration

At `f200e5440e`, 786 game-category MWCC TUs use GC/1.3. Two GC/2.0 overrides
remain: engine 23 (save game) and object 625 (Drakor hoverpad). Ten exact math
TUs still use GC/1.2.5n, and `zlb` uses its custom ProDG build. These total 799
reported game units. The decompressor inherits the library's scratch compiler
label in objdiff; its actual build command, not that label, determines its compiler.

The current report has 8,045/8,213 exact game functions, 2,222,584 matched code
bytes (88.15818%) and 983,079 matched data bytes. No migration demotes an exact
function or changes source linkage. These totals also include independent staging
work: Game UI constant ownership, `hudDrawButtons`, and Tricky's `moveTricky`.
The glow-rendering correction below contributes one exact function and 1,640
matched code bytes. Every integrated cleanup passes the strict matching and
`all_source` builds; the retail DOL checksum above remains unchanged.

Additional clean-source compiler controls retain each TU's existing optimization
profile and the explicit signed-char setting:

| TU | Clean GC/1.3 | Clean GC/2.0 | GC/2.0 with noauto |
| --- | ---: | ---: | ---: |
| 237 collectible | 100% | 88.345695% | 95.85015% |
| 294 trigger | 100% | 84.800385% | See trigger controls |
| 364 imSnowClaw | 100% | 83.76298% | 93.34256% |
| 483 DIM_BossGut | 100% | 86.15749% | — |
| 578 DBstealerwo | 100% | 95.730446% | 99.30891% |
| 592 KT_Rex | 100% | 98.03416% | — |
| 597 SnowBike | 100% | 96.4732% | 97.93634% |
| 663 WCTempleBri | 100% | 81.4% | — |

These source forms remove function-pointer casts around ordinary helper calls.
Retail and GC/1.3 keep those calls while GC/2.0 inlines them. Where tested,
whole-TU `noauto` introduces other calls that retail inlines. Trigger additionally
names its integer sequence-range argument before passing it; this retains its
endpoint-sphere call without changing the smaller math helper inlining. Whole-TU
noauto trigger alternatives were investigated, but the accepted source keeps
its original auto profile and helper definitions. imSnowClaw also removes a
`long long` cast from an ordinary 32-bit flag clear: GC/1.3 emits the retail
sequence, while GC/2.0 shortens it by one instruction.

The final exact GC/1.3 objects preserve allocated bytes, symbol locations and
relocation targets. Most differ from their old exact objects only in compiler
metadata. SnowBike renumbers anonymous symbols at unchanged offsets. DBstealerwo
adds a local `.data` base alias; its six changed ADDR32 relocations resolve to the
same existing data addresses. Each local packet under `build/gc13_migration/<slot>/`
records whole-TU scores, actual commands, controls, layout and relocation audits.
These are source/profile discriminators, not an exhaustive exclusion of every
possible GC/2.0 spelling or setting.

Indexed loops also replace pointer walks in Baddie's nearby-object output,
TumbleWeedB's object searches, staff's slot cleanup, DIMExplosio's flame/debris
loops, wallcrawler's floor selection, SnowBike's two reverse trail-point loops,
and HighTop's weighted selections and shackle rendering. Cloudrunner owns its
three rider coordinates as an array and uses its own state in its sequence-free
callback. These indexed forms are exact under both compilers. Failed indexing
controls remain outside the source tree; proven pointer storage and lifetimes
are retained where indexing changes code generation.

Engine migrations remove casted calls in ObjSeq, modgfx and Hcurves_romcurve,
use ordinary angle comparisons in camera code, and preserve unsigned flag/DMA
operations at their actual widths. In `objprint_dolphin`, a chained color
assignment expresses one blue-channel read used by both red and green. These
changes preserve every existing per-unit match measure. Canonical object headers
replace legacy ownership, and affected shared consumer objects are compared
before and after; consumer formatting remains untouched.

`intersect_render` now uses the SDK GX prototypes directly. The alpha-threshold
getter returns the byte type of its existing storage, removing the forced integer
call signatures and pointer laundering at its callers. All 65 rendering functions
match, while the existing data score remains 384/620 bytes (61.935486%); the TU
retains its NonMatching status. Every other affected object is byte-identical.

`tex_dolphin` declares its two externally referenced `.sdata2` texture coordinates
as `const f32`. Retail stores 0.0 and 1.0 at these symbols; the TU only reads them.
This lets GC/1.3 retain the values across FIFO writes and makes `renderGlows`
100% exact. The same clean GC/2.0 function stays at 99.560974%. The complete TU
improves from 99.79206% to 99.849205%, with 31/33 functions exact. Only that
function's instructions change; all data, symbol locations and relocation targets
are preserved. Replacing the external constants with literals instead regresses
both compilers and is not retained.

## Remaining runtime investigation

Staging commit `03f9409456` subsequently moved all MWCC source units, including
SDK, runtime and the ten GC/1.2.5 math units, to the common GC/1.3 default.
Commit `e9c9955b16` marked regressed units NonMatching to preserve the retail
link, and `b1d79d13c1` restored signed-char runtime behavior and exact varargs
dispatch. Earlier counts in this document describe the staged cleanup before
that broader experiment; they are not the common-compiler baseline's results.
The user confirmed that the ten math units are included and the ProDG
decompressor is excluded. Its existing ProDG default is therefore retained.
No MWCC compiler-version overrides remain. Recovering source matches under
GC/1.3 remains unfinished work.

After those commits and restoration of the ProDG default, the generated build
has 1,002 GC/1.3 compilation commands and one ProDG command. The game category
has 8,000 exact functions, 2,221,024 matched code bytes (88.0963%), and 982,235
matched data bytes. Both build gates pass and the final DOL is byte-identical
to retail. These source-match counts include concurrent staging improvements;
they are not an isolated unchanged-source compiler comparison.

Removing the unsupported legacy `-opt functions` option allows all ten older
math candidates to compile on GC/1.3, but none preserves its exact match. The
option's GC/1.2.5n help describes function prologue/epilogue optimization. A
concrete retail example, `trigReduceQuadrantHighPrecision`, calls `_savefpr_30`
and `_restfpr_30` and spills its parameters; the tested GC/1.3 build emits local
paired-single saves/restores and keeps the pointer in a nonvolatile register.
Processor, debug-symbol and multiple-register-save controls have not reproduced
the retail frame. This is independent ABI evidence to investigate alongside
source recovery, rather than treating aggregate regression as compiler provenance.
The local controls are in `build/gc13_migration/math_drop_functions/` and
`build/gc13_migration/math_abi/`.

`configure.py`'s comments have been removed, retaining its executable shebang.
Its Python AST and generated Ninja/objdiff configurations are byte-neutral.

## Reproducing the audit

`tools/compiler_impact.py --all-mwcc-game --compiler GC/1.3 --output <new-directory>`
includes every game-category MWCC unit. Add `--extra-cflags '-char signed'` to
probe the explicit character setting. Failed compilations have absent candidate
objects and zero source-match credit in the report; they never fall back to the
baseline object. Commands, logs, source hashes, per-function scores, and object
comparisons are retained in the output manifest.

Initial local audit artifacts are under
`build/compiler_impact/full_gc13_6c4919813e/` and
`build/compiler_impact/full_gc13_signed_6c4919813e/`.
Earlier indexed-loop recovery is recorded in
[compiler_gc13_cleanup.md](compiler_gc13_cleanup.md).
