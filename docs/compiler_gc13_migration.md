# Game-code migration to GC/1.3

The migration preserves EN v1.0's per-unit match measures and source linkage.
The starting point is `6c4919813e`: 799 game-category units, 8,042 exact functions,
2,214,856 matched code bytes (87.85165%), and 982,099 matched data bytes.

## Compiler default migration

GC/1.3 is now the main game library default. An unchanged-source comparison
migrates 699 GC/2.0 units and `main/rand.c` from GC/1.2.5n. Explicit
`-char signed` in the game flags restores another 20 units: the compiler help
and compiled `(char)-1 < 0` controls confirm that GC/2.0 defaults to signed
plain char while GC/1.3 defaults to unsigned. All previously exact GC/1.3
controls also retain their match with the explicit setting.

This leaves 743 game units on GC/1.3, 45 temporary GC/2.0 overrides, ten older
math overrides, and the ProDG decompressor. The remaining overrides record
unfinished migration work; their current-source regressions are not compiler
provenance. SDK and third-party compiler profiles are outside this game-code
migration. The ProDG unit remains in the inventory.

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
