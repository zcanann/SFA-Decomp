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

## Reproducing the audit

Subsequent source fixes migrate `main/gameloop.c`, `main/gameloop_main.c`, and
`main/thp/n_options.c`: unsigned mask literals restore the immediate mask/XOR
instructions for cache alignment, game-bit inversion, and audio DMA buffer
selection. The final source is exact under both compilers; formatted objects
preserve the baseline sections, symbols, and relocations. This brings the
migration to 746 GC/1.3 units and 42 temporary GC/2.0 overrides.

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
