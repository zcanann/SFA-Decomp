# Engine compiler settings audit, September 8, 2026

The current evidence favors GC/1.3 and the existing engine-0 optimization
profile. It does **not** establish that its awkward matching source resembles
Rare's original source. In particular, the one-element offset array in
`cMenuSetItems` is a documented matching workaround, not recovered storage.
No tested compiler/profile combination eliminates the remaining mismatch.

Baseline: staging `e364ce1474b9b8ea095a75115b5ff57b8b75bc20`, EN v1.0.
Both the original and built DOL have SHA1
`e750e8e894707a52446118a4b84f1b58b677b269`.
Game source, compiler configuration, and splits are unchanged by this audit.

## Controlled experiment

Compiled the complete engine-0 TU 256 times: four source shapes, four
compilers, and sixteen profiles. Every compilation and objdiff report
succeeded. All changes were confined to scratch copies of the source.
The current Ninja invocation supplies includes, defines, language, and ABI
options. Candidate settings are appended before `-c`; `-opt display` records
the effective optimizer state. Each candidate is compared to the same retail
object with `objdiff-cli`, including all 118 functions.

The four source shapes change only `cMenuSetItems`:

| Shape | Change | GC/1.3 score | Bytes |
| --- | --- | ---: | ---: |
| `current` | Baseline, including offset-array workaround | 98.84106% | 1,208 |
| `indexed` | Replace inventory byte dereferences with typed HUD array indexing; remove manual offsets and the one-element array; preserve branches and other loops | 96.572845% | 1,192 |
| `typed_split` | Also use indexed clearing, Tricky, and texture loops, retaining separate staff and inventory branches | 84.25497% | 1,152 |
| `shared` | Previous readable implementation from `8dca115635`, including shared inventory filling | 66.21192% | 976 |

All four score best with GC/1.3's configured profile, with ties for some
individual-function alternatives. No alternative improves the whole TU over
its corresponding GC/1.3 configured source control.

The inventory-indexing change removes exactly four `add` instructions from
the mnemonic sequence; every remaining mnemonic stays in order. These are
the repeated HUD-base/item-count address additions at the enabled-byte stores
(baseline instruction indices 118, 122, 171, 175). Registers also change.
Thus ordinary indexed C already generates almost the entire retail sequence,
including derived induction counters. Explicit byte offsets are not necessary
to express those loops to this compiler.

The much larger regression in the previous readable rewrite therefore cannot
be attributed just to removing raw dereferences. It also changes loop source
forms and merges the staff/non-staff fill paths. The retail control flow and
the most concise behaviorally equivalent C are different matching targets.
This does not establish whether retail's repeated fill came from duplicated
source, a macro, or an inlined helper.

Each of the three alternative bodies passes 10,000 deterministic differential
cases against the current body, using `cmenu_set_items_probe.py`'s layouts,
fixtures, and ordered service-call recording, compiled with Clang ASan/UBSan.
These are host behavior checks with stubbed services, not retail execution.

## Compiler and optimization results

Same current source, same configured flags:

| Compiler | C-menu score | C-menu bytes | Exact functions / 118 | TU score |
| --- | ---: | ---: | ---: | ---: |
| GC/1.2.5n | 87.35099% | 1,228 | 25 | 86.815025% |
| GC/1.3 | 98.84106% | 1,208 | 116 | 99.97473% |
| GC/1.3.2 | 98.84106% | 1,208 | 113 | 99.82577% |
| GC/2.0 | 98.84106% | 1,208 | 113 | 99.82577% |

GC/1.3, 1.3.2, and 2.0 emit **identical raw function bytes** for the current
C-menu source, SHA256
`20b9926994fbbfc59b4f017fb1133bcad57c4661e6f6cb71fce84c88abc397d9`.
Changing between these compilers cannot repair this particular residual with
the tested source/profile. The same three-way equality holds for `indexed`
and `shared` under the configured profile.

The configured profile is level 4, speed, peephole off, scheduling off,
automatic inlining off, and signed plain char. The name `cflags_dll_noopt`
does **not** mean optimization is disabled.

GC/1.3 controls on the current source:

| Profile change | C-menu score | Exact functions / 118 |
| --- | ---: | ---: |
| None | 98.84106% | 116 |
| Level 0 | 47.407284% | 28 |
| Level 1 | 63.4404% | 34 |
| Level 2 | 75.07947% | 42 |
| Level 3 | 98.84106% | 107 |
| Enable peephole | 93.486755% | 42 |
| Enable scheduling | 77.02649% | 29 |
| Standard `-O4,p` (peephole and scheduling enabled) | 75.39073% | 22 |
| Optimize for space, retaining disabled peephole/scheduling | 86.695366% | 80 |
| Enable automatic inlining | 98.84106% | 115 |
| Disable copy/constant propagation | 97.48013% | 79 |
| Disable common-subexpression elimination | 89.13908% | 67 |
| Disable lifetime analysis | 96.17219% | 103 |
| Disable loop-invariant motion | 98.84106% | 104 |
| Disable strength reduction | 98.84106% | 101 |
| Disable dead-store elimination | 98.84106% | 96 |

The [complete matrix](engine_compiler_settings_audit.csv) includes these same
sixteen profiles on every compiler/source combination. These are controlled
alternatives, not an exhaustive search of every flag interaction, compiler
release, language mode, or possible original source form.

## Interpretation and next work

Aggregate scores are biased by source already tuned to the chosen compiler.
They alone cannot prove provenance. Stronger evidence for GC/1.3 comes from
the retail pointer reloads in `gameUiLoadResources` and selective helper-call
topology elsewhere; see [compiler controls](compiler_gc_versions.md) and
[engine-0 declaration recovery](engine_0_matching.md). This audit reproduces
the loader's 100% versus 98.66071% newer-compiler distinction.

The current C-menu has retail's 302 instruction mnemonics in order, with 55
differing instruction words. Earlier verified compiler traces reduce that
residual to register allocation and four commuted additions. The awkward
one-element array and offset locals manipulate the reconstructed compiler's
intermediate values; their existence is not evidence of original source.
The already-exact `pauseMenuDraw` is a concrete counterexample: replacing its
manual string offset with indexing recovered its last register mismatch.

Prioritize preserving retail branch structure while recovering indexed
accesses, true API argument widths, and local lifetimes. Treat a broad
readability rewrite and an isolated source-form experiment separately. Retain
whole-TU controls, but require independent evidence before claiming any of
the many existing exceptional profiles as original settings. This result is
specific to engine 0; it does not certify every engine TU or extend the game
compiler experiment into SDK, middleware, runtime, or ProDG code.

Local reproducibility artifacts are in ignored `build/engine-settings-audit/`:
`run.py` generates and measures the first three source shapes; `followup.py`
measures `typed_split`. Full source snapshots, per-build command JSON and
optimizer logs, objects, results JSON, compiler/source hashes in
`manifest.json`, and compiled behavior fixtures remain there. Objdiff reports
are under `build/flag_probe/proj_*`. The scripts use this baseline's Ninja
command and headers; they are local audit artifacts, not standalone tools.

Validation: `python3 configure.py --matching`, strict `ninja`, and
`ninja all_source` pass, with each Ninja build limited to 30 seconds.
No experimental source or compiler setting is installed.
