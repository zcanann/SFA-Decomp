# Priced residual classes — the banned-fix ledger

Classes of residual divergence whose only known cure is a construct banned by the hack purge
(see `docs/HACK_AUDIT.md`), or a compiler/toolchain behaviour with no source-level lever at all.
Every row below is BANKED: the mechanism is root-caused and the listed probes were measured.
Do not re-probe a row without a genuinely new lever; when a new function shows a class tell,
bank it here on sight instead of re-deriving.

Scores are per-function `fuzzy_match_percent` at tip `d3addebce3` (2026-08-01) unless dated.
The "price" of a class = the score a row gives up because the historical fix is banned
(or, for compiler-side classes, because no fix exists).

## Index of the measured laws

Sections 8-13 outgrew the "banned fix" framing: they are the campaign's measured model of what
MWCC's front end puts where, and of what a declaration costs. This index is the entry point.
Each row states the law in one line and says where its measurement lives; nothing is restated
here that the target section already says.

| Law | Where | The measurement behind it |
|---|---|---|
| **The mover.** Only one file-scope construct puts a pool word ahead of its first live loader: a `static const` aggregate of at most 8 bytes. A plain literal and a `static const` scalar land at the use; an external-linkage `const` lands at the declaration *and* emits a duplicate that the use loads. | §12, table in §11 | `main/rcp_dolphin` `.sdata2` 14.63 -> 100, `279_AppleOnTree` 90.62 -> 100, `701` 95.65 -> 100; `matched_data` +300, `complete_units` 906 -> 909, every function byte-identical. The spelling is the banned `SINGLE_ELEM_CONST_ARRAY`, and §12b measures four spellings of it emitting the same object byte for byte, so **the ban is on the shape, not the bracket**. Not landed; patch parked at `/private/tmp/A68_declared_consts.patch`. |
| **An aggregate places only its FIRST word for free.** Every mover word therefore needs its own four-byte symbol. | §12c | `701` with `{0.0f, 1.0f}` comes out `.sdata2` byte-identical, but element `[1]` compiles to `li rN,0` + SDA21 + `lfs f,4(rN)` where retail has one `lfs f,0(r2)`. |
| **Mint order is the source TEXT's order, not the code's.** The front end interns at the *use*, before the code generator runs, so a function can sit at 100.0 with a rotated pool. Within one expression the order is increasing expression-tree depth; an 8-byte literal defers to the next 8-aligned offset and the 4-byte hole it leaves is back-filled by the next 4-byte literal interned — if one follows, and otherwise it stays a zero word. | §10, §11 | The value-sequence oracle (`tools/pool_value_sequence.py`) at `e173a2c951`: 22 of 33 sub-100 sections have every function's value sequence *identical* to retail's, so their code already asks for the same constants in the same order. `704` and `trig`'s `fsin16Approx` reproduce the depth rule exactly; `704`'s `titleScreenShowCopyright` reproduces the deferral and the back-fill. The unfilled case is the leading `00000000` §12's survey finds at the hole in front of a double. |
| **`.bss` is the same question asked for free.** Declaration order is completely inert; layout is first-use order, shallowest sub-expression first. | §11, "`.bss` order is a second, free oracle" | A 36-cell declaration x use matrix (6 declaration permutations x 6 use permutations of three `.bss` arrays) depends only on the use order. `main/objlib` is the specimen where `.text`, `.bss` and `.sdata2` disagree about the same file's source order. |
| **`.sdata2` scores all-or-nothing per section, so a partial fix is worth strictly less than zero.** Removing five of a section's words rotates the whole pool. | §6b, §8; `docs/source_shape_levers.md` "a section scores ALL-OR-NOTHING" | `4461d0aa45`: `trig` `.sdata2` 100.0 -> 61.458 at *unchanged section size*, unit `matched_data` 192 -> 0. |
| **A value can carry its own sign.** Retail stores `-C` in the pool and adds; spelling the same polynomial as `A - C` mints words retail never had and emits `fnmsubs` for `fmadds`. | §6b (standing verdict) | 44 sites in `src/main/trig.c` rewritten `A + -C`: tree 99.811966 -> 99.815640, `.text` 95.926 -> 99.975, `.sdata2` 61.458 -> 93.750, all eight sin/cos functions back to their pre-purge figures to the digit, 0 REGRESSED. An operator deleted, no shape added. |
| **Restore is not declare.** If the pool's value *multiset* already matches and only the positions are wrong, you are looking at a deleted function, not a missing constant - MWCC interns plain literals across a TU, so restoring a body mints nothing new. | `docs/purge_campaign_audit.md`, "The recovery law" | `997e72e3e1`: `tricky` differed in zero words and 101 of 102 positions, `player` in zero words and 8 of 196; restoring seven deleted bodies took `matched_data` +1192 with both pools byte-identical to the carve. Where the TU *also* carries a one-element anchor minting the same value, delete the anchor (`558c86a421`). |
| **Price the opaque-extern crutch PER SYMBOL, not per unit**, and use the oracle before assuming one: a never-defined extern is a crutch only if retail's own split object defines the symbol; a carve-blob symbol is faithful. | §9, §9b, §10b | The `nm` oracle over retail's split objects. `engine/5` used to be the specimen here ("+176 data costs `renderSunAndMoon` 99.476 -> 98.214, a net tree loss") and is now the counter-example: 99.476 was bought by an extern nothing defined, and §18's cure takes the same +176 at 96.828 -> **98.840**. |
| **A crutch that blocks a sink is a CODE row wearing a pool row's clothes**, and the cure is to delete the single-def/single-use temp, not to hide the constant from it. A price is only valid against the baseline it was measured at. | §18 | `engine/5` `renderSunAndMoon` 96.828 -> 98.840 with `.sdata2` 100.0 (`5bf6287066`); `engine/68` `firstPersonDoControls` stays 100.0 with `.sdata2` byte-identical, +128 data (`ab2a7a3016`), a row §8 had priced at 128 B. `tools/fwdsub_scan.py` (35 sites, every curable one already at 100), `tools/crutch_sink_scan.py` (45 pins, 40 load-bearing, 5 not), `tools/ledger_baseline_audit.py`. |
| **The defining TU proposes, the reading TU disposes**, and a declaration can only move into a header that can NAME the type - type visibility, not the include, is the constraint. Extern arrays stay UNSIZED. | §13 | See §13; every rule there was established md5-identical over all 1013 source objects. |
| **A new `#include` costs nothing unless the header emits an object into an allocated section.** The only construct that does so unreferenced is a `static const` aggregate — the same shape §12 calls the only mover. `@NNN` renumbering and `.comment` growth are the two visible effects and neither is allocated. | §22 | 51 include-additions across 8 targets x 8 headers: 47 EQUAL, 4 RENUMBERED, **0 hard differences**. Eight synthetic probe headers isolate the boundary: only the `static const` array moves an allocated byte (`.sdata2` 80 -> 88, 64 of 426 `.text` relocations retarget). Nine header rows landed at 0 differ. |
| **The gate blind spots, and why md5-of-every-`.o` dominates.** Demotion blinds the DOL gate; `matched_code`/`matched_functions` are threshold counters; a pool rotation inside an already-NonMatching unit is free on every score axis. | `docs/purge_campaign_audit.md`, "Three sensor blind spots"; the docstring of `tools/score_delta_gate.py` | `4461d0aa45` moved neither counter and still took a function 99.981 -> 94.212; `5d467157cb`/`f5fe00213f`/`620b69dc2d` lost 144/60/16 B at `dfuzzy +0.000000`, zero regressions, zero demotions. The pool word-diff catches the third class; md5 of every `.o` catches all four *and* the score-neutral ones (class #70 renumbering), which no score can see. |
| **A window where `matched_code` rises and `matched_data` falls is not automatically a partial pool fix.** Bisect it: the two halves can be one commit, and the data half can be the priced cost of retiring a banned shape. | §25 | `3d9406bfe8` alone: `+1900` code / `−408` data / `+0.00043` fuzzy, reproduced to the digit by reverting its seven files and its `nodead` cflag. The `−408` is `tricky` `.sdata2` going 100.0 -> 88.67 (all-or-nothing) because five `UNCALLED_STATIC_FN` baseline rows were deleted; the two pools hold the same 408 bytes and the same 96-slot value sequence, permuted from offset `0x50`. |
| **The colouring cap is thin, not solid — and it has ONE key.** Declaration order is the only source key for the register assignment; statement order is the source key for emission ORDER, which is why the two sweepers' hit sets are disjoint. (This row used to state §26's two-key model; **§27 refuted it and the row was not updated for a day** — the correction is §27's, the sweep numbers below are still §26's.) Never prune a colouring row on equal length. | §26, corrected by §27 | **34 100 orderings** built and scored over all 128 attackable colouring rows (25 335 decl + 8 236 stmt + 529 by hand): **8 hits**, disjoint between the two axes, tree 99.81612 -> 99.816765 with `matched_code`/`matched_data`/`complete_units` unchanged. `tools/direct_build.py` took a probe from 83 s to 1.9 s by dropping ninja's global mutex. A K&R-style definition is invisible to both sweepers and was the eighth hit — **count a sweep's errors before believing its zero**. |
| **Statement order IS a source key for the register assignment — §27's "declaration order is the ONLY key" is refuted.** What decides whether a statement permutation moves a home is the run's SHAPE, not reuse: permuting structurally interchangeable statements (§27's control, and three synthetic regimes including a hard-packed one) never moves the band; give the run's members different shapes and it moves in 81 of 100 orders, and eight real frontier bodies move in 31 of 64. Both order axes are nevertheless MEASURED EXHAUSTED on the non-bijective frontier. | §31, refuting §27 | `tools/stmt_reuse_control.py` (band-signature discriminator + a declaration-order positive control, 50/50, + `--real`); **7 000 orderings and rewrites over the 67-row / 113 512 B population — 5 717 statement, 503 split, 381 operand, 399 declaration — 0 hits, 0 bytes.** 12 of the 67 rows have no reorderable run at all and 32 of 40 no split-enlarged neighbourhood: **count what a sweep skipped before believing its zero.** |
| **The reuse law holds on the FLOAT band too, and a declaration never touches `f0`-`f13`.** 9 float locals under the band -> 120/120 PERM; 24 over it -> 120/120 NONFUNC; **8 085 differing FPR operands, 0 volatile.** So #82's scratch half is not declaration-reachable. And because `perm_class_scan` abstracts only `r` names, every float colouring row in the tree is filed under its **OPERAND** bucket. | §31e | `tools/fpr_reuse_control.py`. FPR-ONLY census: **15 rows / 18 820 B, 13 of them volatile-only**. MWCC saves FPRs one instruction per register, so the save block names the SET and any whole-stream permutation check reports NOTPERM on every float colouring difference unless the spill lines are excluded — 30/30 NOTPERM becomes 30/30 PERM. |
| **The toolchain caps and the never-touch islands.** Bank on sight; do not re-probe — but §5's wording was audited in §28 and three of its entries were wrong. | §5, audited by §28 | Per-class detail in the memory topic files. |
| **149 of the 204 sub-100 rows are within THREE instruction-equivalents of exact, and they hold 59% of the code gap.** Rank the frontier by bytes, not by fuzzy: the largest rows are among the closest, and the whole-instruction bucket that §5 named without pricing is 21 rows / 19 032 B, attributed to the byte. | §29 | `Effect3_spawnObject` forfeits **7 796 B for 15 register operands**; `Scarab_update` **3 476 B for one instruction**. Eight rows worked off the byte ranking, **33 spellings, yield 0** — including the six-permutation proof that a parameter home is not reachable from the declaration list, and the `errorThreadFunc` row that **refutes §15's sufficiency test**: the slid instruction is one the source names and nine spellings are still inert. |
| **objdiff charges per OPERAND, and a displacement is not free.** 0.05 instruction-equivalents per differing register, **0.01 per differing immediate/displacement**, 1.00 per differing mnemonic or inserted instruction, **0.000 for a relocation name at an equal address**. And `matched_code` is a threshold counter, so the cheapest class in fuzzy forfeits exactly as many bytes as the dearest: `matched_code = total_code − Σ(sub-100 function sizes) − Σ(unscored sizes)`, to the byte. | §28 | The 205 sub-100 rows at `34c954cf62`: 92 pure-register rows give `loss/register` = 0.0500 with min equal to max; 8 pure-immediate rows give 0.0100; 110 rows fit the model exactly and **84 of them carry relocation-name differences weighted at 0.000** — the first positive control for class #70 being free. | 
| **A 100.0-everywhere unit that still will not flip fails at the LINK, not at the sha1, and the undefined-symbol list names the sibling TU it belongs to.** Read it before assuming a layout bug. | §23a | The census re-run from scratch at 920 `complete_units`: six members, four link and fail sha1 (one dead-strip, three `.sdata2`), two fail to link — `gametext` on a compiler-minted int->double pair the carve exports as `lbl_803DE6F0/F8`, `voice` on three `static`s that `vid_init.h`/`voice_conv.h` declare `extern`. `shader_dolphin` cured with two `force_active` arms: 920 -> 921. |
| **A multiset delta made entirely of `li` against `mr` is rematerialisation — an allocator decision wearing an operation's clothes.** Subtract it before working §14's operation bucket. | §23b | 17 of the 67 operation rows. `curves_advanceCollision` writes one preamble five times and our own build emits `mr` at four sites and `li` at the fifth, at retail's own register assignment. 45 lab compiles (9 spellings x 5 `-opt` settings) and 5 in-tree spellings of `Scarab_update` are all `li`. The only construct that defeats the fold is the banned 4-byte-aggregate respelling. Operation bucket worth opening: **50, not 67**. |
| **Every sub-100 code row is one of three kinds, and the kinds are decidable without reading any source.** Same opcode sequence, different registers = colouring. Same opcode multiset, different sequence = order. Different multiset = a different operation, which only the source text chooses. | §14 | `tools/a71_mnhist_scan.py` + the partition in §14 over all 213 sub-100 rows at `97746b6bd3`: **136 colouring / 10 order / 67 operation**, no fourth kind and no reloc-only row. |
| **The order bucket is not a third kind.** Every "order" row is one (at most two) instructions out of place inside a register permutation, so open one only when the slid instruction is the one the source text names. | §15 | All 10 order rows of §14 worked one at a time: mnemonic-sequence delta is 1 for eight of them and 2 for the other two. One paid (`renderShadows` 99.69954 -> 99.71494, the two squares of a magnitude named in retail's order); the nine that did not slid a parameter home, a rematerialised constant, a LICM hoist or a scheduler's delay-slot filler. |
| **The carve's symbol table is an oracle no score reads.** `.bss` order is free evidence of the source's use order (§11), and a name that contradicts the carve at the same offset is a naming defect that every gate is blind to. | §16 | `tools/bss_order_scan.py` over all 1013 source objects: **21** `.bss` sections ordered differently than the carve and **109** name divergences. Exactly ONE object says `lbl_` where the carve has a recovered name — `597.c`'s `lbl_803E5AE0`, already `sSnowBikePathPointParams` in `config/GSAE01/symbols.txt`: renaming it is byte-identical across all five sections, deleting it costs `matched_data` −396 and `matched_code` −1364. |
| **`.bss` allocates at the first use that FOLLOWS the definition** — and an object with no use after its definition is allocated at end of TU, in reverse definition order. Refines the `.bss` row above: definition order is inert only among definitions that all precede their uses. **A NonMatching unit is linked from the carve, so its `.bss` order is invisible; a Matching one is linked from our object, and a permuted `.bss` moves every DOL word that names it.** | §17 | A six-case probe battery under the live flag sets, then all 21 mis-ordered sections closed by moving definitions past their last use: `bss_order_scan` 21 -> 0, section contents identical over all 1013 objects, `complete_units` 910 -> 914. |
| **The sign-in-the-constant class is EMPTY outside `trig`.** The `A + -C` recovery does not generalise; nothing else in the tree holds a value at retail's opposite sign. | §14 | `tools/a71_signscan.py` over all 1050 units: **0** units hold a mirror-signed float, and the opcode partition finds **0** `fnmsubs`/`fnmadds`/`fsubs`-for-`fmadds` rows outside the three never-touch PS islands. |
| **A dead-stripped body is NOT cleanup fodder — DO NOT DELETE.** A `.text` surplus is 58% *inlining*, not fabrication; every gate in the tree is blind to its deletion. And class C is a linkage test, not a reference test. | §7b | `tools/dead_strip_census.py`: 86 fns / 12 348 B / 49 units, split 50 A / 27 B / 9 C; **excising exactly the stripped ranges reproduces the carve `.text` byte for byte in 34 of the 49 units**, with a 4-byte-shift negative control; **0 fabrications**, and 0 of the 36 class-B/C bodies carry zero relocations. |
| **A source screen has no power over a GLOBAL function; only the linker does.** Widening the uncalled-function census to any linkage is refused, measured — do not retry it. Widening it to the exempt roots for STATICS is free and was taken. | §7b; `tools/banned_shapes_check.py` | Whole tree, any linkage: **4969 rows, 60 really dead — 1.2% precision**, because a global's reference may be a relocation in data we have not decompiled. Whole tree, statics only: 26 -> **30 rows, 27 really dead**, `lost-old=0`, and the gating hit set is byte-identical at **103**. The 4 new rows are 3 SDK `asm` exception vectors plus `synth_jobs.c streamGainFromVolume`, the one uncalled function that nothing in the tree screened — dead code, LIVE POOL: deleting it costs 20 matched_data (§7). |
| **5 of the 915 `complete_units` are VACUOUS, and they are excluded from BOTH halves of the completion figure.** A unit with no `total_code`, no `total_data` and no `total_functions` had nothing compared, so its 100.0/complete is not a statement about correctness — and its carve can never gain content, so it can neither be earned nor lost. | `tools/vacuity_audit.py --family report` | `AX`, `MWCriticalSection_gc`, `OSExec`, `synth_sequence`, `synth_seq_queue`: all five carry a **zero-length** `.text` range in `splits.txt`, and all five carve objects are `.text` size 0. Three are stub `.c` files that emit nothing; two emit real code (0x1074 and 0x194) that never entered the link. Separately, the **38 `main/auto_*` units are selected by `total_data` present / `matched_data` absent / no `total_code`** (2 342 B) and **0 of them are inside `complete_units`**. Informative completion: **910 of 1000**. |

## 1. Target-unmerged dot-compare (purge-priced)

**Mechanism.** Our `-O4,p` peephole record-merges a shift/rotate with the following compare
across the statement boundary, emitting a dotted form (`rlwinm.`/`rlwimi.`/`srwi.` setting cr0
directly). Retail's compile of the same code did not merge: it keeps the plain shift plus a
separate `cmpwi`/`cmplwi`. Historical fix was `#pragma peephole off` around the function — banned.

**Tell.** LEN-1 (or LEN-0 with one substitution) rows where target shows `shift + cmpw/cmplwi`
and ours shows a single dotted `rlwinm./rlwimi./srwi.` feeding the same branch.

**Rows and standing price (gap to 100):**

| Function | Unit | Score | Gap |
|---|---|---|---|
| atan2fHighPrecision | main/acosf | 99.125 | 0.875 |
| atan2f | main/acosf | 98.456 | 1.544 |
| atan2f_fast | main/acosf | 98.250 | 1.750 |
| removeButtonObject (unroll-guard `srwi.`+`cmplwi`) | main/gameloop_buttonobj | 98.091 | 1.909 |
| mathSinCosf (family cousin: surplus target `fmr f1,f28` O0 arg copy-back) | main/sincosf | 98.750 | 1.250 |
| mathTanf (same copy-back, added 2026-08-03 by A97) | main/dolphin/MSL_C/.../math_8029454c | 97.297 | 2.703 |

Probed dead ends: switch-on-expression loses the r31 web; splitting via `|=` flips the base
instruction; five spellings of the sincosf copy-back are inert. Un-banning `#pragma peephole off`
for exactly these functions would be expected to recover roughly the summed 7.33 fn-points
(tree-level impact well under 0.01%).

## 2. DLL literal-pool provenance: @-anon vs lbl_ pool (purge-priced)

Retail DLL-origin TUs place f32/f64 literals differently from what our per-TU compile can mint.
Two verified sub-shapes (both re-verified at tip; note A57's original record claimed the
DBstealerwo target object "has no .sdata2 at all" — that is the TRICKY target; DBstealerwo's
target has its own 0xE8-byte .sdata2):

- **(a) Cross-TU shared pool.** `dlls/objects/196_Tricky/tricky.c`: the target object has NO
  .sdata2 section; its relocs name `lbl_803E23xx/24xx` literals living in an sdata2 region that
  `splits.txt` assigns to no unit (a shared pool gap). Our TU mints local `@NNN` anons instead.
  The only organic spelling that reproduces the reloc is a banned `extern const` `lbl_` load.
  Row: trickyUpdateCircling 99.983 (T==C sequence-identical; residual is reloc-only).
- **(b) Own-pool mint-order rotation.** The target TU's own .sdata2 holds the same values in a
  different order than our mint (mint order is compiler-internal: proven immune to source
  branch swaps, and not statement-lowering order — measure, don't model). Reconstructing the
  order via `lbl_`-named consts is banned. Rows: dbstealerworm_update 100.0 but unit
  matched_data 1232/1464 (578_DBstealerwo, first two pool words swapped); objects/332 unit
  matched_data 168/236; engine/24 unit matched_data 1904/1936 (0.0f rotated around the three
  named drift consts).

**Tell.** `ndiff.py` shows ONLY `RELOC lbl_803Exxxx` vs `RELOC @NNN` replace rows on an
otherwise sequence-identical function, and/or unit matched_data short by a rotated .sdata2.

**Scoring facts (proven by experiment, use freely):** pool `lbl_`-vs-`@NNN` NAMING is not
scored at an equal address (#70; asinf is 100.0 with a fully permuted, all-named pool);
what scores is the different address/offset — and an extern `lbl_` reloc against an own-pool
`@NNN` reloc *is* a different address, which is section 21's sub-case (iii) and is priced. Pool mint order is immune to source branch swaps.
The legal named-const reconnect — `const f32 name[1] = {v};` with `[0]` uses (scalar const
folds to an anon; extern-decl+def lands .sdata, wrong section) — is exactly score- and
matched_data-neutral (24.c `gBoneParticleDriftMax/Rebound/Min`, commit `d3addebce3`); it may
only be used when the naming law is satisfied, and it does NOT recover the rotation bytes.

## 3. Peephole-gated unroll base-chunking (purge-priced)

**Mechanism.** In an unrolled copy loop retail folds the stride into the load/store
displacements of up to 32 copies off ONE base register; with peephole ON our compile re-bases
(surplus `addi base,base,stride` per copy, chunk 8). Controller isolated to `-opt nopeephole`:
retail's TU had peephole off AND chunked at 32 — unreachable from source (25 source shapes
swept on the walkgroup row; `lwz`-fed opaque bases fold but wreck the prologue, 95.832).
TU-wide flag path CLOSED: flipping the Hcurves unit's flags costs the rest of the unit far
more than the row recovers (unit fn-score sum 6598.9 -> 5941.0 measured at B21 time).

**Rows:** Objfsa_UpdateWalkGroupPatches (Hcurves, ex-`walkgroupFindExitPointFn_800dc398`)
99.459; SaveGame_gplaySetObjGroupStatus (engine/23) 97.981 (retail folds the 3-byte stride of
the 4x-unrolled transient-bit scan into `lbz` displacements; 3 rewrites probed inert).

**Tell.** Target: single `mr`/base + arithmetic-progression displacements across unroll copies.
Ours: identical base plus one surplus `addi` per copy.

## 4. Large-constant-HI never CSE'd across a call (compiler-side; GC/2.0 AND GC/1.3)

**Mechanism.** MWCC never CSEs the `lis` half of a large constant across a call. Retail hoists
`lis rSAVED,K` once and emits `addi rD,rSAVED,lo` at each site; we re-materialise `lis;addi`
per site. Probe-proven with a minimal harness (plain literal, propagated locals, 3-use,
differing-LO, 0x1ffffff variants all re-materialise). The only hoisting spelling is a rolled
2-trip loop, but MWCC will not unroll a loop containing a call — in-tree that craters the row
(TryCastSpell 98.714 -> 94.44). No fix exists, banned or otherwise.

**Rows (the 0x200001 spawnObject quartet, player.c):** playerState30 99.173,
playerStateShootFireball 98.905, playerStateTryCastSpell 98.714, playerStateAimStaff 99.320.

**Tell.** Target `lis rS,K` into a saved reg + N x `addi rD,rS,lo` spanning `bl`/`bctrl`;
ours repeats the pair per site.

**ADDENDUM 2026-08-03 — the price above is DEAD; what survives of the class is a one-home
recolour.** The "no fix exists" verdict was priced against per-site literal rematerialisation,
and the enabling spelling has since landed: `ec4841324d` (2026-08-03) writes
`spawnFlags = PARTFXFLAG_200000;` once and passes `spawnFlags + PARTFXFLAG_1` at both spawn
sites in each of the four functions (`player.c` 3744/4049/4196/4435), so our compile hoists the
`lis` into a saved register just as retail does — no rolled loop, no banned shape. The rows
re-measure at `574310f3e0` (report `20dbc442e5`): playerState30 99.173 -> 99.960,
playerStateShootFireball 98.905 -> 99.947, playerStateTryCastSpell 98.714 -> 99.938,
playerStateAimStaff 99.320 -> 99.967. The residual in all four is `ndiff 3 / struc 0` — a
single-home recolour of the hoisted-`lis` web (target r30 vs ours r26 in AimStaff, r28 vs r26 in
State30 and ShootFireball, r30 vs r28 in TryCastSpell), i.e. §5's #108 class, not this one. A
fresh 5-position out-of-tree declaration sweep of `spawnFlags` on the narrowest member
(playerStateTryCastSpell, 4G band, the sub-cliff regime) came back completely flat at 3/0: the
web is propagation-fed and no named-local key reaches it. Per-row detail is in
`docs/band_width_worklist.md` (2026-08-03 rows tagged "STALE priced 4"). The mechanism paragraph
stands as a compiler fact — MWCC still never CSEs the `lis` across a call when each site spells
the literal — but the price it carried is retired: the source-level hoist was reachable all
along, through a named flags local rather than a loop.

## 4b. Retail-deleted redundant ext before a narrow store in a nopeephole TU (compiler-side)

**Mechanism.** The narrow-store extension rule (lane C9) is upheld: at `-opt nopeephole`,
`s16field += <int-typed expr>` always emits `extsh` before the `sth`. Retail's
`babyCloudRunner_turnTowardTarget` (objects/332, nopeephole TU proven by its siblings) shows
that ext deleted while every other instruction — including the surrounding
extend-at-use pattern — matches our nopeephole compile byte-for-byte. Recompiling the same
source with `-opt peephole` reproduces retail's store region exactly, but full peephole also
transforms the rest of the function (fn 98.86->93.52 on the TU flip; render 100->91.25,
sequenceCallback 100->94.22). Retail's pipeline applied the redundant-ext deletion without the
other peephole transforms — a pass subset no flag or (banned) pragma selects. No fix exists.

**Probe evidence (A59).** 34-case spelling fuzz + targeted probes over local type x callee
return type x statement structure x cast placement x lhs form (bitfield/union/pointer): the only
source-level elision paths are (a) an unpromoted-narrow-typed rhs per the C9 matrix, and
(b) a NEW deferred form — `s16 y = s16call();` leaves `y` unextended, a statement-level
`y >>= k` then shifts the RAW register and `field += y` elides — but under `-O4,p` (GC/2.0 and
GC/1.3.2) the shifted value is rematerialised (`srawi`+`extsh`) at every later use, never
materialised once (measured in-tree: 98.86 -> 89.20). GC/1.1/1.2.5 canonicalise eagerly
instead. The retail single-`srawi` + extend-at-use shape is unreachable from source; the
refcorpus has ZERO instances of `lha; srawi; add; sth`-without-ext across all 38,736
functions x 4 profiles.

**Rows:** babyCloudRunner_turnTowardTarget (objects/332) 98.864, gap 1.136. Sibling tell
banked by C9: dll_98_func03 (152) `sth`->`lha` store-forward weld 99.77.

**Tell.** A nopeephole unit whose ONLY diff is a surplus `extsh`/`extsb`/`clrlwi` immediately
before a narrow store, with the rhs int-typed and extend-at-use everywhere else matching.

## 5. Toolchain caps (source-unreachable; sight-list)

Closed classes with no reachable spelling — bank on sight, details in the memory topic files:

**Every entry below was re-measured in §28 (2026-08-03, A96). Three of them were wrong; the
corrected wording is here and the measurement is there. "Unreachable" and "score-free" are
different claims and this list used to conflate them.**

- **#108 GPR reg-perm** — still the dominant residual (**80 functions / 139 544 B of
  `matched_code`, 40.1% of the whole code gap**), but NOT "welded": §26 built 34 100 orderings
  over it and landed 8. Read §26/§27, not this line. r0-vs-r3 and the fcmpu operand pair are in
  the class; mixed-kind perms inert.
- **#82 FP-perm** at the same load count — uncontrollable except the sdata2-literal->plain
  crack (saved FPRs) and the cross-branch launder. **11 functions / 13 952 B exclusively**, and
  §27 measures why declaration sweeps come back empty on it: it is overwhelmingly a
  scratch-register class.
- **#67 frame/displacement — SCORED, and the old wording here was FALSE.** objdiff does not
  normalise an r1 displacement: it charges **0.01 instruction-equivalents per differing
  displacement operand**, five times cheaper than a register and a hundred times cheaper than a
  whole instruction, but not zero. That 0.01 is the entire reason all eight `trig` functions read
  99.97 instead of 100.0, and because `matched_code` is a threshold counter it costs the unit's
  **whole 2 608 bytes**. The class is UNREACHABLE (§28 measures eight parameter spellings, all
  worse); it is not free. Cheapest in fuzzy, dearest per byte of divergence.
- **#70 reloc-name-vs-@NNN at an EQUAL address**: score-neutral — and as of §28 that is
  MEASURED, not assumed: 84 of the 110 rows whose alignment is exact carry relocation-name
  differences (one row carries 174 of them) and every one of those rows fits the scoring model
  with the relocation weight at **exactly 0.000**. No sub-100 function anywhere in the tree has a
  residual made only of relocation names. It still blocks a Matching flip; prove with
  `tools/obj_equal.py`, never with `objdump -s` — and read section 21 first, the class splits
  three ways and only the equal-address one is free.
- Zero-weld `li`-vs-`mr`; dead-tail `b`-stubs; allocator remat (incl. unroll-tail-bound remat —
  respelling the bound flips the whole unroll shape, -4); invariant-address CSE weld;
  same-field-reload (our CSE forwards where retail reloads a field it also names — but see the
  asymmetry law: a raw SECOND read of a reloaded DISTINCT field is load-bearing);
  peephole branch-FOLD; array-subscript value-numbering; flow-sensitive const-prop;
  large-const misc (#110, #113, #126).
  **PRICED in §29c: this bullet owns the whole-instruction-only bucket, 21 rows / 19 032 B, and
  every one of the 21 is attributed there.** Within it, allocator remat is 7 300 B, the
  dot-compare family 1 680 B, the §24b inliner/const-prop rows 788 B, same-field-reload 1 040 B;
  and **branch-FOLD, array-subscript value-numbering, `#113` and `#126` own 0 B** — no row on the
  frontier has a residual exclusively theirs.
- **Foreign islands (never touch)**, with their scores and their CURRENT names re-read in §28 —
  two of the names here had gone stale and named nothing: `model.c`
  `modelApplyBoneTransform` (10.784, 464 B) + `modelBoneTransforms_next` (10.833, 72 B) (private
  ABI); the three `ObjModel_Transform*` PS-asm bodies (permanently unscored, 1 452 B);
  `zlbDecompress` (53.531, 2 352 B); `pi_videoinit` `videoInit` (99.512, 2 132 B); the carve gap
  in `render.o`, whose symbol is **`gap_03_80006C6C_text`** (0x130C B, no source counterpart, so
  it never appears in the report at all — grepping `gap_03` finds nothing in `src/`).
  **`fn_80007F78` no longer exists under that name: it is `modelRenderInterpolateRootTransform`
  in `main/render`, 96.682, 2 212 B, and it is one of the live 205 sub-100 rows.** A lane that
  greps the old name finds nothing and either drops the island or works it unaware.
  Island total: **6 488 B of `matched_code`, 1.9% of the code gap.**
- **`setGQR6` / `setGQR7` — no `mtgqr` intrinsic (priced at 50.000, measured 2026-08-03).**
  Retail is two instructions, `mtgqr N,r3` and `blr`; MWCC GC/2.0 exposes no intrinsic for the
  GQR write and inline `asm{}` is banned in `src/main`, so the body can only be empty or a lie.
  `6b383c0b7f` deleted `setGQR6`'s write-only `sGQR6Config` shadow — correctly, it was fabricated
  `.sbss` — which lands the section at the carve size at `matched_data` +0 and takes the function
  **70.000 -> 50.000** (`main/main/model` `.text` 92.276 -> 92.270). That is the whole price and it
  is not recoverable: any two-instruction body still misses `mtgqr`, so it scores the same 70.000
  the fabrication did. `setGQR7` **stays** — the `ObjModel_Transform*Vertices*` scalar
  reconstructions genuinely read the quantisation exponent back out of `sGQR7Config`, and
  hard-coding a scale reaches the exact section size only by replacing a runtime value with a lie.
  A window that flags `setGQR6` is reading this row, not a new regression.

## 6. Banned-shape removal in a demoted DLL TU (purge-priced, measured 2026-08-02)

The `tools/banned_shapes_check.py` sweep of `21b90aff9f` + `5b120c0545` removed 22 pool
anchors / volatile puns and 2 gotos across 15 DLL units, demoting each. Both commit messages
record `dfuzzy +0.000000 / ddata +0.000000 / 0 per-function regressions`; a full rebuild plus
`report.json` at each of the two shas measures otherwise, so the rows below are the real
standing price. That false zero is what `tools/score_delta_gate.py` now exists to prevent: the
purge DEMOTED every unit it touched, and a demoted unit is invisible to the forced-link/DOL gate,
while `matched_code` does not move when a unit's literal pool shrinks. Only a scan of per-function
`fuzzy_match_percent` **and** per-unit `matched_data` **and** the complete flags, over full
rebuilds at both endpoints, can see this class. The gate reproduces the rows below from the two
shas, and refuses to print a zero until a synthetic regression injected into real source has come
back RED.

Window `cd782d6179` -> `5b120c0545`: tree 99.81533 -> 99.81422, matched_data 1198129 ->
1197137 (-992), complete_units 877 -> 862. Every row below was 100.0 before the purge.

| Function | Unit | Score | Gap | Shape removed |
|---|---|---|---|---|
| worldobj_spawnGreatFoxEffects | objects/467 | 98.333 | 1.667 | `static const f32 s...[1] = {0.64f}` |
| renderClouds | engine/9 | 99.429 | 0.571 | `volatile f32 gCloudActionGlareQuadSize[2]` |
| mmpMoonRock_update | objects/386_MMP_moonroc | 99.516 | 0.484 | inner-loop early-exit `goto` |
| trickyBallMove | objects/245_SidekickBal | 99.637 | 0.363 | cross-arm `goto noFloorDepth` |
| SmallBasket_spawnContents | objects/260_SmallBasket | 99.908 | 0.092 | `const f32 g...[1]` x4 |

**Mechanisms, one per row.**

- **467.** The anchor's `[0]` read is a load from a user object, so it stays a source-placed
  statement and is emitted before the loop-invariant array-base hoist. A plain `0.64f` is
  const-folded, its load becomes an optimizer-placed invariant remat, and it lands AFTER
  `lis/addi gGreatFoxEffects` instead of before it. That 2-instruction move is the entire
  divergence; the pool itself still mints in retail's order. Probed inert or worse: hoisted
  assignment statement, initialiser-at-declaration, literal inlined with the local deleted,
  `while` form, swapped comma-init order, function-scope `effect`, all 24 local-decl
  permutations (all 98.333), explicit base-pointer local (96.667), block-scope `effect`
  initialiser (96.575).
- **engine/9.** Retail issues two back-to-back `lfs` of `gCloudActionGlareQuadSize` for the
  third quad vertex; without `volatile` our build value-numbers them into one. No non-volatile
  spelling forces a reload of a plain global that the compiler has already proven unchanged.
- **MMP_moonroc.** Seeding `spacingClear = 1` before the loop makes it live ACROSS the loop,
  costing one extra callee-saved GPR (`_savegpr_26` vs retail `_savegpr_27`); the `goto` wrote
  the flag on both exit paths and needed none. Probed: assign-on-both-paths 98.606,
  `spacingClear = i == count` after the loop 99.240, zero-seed + post-loop test 98.813 — the
  landed seed-and-break form is already the best structured spelling.
- **SidekickBal.** The `goto` tail-shared the else arm's `li r0,0`; the structured form
  duplicates it. Probed: hoisted zero-init 98.924, merged-condition else 97.128, ternary
  98.045 — again the landed form is the best.
- **SmallBasket.** #82 scratch-FPR perm (`fdivs f2,f31,f30` vs ours `f1`) that the anchor had
  pinned. Four spellings of the health-percent chain probed: two inert, two worse.

**Data price.** The anchors were real `.sdata2` atoms, so deleting them shortens and rotates
each unit's pool: 209_TumbleWeedB -148, 260_SmallBasket -120, 678_ARWSquadron -120,
213_Kaldachom -112, 701 -92, 300_Transporter -80, 373_DFropenode -76, 523_FireFly -76,
679_ARWProximit -64, 683_LGTProjecte -32. Not recoverable without the anchors; the
class-2 note applies (the legal `const f32 name[1]` reconnect needs a satisfied naming law,
and none of these symbols has one).

The `203 -72` row that stood here is RECOVERED and struck (`a21f332847`, 2026-08-02): that
unit's anchor was not deleted, it was demoted to a `const f32` SCALAR, and MWCC folds a read
of a const scalar into a fresh pool literal. The named object was emitted at its declaration
point and then never referenced, while the two reads minted a second copy of `0.1f` at the
end of the pool. Restoring the one-element array form — legal here because
`gDllCBDefaultAnimSpeed` is in `config/GSAE01/symbols.txt` — reconnects the reads, drops the
duplicate, and returns 203 to 328/328 data. **Scalar-vs-array is the tell to check before
pricing any row in this section: a folded scalar shows up as a named `.sdata2` object with
zero relocations against it and a duplicate of its value elsewhere in the pool.**

**Standing verdict.** All five rows are at their best structured spelling; do not re-probe
without a genuinely new lever. The DOL still holds because every affected unit was demoted.

## 6b. Same class in two `src/main` units: `trig` + `rcp_dolphin` (purge-priced, measured 2026-08-02)

`4461d0aa45` removed eight `const T x[1] = {V}` anchors — five sin/cos approximation
coefficients from `src/main/trig.c`, three distortion constants from `src/main/rcp_dolphin.c`,
demoting `rcp_dolphin`. The commit measured and stated `matched_data -272` (trig -192,
rcp_dolphin -80) at `matched_code +0` and `matched_functions +0`. All three of those figures
reproduce exactly. They are also the half of the price that a threshold counter can see:
`matched_code` and `matched_functions` only move when a function crosses 100.0, and every
`trig` function was already at 99.97-99.98, so eight of them lost fuzzy score without moving
either counter by a byte.

| Function | Before | After | Gap |
|---|---|---|---|
| fsin16HighPrecision | 99.981 | 94.212 | 5.769 |
| fcos16HighPrecision | 99.981 | 94.212 | 5.769 |
| fsin16Precise | 99.976 | 95.585 | 4.390 |
| fcos16Precise | 99.976 | 95.585 | 4.390 |
| fcos16 | 99.973 | 96.730 | 3.243 |
| fsin16 | 99.973 | 96.730 | 3.243 |
| fsin16Approx | 99.970 | 98.152 | 1.818 |
| fcos16Approx | 99.970 | 98.152 | 1.818 |

Tree fuzzy 99.81535 -> 99.811676, **-0.003674 — 3.3x the entire 22-instance section-6 window
(-0.00111) from a quarter as many instances.** `trig` `.text` 99.975 -> 95.926 and its `.sdata2`
100.0 -> 61.458 at unchanged section size, with unit `matched_data` 192 -> 0: removing five words
rotates the whole pool, so the section loses every byte rather than the five. `rcp_dolphin` keeps
`.text` at 100.0 and pays only `.sdata2` 100.0 -> 14.634 (-80), and its demotion is what keeps the
DOL green.

**Standing verdict — REFUTED for `trig` by `e173a2c951`, still standing for `rcp_dolphin`.**
The reading above assumed the anchors were load-bearing for the pool's ORDER. For `trig` they
were load-bearing for its VALUES: retail's `.sdata2` carries every Horner coefficient with the
sign already in the word (`bfc55555 5554c4d0`, `af9dd246`, `be927d83 c50b46da`), and the
post-purge source spelled the same polynomial as `A - C` with a positive `C`, so MWCC interned
eleven words retail never had and emitted `fnmsubs` where retail has `fmadds`. Writing `A + -C`
at the 44 sites — plain C, no shape added, an operator deleted — returns all eight functions to
the exact figures in the table above, `.text` 95.926 -> 99.975 and `.sdata2` 61.458 -> 93.750, and
the tree to 99.815640: `4461d0aa45`'s stated -0.003674 recovered to the digit, at 0 REGRESSED.
`rcp_dolphin` is a different problem — its value sequences already match retail's (section 10),
so its 14.634 is pure source-text order. Reproduce the original loss with
`python3 tools/score_delta_gate.py --commits fff7ee912c 86334e8343`.

The last 192 bytes of `trig` `.sdata2` are section 10's problem, not this one: retail interned
`fsin16Approx`'s cosine coefficients before its sine ones, and the case reorder that reproduces
it moves the emitted blocks and costs that function 94.667.

**RE-PRICED at `739030b8ce` (A77).** Both figures in the sentence above were measured against the
post-purge state and neither survives it. The `A + -C` recovery took `trig` `.sdata2` from 0 to
**93.75**, so the case reorder is worth **+12 bytes, not +192** — five words differ, all of them a
rotation of one group past the other (`0.99999f, -2.8707542e-10f, 1.3332733e-20f` ahead of
`0.000023945184f, -2.2078018e-15f`), and `tools/pool_value_sequence.py` reads DIFF 0, so the values
and the request order are already retail's. And the cost is now measured from **99.9697**, not
98.152: swapping the first two case arms of `fsin16Approx` gives `.sdata2` **93.75 -> 100.0** with
`fsin16Approx` **99.9697 -> 94.667**, unit `.text` 99.975464 -> 99.43865 — about **-14 bytes of
matched_code for +12 of matched_data**, and one function off 100.0. STILL DECLINED, and now for
the opposite reason: the gain shrank by 16x while the cost grew. Do not re-probe; the arms are
laid out in source order, not in case-value order, which was the only hypothesis that could have
made it free.

## Related recurring REGRESSION class (fixable — not priced, listed so windows get scanned)

Pool-const purge/retune commits historically gated on matched_code only and twice shipped
per-fn regressions (fcmpo operand-order flips: sky2_run via `zero < best.x` -> `best.x > zero`,
fixed in `2c32711828`; DIMCannon_updateAim sibling) and once shipped matched_data -4936
(engine/0 purge, retuned in `f596800ffa`). Delta-scan every merge window with per-fn fuzzy
AND matched_data; an fcmpo flip is repaired by restoring the retail operand order in source.
The `21b90aff9f`/`5b120c0545` pair (section 6) is the third instance and the first where the
regression was NOT retunable — a purge whose price is real still has to be measured and
banked, not reported as zero.

**The scan for this class is `tools/invcmp_scan.py`, and the tell is DEFINITION ORDER, not a
mirrored register pair** (measured 2026-08-03). It is tempting to look for our stream carrying
retail's compare with its two operands swapped and the branch inverted; a tree-wide scan for
exactly that shape over all 211 sub-100 functions reports **zero** hits, and re-injecting the
historic `8c611c5062` mutation (`zero < best.x` -> `best.x > zero`, which cost sky2_run
99.653 -> 99.497) does **not** make it fire. The registers are not swapped at all. MWCC lists the
first-evaluated operand first, so flipping the source operands moves *which value is loaded
first*: retail emits `lfs f1,<zero>` then `lfs f2,20(r1)` and compares `fcmpo cr0,f2,f1`, while
the flipped source loads the live value first and compares against a zero it re-materialises.
What changes is the definition order of the two operands, which is what `invcmp_scan.py` already
measures — so run that, not a mnemonic-and-register differ.

At `79e394cfda` the scan reports three functions and no live row: `sky2_run`'s two `fcmpo` sites
(the pinned 99.65298 residual — retail defines the LEFT operand LAST at both, a shape
`invcmp_scan.py`'s own docstring attributes to a call or a call-ordered `static inline` on the
right-hand side, and the plain operand flip does not reach it), plus `modelApplyBoneTransform`
and `zlbDecompress`, which are §5 never-touch islands.

## 7. Uncalled statics are NOT automatically fabricated (class REFUTED, 2026-08-02)

A census of our-only `.text` symbols (present in `build/GSAE01/src/**.o`, absent from the
retail carve) reports ~2.4 KB across 18 game units, and the shape is genuinely dangerous:
objdiff pairs our functions against RETAIL functions by name, so a body that is not in the
DOL has no pair and is never scored. It is therefore a free place to park fabricated code
that exists only to mint `.sdata2` literals in the order the carve wants. Two separate
classes hide under that one census number, and only one of them is a hack.

**Not the class — a plain static WITH call sites (820 B, 14 units).** MWCC inlines a plain
`static` at every call site and *still* emits the out-of-line body; mwld strips it at link.
`WM_LevelCon`, `LargeCrate`, `Landed_Arwi`, `502`, `DIMCannon`, `ARWSpeedStr`, `obj_movelib`,
`329`, `engine/73`, `446`, `501` and `WCTempleBri` are all this. It is the deliberate idiom
of `caf9ee4472` (WCTempleBri), where compiling the deform helper at its definition site is
what puts retail's bias doubles in the right order. Leave them.

**The real question — a static with NO call site (1616 B, 8 units).** Decided by one
experiment: *MWCC does not intern a file-scope const against a pool literal.* Declaring
`const f32 k[1] = {4.0f};` in `main/curves.c` alongside functions that already load `4.0f`
grew `.sdata2` from 0x44 to 0x64 — nine duplicated words. So a slot that live retail code
loads can never have been a declared const; it is a pool literal, minted on FIRST USE in text
order. Whenever such a slot sits AHEAD of the first live function that loads it, the only
possible minter is code that ran earlier and is not in the DOL — dead code that mwld stripped.

Every phantom-minted slot in all eight units is loaded by a live retail function:

| unit | uncalled statics | phantom-minted slots | shared with live code | delete cost |
|---|---|---|---|---|
| `main/curves.c` | 4 | 9 | 9 | -68 |
| `599_DR_EarthWar` | 2 | 14 | 14 | -192 |
| `625` | 2 | 6 | 6 | -104 |
| `700_Andross` | 1 | 9 | 9 | -268 |
| `main/shadow_dolphin.c` | 1 | 2 | 2 | -88 |
| `engine/20_Hcurves` | 1 | 1 | 1 | -72 |
| `Hcurves_romcurve` | 1 | 1 | 1 | -88 |
| `203` | 1 | 0 | 0 | 0 |

The sharpest single proofs: `curves.c` slot 0x18 holds `0.16666667f`, which no surviving
function computes with, yet it sits eighth in a pool whose ninth slot is the first live
function's first literal; and `599_DR_EarthWar` puts the compiler's own int-to-float bias
double at 0x08, ahead of `DR_EarthWarrior_feed`'s `4.32f` at 0x10 — a bias double cannot be
declared, so something converted an int before the first surviving function ran. Its second
uncalled helper accounts for slots 0x38-0x48 as `0.02, 2.0, 0.5, 0.75, 32768.0`, the exact
literal order of a five-statement body. **Deleting these seven reconstructions would cost 880
matched_data and buy nothing; they stay, and they are in the checker baseline.**

`203`'s `dll_CB_getStateHandler` was the one true positive: no call site, no minted slot, not
one data byte moved. Deleted in `a21f332847`.

**A ninth unit, outside the gate's reach (measured 2026-08-04).** `UNCALLED_STATIC_FN` gates on
the game roots only, so the table above is the *game-root* population, not the tree's. The
object-level census finds one more: `musyx/runtime/synth_jobs.c`'s `streamGainFromVolume`
(`0x30`, class B; the census reports it as `UNCALLED_STATIC_FN_SDK`, which never gates). It is
the sharpest specimen of the shape §7 describes, and its own commit `ee10dc4d9e` says so — it was
written to mint `{1/127, the unsigned-conversion bias}` ahead of `streamHandle`, which creates
`4096.0f` first and so cannot produce the retail order alone. It is load-bearing and it is
priced: removing it drops `.sdata2` from `0x14` to `0x10` and reorders it (ours becomes
`45800000 3c010204 43300000`, retail is `3c010204 00000000 43300000 … 45800000`), costing
**20 matched_data** and taking the unit's data from 80/80 to 60/80. `.text` alone would
*improve* — `0xa78` → the carve's `0xa48` — which is exactly why no code gate can see this row.
So "genuinely dead" is true of its call graph and false of its data: **dead code, live pool.**
It stays, and it is recorded here rather than in the checker baseline because the checker's
gating roots do not reach it.

**Gate.** `tools/banned_shapes_check.py` now carries `UNCALLED_STATIC_FN` — a source-only,
transitive census (a cluster reachable only from other uncalled statics is itself uncalled,
which is how `curveSpeedAt` is caught). `static inline` is out of class: an inline nothing
calls is never expanded and never emitted. A new hit is not automatically a hack — adjudicate
it against the unit's pool with the sharing test above before accepting or deleting it. The gate
sees game roots only; for the rest of the tree the instrument is
`tools/dead_strip_census.py census`, and `tools/source_coverage_audit.py` states what each
source-walking screen excludes by file type.

## 7b. The inlined-and-stripped class: DO NOT DELETE (measured 2026-08-03, re-measured 2026-08-03)

§7 refuted "an uncalled static is fabricated". This section is the standing **do-not-delete
registry entry** for the much larger class §7 only glimpsed, and it exists because the evidence
for it is *positive* — not an absence of evidence — and because no gate in the tree can see a
lane that deletes one of these bodies.

**The population.** `tools/dead_strip_census.py census`: **86 functions, 12 348 B, across 49
units** are in our objects and absent from the retail carve. They are three mechanisms, and only
the middle one is §7's:

| class | mechanism | count | bytes |
|---|---|---|---|
| **A** | **INLINED-AND-STRIPPED** — live code calls it, MWCC inlined every call site *and* emitted the out-of-line copy, mwld dropped the copy | **50** | **7 332** |
| B | UNCALLED STATIC (§7's class) | 27 | 2 228 |
| C | STRIPPED GLOBAL | 9 | 2 788 |

**Class A is 58% of it, and it is the normal fate of a small static helper at `-O4`.** The type
specimen is `446.c`'s `lavaball1be_applyDebrisGravity`: it is called at line 167 of its own file,
our object carries the body at `.text+0`, and **our object contains no `bl` to it anywhere** —
every call was inlined. Retail's compiler did the same, which is *why* the carve's `.text`
starts later. So a `.text` surplus is not evidence of invented code; for most of this population
it is evidence the compiler did its job.

**The positive proof.** `dead_strip_census.py excise` removes exactly the stripped byte ranges
from our `.text` and compares what is left with the carve's. **34 of the 49 units reproduce the
carve BYTE FOR BYTE.** That proves two things at once: the stripped bodies are the *whole* of the
difference, and every surviving instruction — including the inlined copies of the class-A
helpers — is retail's. A fabricated helper would have to inline into exactly retail's instruction
stream. All 34 are `fuzzy 100.0` / `complete: true`; all 15 that fail are sub-100 on an ordinary
residual elsewhere, which says nothing about their dead code either way. The negative control is
in the self-test: shifting every excision range by 4 B keeps the length right, the content wrong,
and drops the pass count — the test is not comparing sizes.

**Fabrications found: zero.** The only true-positive shape is a body that mints nothing and moves
no data byte (`203`'s `dll_CB_getStateHandler`, §7). Disassembled over their own byte ranges,
**0 of the 36 class-B/C bodies carry zero relocations** — every one mints pool literals or names
real data or callees.

**Class C is a LINKAGE test, not a reference test.** The classifier is literally
`cls = "C" if not is_static`, so "unreferenced global" was never measured and three of the nine
are demonstrably called in **compiled** sources: `__OSBootDol` at `OSExec.c:349`,
`__OSBootDolSimple` at `:333`, `__OSSetExecParams` at `:80` and `:220`. Eight sit in two units —
`OSExec.o` and `synth_seq_queue.o` — whose carve `.text` is **0**: the whole object never entered
the link, which is what took their callers with it. `OSExec.c` is settled independently:
`reference_projects/super_mario_strikers/src/Dolphin/os/OSExec.c` has the same 18 functions in the
same order.

The ninth is `__OSFPRInit`, and it is a different row: it lives in `OS.o`, a **live** unit whose
carve `.text` is `0x95c`, and nothing the build compiles calls it. Excising its `0x128` alone
reproduces `OS.o`'s carve byte for byte. It was recorded as called on the strength of
`bl __OSFPRInit` in `src/dolphin/os/__ppc_eabi_init.cpp`, which is **not compiled** —
`configure.py` builds the sibling `.c` — and whose `__init_hardware` contradicts retail's:
`.init:0x80003354` is `0x20` long and calls `__OSPSInit` and `__OSCacheInit` only, which our
compiled `Runtime.PPCEABI.H/__start.c` reproduces. Keep it: it is authentic SDK `OS.c` that this
game's link had no reference for, exactly as retail's link had none.

**Genuinely undecidable: 1.** `musyx/runtime/synth_seq_queue.c` — its carve `.text` is 0, so the
excision test compares 0 bytes with 0 and has **no power at all**, and the only reference project
carrying its two function names is an older copy of *this* project, which is circular. Leave it
alone rather than guess in either direction.

**The rule.** A dead-stripped body is **not** cleanup fodder. Before removing one: run
`dead_strip_census.py census`; if the row is class A it has live call sites and deleting it
changes what those sites inline; if it is class B, apply §7's pool-sharing test; if it is class C,
the question is whether the *unit* belongs in the link at all, not whether the body is dead. And
the deletion is invisible to every score: objdiff pairs by name, a body absent from the DOL has no
pair, `matched_code` never counted it, and the forced link never notices. Gate on
`tools/obj_equal.py --tree` and on this census, never on the score.

## Campaign-wide audit of the purge lane (2026-08-02)

`docs/purge_campaign_audit.md` rebuilds BOTH endpoints of all 42 purge-shaped commits and diffs
them with `tools/score_delta_gate.py`: 27 clean, 15 RED, gross -8168 B `matched_data` and
-0.032980 tree fuzzy, of which 5016 B were given back by the retunes already recorded here,
672 B by later pool work, and 2480 B still stand. Sections 6 and 6b cover 1192 B of that
residue. The remaining 1288 B is `72eec6655f`, which shipped with an empty commit body and is
priced nowhere; its open rows are listed in the audit and are recoverable.

The audit also adds a third sensor blind spot to the two this file already records: a pool
rotation inside an already-NonMatching unit loses `matched_data` at `dfuzzy +0.000000` with zero
per-function regressions and zero demotions, so neither the demotion tell nor the threshold
counters fire. `5d467157cb` -144, `f5fe00213f` -60, `620b69dc2d` -16.

## 8. `.sdata2` mint-order divergence with byte-identical code (measured 2026-08-02)

The residual `.sdata2` gaps left on the pool leads are one class, and it is not the
folded-scalar class of §7. Code is byte-identical; only the ORDER in which MWCC minted the
pool differs. Measured layout rule (this tree, GC/2.0):

1. `.sdata2` objects are laid out **sequentially in mint order**, 8-byte objects forced to
   8-alignment. The 4-byte hole that forcing leaves is **never backfilled** — 0 backfills
   across all 675 source objects that have a `.sdata2`.
2. Mint order is: file-scope objects at their **declaration point**, then per function in
   source order — its front-end literals in source order, then the backend's own
   int-to-float bias doubles.
3. A file-scope `const f32 X = V;` (`static` or not) is **folded at the read site**: the
   object is still emitted at its declaration point *and* a duplicate literal is minted at
   first use. Measured in `679_ARWProximit`: adding the three consts left all three duplicate
   literals in place, 18 words against retail's 16.
4. The only read that does not fold is an array subscript — i.e. the `SINGLE_ELEM_CONST_ARRAY`
   that `tools/banned_shapes_check.py` bans (75 baselined, regrowth is a gate failure).

**RETRACTION (same day).** The paragraph that stood here concluded that a displaced pool head is
unreachable because the only non-folding read is the banned 1-element pin. That is wrong, and
`015b98abbd` ("pool: recover the constants nine more units declare") had already refuted it.
The pin is adjudicated per instance, not forbidden outright: when the retail pool proves a slot
was a declared const, the instance is accepted into `tools/banned_shapes_baseline.txt` (75 -> 86
entries over that commit). Its reference-count spec is the adjudication test — a literal never
dedups into a file-scope const, so a slot's retail reference count says how many sites must
convert, and a value appearing twice in retail's pool but once in ours means the earlier copy is
a const and the later a literal. `679_ARWProximit`, listed below as priced, was recovered that
way. What survives from this section is the layout model above, the classifier in 8b, and the
three rows the const rule does not reach.

A second, hack-free route exists whenever the displaced values sit in a **duplicated block**
rather than in scattered scalars: extract that block as a `static` helper defined at the point
the pool wants the mint (the definition-site lens — `a4656c3766`, `144c1a9855`). Measured on
`679_ARWProximit` before the const version landed: two teardown helpers
(`arwproximit_destroyByHit` minting `0.0f, 100.0f`, then `arwproximit_detonate` minting
`127.0f`) placed ahead of `arwproximit_render` gave `.sdata2` 120/120 with all nine functions at
100.0, zero `banned_shapes_check` hits, and a clean `MatchingFor` flip (DOL sha1 unchanged).
Prefer it when the block is genuinely shared; it costs no baseline entry.

Sweep result: the §7 folded-scalar tell (a named `.sdata2` object with zero relocations) has
**17 instances tree-wide and every one is in a unit with `gap == 0`** — that lens is exhausted,
do not re-survey it.

| unit | gap | mechanism | probe result |
| --- | --- | --- | --- |
| `679_ARWProximit` | 64 | retail mints `0.0f, 100.0f, 127.0f` ahead of `arwproximit_render`'s `1.0f`; all three are read only from inside `arwproximit_update` | 1-element-array form gives **120/120 data, all 9 functions still 100.0** — and trips `banned_shapes_check` as regrowth. RECOVERED in `015b98abbd`; measured price before that was 64 B |
| `engine/68` | 128 | **not** a wrong constant: retail's `120.0f` at `.sdata2+0x44` is a plain literal of `firstPersonDoControls`, minted between `15360.0f` (0x40) and `16.0f` (0x48) | **RECOVERED at `ab2a7a3016` — see §18.** The 94.512 below is real and reproduces at today's baseline, but it prices the wrong variable: every probe here varied how the CONSTANT is spelled, and the sink needs a single-use TEMP. Delete the temp and the plain literal is free. Was: plain literal makes `.sdata2` byte-identical (64/192 -> **192/192**) but drops `firstPersonDoControls` 100.0 -> 94.512; tree 99.811676 -> 99.809730 |
| `engine/7` | 232 | one missing 4-byte mint cascades: retail mints a `1.0f` at 0x0c as a front-end literal of `lightningGetRemainingFraction`, after its `0.0f` and before its two bias doubles. Ours has only the `0.0f`, so 0x0c stays a hole, every later slot shifts 4, and a second hole opens at 0x84 | the missing `1.0f` emits no code in retail's `fn1` either — recovering it needs a phantom minter. DECLINE. **See the 2026-08-03 addendum below the table: the phantom minter is now proven to have existed, and the row awaits an owner call** |
| `237`, `704`, `model`/`modellight`, `213_Kaldachom`, `279_AppleOnTree`, `597`, `195_Player`, `intersect_render`, `main/object` | 88-784 | same class; several heads are led by a bias double, which cannot be declared at all | not probed individually — the class verdict covers them. **2026-08-03: `intersect_render` and `main/object` have since been probed and GATE-PASSED to proven-lost-body — see the batch addendum below** |

`engine/68` carries a second, separate defect worth a code lane: `firstPersonDoControls` only
holds 100.0 because it divides by `gCameraModeViewfinderStickScale`, an `extern const f32` that
**no translation unit defines**. Being an opaque global, it blocks `-opt propagation` from
sinking the single-use temp `spinI` past the `camera->anim.rotX` store; with any in-TU form of
the constant MWCC sinks it and ~14 instructions move. The extern is a crutch, not a constant.
Also measured there: file-scope `const f32` 94.512; function-local `static const f32` folds to a
literal (data 192/192, code 94.512); `const f32 X[1]` restores 100.0 but the object lands at the
declaration point (0x00) or at the start of the function's static run (0x20), never at 0x44.

**ADDENDUM 2026-08-03 — the `engine/7` DECLINE's basis is superseded by the mint law; the row
moves from "DECLINE — phantom minter" to an owner call.** The verdict above was written as a
sight-decline: "the missing `1.0f` emits no code in retail's `fn1` either", with the phantom
minter treated as a fabrication. Two facts measured since decide what that minter was
(fold probes re-run out-of-tree today against the tree's `7.c`; the baseline object is
byte-identical to `build/GSAE01/src/dlls/engine/7/7.o` in both `.text` and `.sdata2`):

1. **A literal folded at parse mints nothing.** `/ totalFrames * 1.0f`, `/ totalFrames / 1.0f`
   and a dead `f32 one = 1.0f;` inside `lightningGetRemainingFraction` each compile `.text`-
   AND `.sdata2`-identical to baseline — §8b's dead-store row and §11's dead-initialiser
   result, confirmed on this row's own slot. Minting requires the literal to survive to an
   emitted use.
2. **Every spelling that makes a `1.0f` survive in `fn1` changes `.text`** (probe set:
   multiplication fold, dead local, early-return restructure, accumulator restructure — the
   folding spellings mint nothing, the surviving ones move code), and `fn1` is byte-exact at
   100.0. Retail's slot `lbl_803DF1A4` (`.sdata2+0x0c`) carries **28 refs and not one is in
   `fn1`** — `fn1` spans `.text` 0x00-0x5c and the slot's first ref is 0x120, inside
   `lightningDrawStrand`. The slot is a ghost where `fn1` is concerned.

So no spelling of the surviving source reaches the slot, and §12's dichotomy — the only two
origins for a word ahead of its first live loader are a file-scope constant and a dead static
that `mwld` stripped — is decided by the reference-count spec: retail's pool holds ONE
`3f800000` against those 28 loads, and a literal never dedups into a declared const, so a const
origin would have left a second word. **By elimination, retail's TU carried a function body
ahead of `fn1` that parsed `0.0f, 1.0f` with surviving uses and was dead-stripped by `mwld`** —
the row's mechanism cell is thereby re-read: the 0x08/0x0c pair is that body's mint group, and
`fn1`'s own `0.0f` dedups into it. This is the identical structure `558c86a421` and
`997e72e3e1` adjudicate by byte-exactness ("the restored bodies take the section to byte-exact
100.0 against retail, which is direct evidence that retail's TU minted those literals at
exactly those points"). Probe, reproduced out-of-tree today: an uncalled `static` placed before
`fn1` minting `0.0f` then `1.0f` (a two-branch clamp) takes `.sdata2` **byte-identical to the
carve** (232/232, both holes closed; in-tree `matched_data` 984/1216 -> 1216/1216) with every
surviving function's bytes unchanged.

The honest counterweight, and why this is an owner call rather than an auto-land: unlike
`997e72e3e1`, **git has no deleted body here** — the seven player/tricky ghosts were restored
from history; this one would be written fresh. The body's *existence* is proven; its *content*
is conjectured — any two-literal body with surviving uses reproduces the pool, so the
byte-exact result certifies the mint structure, not the text. Landing it would enter
`tools/banned_shapes_baseline.txt` under §7's `UNCALLED_STATIC_FN` adjudication with exactly
that caveat on record.

The elimination is this row's only. It does NOT transfer to the class row below, and not to
`objects/332` (§2b's rotation row, §12d's cross-function list): there the moved words all have
live loaders and the divergence is a pure rotation — retail heads `0.0f`, bias, `1.0f` ahead of
our `0.01f`-led order while `babyCloudRunner_updateBurrowAnimation` holds 100.0 — so literal
arrangements inside the existing functions remain unrefuted (the probe set above was never run
there) and a stripped body is one candidate, not a forced conclusion. A row earns this upgrade
only when both halves are measured: the ghost slot inside a byte-exact function's mint run, and
the probe sweep showing every surviving spelling in that function moves `.text`.

**ADDENDUM 2026-08-03 (later) — the gate above, run as a batch over every remaining ORDER_ONLY
pool unit.** Out-of-tree probes only (each unit's own cflags; every baseline compile reproduced
the in-tree object byte-for-byte before any variant was scored; `.text` compared per function on
instruction bytes with `.sdata2` relocs resolved to slot values, so pool renumbering cannot fake
a diff). One front-end fact the reproductions forced, recorded so the next lane does not
re-derive it: inside one statement pair `if (x < K1) x = K2;`, MWCC mints K2 *before* K1 — the
assignment's literal precedes the compare's — so a phantom probe that needs K1-first must spell
K1 in an earlier plain-arithmetic statement. Verdicts:

- **`objects/332` — GATE PASSED; the paragraph above is superseded and the probe set has now
  been run there.** The divergence is not a pure rotation: retail's `[0.0f, pad, signed-bias,
  1.0f]` head precedes fn1's `[0.01, 0.07, 0.5]` run, and a lone `10.0f` sits between fn1's and
  `turnTowardTarget`'s runs; referrers exclude every function positioned at each mint point, and
  the head bias is undeclarable by construction. Probes on the byte-exact fn1: dead `0.0f` local
  inert; dead `(f32)` conversion inert (**a dead conversion is eliminated before codegen and
  mints no bias** — measured here); a *live* `f32 zero = 0.0f;` used at both clamp sites is
  propagation-folded back — pool AND `.text` both unchanged, so even the surviving-local
  spelling cannot re-order the mint. Three uncalled statics (one minting `0.0f`+signed
  conversion, one `1.0f`, one `10.0f` before `turnTowardTarget`) take `.sdata2` **byte-exact to
  the carve (68/68, hole at 0x04 included)** with every function's bytes unchanged. At least one
  code-bearing lost body is forced (the bias); the `1.0f`/`10.0f` slots are individually
  body-or-const undecidable. `turnTowardTarget`'s 98.86 residual is independent (its own slots
  agree). Owner call to land, same conjectural-text caveat as `engine/7`.
- **`main/object` — GATE PASSED.** Retail mints the *signed* bias at 0x28, between
  `Obj_TickModelColorFadeRecursive`'s run and `objApplyVelocity`'s `0.5f`, with referrers
  (`mapSetupPlayer`, `Obj_UpdateObject`, `loadCharacter`) all later; every function positioned
  there is byte-exact and none converts. A bias cannot be declared (§12), and the dead-conversion
  probe (in `objGetFlagsE5_2`) is inert — so the minter was code-bearing and stripped. Second
  ghost group: `loadCharacter`'s `10.0f, 255.0f` minted ahead of `modelInitBones`' `0.01/0.1`
  (body-or-const undecidable alone). Two uncalled statics (`(f32)v` signed; `v*10.0f` then
  255-clamp) reproduce the carve pool **byte-exact through 84 of 88 bytes, the remainder being
  the carve's linker 8-align tail word** (the tolerated PAD class, `tricky`/Transporter
  precedent), `.text` unchanged everywhere. `loadCharacter` at 99.76 is the unit's only
  non-exact fn and owns no disputed slot.
- **`track/intersect_render` — GATE PASSED, the cleanest specimen.** Retail mints `[-0.5f, 0.5f,
  pad, unsigned-bias]` at 0x54-0x60, between `doColorFilter` and `doDistortionFilter`; first
  live loader of the `-0.5f` is `drawSnowFlashOverlay` (function 57), of the bias
  `moonFxRenderCallback`; every function in the unit is byte-exact (unit `.text` 100.0). The
  bias forces a code-bearing minter; dead `-0.5f` local + dead unsigned conversion in
  `doColorFilter` are inert. ONE uncalled static (`f32 r = (f32)v; x = x * -0.5f;` then
  0.5-clamp) takes `.sdata2` **byte-exact to the carve, 236/236 in full**, `.text` unchanged.
  One lost body explains all three slots. (The unit's git-history removals are hack-purge
  artifacts, not this body — nothing to restore from history; text would be written fresh.)
- **`main/vecmath` — GATE PASSED, and the probe set also REFUTES the declaration origin, which
  the reference count alone could not.** The single head swap (retail `0.0f, 1.0f`; ours
  reversed) sits ahead of byte-exact `interpolate`, whose parse order is proven `1.0f`-first.
  Dead `0.0f` local inert; live `f32 result = 0.0f;` single-exit reaches the pool byte-exact but
  moves `interpolate` (§12's 87.08 row, reproduced); an uncalled static minting `0.0f`
  reproduces `.sdata2` byte-exact with zero `.text` change. The new elimination: a visible
  in-TU definition (`static const struct {f32;}` at head, all nine zero sites converted) fixes
  the head but **moves `mtx44_multSafe` and `mtxRotateByVec3s`** — the two sites that today ride
  the `lbl_803DE7C0` opaque-extern crutch — because a visible initializer lets propagation in
  (§9's mechanism, measured on this row); a definition late enough to stay opaque mints at the
  wrong end. So no const arrangement reaches both the pool and the code ⇒ lost body. Honest
  residue: the crutch survives under BOTH origins — neither explains what retail's `multSafe`
  actually spelled to get an opaque load of its own TU's word — so the row stays coupled to the
  §9 crutch story even after the upgrade; no cross-TU referrer of `803DE7C0` exists (checked),
  so a carve-boundary re-draw is not the answer either.
- **`objects/701` — gate run, elimination FAILS; stays the §12/§12b owner call.** The lone
  `0.0f` wanted at 0x0c sits *between* runs (after `androsshand_handleDamage`'s `120.0f`, before
  `AndrossHand_render`'s `1.0f`) — a legal declaration point — and BOTH origins reproduce
  byte-exactly (92/92, `.text` unchanged): an uncalled static minting `0.0f`, and the banned
  one-member-struct const with all eleven `update`/`init` zero sites read through it. Dead local
  inert; live literal in `render` fixes the pool but moves `render`. With ten refs the
  all-sites-const reading is strained but not refuted; no upgrade.
- **`main/rcp_dolphin` — gate run, elimination FAILS symmetrically; stays §12/§12b.** The three
  head slots are at the file-scope mint region (not inside any function's run — not a ghost in
  this section's sense), each with exactly ONE referrer (`Rcp_InitDistortionEffects`, the last
  function), so the reference-count spec cannot bite. §12b's aggregate spelling reproduces
  byte-exactly; an uncalled static minting `2.146452f, 2.520326f, 255.0f` before the first
  function ALSO reproduces **byte-exact, 80/80, `.text` unchanged** (measured today). Perfectly
  undecidable; the owner's shape decision, not a probe question.
- **`main/trig` — NOT GATED; premise fails.** The disputed five words are an intra-function
  permutation inside `fsin16Approx`'s own run (cos-poly consts minted before sin-poly, against
  sin-first use order) and the minting functions are NOT byte-exact: all eight fns hold ~99.97
  with one real diff each, the s16 frame slot at 10 vs 12 (`sth r0,10(r1)`) — the closed
  trig-cluster stack-slot wall. Pool order and frame slot are plausibly one source-shape
  unknown; stays §8b-priced (and MSL/GC-1.2.5n TU suspicion stands). No probe can certify a
  mint run whose owner's text is already wrong.
- **`dlls/engine/5`, `dlls/engine/68`, `dlls/engine/69` — gate MOOT; disputes closed in-tree.**
  All three `.sdata2` sections verified byte-identical to their carves today (176/176, 128/128,
  64/64): `engine/5` and `engine/68` via §18's crutch-sink deletions, `engine/69` via the
  git-verbatim `CameraModeTalk_resetSmoothing` restore plus the parse-order revert — that body
  was recovered, not invented, so no conjectural-text caveat attaches. `engine/69`'s residual
  50/25 item is `.text`-only (`CameraModeTalk_update` 99.894, the named-const late-load
  mechanism) and is §8b/§9 territory, not this gate's.

Net: the proven-lost-body roster is now `engine/7` + `332` + `main/object` +
`track/intersect_render` + `main/vecmath` (each: existence proven, text conjectured, landable
only under §7's `UNCALLED_STATIC_FN` adjudication); `701` and `rcp_dolphin` remain genuinely
two-origin; `trig` is walled behind its own `.text`; the three engine units are done. Nothing
was landed from this batch.

### 8b. The intra-function half of the class: statement order, and why it is still priced

Some gapped pools are not a cross-function order problem at all — every literal belongs to the
same function in the same sequence, and only the order *within* one function differs. Those look
like a free win (reorder statements, keep the code) and they are not. `engine/69`
(`CameraModeTalk_update`, gap 64, the whole `.sdata2`) is the clean specimen. Retail mints
`6.0, 0.2, 50.0, 25.0, 0.0625` but *loads* them `6.0, 0.2, 25.0, 50.0, 0.0625`: the `25.0f` is a
local assigned before the clamp (hoisted load), the `50.0f` is a literal inside the expression
(load at use). To mint `50.0f` first, the source needs a **live** `50.0f` ahead of the
`followTermB = 25.0f;` statement — and every live form moves its load:

| probe | `.sdata2` 0x2c/0x30 | `CameraModeTalk_update` |
| --- | --- | --- |
| tip | wrong order | **100.0** |
| `followDist = 50.0f;` temp, used in the expression | fixed | 98.773 |
| drop the `followTermB` temp, write `(50.0f + 25.0f * heightT)` | fixed | 99.033 |
| `followDist = 50.0f;` as a **dead** store, expression unchanged | unchanged | 99.907 |

The last row is the general fact worth keeping: **a dead store is eliminated before literal
minting and mints nothing**, so it is useless as well as a phantom minter. Every intra-function
row therefore has the same shape — the mint order is only reachable through a live use, and a
live use is exactly what moves the load. `engine/69` is PRICED 64 B; `578_DBstealerwo`,
`main/trig`, `609_DR_LaserCan`, `engine/19`, `429_SH_thorntai`, `202/mikaladon` are the same
sub-class.

Classifier for a new row (`.sdata2` all-or-nothing, so a partial pool fix scores zero): map each
pool slot to the function of its first reference on both sides. Same function sequence with
different first-reference offsets = intra-function (8b). Different function sequence = the
cross-function mint order of §8.

## 9. The opaque-extern crutch: the oracle, the tree-wide census, and the plain-literal price

§8 named one instance of this shape — `engine/68`'s `gCameraModeViewfinderStickScale`, an
`extern const f32` that no translation unit defines, whose only working role is to be opaque
enough to stop `-opt propagation`. `90b1a0f251` then closed five instances of it by defining the
constant in the unit that reads it. This section is the tree-wide sweep behind that class: the
oracle that tells a crutch from an honest cross-TU reference, what is left after `90b1a0f251`,
and a measured price for the plain-literal route so it is not tried again unpriced.

### The oracle: `nm` retail's own split object

The tree carries ~3040 `extern` object declarations. 371 name a symbol **no object in the tree
defines**; 211 of those are scalars in game code (`src/main`, `src/track`, `src/dlls`) that
`symbols.txt` places in `.sdata2`. Neither "nothing defines it" nor "it is in `symbols.txt`"
separates a crutch from an honest reference: the honest form is also undefined by us, and
`symbols.txt` carries no linkage information at all.

What separates them is the **retail split object for the same unit**:

- retail's `.o` also lists the symbol `U` → retail's own TU referenced it across a TU boundary,
  and our `extern` is a faithful reconstruction. `engine/75`'s eleven `gCamClimb*` are this
  case: retail's `75.o` UNDs every one of them.
- retail's `.o` **defines** it (`R`/`D` at an offset) → retail's TU minted that word itself and
  we did not. The `extern` is standing in for a mint. That is the crutch, and it is also a
  latent link failure, because only the carve is supplying the symbol.

The sweep is cheap and exhaustive, and its result is mostly a **retirement**: of the 211 rows,
**148 are honest** and should never be flagged by a later census. **71 were crutches** at
`8c2eb8998a`; `90b1a0f251` closed five (`render`, `589_BossDrakor`, and one slot each in
`engine/68`, `vecmath`, `engine/5`), leaving **66 in 10 units** at that tip:

| unit | crutches | pool words missing / extra | data at `90b1a0f251` |
| --- | --- | --- | --- |
| `dlls/engine/0/0` | 20 | 18 / 1 | 8972/9952 |
| `main/object` | 16 | 18 / 0 | 520/608 |
| `main/newshadows` | 12 | 13 / 0 | 16388/16668 |
| `main/model` | 7 | 9 / 1 | 496/612 |
| `dlls/objects/195_Player/player` | 3 | 0 / 0 | 10168/10168 |
| `main/objhits` | 2 | 2 / 0 | 8352/8440 |
| `main/vecmath` | 2 | 3 / 0 | 0/84 |
| `dlls/engine/5/5` | 2 | 1 / 0 | 600/776 |
| `dlls/engine/68/68` | 1 | 1 / 1 | 64/192 |
| `dlls/objects/704/704` | 1 | 0 / 1 | 720/884 |

The census reproduces the ELF-level pool shortfall from the other side — `engine/0`,
`main/object`, `main/newshadows` and `main/model` are the top rows of both — which is the useful
consequence: **most of the missing-word debt in those four units is this shape, not a naming gap.**

### The plain-literal route is priced everywhere (negative control)

Replacing every crutch read in a unit with the plain literal carried in retail's own pool word,
rebuilding only that object, all other gates unchanged. Measured at `8c2eb8998a`, before
`90b1a0f251` reworked five of these slots; the rows are kept because they are the control the
`const`-definition route should be judged against, and because nine of the ten recover nothing.

| unit | tree fuzzy | tree matched_data | worst function |
| --- | --- | --- | --- |
| `engine/0/0` | 99.81176 -> 99.79668 | 1201521 -> **1196585 (-4936)** | `pauseMenuDrawTaskHintPanel` 100.0 -> 71.028 |
| `main/newshadows` | -> 99.80027 | +0 | `evalNoisePlacements` 100.0 -> 87.057 |
| `main/model` | -> 99.80949 | +0 | `Model_GetVertexPosition` 100.0 -> 73.033 |
| `main/vecmath` | -> 99.81110 | +0 | `mtx44_multSafe` 100.0 -> 98.640 |
| `main/objhits` | -> 99.80982 | +0 | `ObjHits_CheckSkeletonPair` 99.247 -> 96.792 |
| `main/object` | -> 99.81141 | +0 | `modelInitBones` 100.0 -> 98.267 |
| `dlls/objects/704/704` | -> 99.81149 | +0 | `titleScreenDrawMenuFrame` 99.776 -> 99.488 |
| `589_BossDrakor` | -> 99.81158 | +0 | `bossdrakor_update` 99.854 -> 99.626 |
| `engine/68` | -> 99.80965 | 1201521 -> 1201649 (+128) | `firstPersonDoControls` 100.0 -> 94.512 |
| `engine/5/5` | -> 99.81089 | 1201521 -> 1201697 (+176) | `renderSunAndMoon` 99.476 -> 98.214 |

`engine/68` reproduces §8's figures exactly on an independent harness, which is the control for
the rest of the table. Three facts fall out:

1. **The all-or-nothing law holds in both directions.** Nine rows recover **zero** data even
   where the literal lands in the right slot, because one displaced word voids the section.
   `engine/0` is the reverse case and the one to be careful with: inserting 20 correct words
   into a section that was already scoring **destroyed 4936 bytes**. A partial pool fix is not
   merely worth 0, it can be worth far less than 0.
2. **Where the pool already matches byte-for-byte, the crutch is buying code and nothing else.**
   `player`, `704` and (before `90b1a0f251`) `BossDrakor` already emit the very word the extern
   points at; the extern's only effect is to force a separate opaque load instead of letting
   MWCC fold or CSE the literal. Removing it costs 0.06-0.29 on a function for no data at all,
   so those three rows are ban-reduction with no compensating recovery.
3. The plain literal is therefore the wrong instrument. `90b1a0f251`'s rule is the operative one:
   a named `.sdata2` symbol is materialised after the other operand and is not CSE'd, an interned
   literal is materialised before it and is, so the choice is a `.text` decision first.

### `engine/5`'s last word: reachable, and priced (measured at `90b1a0f251`)

`engine/5` is one slot from a byte-identical pool: retail's `0.55f`
(`gSkySunMoonRiseScale`) at `.sdata2+0x5c`, a front-end literal of `renderSunAndMoon` minted
between `28800.0f` (0x58) and `2.0f` (0x60). It cannot be reached by a definition, because a
file-scope object mints at its **declaration point** and 0x5c sits in the middle of the
function's own literal run — no declaration position exists that lands there. Writing the plain
literal does not reach it either: `scale` is single-use and `-opt propagation` sinks the whole
assignment past the `2.0f` and `400.0f` statements to its consumer, so `0.55f` mints two slots
late. Splitting the statement blocks the sink and is the only form that reaches the slot:

```c
scale = 0.55f * riseT;
scale = 1.0f - scale;
```

`.sdata2` then goes byte-identical, **600/776 -> 776/776**, tree 99.81176 -> 99.81078,
matched_data **1203257 -> 1203433 (+176)**, `renderSunAndMoon` 99.476 -> 98.018. The `-(x - 1.0f)`
spelling of the same split is worse (97.608), and a *named* second temp (`riseScale`) does not
work at all — it changes the liveness, the sink returns and the pool goes back to three wrong
words.

**OVERTURNED and LANDED at `5bf6287066` (A76); baseline note added at `739030b8ce` (A77).** Every
figure above is measured against **99.476**, and 99.476 was a score the undefined
`extern const f32 gSkySunMoonRiseScale` was buying. `73abfd6123` had to delete that extern because
no TU defined it and the unit could not link, which put the honest baseline at **96.828** — so the
"price" was never a price. The landed spelling is not a second temp and not a split statement: it
is **one variable doing both jobs**, clamped and then scaled in place, which deletes the single-use
temp the sink needs rather than trying to hide the constant from it. `renderSunAndMoon`
**96.827515 -> 98.839836**, `.sdata2` **95.454544 -> 100.0**, matched_data **+176**. The row is
closed on both axes at once. The general form is §18.

### Do not re-survey

The 148 honest rows are settled by the oracle; a later census should not re-flag them.
`main/render` is the one structurally unreachable row even after `90b1a0f251`: retail's
`.sdata2` there is 64 bytes of which 60 are `pad_11_803DE508_sdata2`, another TU's data, so the
section stays 15 words short (9040/9104) no matter how its own constant is spelled.


## 9b. Which crutch slots a declaration point can actually reach

Section 9 sized the crutch class and priced the plain-literal route. It left one question open,
and the whole remaining decision rests on it: for a given crutch, is retail's pool slot
**reachable from a declaration point** - so that the const route of `90b1a0f251` could in
principle put a word there - or is it a front-end literal minted in the middle of one function's
own run, where no declaration can land? Section 9 answered that for a single instance
(`engine/5`'s `0.55f` at 0x5c, measured mid-run) by trying it. This section answers it for all
of them, and it starts by correcting the model everyone has been reasoning from.

### The declaration point is NOT the head of the pool

The natural reading of the `objhits` experiment - two file-scope consts declared together at the
top emitted at 0x000 and 0x004 - is that declarations land at the head of `.sdata2` and the
minted literals follow. **That is wrong, and it is wrong in the direction that matters.** Three
`const f32` objects declared at three different points of `dlls/engine/68/68.c` - before the
first function, after `firstPersonPlaceCamera`, and after `firstPersonEnter` - emit at

    0x04    declared before the first function
    0x0c    declared after the first function
    0x60    declared after the third function

interleaved with the literal groups of the functions they sit between. The tree already contains
the same evidence from a landed commit: `90b1a0f251`'s `gVecMathAngleScaleInv`, declared at
`vecmath.c:218`, sits at `.sdata2` **0x30**, not at 0x00. A file-scope const emits **at its
declaration position in the translation unit**. The `objhits` pair landed at 0x000/0x004 only
because both were declared in the same place.

So the reachable set is not "the first word of the pool" (which would be three slots out of
fifty-one). It is **every slot that falls on a boundary between two functions' mint groups**.

### Reading the boundaries off retail's own object

Retail's split object gives the groups directly. Take its `.sdata2` symbols in offset order and
its `.text` relocations; each pool slot is referenced by a set of functions, and walking the
slots in order while holding a current owner - keep it if it still references this slot,
otherwise advance to the next function that does - segments the pool into contiguous mint groups
in `.text` order. A crutch is at a **declaration point** when the last non-crutch slot before it
and the first non-crutch slot after it are minted by *different* functions (or when it is at the
head or tail of the section); it is **mid-run** when both neighbours are minted by the same one.

The segmentation is calibrated against the three instances other lanes have already measured,
and it reproduces all three:

| slot | measured elsewhere | this model |
| --- | --- | --- |
| `engine/5` 0x5c `gSkySunMoonRiseScale` | section 9: front-end literal mid-`renderSunAndMoon` | mid-run |
| `engine/68` 0x44 `gCameraModeViewfinderStickScale` | section 8: no declaration point reaches it | mid-run |
| `704` 0x18 `lbl_803E2300` | section 9: plain literal recovers 0 | mid-run |

### The table

51 crutches in 9 units at `10b2cb641b` (`main/object`'s 16 were closed by `ca33bc08`).
**26 sit at a declaration point; 25 are mid-run.**

**`dlls/engine/0/0`** - 20 crutches, 9 at a declaration point, 11 mid-run

| slot | symbol | verdict | run it sits in |
| --- | --- | --- | --- |
| 0x0094 | `gGameUiAngleDivisor` | mid-run | inside `pauseMenuSetHoloTransform` |
| 0x00c0 | `hudElementOpacity` | mid-run | inside `drawViewFinderHud` |
| 0x00c4 | `lbl_803E1EC4` | mid-run | inside `drawViewFinderHud` |
| 0x00c8 | `gGameUiPi` | mid-run | inside `drawViewFinderHud` |
| 0x0130 | `lbl_803E1F30` | mid-run | inside `drawViewFinderHud` |
| 0x0134 | `lbl_803E1F34` | mid-run | inside `drawViewFinderHud` |
| 0x0170 | `gViewFinderBamToDeg` | mid-run | inside `drawViewFinderHud` |
| 0x01bc | `gHudElemOpacityFloor` | **declaration point** | `hudDrawCounter` / `pauseMenuDrawStatus` |
| 0x0210 | `lbl_803E2010` | mid-run | inside `hudDrawButtons` |
| 0x024c | `lbl_803E204C` | mid-run | inside `headDisplayDraw` |
| 0x029c | `lbl_803E209C` | mid-run | inside `pauseMenuDraw` |
| 0x02b8 | `lbl_803E20B8` | **declaration point** | `pauseMenuDrawStatusPage` / `pauseMenuDrawSideRails` |
| 0x0308 | `gPauseMenuGridCursorScale` | mid-run | inside `pauseMenuDrawGrid` |
| 0x0328 | `lbl_803E2128` | **declaration point** | `pauseMenuDrawGridCell` / `timeListDraw` |
| 0x0378 | `gPauseMenuPodiumRollAmplitude` | **declaration point** | `pauseMenuRunSubmenu` / `pauseMenuAnimateCarousel` |
| 0x037c | `gPauseMenuPodiumBaseY` | **declaration point** | `pauseMenuRunSubmenu` / `pauseMenuAnimateCarousel` |
| 0x0380 | `gPauseMenuPodiumBobAmplitude` | **declaration point** | `pauseMenuRunSubmenu` / `pauseMenuAnimateCarousel` |
| 0x038c | `gPauseMenuCommunicatorMaxScale` | **declaration point** | `pauseMenuAnimateCarousel` / `mapScreenDrawHud` |
| 0x0390 | `gPauseMenuRingScale` | **declaration point** | `pauseMenuAnimateCarousel` / `mapScreenDrawHud` |
| 0x0394 | `gPauseMenuRingUnselectedScale` | **declaration point** | `pauseMenuAnimateCarousel` / `mapScreenDrawHud` |

**`dlls/engine/5/5`** - 2 crutches, 1 at a declaration point, 1 mid-run

| slot | symbol | verdict | run it sits in |
| --- | --- | --- | --- |
| 0x0000 | `lbl_803DF058` | **declaration point** | `head of pool` / `skySetLightIndex` |
| 0x005c | `gSkySunMoonRiseScale` | mid-run | inside `renderSunAndMoon` |

**`dlls/engine/68/68`** - 1 crutches, 0 at a declaration point, 1 mid-run

| slot | symbol | verdict | run it sits in |
| --- | --- | --- | --- |
| 0x0044 | `gCameraModeViewfinderStickScale` | mid-run | inside `firstPersonDoControls` |

**`dlls/objects/195_Player/player`** - 3 crutches, 1 at a declaration point, 2 mid-run

| slot | symbol | verdict | run it sits in |
| --- | --- | --- | --- |
| 0x003c | `lbl_803E7EA4` | mid-run | inside `playerUpdateTail` |
| 0x0078 | `lbl_803E7EE0` | **declaration point** | `playerCastSpell` / `playerGetAimAngles` |
| 0x00ac | `lbl_803E7F14` | mid-run | inside `playerState3D` |

**`dlls/objects/704/704`** - 1 crutches, 0 at a declaration point, 1 mid-run

| slot | symbol | verdict | run it sits in |
| --- | --- | --- | --- |
| 0x0018 | `lbl_803E2300` | mid-run | inside `titleScreenDrawMenuFrame` |

**`main/model`** - 7 crutches, 7 at a declaration point, 0 mid-run

| slot | symbol | verdict | run it sits in |
| --- | --- | --- | --- |
| 0x0024 | `gModelDotClampMax` | **declaration point** | `modelAnimResetState` / `modelChainUpdateNodesPassive` |
| 0x0028 | `gModelDotClampMin` | **declaration point** | `modelAnimResetState` / `modelChainUpdateNodesPassive` |
| 0x0040 | `gModelPhaseWrapPeriod` | **declaration point** | `modelChainApplyDampingAndJitter` / `ObjModel_ApplyBlendChannels` |
| 0x0044 | `gModelDefaultOriginX` | **declaration point** | `modelChainApplyDampingAndJitter` / `ObjModel_ApplyBlendChannels` |
| 0x0048 | `gModelDefaultOriginY` | **declaration point** | `modelChainApplyDampingAndJitter` / `ObjModel_ApplyBlendChannels` |
| 0x004c | `gModelDefaultOriginZ` | **declaration point** | `modelChainApplyDampingAndJitter` / `ObjModel_ApplyBlendChannels` |
| 0x0050 | `gModelVertexScale` | **declaration point** | `modelChainApplyDampingAndJitter` / `ObjModel_ApplyBlendChannels` |

**`main/newshadows`** - 14 crutches, 5 at a declaration point, 9 mid-run

| slot | symbol | verdict | run it sits in |
| --- | --- | --- | --- |
| 0x0028 | `gNewShadowFovY` | **declaration point** | `renderObjectShadowTexture` / `renderShadows` |
| 0x0030 | `lbl_803DED38` | mid-run | inside `renderShadows` |
| 0x0038 | `lbl_803DED40` | mid-run | inside `renderShadows` |
| 0x0070 | `gNewShadowAspectWide` | mid-run | inside `renderShadows` |
| 0x0074 | `gNewShadowAspectNarrow` | mid-run | inside `renderShadows` |
| 0x00b8 | `lbl_803DEDC0` | mid-run | inside `createNewShadowDistortionTexture` |
| 0x00c8 | `lbl_803DEDD0` | **declaration point** | `createNewShadowDistortionTexture` / `evalNoisePlacements` |
| 0x00d8 | `lbl_803DEDE0` | mid-run | inside `newShadowsInitProceduralTextures` |
| 0x00e8 | `lbl_803DEDF0` | mid-run | inside `allocLotsOfTextures` |
| 0x00ec | `lbl_803DEDF4` | mid-run | inside `allocLotsOfTextures` |
| 0x00f4 | `lbl_803DEDFC` | mid-run | inside `allocLotsOfTextures` |
| 0x010c | `lbl_803DEE14` | **declaration point** | `allocLotsOfTextures` / `end of pool` |
| 0x0110 | `lbl_803DEE18` | **declaration point** | `allocLotsOfTextures` / `end of pool` |
| 0x0114 | `lbl_803DEE1C` | **declaration point** | `allocLotsOfTextures` / `end of pool` |

**`main/objhits`** - 2 crutches, 2 at a declaration point, 0 mid-run

| slot | symbol | verdict | run it sits in |
| --- | --- | --- | --- |
| 0x0000 | `gObjHitsScalarZero` | **declaration point** | `head of pool` / `ObjHits_InitWorkBuffers` |
| 0x0008 | `gObjHitsScalarOne` | **declaration point** | `ObjHits_InitWorkBuffers` / `ObjHits_CheckTrackContact` |

**`main/vecmath`** - 1 crutches, 1 at a declaration point, 0 mid-run

| slot | symbol | verdict | run it sits in |
| --- | --- | --- | --- |
| 0x0000 | `lbl_803DE7C0` | **declaration point** | `head of pool` / `interpolate` |

### What the table does and does not license

A **declaration point** verdict is necessary, not sufficient. It says the slot's *position* is
reachable; it says nothing about the *read*. A plain `const f32` read folds at `-O4`, and the
folded value mints a duplicate further down the pool - that is what the `objhits` probe showed,
and it is why the only spelling that has actually reached one of these slots is the
single-element const array. That pin is adjudicated per instance by the const lane
(section 8's retraction), and nothing here changes who decides it.

A **mid-run** verdict is a real closure. It says the word was minted by a literal written inside
that function's body, so the fix is in the function, not in any declaration - and 25 of the 51
crutches are in that class, including every crutch in `engine/68` and `704` and eleven of
`engine/0`'s twenty. Those rows should stop being counted as candidates for the const route.

Two further consequences worth recording. `main/model`'s seven crutches are **all** at
declaration points, in two adjacent runs (0x24-0x28 and 0x40-0x50) - the cleanest remaining unit
of the class,
and section 9 measured its plain-literal route at 0 recovered data, so nothing about it has been
tried at the right instrument yet. And `dlls/engine/0`'s nine reachable slots fall into four
adjacent runs (0x1bc, 0x2b8, 0x328, 0x378-0x380, 0x38c-0x394), which matters because section 9's
decisive negative there - twenty correct words inserted **lost 4936 bytes** - was measured on the
all-or-nothing literal route across the whole section, not on those runs.

## 10. The pool is a fossil of the source text, not of the code (measured 2026-08-03)

Sections 8, 8b and 9b all try to predict a `.sdata2` slot order from something the compiler
emits — the order functions appear in `.text`, the order a function's own run references its
words, the position of a declaration. Section 8's author already retracted the strongest claim,
and a later lane recorded that the model has "a hole" it could not name: `main/acosf` and
`track/intersect_render` sit at 75.410 and 91.525 with retail's mint groups in an order that is
a *permutation* of `.text` order, which no source edit appears able to produce.

There is a one-command test that closes it, and the answer is that the premise is wrong.

### The value-sequence oracle

For each function, walk its `.text` in address order and write down the **value** of every
`.sdata2` word it references, in that order. Do it for our object and for the retail carve, and
compare the two sequences. If they are equal, the two objects' code asks for exactly the same
constants in exactly the same order, and only the slot each constant lives in differs.

`tools/pool_value_sequence.py <src> [section]` does this, and `--all` runs it over every
sub-100 data section in the report. At `e173a2c951`:

| result | sections |
| --- | --- |
| every function's value sequence **identical** to retail's | **22** |
| some function's sequence differs | 11 |

`main/acosf` (8 functions, sequences of 6 to 36 words), `track/intersect_render` (31 functions),
`main/object`, `main/rcp_dolphin`, `main/shader_dolphin`, `engine/19`, `SmallBasket`,
`AppleOnTree`, `objlib` and thirteen more are all in the first row. **Their `.text` is already
saying, word for word, what retail's says.** The pool is nevertheless laid out differently.

So the slot order is not a function of the emitted code at all. It is fixed by the front end,
from the order the literals appear in the **source text**, before the code generator runs — and
the code generator is free to schedule the loads into any order it likes afterwards. That is why
a function can sit at 100.0 with a rotated pool, and why no amount of register, schedule or
statement-level work moves the section: there is nothing in the generated code left to fix.

The corollary is the useful part. **Run the oracle before spending any effort on a sub-100 data
section.** All-identical means the only remaining lever is the source *text* — which expression
was written where — and that is a decompilation question, not a codegen one. A differing
sequence means there is still a real value or a real reference to recover first, and that is
where the work belongs.

### Two sub-rules, both measured

Within one statement the intern order is neither left-to-right nor evaluation order; it is
**increasing expression-tree depth**. `704`'s

```c
gTitleScreenPulseAlpha = 127.0f * mathCosf(3.142f * (2.0f * t) / 100.0f) + 128.0f;
```

mints `128.0f, 127.0f, 3.142f, 2.0f` — the depths 1, 2, 5, 6 of that tree, with `100.0f` skipped
because an earlier statement already interned it. `trig`'s `fsin16Approx` mints
`0.99999f, -2.8707542e-10f, 1.3332733e-20f` from `x2 * (C2 * x2 + C1) + C0`, again shallowest
first. Both reproduce exactly.

An 8-byte literal is **deferred to the next 8-aligned offset, and the 4-byte hole it leaves is
back-filled by the next 4-byte literal interned.** `704`'s `titleScreenShowCopyright` references
`1.0f, 0.9999f, 80.0f, D(bias), 255.0f` in that order and lands them at
`0x00, 0x04, 0x08, 0x0c=255.0f, 0x10=D` — the double stepped over `0x0c` and `255.0f` took it.
This is the mechanism behind the "the displaced item is always a double or the word beside one"
observation, and behind an off-by-one-word section size: a pool whose doubles are interned one
slot earlier or later needs a pad where retail needed none.

### What this costs the terminal rows

`main/acosf` 248 B and `track/intersect_render` 236 B are terminal for this reason and no other:
their code is already correct, so the residual is purely which statement of which function was
written where in retail's `.c`. Nothing in this repository's normal toolkit reaches it. They
should be scored as **closed on the code axis and open only on the text axis**, and a lane that
wants them must go after the source text — not the registers.

## 10b. Pricing the opaque-extern crutch PER SYMBOL, not per unit

Section 9's control table prices the plain-literal route one unit at a time: replace every
crutch read in a unit, rebuild, measure. Nine of its ten rows recover nothing, and the section
concludes that the plain literal is the wrong instrument everywhere. `ca33bc08` had already
shown one unit escaping that verdict (`main/object`, 16 crutches, free once `modelInitBones`'s
`zero` temp was hoisted above the radius compare).

Priced **per symbol** the picture changes again: a unit's price is almost never spread across
its crutches, it is concentrated in two or three of them. Sweeping all 51 crutches individually
at `f64f18ca9f`, one symbol at a time, rebuilding only that object and regenerating the whole
report:

| unit | crutches | free | priced | the price |
| --- | --- | --- | --- | --- |
| `main/model` | 7 | **6** | 1 | `gModelVertexScale` -> `Model_GetVertexPosition` 100.0 -> 73.033 |
| `main/newshadows` | 14 | **3** | 11 | every one of the 11 moves `allocLotsOfTextures` |
| `dlls/engine/0/0` | 20 | **6** | 14 | `lbl_803E209C` alone costs **4936** bytes of matched_data |
| `dlls/objects/195_Player/player` | 3 | 0 | 3 | `lbl_803E7EE0`/`lbl_803E7F14` cost 8232 B of `.data` |
| `main/objhits` | 2 | 0 | 2 | ~100 read sites, `ObjHits_CheckSkeletonPair` |
| `main/vecmath` | 1 | 0 | 1 | `mtx44_multSafe` 100.0 -> 98.639 |
| `dlls/engine/5/5` | 2 | 0 | 2 | `renderSunAndMoon` |
| `dlls/engine/68/68` | 1 | 0 | 1 | `firstPersonDoControls` 100.0 -> 94.512 (+128 data) |
| `dlls/objects/704/704` | 1 | 0 | 1 | `titleScreenDrawMenuFrame` 99.776 -> 99.488 |

`b93a5f226d` landed the 15 free ones: tree fuzzy 99.811850 -> 99.811966, matched_data held,
0 REGRESSED, 2 IMPROVED, and the missing-word count in those three units halved (engine/0
18 -> 8, newshadows 13 -> 9, model 9 -> 3). **Section 9's per-unit table is an upper bound on
the price, not the price.** Any later census of this class should sweep one symbol at a time.

### Two distinct prices, and only one of them is a colouring

`ca33bc08`'s lesson - that the regression is the register colouring and an ordinary source move
fixes it - does not generalise. The 36 priced rows split cleanly:

- **Address-priced.** A self-owned `lbl_XXXXXXXX` extern resolves to retail's own address, so
  every reference through it is a *guaranteed* hit. Replace it with a literal and the reference
  moves to wherever our own pool happens to put that word. `704` is the pure case: with the
  crutch gone the instruction streams are identical (T=836, C=836, every region a reloc name),
  and the whole 0.288 is the address. **These rows are gated behind fixing the pool order
  first**, after which they become free by construction.
- **Schedule-priced.** A load of a named global is a memory reference the instruction scheduler
  will not move across; an interned `@NNN` literal is not, and MWCC hoists it. `engine/68`'s
  `firstPersonDoControls` is the clean instance: `spinI = (int)(15360.0f * ((f32)stickY /
  120.0f))` and the `camera->anim.rotX` statement after it swap wholesale, T=306 C=306.
  Swapping the two statements in the source, and splitting the division into its own temp, both
  reproduce **the identical 94.512** - the scheduler is deciding, not the text. No source move
  reaches these; they are as priced as section 9 says.

## 11. The front-end storage-order laws, and which text-axis rows they reach (measured 2026-08-03)

Sections 8, 8b and 10 model the `.sdata2` slot order and conclude that it is a fossil of the
source text. This section is the constructive half: what every file-scope construct actually
emits and where, which sub-100 rows that reaches, and a second oracle - `.bss` - that asks the
same question for free.

### What each construct emits, and where

Measured with single-TU probes under both live flag sets (`-O4,p -opt nopeephole,noschedule
-inline noauto` for `src/main`, `-O4,p -opt nopeephole,noschedule,nopropagation -inline auto`
for the DLLs); both sets agree.

| construct | what lands in `.sdata2` | what the read compiles to |
| --- | --- | --- |
| plain literal in an expression | a word where the expression is lowered | that word |
| `static const f32 X = V;` | **nothing** - folded, then dead-stripped | a duplicate literal at first use |
| `const f32 X = V;` (external linkage) | a word **at the declaration point** | a duplicate literal at first use; the object itself is never referenced |
| `static const` aggregate (struct or `[2]`), size <= 8 | a word at the declaration point | a real SDA21 load - no fold, no duplicate |
| any aggregate larger than 8 bytes | `.rodata`, never `.sdata2` | - |
| `static __inline` fn defined above the users | its literals intern **at the use site** | - |
| plain `static` fn defined above the users | its literals intern at the **definition**, but MWCC also emits the body into `.text` | - |

Two consequences. First, the only construct that places a word at a chosen position while
emitting zero instructions is the external-linkage scalar `const`: it is a pure **insertion**,
able to add a word between any two mint points and unable to move an existing one. Second, the
`static` function is not a usable phantom minter - the body is emitted, and
`banned_shapes_check.py` scans uncalled statics anyway.

Because nothing references an inserted const, `mwld` dead-strips it and the pool shortens again,
shifting every later SDA2 reference and breaking the DOL. The symbol must be listed in
`config/GSAE01/config.yml` `force_active`; the entries already there
(`lbl_803E06C4`, `gGcRobotPatrolZero`, `gDIMSnowHorn1ZeroOffset`, `lbl_803E3E44`, ...) are the
same class, and the tree already carries six of these consts in game code
(`gMikaBombZero`, `gDll76Zero`, `gDll77Zero`, ...).

### The insertion classifier, run over the whole frontier

`tools/pool_value_sequence.py --all` says which sections are open only on the text axis. A second
pass says which of those the const lever can actually close: diff the two slot sequences (size,
bytes) with an LCS and ask whether every opcode is `equal` or `insert`, and whether each inserted
word is referenced on retail's side. Over all 33 sub-100 data sections at `590dce7361`:

| row | verdict |
| --- | --- |
| `main/objlib` | one **unreferenced** zero word at slot 1. CLOSED - `.sdata2` 91.667 -> 100.0, +48 `matched_data` |
| `300_Transporter` | not a pool row at all - see below. RETIRE |
| `engine/5`, `engine/68` | INSERT-ONLY, but the inserted word is **referenced**, so it needs a real minter; these are exactly the priced crutch rows of section 9 |
| `main/render` | the insertion is the 60-byte `pad_11_803DE508_sdata2` blob - a splits-ownership question, not a text-axis one |
| the other 28 | need words **moved**; no file-scope construct moves a literal |

### `300_Transporter` is a carve-attribution artifact, not a gap

Both `.sdata2` sections carry `2**3` alignment (each holds a bias double). Our object's section is
0x4c bytes and `302`'s starts 8-aligned at `0x803E3EE8`, so `mwld` inserts four bytes of padding
that `splits.txt` attributes to Transporter's range; objdiff compares 76 bytes against 80 forever.
The DOL is byte-identical either way. The row should leave the frontier rather than be "fixed"
with a fabricated tail object.

### `.bss` order is a second, free oracle for the same question

Declaration order is **completely inert** - a 36-cell declaration x use matrix (all six
declaration permutations of three `.bss` arrays against all six use permutations) gives results
that depend only on the use order. The law is **first-use order**, where "use" is the front end's
and not the code generator's:

- uses in separate statements, or in separate functions: layout == first-use order exactly;
- three uses inside one expression `A[i] + B[i] + C[i]`: layout `C A B`, the shallowest
  sub-expression first. That is section 10's increasing-tree-depth rule, now confirmed on a
  second kind of storage.

So `.bss` asks the source-text question for the price of one `objdump -t`, and on a mover row it
corroborates the pool. `main/objlib` is the specimen: retail's `.bss` is `gObjectTypeList,
gObjectTypeIndices, gObjContactCallbacks`, ours is `gObjectTypeIndices, gObjectTypeList,
gObjContactCallbacks`, and the two spellings that do fix the order (`entry = gObjectTypeList;`
hoisted, and `entry = gObjectTypeList + (index = gObjectTypeIndices.offsets[group]);`) both lift
the list base's `lis`/`addi` above the `limit` load and break `objIsObjectType`. `.text`,
`.bss` and `.sdata2` therefore disagree about the source order of the same file - which is the
sharpest statement yet of what section 10 found, and it is why `main/objlib` stays `NonMatching`
even with a byte-identical `.sdata2`: flipping it links our `.bss` order and moves 33 DOL words.

### Phantom minters: the negative results

None of these interns anything (single-TU probes): a dead local initialiser `f32 t = 100.0f;`,
a dead store `t = x * 200.0f; t = 0.0f;`, an unused `(f32)n` conversion (no bias double), a
function-local `const f32 t = 300.0f;`, and `x * 500.0f * 0.0f` (folded). The one shape that does
mint a word it never loads is a dead **comparison** - `(x > 400.0f) ? x : x` emits `400.0f` - so
the front end interns when it lowers a compare, not when it folds arithmetic. It is not plausible
C and is recorded only to close the search.

## 12. The mover: which construct can put a pool word ahead of its first live loader (measured 2026-08-02)

Sections 10 and 11 established that `.sdata2` order is the source text's order, and that no
file-scope insertion can reorder two words that a function body already minted. This section
closes the remaining question: when retail's pool holds a word **ahead of the first function that
loads it**, what did the source do? Twenty-eight sub-100 data sections need exactly that.

### The survey

Of the 32 sub-100 data sections at `98445c52ec`, the value multisets already agree on 12
(`PURE-ORDER`); of the rest, most of the "missing" words are `00000000` at an offset that is the
alignment hole in front of an eight-byte double, so the bytes are already identical and only the
symbol granularity differs. The residue is genuinely an ordering problem, and in every case the
words that have to move are ones whose only loads are in a *later* function.

### The construct table, re-measured on `main/rcp_dolphin`

`Rcp_InitDistortionEffects` is the last function in the unit and its three constants are the
first three pool words; the section scores 14.63%. Four spellings, each one build:

| spelling | where the word lands | how it is loaded |
| --- | --- | --- |
| plain literal | at the use | direct SDA21 |
| `static const f32 x = V;` | at the use (folded, re-minted) | direct SDA21 |
| `const f32 x = V;` (external) | at the declaration **and** at the use | the *duplicate* is loaded |
| `static const` aggregate <= 8 B | at the declaration | direct SDA21, no duplicate |

Only the last one moves a word. A twelve-byte aggregate goes to `.rodata` instead, and a member
at a non-zero offset costs a base-register materialisation (`addi rN,r2,sym` + `lfs f,4(rN)`)
where retail has one `lfs`, so each word has to be its own symbol at offset zero. With three
such declarations placed before the first function, `main/rcp_dolphin`'s `.sdata2` goes
14.63% -> 100% and **every function stays byte-identical**; the same lever takes
`279_AppleOnTree` 90.62% -> 100% (three words: `1.0f` and the two halves of the fall-scale
blend) and `701` 95.65% -> 100% (one word: the zero `AndrossHand_update` and `AndrossHand_init`
share, declared between `AndrossHand_free` and `AndrossHand_render`). Measured together:
`matched_data` 1203317 -> 1203617, `complete_units` 906 -> 909, `fuzzy_match_percent` unchanged,
`main.dol` OK, and md5 of every `.o` identical outside the three units.

**That spelling is `const T name[1] = {V}`, which `tools/banned_shapes_check.py` gates as
`SINGLE_ELEM_CONST_ARRAY`.** So the lever exists, it is exact, and it is the banned one. Landing
these three rows is a decision for whoever owns that baseline; the measurement is recorded here so
the decision can be made on numbers.

### Why there is no third option

The two candidate origins for a word ahead of its first live loader are a file-scope constant and
a dead static that `mwld` stripped (`UNCALLED_STATIC_FN`, and see that check's own rationale).
Both are gated. Nothing else reaches: a declared constant is **never** interned against the
literal pool - declaring `static const f32 sCrTestOne[1] = {1.0f}` in `362_CRrockfall` while a
`1.0f` literal survives elsewhere in the unit emits **two** words, at `0x0008` and `0x000c`.

### What statement order inside a function can and cannot do

Section 11's text-axis model predicts that a literal moves with the statement that uses it. It
does, but only when the *use* moves - the front end interns at the use, not at an assignment the
optimiser will propagate away:

- `dlls/engine/24` wants `boneParticleEffect_update`'s `0.0f` first. Hoisting `zero = 0.0f;` from
  the loop preamble to the top of the function changes **nothing** - not one pool byte, not one
  `.text` byte - because the assignment is propagated and the load is re-materialised at the
  three `vtx.x = zero;` uses.
- `main/vecmath` wants `interpolate`'s `0.0f` ahead of its `1.0f`, with retail's code an exact
  match for the `if (t <= 1.0f) { ... } return 0.0f;` shape we already have. `f32 result = 0.0f;`
  plus a single exit reaches the pool order but costs the function 100 -> 87.08; `f32 result =
  0.0f;` keeping the early return is inert, confirming section 11's dead-initialiser result.

So an intra-function mover needs a genuinely different *use* order, which is a semantic
rewrite, not a reordering - and on these rows retail's own code shape rules it out.

### Rows that the lever cannot reach at all

`328_CFGuardian` and `362_CRrockfall` each need a compiler-generated **bias double** moved ahead
of an earlier function's literals (`CFGuardian`: `4330000080000000` before `cfguardian_flyAlongPath`'s
`200.0f`, whose code is byte-identical to retail; `CRrockfall`: `4330000000000000` ahead of
`crrockfall_findFloorY`, the unit's *first* function). A bias is minted by the code generator, so
no declaration can place it; these are dead-static rows or nothing. `main/shader_dolphin` needs
`0.0f` hoisted, and the file has 181 `0.0f` literals - every one would have to be rewritten for
the pool to hold a single word, which is not plausible source at any price.

### 12b. The spelling census: the ban is on the shape, not on the bracket (measured 2026-08-03)

Section 12 left one question open: its mover is `const T name[1] = {V}`, which
`tools/banned_shapes_check.py` gates as `SINGLE_ELEM_CONST_ARRAY`, so it asked whether some
other aggregate spelling reaches the same layout without tripping the checker. Seven spellings
were measured, one build each, on `701` -- the smallest specimen, one word (`0.0f`) wanted at
`.sdata2+0x0c` ahead of `AndrossHand_render`'s `1.0f`:

| spelling | word emitted at | how the use loads it | checker |
| --- | --- | --- | --- |
| plain literal | at the use | `lfs f,0(r2)` via SDA21 | silent |
| `static const f32 x = V;` | **nowhere** -- folded *and* dead-stripped, section size unchanged | literal at the use | silent |
| `const f32 x = V;` (external linkage) | declaration point **and** a duplicate at the use | the duplicate | silent |
| `static const f32 x[1] = {V};` | declaration point, offset 0 | `lfs f,0(r2)` via SDA21 | **gated** |
| `static const struct { f32 v; } x = {V};` | declaration point, offset 0 | `lfs f,0(r2)` via SDA21 | silent |
| `static const union { f32 f; } x = {V};` | declaration point, offset 0 | `lfs f,0(r2)` via SDA21 | silent |
| named one-member `struct` typedef | declaration point, offset 0 | `lfs f,0(r2)` via SDA21 | silent |

The four aggregate rows produce the same object file byte for byte. The checker does not see
three of them because `RE_ONE_ELEM` keys on the literal `[1]` subscript and `RE_LBL_UNION` only
on an `lbl_`-named union. Re-deriving section 12's three units with the struct spelling
reproduces its figures to the digit: `matched_data` 1203321 -> 1203621 (+300), `complete_units`
906 -> 909, `fuzzy_match_percent` 99.81558 unchanged, every section of `main/rcp_dolphin`,
`279_AppleOnTree` and `701` at 100.0, `all_source` EXIT=0 -- and `banned_shapes_check` at
102 hits / 83 baseline / 19 regrowth, **unchanged, adding zero**.

**Verdict: there is no clean spelling, and none of these was landed.** A one-member struct or
union read only through that member is the banned construct in different syntax: its only
function is to stop MWCC folding a scalar `const`, which is exactly what the check's own
rationale says the one-element array is for. Passing the gate on a regex technicality is not a
recovery, and no 2002 developer writing "a named constant zero" reaches for a struct wrapper.
The verified array-spelling patch stays parked at `/private/tmp/A68_declared_consts.patch`; the
decision to accept any of these forms into `tools/banned_shapes_baseline.txt` belongs to whoever
owns that baseline, and it is now a decision about a shape rather than about a spelling.

### 12c. Why a genuine multi-word aggregate cannot stand in for it

The one honest aggregate is a table whose words are all real and adjacent in retail's pool, so
the obvious escape is a two-element array with two honestly-named words. It is closed on the
code side, not on the naming side. Measured on `701` with
`static const f32 sAndrossHandProgressRange[2] = {0.0f, 1.0f};` covering both the zeros and the
ones: `.sdata2` comes out **byte-identical** -- the pair lands at 0x0c with both words in
retail's order -- but `.text` breaks at every read of element `[1]`, which compiles to

    li      r8,0            ; R_PPC_EMB_SDA21 sAndrossHandProgressRange
    lfs     f1,4(r8)

where retail has the single `lfs f1,0(r2)` against its own symbol. Retail loads every one of
these words at offset zero from its own symbol, so a member at offset 4 is the wrong shape by
construction. Section 12 predicted this cost as `addi rN,r2,sym`; the emitted form is the base
materialised into a GPR by the SDA21 relocation, and the conclusion is the stronger one: **an
aggregate places only its first word for free**, so every mover word needs its own four-byte
symbol, and a four-byte aggregate holding one `f32` is the banned shape whatever brackets or
braces it wears.

That also settles the three rows individually, because each needs at least one *lone* word that
no honest pair can carry: `main/rcp_dolphin` wants `2.146452f, 2.520326f, 255.0f` and a
three-word array is twelve bytes, which goes to `.rodata`; `279_AppleOnTree` wants a lone `1.0f`
ahead of the fall-scale pair `{0.25f, 0.75f}`; `701` wants a lone `0.0f`, and the only pair that
would cover it is `{0.0f, 1.0f}`, whose members are a move start time, four velocity components,
a render scale and a progress limit -- no honest name spans them.

### 12d. The intra-function frontier is complete, and every row on it is adjudicated

Section 8b's classifier -- map each pool slot to the function of its first reference on both
sides -- was applied to all 31 sub-100 data sections at `f63cb3dc08`, extending its list of six
named specimens to the whole frontier. The 31 rows split 18 intra-function against 13
cross-function:

- **intra-function (8b), 15 with a single owning function**: `main/vecmath`
  (`interpolate`), `main/rcp_dolphin` (`Rcp_InitDistortionEffects`), `dlls/engine/5`
  (`renderSunAndMoon`), `dlls/engine/7` (`lightningDrawStrand`), `dlls/engine/19`
  (`waterfx_drawSplashBurst`), `dlls/engine/24` (`boneParticleEffect_update`), `dlls/engine/68`
  (`firstPersonDoControls`), `dlls/engine/69` (`CameraModeTalk_update`), `202/mikaladon`,
  `260_SmallBasket` (`SmallBasket_spawnContents`), `328_CFGuardian` (`cfguardian_steerToward`),
  `362_CRrockfall` (`crrockfall_update`), `429_SH_thorntai`, `609_DR_LaserCan`
  (`drlasercannon_aimAtTarget`), `main/trig` (`fsin16Approx`). Three more are degenerate:
  `300_Transporter` and `musyx/sal_volume`'s two `extab` sections have no owning function at all.
- **cross-function (8), 13 rows**: `main/model`, `main/object`, `main/objhits`,
  `main/pi_videoinit`, `main/shader_dolphin`, `main/newshadows`, `main/acosf`,
  `track/intersect_render`, `dlls/engine/0`, `704`, `279_AppleOnTree`, `701`, `332`.

One refinement the sweep forced: 8b's test ("same owning function on both sides") is necessary
but not sufficient. `main/rcp_dolphin` passes it -- all three moved words are
`Rcp_InitDistortionEffects`'s on both sides -- yet it is a section 12 mover, not an 8b row,
because retail puts them at the pool *head*, ahead of four other functions' words, and
`Rcp_InitDistortionEffects` is the last function in the unit. The test has to be read together
with the destination: an 8b row is one whose moved words stay inside their own function's
contiguous run.

No unadjudicated row survives: section 8b prices `engine/19`, `engine/69`, `202/mikaladon`,
`429_SH_thorntai`, `609_DR_LaserCan` and `main/trig`; section 9 prices `engine/5` (its lone
missing word is the `gSkySunMoonRiseScale` crutch, and defining it costs `renderSunAndMoon`
99.476 -> 98.214 for +176 data, a net tree loss) and `engine/68`; section 8's table declines
`engine/7`; section 12 covers `main/vecmath`, `engine/24`, `328_CFGuardian`, `362_CRrockfall`
and the movers; `300_Transporter` was retired as a padding artifact in section 11; and
`musyx/sal_volume`'s two rows are zero-size sections. **Mission-2-style pure statement or use
motion reaches none of them** -- confirming 8b's finding from the other direction, since every
intra-function row's mint order is only reachable through a live use and a live use is what
moves the load.

(2026-08-03, later: the §8 proven-lost-body gate was subsequently run as a batch over the
remaining ORDER_ONLY units -- see the second addendum under §8's table. It upgrades `332`,
`main/object`, `track/intersect_render` and `main/vecmath` to proven-lost-body, leaves `701`
and `main/rcp_dolphin` two-origin, and walls `main/trig` behind its own `.text`; the
adjudications above stand otherwise.)

## 13. The cross-TU declaration laws (measured 2026-08-02/03)

Sections 9-12 price what a declaration *places*. This section records what a declaration *costs*
when the same object is spelled two different ways in two translation units. MWCC type-checks one
TU at a time, so an `extern` that contradicts its definition reaches no diagnostic and no gate;
`tools/extern_type_census.py` finds them by comparing every file-scope declaration of every symbol
across `src/` and `include/`. Every rule below was established by rebuilding and comparing the md5
of **all 1013 source objects**, so each is exact rather than inferred.

### The defining TU proposes, the reading TU disposes

A disagreement is a defect, not a style choice: one side is wrong, and which side is wrong is
decided by the emitted code, not by seniority. The definition is the proposal; the reader's
opcodes are the adjudication. Three tells settle nearly every row:

- **signedness** — a compare feeding a branch emits `cmpwi` for `int`/`long` and `cmplwi` for
  unsigned, so the reader's compare names the type. `gForceLoadImmediately` was defined `u32` and
  read signed by `pi_dolphin.c`; the *definition* changed. Same tell moved `gSaveCardState` to
  `volatile s32`, `sMapFileNameIndexRemapTable` to `int[]`, and the two map-block draw-order
  tables to `s8[16]`.
- **`volatile`** — `gAssetLoadCompletedFlags` is polled across an asset load, and the polling loop
  prices both halves of its type exactly: dropping `volatile` costs `initLoadFiles`
  100.0 -> 97.565, and `volatile u32` instead of `volatile int` costs 100.0 -> 98.756. The
  definition becomes `volatile int` and `objprint_dolphin.c`'s plain `u32` goes.
- **what the address is actually made of** — `gMapsTab` does integer arithmetic, so typing it as a
  pointer *changes `shader.o`* and `int` is the object; `gMapBlockCellStateTables` has
  `&...[4]` taken into an `int*`, so its twenty bytes are five `int`s, not `u8[0x14]`; `gTrkBlkTab`
  is read as halfwords, so it is `u16*`, not `void*`.

`d658fa7be5` settled six rows this way, `96ef150510` fifteen more, `1b59bb079c` six of a further
sixteen, `8722b792b1` `gGlowLightList` (`u8[0x190]` held against `ModelLightStruct*[100]` read —
400 bytes is 100 pointers). Every one of those commits is md5-identical over all 1013 objects: a
type disagreement that is genuinely a spelling costs nothing to settle, and one that is not shows
up as a changed object immediately.

At `cb88387945` the census reports 47 residual rows. Most are the tool's own spelling blindness
(a typedef against its `struct` tag: `GXData*` vs `struct __GXData_struct*`,
`FrontendSaveSlot*` vs `struct FrontendSaveSlot*`). The rest are the adjudicated pins —
`renderFlags` (`int` in `tex_dolphin` only), `gLightmapDrawQueue`,
`gAttractMoviePrepareReadyQueue`, `gTexIndMtxTable`, `gDll12Interface`, `aramNormalPriorityQueue`,
`gSceneCamera`, `gGlowLightList` — which are load-bearing or priced below. **Do not "fix" a pin.**

### Type visibility, not the include, is the relocation constraint

Moving a declaration out of a `.c` and into a header the reader already includes is free by
construction — the token stream each TU sees is unchanged. It fails for exactly two reasons: the
symbol is already declared there as something else (settle it first, above), or **the header cannot
name the type**. Fifteen declarations were stranded on the second reason alone — the target header
could not see `ModelLightStruct`, `OSMessageQueue`, `GXColor`, `AIDCallback`, `OSThread`,
`GXFifoObj`, `Camera` or `EnvironmentUpdateInterface`.

Gaining that visibility is a *per-object* question, and the answer is not uniform:

- **Free (measured, md5-identical over all 1013):** `pi_dolphin.h += GXFifo.h, OSThread.h,
  OSStopwatch.h`, which carries `gGxFifoObj`, `gVideoWaitThread` and `gFrameStopwatch` out of
  `pi_videoinit.c`; `attract_movie_api.h += dolphin/ai.h` for
  `gAttractMovieAudioPrevDmaCallback`. Also free: adding the *owning* include to a `.c`
  (`mm.c`, `engine/52`, `engine/0`, `shader.c`, `MWTrace.c`, `dll_80136a40.c`), each measured on
  its own object first.
- **Was "priced by class #70", LANDED FREE (sections 21 and 22):** `shader_api.h +=
  main/model_light.h` rewrites **33 DLL objects**. Every section's *content* is byte-identical and
  no score moves; the local literal-pool symbols renumber — `@103 -> @105` at the same address, in
  the same section, with the same size. That renumbering was declined for want of evidence it was
  harmless; the evidence exists now — with all 33 renumbered the forced link produces a
  byte-identical `main.dol`. Same for `textrender_internal.h += GXStruct.h` (`subtitle.o`,
  renumbering only) and `shader_api.h += camera.h` (4 DLL objects, `.comment` only — never a
  renumbering at all). All three are in the tree.

So the rule is: propose the include, then **measure the object, not the tree** — a score-flat,
content-identical rewrite of 33 objects is exactly the shape that a score gate reports as zero
and that md5-of-every-`.o` reports as 33. **A new `#include` is not priced by default**; section
22 measures the whole axis and finds the only priced construct is a header that emits an object.

### An extern array stays UNSIZED — and so, sometimes, does the definition

Completing an array type is a semantic change, not a declaration move, and it is priced on both
sides:

- **Declaration side.** `gAttractMovieAudioDmaBuffer` moves into `attract_movie_api.h`, but the
  declaration must stay `extern char gAttractMovieAudioDmaBuffer[];`. Carrying the `[0x50C]` into
  the header completes the type for `dll_3e.c` and costs `prepareAttractMode` 100.0 -> 99.087.
- **Definition side, and it is the data axis.** `2589a58b75`: `projgfx/194`'s
  `sProjdfp1rDoNoLongerSupported` was defined `char [40]` where the string is retail's 0x24 bytes.
  The four surplus bytes over-size the object, and because `matched_data` is all-or-nothing per
  section (§8), the *whole* `.data` section leaves `matched_data` even though every byte already
  matched. Declaring it `char []` and letting the initialiser size it: data 0/72 -> 72/72, unit
  100/100, `matched_data` +72 at zero tree regression. Its twenty sibling `OSReport` strings are
  all `[]` and all 0x24; `194` was the lone outlier.

The mirror rule for qualifiers: `const` on a *definition* is a section decision, not decoration.
`sReverbStdDelayLengths` is **not** `const` — making the definition `const` moves it out of
`.data` and costs 16 bytes of `matched_data`, so `1b59bb079c` moved the reader's `const` instead.

### The zero-build census, and what it is allowed to conclude

`b50bfac4ff`, `e133454ffd` and `cb88387945` extend the same method past objects to the other
declaration kinds — prototypes, macros, struct tags — where a disagreement can be found by reading
the tree rather than by building it: an `#ifdef` selecting between two prototypes for one function
where the macro is never defined anywhere (`DLL_0126_TRIGGER_LEGCODE_INT`,
`FRONT_GAMETEXTBOX_NARROW`, `OBJECT_RENDER_LEGACY_DIRECT_CALL`, one dead branch each); a struct tag
whose member is `m` in the header and `v` in a local copy (`IndTexMtx23`); a fabricated
`#define NAN 0.0f` in `ghidra_import.h` colliding with `math.h` for ~180 files, plus the bare
`#undef NAN` written to work around it; a header included by nothing whose five prototypes are all
contradicted elsewhere (`MSL_Common/math_ppc.h`, including a one-argument `atan2(double)`); and 99
local `#define`s shadowing an identical-valued definition in a header the file already reaches.

The census tells you a hunk is byte-identical **by construction**, and that claim is worth
believing only because it was checked: all 1013 objects came out md5-unchanged in each case, and
the 18 macros a file genuinely needs (`PAD_BUTTON_*`, `RENDERFLAG_*`, `TEXT_CTRL_*`, `*_OBJGROUP`)
were kept rather than assumed redundant. "Byte-identical by construction" earns the full gate, not
an exemption from it.

## 14. Re-sweep of the sub-100 code frontier against the post-convergence laws (measured 2026-08-03)

The code axis was declared converged before most of the current law set existed. This section is
the one re-opening, run at `97746b6bd3` with the `A + -C`, per-symbol and source-text-order lenses.
It reports a partition, two emptiness results and two re-priced rows. The verdict: **convergence
stands** — every row the new lenses reach was already banked, and the two whose mechanism the new
lenses genuinely corrected are still priced.

### The partition, and why it is worth having

`tools/a71_mnhist_scan.py` compares a function's normalised target and current instruction streams
three ways instead of one. That splits every sub-100 row into exactly three kinds:

| Kind | Test | Rows |
|---|---|---|
| colouring | opcode SEQUENCE identical, registers differ | 136 |
| order | opcode MULTISET identical, sequence differs | 10 |
| operation | opcode multiset differs | 67 |

There is no fourth kind, and no row is reloc-only. The test is cheap, needs no source, and answers
the question that decides whether a row is worth opening at all: a colouring row is #108/#82 by
construction and no source edit reaches it, whereas an operation row is asking the code generator
for something the source text chose. Of the 67 operation rows, 5 are the never-touch islands
(the three `ObjModel_Transform*`, `zlbDecompress`, `modelApplyBoneTransform`), 13 are the closed
zero-weld `li`-vs-`mr` cap of §5, and the rest are the already-banked §1-§4b rows. Exactly two of
the 213 had no prior mechanism on record, both `li`-vs-`mr`.

### Emptiness result 1: the sign-in-the-constant class does not generalise

`tools/a71_signscan.py` reads the f32 and f64 words of every unit's pool sections on both sides and
reports any value one side holds at the other's opposite sign. Over all 1050 units the answer is
**zero**. The opcode partition agrees from the other direction: no row outside the PS islands emits
`fnmsubs`/`fnmadds`/`fsubs` where retail emits `fmadds`/`fmsubs`/`fadds`. `trig` was the whole
class, and `e173a2c951` closed it.

### Emptiness result 2: the load-order flip has one live site, and it is priced

`tools/invcmp_scan.py` finds three functions; two are never-touch islands. The third is
`dlls/engine/6` `sky2_run`, and its banked description — "the ENTIRE residual is ONE `fneg`/`lfs`
schedule swap, 8 spellings inert" — is **refuted**. The residual is an operand-order row: retail
compares `best.x` against a once-loaded zero and skips with `ble-`, we load the zero first and skip
with `bge-`. Rewriting `if (zero < best.x)` as `if (best.x > zero)` reproduces retail's compare
exactly, both `fcmpo`/`ble-` pairs collapse into the matched region — and the surrounding scratch
FPRs rotate f1<->f2 across ten `fmadds`, so the row measures **99.65298 -> 99.49717**. Dropping the
`zero` temp for a bare `0.0f` gives the identical 99.49717 (MWCC interns the load either way), and
hoisting the `zero = 0.0f;` initialiser above the search loop gives the identical 99.49717 again —
which is the statement-order law stated as a measurement: **a dead initialiser move is inert.**
The row is priced by #82, not by the operator.

### The ternary's arm order is real, reachable, and still priced

`454_DIMCannon` `DIMCannon_updateAim` is the same story on the order axis. Retail's clamp emits
`ble-` to the assignment plus a `b` over it and leaves the result in the variable's own saved `f31`;
ours emits `bge-` and lands the result in scratch `f3`. Retail's spelling is the one its own sibling
two lines later already uses, `(distSq > 10.0f) ? distSq : 10.0f`, and writing it that way does make
the `ble-` match — but MWCC then folds the `b` away and still targets `f3`, so the whole downstream
chain diverges: **99.76923 -> 99.28205**. The in-place `if (distSq < 10.0f) { distSq = 10.0f; }`
keeps the variable in `f31` and costs more still, **98.82051**. Both spellings are more faithful
readings of the target than the baseline and both lose; the baseline stays.

### What this says about the frontier

Three of the new laws fired on real rows and none of them paid. The pattern in all three is the
same and is worth stating once: **the new lenses locate mechanisms the old ones could not name, and
the located mechanism is downstream of a register decision that no source edit reaches.** A row
whose residual survives a correct operator is a colouring row wearing an operator's clothes. The
136 colouring rows never needed re-opening, the 10 order rows are all §2/§3/§6-banked, and the 67
operation rows are the banked §1-§4b set plus two `li`-vs-`mr`. Re-open a row only when a lens finds
a mechanism *and* the mechanism's fix does not have to survive an allocator.

## 15. The ten order rows, worked one at a time (measured 2026-08-03)

§14 partitioned the sub-100 code frontier into 136 colouring / 10 order / 67 operation rows and
left the order bucket described as "all §2/§3/§6-banked". This section opens all ten, because the
order bucket is the only one whose defining property — the same instructions in a different
sequence — names a lever the campaign actually has: source-text order. Every row below was worked
with the text axis (statement order, operand order, expression grouping, temp naming, declaration
placement, loop shape) and each gets a verdict.

### The measurement that reframes the bucket

Diff the two streams with the operands thrown away and the order rows stop looking like a kind:

| Row | Unit | Score | Mnemonic-sequence delta |
|---|---|---|---|
| renderShadows | main/newshadows | 99.715 | 1 instruction slid |
| mmpMoonRock_update | 386_MMP_moonroc | 99.516 | 1 |
| gameTextFinalizeLoad | main/textrender_run | 99.334 | 1 |
| boxBlurTexture | main/newshadows | 99.167 | 1 |
| wispBaddieProcessAnimEvent | 202/sharpclaw | 99.156 | 1 |
| Checkpoint_buildControlPoints | engine/3 | 98.464 | 1 |
| playerUpdate | 195_Player | 98.432 | 1 |
| debugTextDrawToFrameBuffer | main/dll_80136a40 | 97.656 | 1 |
| staffUpdateSegmentTransforms | main/objprint | 97.018 | 2 |
| expgfxGetSlot | engine/10_expgfx | 95.899 | 2 (the same slide at two sites) |

**Every order row is one — at most two — instructions out of place, sitting inside a register
permutation that accounts for the rest of its gap.** `boxBlurTexture` is the extreme case: 1356
instructions, one slid `clrlwi`, and 115 diff hunks of which 114 are `r26`<->`r28` / `r30`<->`r31`.
So the order bucket is **not a third kind of divergence**. It is the colouring mass plus a slid
instruction, and the honest reading of §14's partition is that the three-way test is really a
two-way one with a one-instruction tolerance band. Keep the test — the slide is exactly where a
source-text mechanism can hide — but do not read "order" as "reachable".

### The one that paid

`main/newshadows` `renderShadows`. The elevation angle is `sqrtf(sqA + sqB)`; retail emits
`fmuls f0,f22,f22` (the X term) before `fmuls f1,f21,f21` (the Z term), and we named the squares
the other way round, so both products and the `fadds` that consumes them came out in the wrong
order. Swapping the two declarations is the whole fix: **99.69954 -> 99.71494** (`9b4d9f45b9`).
Two things were priced on the same row: collapsing the temps into an inline
`sqrtf(vAx*vAx + vAz*vAz)` costs **99.48382**, so the named temps are load-bearing; and the
`castSlot` address wants retail's `add base,index` operand order, but *every* spelling that writes
the base on the left of the sum — including the natural `&shadowData->castSlots[i]` — makes MWCC
group the constant with the scaled index instead and costs **99.40678**.

### The nine that did not, and what stopped each

- **`mmpMoonRock_update`** — a real structural row, and the closest any of the ten came. Retail
  materialises the "no conflict" flag *in the loop's exit block* (`li r0,1` between the back edge
  and the join) and the `break` path jumps over it, so the flag never crosses a call and never
  needs a saved register; we hoist `li r26,1` into the preheader and pay a callee-saved home. The
  shape retail has is what a `goto` past the exit assignment emits, and `goto` is banned. Two
  non-`goto` spellings measured: moving the declaration to function scope **99.51613 -> 99.36636**,
  and rewriting the loop as `while (1)` with the exit test and its `spacingClear = 1` inside the
  body **-> 98.23733**. Moving the declaration into the inner block does not compile — the flag is
  read after that block closes. PRICED.
- **`gameTextFinalizeLoad`** — retail computes `(stringTable + numStrings*4) + 4`, we compute
  `(numStrings*4 + 4) + stringTable`. This is a front-end canonicalisation, not a source choice:
  `&stringTable->offsets[n]`, `&strs[n]` and an explicit `(u8*)stringTable + n*sizeof(int) +
  sizeof(int)` all produce the **same object byte for byte**. MWCC always folds the constant into
  the scaled index first. PRICED.
- **`boxBlurTexture`** — one `clrlwi` (the `u16 fillHalfword = fill;` truncation) that our
  scheduler emits two slots earlier than retail, inside a 114-hunk register permutation.
  COLOURING.
- **`wispBaddieProcessAnimEvent`** — retail materialises the `0` for `activeEventIndex = 0` in
  `r0` immediately before its `stb`; we allocate it to `r4` and the scheduler then hoists it eight
  instructions into a load-delay slot. The statement order already matches retail. COLOURING.
- **`Checkpoint_buildControlPoints`** — the slide is one `lfd` in a LICM preheader: retail hoists
  the s32->double bias, then pi, then 32768.0f, then 2.0f (exactly the loop body's first-use
  order), and we hoist 2.0f first and the bias third. The other 73 hunks are a parameter-home
  permutation. COLOURING.
- **`playerUpdate`** *(195_Player, owner-hot under C73 — analysed read-only, not edited)* — an
  argument-setup `mr` that retail emits seven instructions earlier, inside an `r29`<->`r30` swap
  that accounts for essentially the whole 1.57 gap. COLOURING.
- **`debugTextDrawToFrameBuffer`** — retail schedules the `mr r26,r5` parameter home into the
  `addi`/`mulli` dependency gap; we emit it after both `mulli`s. Underneath, retail gives the `x`
  parameter `r29` and puts `row1`/`row0` in `r27`/`r28`, while we give `row1`/`row0` `r29`/`r28`
  and push `x` down to `r27`. Swapping the `row1`/`row0` declarations does move the pair (to
  `r29`/`r28` in retail's relative order) but never lifts the parameter above them:
  **97.65625 -> 97.39584**. The target colouring is not reachable from the declaration list
  because the register that has to move belongs to a parameter. COLOURING.
- **`staffUpdateSegmentTransforms`** — two slides. Inlining the `joint` temp into its
  `ObjModel_GetJointMatrix` call is **exactly byte-neutral** (97.01807 both ways), and writing the
  second site's matrix address in retail's addend order (`*(int*)(...) + idx2 * 0x40`) costs
  **97.01807 -> 92.28915**. PRICED.
- **`expgfxGetSlot`** *(engine/10_expgfx, owner-hot under C73 — analysed read-only, not edited)* —
  retail materialises the `1` of `1u << slotIndex` before loading the active mask; we load first.
  The same slide appears at both unrolled sites. PRICED pending an owner with the file.

### What this adds to §14's closing rule

§14 said to re-open a row only when a lens finds a mechanism *and* the fix does not have to survive
an allocator. The ten order rows sharpen that into a test you can apply before spending a build:
**an order row is worth opening only when the slid instruction is the one the source text names.**
`renderShadows` slid an `fmuls` whose operand the source picks by writing one square before the
other — reachable, and it paid. The other nine slid a parameter-home `mr`, a rematerialised `li`,
a LICM hoist or a scheduler's load-delay filler — none of which any source text names, and none of
which paid. A dead-initialiser move stays inert (§14), a canonicalised address expression stays
canonical, and a constant that retail rematerialises where we colour is a colouring row wearing
order's clothes.

## 16. The symbol-identity oracle: what the carve's symbol table says that no score reads (measured 2026-08-02)

§11 measures that `.bss` layout is set by first-use order and that declaration order is
completely inert. That makes the retail carve's `.bss` order a free oracle for the source
text's use order — and nothing in the tree was reading it. `.bss` has no bytes, so objdiff's
data score cannot see a permutation; md5-of-every-`.o` cannot see one either when the unit is
not linked, which the carve-linked units are not. `tools/bss_order_scan.py` reads it, on both
axes, over all 1013 source objects against their carve.

**Order.** 21 sections place their shared symbols in an order the carve does not. Every one is
`.bss`. Each row is a claim that our TU touches those objects in the wrong order: a missing use,
a use spelled against the wrong object, or a wrong TU boundary. The specimen worked here is
`main/tex_dolphin`: ours is `gViewFrustumPlanes, gPlayerRelativeFrustumPlanes, gRcpPendingWarpDest`
and the carve is `gPlayerRelativeFrustumPlanes, gViewFrustumPlanes, gRcpPendingWarpDest`.
Swapping the two declarations is inert exactly as §11 predicts, and both frustum relocations in
`tex_dolphin.o` already agree with the carve's — mnemonic, register and symbol — so the source
text is missing whatever makes the player-relative array first. The carve's naming is not the
suspect: retail's own `buildPlayerRelativeFrustumPlanes` materialises `0x803878D8` (`lis r3,0x8038;
addi r31,r3,0x78d8` at `0x8005aadc`, read out of `main.dol`), which is the carve's offset 0, so
the address-to-role assignment in `config/GSAE01/symbols.txt` is right and the ordering defect
is ours.

**Identity.** 109 symbols carry a different name than the carve gives the same
section/offset/size. Two kinds, and only one of them is debt:

* *naming debt in the map* — ours is a recovered name, the carve's is still `lbl_`/`gap_`. 76 of
  the 89 same-size rows. Score-free either way; it means a rename landed one-sided.
* *a contradiction* — both sides carry a real name and they disagree. `main/tex_dolphin` and
  `main/subtitle` each transpose a pair (`gSubtitleLineTimes` <-> `gSubtitleLineTable`);
  `main/model`'s `.sbss` is shifted one slot by a leading static; `dolphin/os/OS.o` calls
  `__OSInIPL` `AreWeInitialized`.

**The `lbl_` direction is itself an oracle.** Of 1013 objects exactly ONE has the divergence the
other way — our source saying `lbl_` where the carve has a recovered name — and it is the whole
of the `LBL_CONST_DEF` question: `src/dlls/objects/597/597.c`'s `const GXColor lbl_803E5AE0 =
{5, 5, 5, 5};` is the object `config/GSAE01/symbols.txt` already calls
`sSnowBikePathPointParams` at `0x803E5AE0`. The name is stale source from a half-landed rename,
not a pool-forcing const, and the two readings price as follows:

| Reading | Tree | 597 unit | `.sdata2` word 0 |
|---|---|---|---|
| baseline | 99.81598 / 2515196 / 1203321 | 99.90702, data 896/896 | `05050505` |
| rename to `sSnowBikePathPointParams` | 99.81598 / 2515196 / 1203321 | 99.90702, data 896/896 | `05050505` |
| delete, spelling it `GXColor pathParam = {5,5,5,5};` at the use | 99.81542 / 2513832 / **1202925** | **99.81951**, data **500**/896 | **gone** |

All five section digests of `597.o` are byte-identical across the rename; only the symbol string
moves. Deleting it costs the unit's entire 396-byte `.sdata2` — the pool slides down four bytes —
plus 1364 bytes of matched code, because `05050505` is an aggregate no float literal mints and
only a file-scope definition can place. It is read (`SnowBike_init` copies it into the `GXColor`
it hands to the path interface's `setup`), it is 100% of the carve, and it is a struct, which
`banned_shapes_check`'s own docstring already exempts — `RE_LBL_SCALAR` catches it only because
the regex excludes `union` and `[` and nothing else. Three of the other five `LBL_CONST_DEF`
baseline rows are the same misclassification (`engine/7`'s three `const SnowVec3`, each read into
a different destination, each a distinct 12-byte `.rodata` object); only `engine/21`'s and
`Baddie`'s `const f32 lbl_... = 0.0f;` are the scalar shape the ban was written for.

## 17. Where `.bss` allocates, and why it is worth `complete_units` (measured 2026-08-02)

Section 11 measures that `.bss` layout is first-use order and that declaration order is inert.
Both halves are true and neither is the whole law: `main/mm.c` defines its three `.bss` objects
at lines 360/372/374 after `extern` declarations at 181/302, uses them first at 193/315/522, and
lays them out in **definition** order — which no reading of "first-use order" produces, and which
survives swapping the two definitions unchanged.

### The law

Measured with a six-case probe battery compiled through the real command line (both live flag
sets agree; `/private/tmp/a74probe/`):

| probe | layout |
|---|---|
| definitions `A B C` at the top, uses `A B C` in three functions | `A B C` |
| definitions `A B C`, uses `C B A` | `C B A` |
| externs at the top, uses `A B C`, definitions `A B C` at the bottom | `C B A` |
| each definition placed immediately *after* its own use | `C B A` |
| `A` used then defined; `B`, `C` defined then used | `B C A` |
| `sizeof(B)` before the uses; separately, `int* pB = B;` before the uses | `A B C` — neither allocates |
| a use of `B` inside an **uncalled static function** above the others | `B A C` |

So: an object is allocated at the **first use that follows its definition**; an object with no
such use is allocated at end of translation unit, and those come out in **reverse definition
order**, after every allocated one. The front end's position is what counts, not the code
generator's — an uncalled (or inlined) static's body allocates where it is written, while
`sizeof` and a `.data` pointer initialiser do not allocate at all. Section 11's intra-expression
depth rule survives unchanged (`A[1]+B[2]+C[3]` gives `A C B`).

### It is not a compiler-version artifact

83 source objects share two or more `.bss` symbols with the carve; 62 already agree. Every other
section agrees everywhere (`.data` 290/290, `.sbss` 159/159, `.sdata` 123/123, `.sdata2` 32/32,
`.rodata` 28/28). Among the units that agree, `main/thp/THPRead.o` and `main/audio_stream.o` are
the specimens: their queue objects are declared `extern` where the types are, defined at the
bottom of the file, and come out in reverse definition order — the law's second clause,
reproduced by our compiler and matching retail. The tree already carries the shape; it was simply
not carried where it was needed.

### What the 21 rows were, and what closed them

Each of `tools/bss_order_scan.py`'s 21 rows is a TU that defines the objects above the code
instead of below it. Moving the smallest sufficient set of definitions past their last use (an
`extern` left behind only where no header already declares the object) reproduces the carve's
order **exactly** in all 21, from one moved definition (`track_dolphin`, `model`, `53`, `203`,
`DBstealerwo`) to seventeen (`engine/0`). `engine/2` needed no move at all: its fifteen
definitions already sit at the bottom of the file in the carve's order, which is precisely
backwards — reversing that block put all fifteen where the carve has them. Every edit leaves every
section's *contents* untouched — but `.bss` is NOBITS and has no contents, so that is not the
invariant to quote: `objdump -s` cannot see a `.bss` reordering at all. What these edits move is
the symbol table, which is the point of them, and `tools/obj_equal.py` shows all 21 (section 21).

### The payoff, and the control that proves it

A NonMatching unit is linked from the retail carve, so its `.bss` order cannot reach the DOL —
which is why this axis has no score. A **Matching** unit is linked from our own object, and a
permuted `.bss` moves every DOL word that references it. `main/objlib` is the control: at
100.00000 fuzzy it stayed NonMatching for exactly this reason, and it is now measured, not
inferred — with the parent's `objlib.c` and `Object(Matching, ...)` the forced link **FAILS** the
sha1; with the two definitions moved it passes.

  objlib, textrender_drawbox, thp/dll_3b, objects/203   NonMatching -> Matching
  complete_units 910 -> 914 of 1050, tree 99.81614 / 2517640 / 1203321 flat

`main/audio.c` is the fifth 100.00000 candidate and does not flip: its `.bss` order is fixed too,
but our `.data` is `0xe6b` bytes against the carve's `0xe70`. The carve carries a five-byte
`gap_07_802C5D73_data` after `sMidiWadPath` that our last string does not produce, and
`section_alignments` does not reach it — that tail is the remaining blocker, not the `.bss`.

### `.sbss` is the same law with the uses removed

`.sbss` layout is reverse declaration order, and 159 of 159 units already agree — but a `static`
declared *below* the file's `.sbss` block takes slot 0 and pushes every global down one word.
`main/model.c` was the one instance: `sGQR7Config` at line 100 against the block at 32-40. The
carve puts a 4-byte `gap_10_803DCB6C_sbss` — an object dtk cannot name because it is a local — at
the end, which is that static in retail's build. Declaring it first puts it last and lands all
nine globals on the carve's offsets (name divergences 105 -> 96; the one row left in that unit is
the unnameable local itself).

### What is left on the axis

`bss_order_scan` is at **0** order divergences and **96** name divergences. Of those 96, 64 are
`.sdata2` and 28 are `ours=<a local static or an unrecovered lbl_> vs retail=gap_*` — benign by
construction, since dtk cannot name a local. The inverse sweep asked for by §16 (we name it,
the carve says `lbl_`) is **68 rows and is the const-recovery lane's**: they are its pool anchors
(`gTumbleweedBushRenderScale`, `gDFropenodeOneHundredth`, `sFireFlyDespawnDelay`, ...), the same
population as `banned_shapes_check`'s 19 `SINGLE_ELEM_CONST_ARRAY` regrowth rows, and not a
naming defect to be "fixed" by another lane. Only **two** rows are the §16 direction — `597.c`'s
`lbl_803E5AE0` (owner-hot) and `model.o`'s `.sbss`, closed above.


## 18. Forward substitution: when a "pool crutch" is really a code row (measured 2026-08-03, A77)

A76 landed `engine/5` `renderSunAndMoon` by deleting a temp. §9 had priced the same slot for a
year of lanes as an opaque-extern crutch. The two readings are not variants of each other, and the
difference is worth stating as a law because it re-opened a second row the same day.

### The mechanism

MWCC's `-opt propagation` sinks a local that is **defined once and read once** into its single use,
and it will move that computation past intervening calls and stores when every operand is
register-resident — another local, or a literal it can see. It will not move it when an operand is
a memory reference a call might clobber, which is why an `extern const f32` nobody defines, or a
1-element `const` pin, "fixes" the code: the opacity is doing the work, not the value.

One sink produces three residuals that read as unrelated defects:

* the defining arithmetic instruction appears at the **store site**, not where the source writes it;
* the callee-saved FPR/GPR the source would give the temp goes to the **other** local, because the
  temp no longer spans the calls;
* and the **pool rotates**, because literal words mint at emission and a sunk expression mints late.

### The two cures, and which one every earlier lane missed

The crutch cures the *third* symptom by making the operand opaque. That is why it is banned and why
it never quite fits: it buys the code at the cost of a pool word in the wrong slot. The other cure
is plain C — **reuse one local for both roles, so there is no single-use temp to sink**:

| row | crutch spelling | plain literal | plain literal + one local |
|---|---|---|---|
| `engine/5` `renderSunAndMoon` | 99.476 (undefined extern; unit could not link) | 96.828 | **98.840**, `.sdata2` 100.0, +176 data |
| `engine/68` `firstPersonDoControls` | 100.0, `.sdata2` 96.875 | 94.512 | **100.0**, `.sdata2` byte-identical, +128 data |

`engine/68` is the sharper specimen because §8 had *already named the mechanism* — "being an opaque
global it blocks `-opt propagation` from sinking the single-use temp `spinI` past the
`camera->anim.rotX` store" — and still priced the row, because every probe it ran varied **how the
constant is spelled** (file-scope `const` 94.512, function-local `static const` 94.512,
`const f32 X[1]` 100.0 but at the wrong slot). None varied the temp. Retail's registers say plainly
which variable is which: `lwz r5,20(r1)` holds the `fctiwz` result at full width across the store
and `extsh r4,r0` narrows only after the `subf`, so the int web carries the subtraction and the
`s16` takes the narrowed result. Merging into the `s16` instead is 99.590 — one misplaced `extsh`.

### The scans, and what they found

`tools/fwdsub_scan.py` finds the source shape directly: a def-use *region* (not a whole-variable
count — `scale` had two) whose value reaches exactly one read, with a call that **closes** before
that read, at the same brace depth, over arithmetic on locals and literals only. It carries the
A76 fix as a positive control and the post-fix source as a negative control, and it reaches 210 of
210 sub-100 bodies. Tree-wide result: **35 sites, and every curable one is already at 100.0** —
the merged spelling is universal in `src/`, so there is no second `engine/5`.

`tools/crutch_sink_scan.py` is the half that matters, because a crutch site is invisible to the
first scan by construction (its operand *is* the blocking memory reference). It asks of every unit
carrying a 1-element pin whether that pin is buying pool position: pool byte-identical means the
pin is load-bearing, and pool still wrong means the pin's only job is opacity — the job §18 removes.
**45 units carry a pin; 40 are load-bearing; 5 are not.** `engine/68` was one. Of the other four,
`engine/7`, `203` and `521_WM_LevelCon` are short a trailing zero word (§8's phantom-minter DECLINE,
not this class) and `main/vecmath`'s pin sits at the correct slot — its pool defect is an unrelated
`0.0f`/`1.0f` head swap and `mtxRotateByVec3s` is a #82 FPR permutation. So the class is closed at
two members, both paid.

`tools/order_bucket_scan.py` re-derives §15's bucket at the current tip and names the slid opcode:
**11 rows, 4 slide an opcode the source text names**, and all four are §15's own adjudications
(`renderShadows` paid, `gameTextFinalizeLoad` and `staffUpdateSegmentTransforms` priced,
`boxBlurTexture` colouring). The eleventh row is `704` `titleScreenDrawMenuFrame`, whose slid
opcode is an `lfs` — not source-nameable, consistent with A76 pricing it.

### The audit law this generalises to

**A price is only valid against the baseline it was measured at.** A69 priced `engine/5` at
99.476 -> 98.214 and called it a net tree loss; 99.476 was bought by an extern that did not exist,
the honest baseline was 96.828, and the ruling inverted with no new idea. `tools/ledger_baseline_audit.py`
reads every figure this file quotes for a named function, attributes it to the nearest preceding
name inside the same sentence, and compares it to the current score. Run it before trusting any
row here, and stamp the baseline sha on any row you re-measure.

### Standing note on `musyx/runtime/voice` (probed 2026-08-03, DECLINED)

`voice.c` defines seven `.bss` objects `static` while `include/musyx/{vid_init,voice_conv}.h`
declare three of them `extern`, so `vid_init.c`, `voice_id.c` and `voice_conv.c` compile against a
symbol nothing exports and the unit cannot be flipped to Matching. **Do not resolve this by
exporting the statics.** The `.bss` order is a positive oracle and it says internal linkage:
retail's `voice.o` lays the seven out in `voice.c`'s **definition** order, which is exactly what
all-`static` produces (`bss_order_scan` clean, unit 100.0). Exporting all seven switches MWCC to
**first-use** order — an order retail does not have — for `synthInitAllocationAids` 100.0 -> 99.966
and unit 100.0 -> 99.99183; A75's 76.196 was the *mixed* case (3 of 7 exported, so two groups,
locals first). Since our `.text` is byte-identical to retail's, retail's first-use order is ours,
so if retail's objects had been external its `.bss` would be in the order we get when we export
them. It is not. The defect is therefore a **translation-unit boundary**, not a linkage keyword:
`vid_init.c`, `vid_get.c`, `voice_id.c`, `voice.c` and `voice_conv.c` occupy one contiguous
`.text` run (`0x80278F0C`-`0x8027A4E0`) and two adjacent `.sbss` runs that a single TU would emit
as one, so the candidate fix is a five-way unit merge in `config/GSAE01/splits.txt`, not a change
to `voice.c`.

## 19. The compiler-invocation audit: what the declared compiler is worth, tree-wide (measured 2026-08-03, A79)

A78 removed three `mw_version="GC/2.0"` overrides from `musyx`, a library whose own declared
compiler is `GC/1.2.5n`, and asked whether the rest of the tree carries the same defect. It does
not, and the emptiness is worth as much as the three rows were: **no unit anywhere in the tree is
held back by its declared compiler version or its optimisation level.**

### The two sweeps, and their emptiness result

Baseline `2567e1014f` (99.815420 / 2517640 / 1204625 / 920 of 1050). The frontier is **87 units**
with `fuzzy < 100`, not 207 — **207 is the count of sub-100 FUNCTIONS**, spread across those 87
units. Every brief that says "the 207 sub-100 units" is miscounting; check `report.json` before
sizing a sweep from it.

* **Compiler version.** Every one of the 87 was rebuilt under each of `GC/2.0`, `GC/1.3`,
  `GC/1.3.2`, `GC/1.2.5n`, `GC/1.2.5` other than its own — **333 probes, 0 wins**, 112 rows exactly
  equal (`GC/1.3` and `GC/1.3.2` are indistinguishable from `GC/2.0` on most game units).
* **Optimisation level.** The same 87 under `-O0`, `-O1`, `-O2`, `-O3`, `-O4`, `-O4,p`, `-O3,p`,
  `-O2,p` appended — **663 probes, 0 wins**.

996 probes, every one gated on the compiler's exit code, and not a single unit improves. A78's
musyx matrix showed how violent a level change is (`vid_init` 100.0 -> 22.065 at `-O2`); the
result here is that the violence is all downside. **The flag axis is closed for the code frontier.
Do not re-run it.**

### The one class that did pay: the inert version override

The productive question is not "is there a better compiler" but "**is the declared one doing
anything at all**". Every per-object `mw_version` that differs from its library's default was
rebuilt under the library default and the two objects compared with `tools/obj_equal.py` — contents,
relocations and symbol table, not score. **42 overrides audited, 6 inert**: the library's own
compiler produces an object identical but for `.comment`, a non-allocated section that never
reaches the DOL.

| unit | declared | library default | verdict |
| --- | --- | --- | --- |
| `dlls/objects/437/437.c` | GC/1.3 | GC/2.0 | inert (`.comment` only) |
| `dolphin/MSL_C/PPCEABI/bare/H/common_float_tables.c` | GC/1.3 | GC/1.2.5n | inert (`.comment` only) |
| `main/rand.c` | GC/1.1 | GC/1.2.5n | inert (whole file byte-identical) |
| `dolphin/MSL_C/PPCEABI/bare/H/exponentialsf.c` | GC/1.1 | GC/1.2.5n | inert (whole file byte-identical) |
| `dolphin/TRK_MINNOW_DOLPHIN/mainloop.c` | GC/1.3.2 | GC/1.3 | inert (whole file byte-identical) |
| `dolphin/TRK_MINNOW_DOLPHIN/dispatch.c` | GC/1.3.2 | GC/1.3 | inert (whole file byte-identical) |

Removing all six drops `GC/1.1` from the project's compiler requirements entirely — it was declared
for exactly two objects and neither needs it. The other 36 are load-bearing, several violently so
(`s_frexp` 100.0 -> 50.657, `printf` 100.0 -> 72.736, `WORLDplanet` 99.480 -> 82.101).

**Law: a declared compiler version is evidence only if the library's own compiler produces a
different object.** Score equality does not establish inertness and object equality does not
establish it either unless the comparison includes relocations — see §20.

### The same question on the flag axis: 50 of 284 overrides do nothing

`configure.py` carries **29 distinct cflag sets for `src/dlls/` alone** and 23 for `src/main/`, a
zoo no 2002 build had. Every object whose cflags differ from its **library default**
(`cflags_dll_noopt` for lib `main`, `cflags_base` for a `DolphinLib`) — 284 of them — was rebuilt
under that default with its own `mw_version` held fixed, and compared with `obj_equal`. **50 are
inert**, 49 of which carry the flags on the `Object()` line and were stripped; the 50th
(`dolphin/vi/vi.c`) takes them from its library, so the object-level pass cannot reach it.

Removing all 49 changes **zero bytes in zero objects** — the tree-wide `obj_equal` diff after both
this and the version pass still reports 1013 compared / 2 differ / 0 missing / 0 new, and the two
are the `.comment` rows of the version pass. Among the 49: `-inline noauto` on eleven units that
have no auto-inlinable callee, `noloopinvariants` on nine with no loop-invariant to hoist,
`nocse`/`nostrength` on nine more, `-use_lmw_stmw on` on three SDK units, `-sdata 16` on
`GXDisplayList`, `-inline all -char signed` on the two `si` units, and `cflags_base` (i.e. dropping
`-opt nopeephole,noschedule` entirely) on four small `dlls/engine` units.

**Beware the modal-set trap.** Taking the *most common* flag set of a source directory as the
default is wrong for `src/main/`, whose modal set is `cflags_dll_noopt_noautoinline` — not the
library default. Audited that way the answer comes out 53 inert, and five of those rows say
"adding `-inline noauto` is inert", which is not the same claim and is not a licence to delete
anything. **Take the default from `configure.py`'s library declaration, never from a histogram.**

### Correction to A78's `hw_break`

A78 recorded that `musyx/runtime/hw_break.c` has PROGBITS byte-identical under `GC/1.2.5n` and
differs only in relocations. **It does not.** Re-measured twice, under `GC/1.2.5n` the `.text` is
80 bytes in both but its md5 differs: the object is an `r3`/`r4` permutation of the `GC/2.0` one
(`mulli r4,r3,244` becomes `mulli r3,r3,244` and the whole dependent chain follows). Its override
is load-bearing for an ordinary reason. The lesson A78 drew from it is still right, and §20 gives
it a counter-example that actually holds.

### The relocation-offset fingerprint is a dtk artifact, not evidence

`R_PPC_EMB_SDA21` fixups land on the instruction word under `GC/2.0` and on its low halfword under
`GC/1.2.5n`/`GC/1.3`, which looks like a free tree-wide oracle for "was this unit built by the
right compiler": scan every source object against its retail counterpart and read off the
disagreements. **It is not an oracle.** All 1045 objects under `build/GSAE01/obj/` carry a
`.note.split` section — they are dtk reconstructions carved out of the DOL, so their relocation
tables are synthesised by dtk and uniformly land on the word. The scan reports 113 "mismatches",
every one of them a unit legitimately built by an older compiler. **Any oracle read off the carved
objects' relocations measures dtk, not retail.** The fingerprint is still sound between two of
*our own* builds, where `tools/obj_equal.py` already reports it.

## 20. Section contents do not certify an object: the relocation gate (measured 2026-08-03, A79)

Every lane in this fleet has been clearing object-level work with a section-content md5 (`secmd5`,
`objdump -s` with the path header stripped). That check is blind to an entire kind of change,
because a relocatable object is contents **plus** a relocation table **plus** a symbol table, and
the field a relocation patches is zero in the object either way.

### The hole, with a control that reproduces from the tree

Rename one file-local function — `heapSpawnSlot` -> `heapSpawnSlotRenamed` in `src/main/mm.c`, two
occurrences, no other edit — and rebuild:

* section contents: **zero differences**. `secmd5` reports the object identical.
* relocations: one entry in `.text` at offset 4388 changes its target symbol name.
* symbol table: one name gone, one name added.

The object genuinely changed and every gate this project runs says it did not. The same shape
covers the whole **#70 reloc-NAME-at-equal-ADDRESS** class, which the ledger has been calling
score-neutral on the strength of "prove `objdump -s` identical" — that proof does not reach the
relocation table, so #70 rows have been cleared by a check that cannot see the thing they change.
It also covers the naming lane's standing claim of "byte-identical over all 1013 objects": a rename
*must* move relocations, so contents-identity is the wrong invariant to quote for it.

### `tools/obj_equal.py`

Compares two ELF32-BE PowerPC objects, or two trees of them (`--tree DIR_A DIR_B`), on:

* **contents** — md5 per allocated/PROGBITS section, `NOBITS` by size;
* **relocations** — per target section, each entry normalised to
  `(offset, type, addend, symbol identity)` where the symbol is identified by **name**, or by
  section for `STT_SECTION` entries, so symbol-index churn is ignored;
* **symbols** — name -> (section, value, size, info), so symbol-table *ordering* is ignored but
  a rename, a binding change or a size change is not. MWCC's `@NNN` literal-pool symbols are keyed
  by **address** instead of by name (section 21): their numbers are emission-order churn, so a
  pool holding the same words at the same offsets is the same pool however it is numbered, and a
  pure renumbering prints `RENUMBERED` rather than `DIFFER`.

`--self-test` runs five controls and exits non-zero on any failure:

1. **negative** — an object against a byte-identical copy under a different filename: must report
   `EQUAL` (the check must not be trigger-happy about paths or ordering);
2. **positive, contents** — two genuinely different objects: must report a `CONTENT` difference;
3. **positive, relocations only** — one relocation in a real tree object repointed at a different
   existing symbol, PROGBITS untouched: must report **contents identical and a `RELOC` difference**.
   This is the class control 1 and 2 cannot distinguish, and the class `secmd5` cannot see;
4. **anon renumbering** — one `@NNN` symbol renamed to an unused number: must report the
   `ANON` note and nothing else;
5. **anon move** — one `@NNN` symbol's address advanced four bytes: must be a hard difference.

The real-world positive control is the `mm.c` rename above; the real-world negative control used
in this lane's own landing is the six inert compiler overrides of §19, where the tool correctly
reports 1013 objects compared, 2 differing, and both only in `.comment`.

**Gate object-level work on `obj_equal.py`, not on section contents.** A change that is genuinely
free will pass both; a change that is only apparently free will pass one.

### The `vecmath` #70 re-attack, priced and declined

`src/main/vecmath.c` declares `extern f32 lbl_803DE7C0;` and reads it at two sites as a zero.
The symbol resolves to vecmath's own `.sdata2` offset 0 — the file declares its own leading pool
word as an extern. Our pool and retail's hold the **same 18 words**; only positions 0 and 1 are
swapped (ours `1.0f, 0.0f`, retail `0.0f, 1.0f`), and `.sdata2` scores all-or-nothing per section,
so the unit sits at `matched_data` **0 of 72** while every function but `mtxRotateByVec3s` is
100.0. `interpolate` is the first function in `.text` and emits its `1.0f` first — in retail's own
instruction sequence, which we reproduce exactly — so under emission order the zero must be minted
by something *ahead of* `interpolate`. Four spellings, all re-measured at `2567e1014f`:

| spelling | `matched_data` | unit fuzzy | `matched_code` | note |
| --- | --- | --- | --- | --- |
| production (`extern f32 lbl_803DE7C0`) | 0/72 | 99.80268 | 4268 | baseline |
| hoisted `f32 result = 0.0f;` in `interpolate` | **72/72** | 99.55801 | 4172 | `interpolate` 100.0 -> **87.083** |
| `const f32 kZero = 0.0f;` at top, uses renamed | 0/72 | 99.60931 | 3680 | pool grows to **80 B**, duplicate zero at 0x08 |
| every `0.0f` in the file replaced by `kZero` | 0/72 | 99.60931 | 3680 | still 80 B — a zero is minted elsewhere |
| forward `extern const f32 kZero;`, defined at end | 0/72 | 99.80268 | 4268 | **code-neutral**, but the word lands at index 3 |

The hoisted spelling is the only one that reaches 72/72 and it costs **96 `matched_code`**;
MWCC will not sink the initialiser back into the branch arm under any flag — ten `-opt` variants
(`propagation`, `nopropagation`, `lifetimes`, `nolifetimes`, `nocse`, `nodeadcode`,
`noloopinvariants`, `peephole`, `schedule`, and dropping `nostrength`) all leave `interpolate` at
87.083. A78's cure — an uncalled `static` helper ahead of `interpolate` that mints the word and
lets `interpolate`'s literal dedup to it — reaches 72/72 at zero code cost but is a **phantom
literal-minter**, and the ban is on the shape. **DECLINED at a measured price of +72 `matched_data`
for -96 `matched_code`.** The carve boundary is not the culprit: `gameloop_main.c`'s `.sdata2` ends
at `0x803DE7BC` and vecmath's starts at the next 8-aligned address `0x803DE7C0`, which its two
embedded doubles require, so there is no word to reattribute. The only legal improvement available
is cosmetic — the forward-`extern const` spelling retires the `lbl_<hex>` crutch at exactly zero
cost in both directions — and it belongs to the const lane, not here.

## 21. The relocation gate applied backwards: re-verifying the naming span, and the three-way split of class #70 (measured 2026-08-03, A80)

Section 20 built `tools/obj_equal.py` and showed that a section-content md5 cannot see a
relocation. Two bodies of landed work had been certified with exactly that blind check: the
semantic lanes from C76 onward, which quote "byte-identical over all 1013 objects" for hundreds of
renames, and the ledger's own class #70 rows, cleared on "prove `objdump -s` identical". This
section re-runs both against the gate that can see the difference.

### The method: walk the chain, not the endpoints

`b8a3aaae64^..850208fbd4` is 52 commits and every lane's work is interleaved in it, so an
endpoint-to-endpoint diff attributes nothing. The chain is linear, so a worktree cut at the span's
parent can be walked forward one commit at a time — materialise each commit's changed files,
re-run `configure.py`, `ninja all_source`, and compare every object ninja rebuilt against the
previous commit's copy of it. Each step is incremental (a full build is 29 s; most steps are
seconds), and the walk ends with a **control that matters**: the final object tree compares
`1013 compared / 0 differ / 0 missing / 0 new` against a pristine build of `850208fbd4`, so the
reconstruction of every intermediate state is exact and every per-commit verdict below is real.

### The verdict: 33 of 52 commits move zero bytes; 19 move something, and all 19 are accounted for

The 33 clean commits include every mass-rename lane, and that is the result worth stating plainly:

| commit | what it renamed | objects rebuilt | verdict |
| --- | --- | --- | --- |
| `3dc6cf38c4` | `ghidra_import.h` retired, 168 files | **908** | identical |
| `5b318ebb46` | 18 struct members | 294 | identical |
| `2f991cb1b1` | 39 machine-named parameters, 18 files | 81 | identical |
| `7fea9c3dbe` | 8 private `Mtx` clones, 1 duplicate macro | 670 | identical |
| `082abe0cbd` | 66 machine-named locals, 21 files | 24 | identical |
| `72182ef109` | 57 dead Ghidra prototypes | 65 | identical |
| `f909e67506` / `b9092bb262` | `Vec` respellings, SDK type restatements | 65 / 52 | identical |

A local, parameter, member or typedef rename really does touch neither contents, relocations nor
the symbol table. **The naming lanes' standing claim survives its own audit** — it was quoted
against the wrong invariant, but the stronger invariant holds too.

The 19 that move something split three ways.

**(a) Anon literal-pool renumbering — the class the old check was blind to.** Three commits that
claimed byte-identity changed 12 objects, all in the same way: section contents identical,
relocations pointing at the same addresses, but MWCC's `@NNN` literal-pool symbols renumbered.

| commit | objects | what changed |
| --- | --- | --- |
| `1476aef86e` (C76 `EffectVertex` collapse) | `modgfx/170`, `modgfx/94` | `@8` -> `@77`, `@6` -> `@75` |
| `d88f1d99b4` (object state through its struct) | 7 DLL objects | pool numbering shifts by 1-3 |
| `3b2d8a17cf` (interfaces through vtable structs) | `player`, `tricky`, `SPitembeam` | 296 of 4705 `.text` relocations renamed |

**This is not a defect and not a cost.** `@NNN` numbers are emission-order churn of exactly the
kind the symbol table's own ordering is: they name nothing the linker resolves, and the retail DOL
has no symbol table at all. `obj_equal.py` now identifies an `@NNN` relocation target by its
**address** and reports a pure renumbering as `RENUMBERED` rather than `DIFFER`, with two new
self-test controls (renumber one -> note only; move one four bytes -> hard difference).
Self-test 5/5.

**(b) Intended, and the certification wording was wrong.** `ed446243a6` moved 21 units' `.bss`
definitions and `672b6b8061` moved `model`'s `.sbss` block; both were landed as "byte-neutral by
construction: `objdump -s` over all 1013 objects gives 0 differ". `.bss` and `.sbss` are **NOBITS**
— they have no contents for `objdump -s` to print, so that check could not have seen the change it
was certifying, and `obj_equal` sees all 21 (`gObjSeqBgCmds` `.bss+15832` -> `+10880`, and so on).
The edits are correct and their payoff is real (four units NonMatching -> Matching in the very next
commit); only the sentence was wrong. Same shape, same verdict, for the three commits that flip a
`static` to external linkage to link a unit (`257c4fc0c0`, `c7f59e3e3c`): a binding change from
`STB_LOCAL` to `STB_GLOBAL` moves no byte of any section either.

**(c) Deliberate code and naming changes.** Eleven commits (`73abfd6123`, `aba5d2f63c`,
`dd06905c7b`, `5bf6287066`, `739030b8ce`, `617bfbe581`, `9a940bebc5`, `8dbcf2f006`, `8d7c8d2ff3`,
`850208fbd4`, `8b8656a52a`) changed objects on purpose and moved `matched_data`,
`complete_units` or the score to prove it. The file-scope renames among them (`850208fbd4`'s six
families, `8dbcf2f006`'s shopkeeper) necessarily retarget relocations — that is what a two-sided
rename *is* — and nothing else moved in them.

**No real defect was found in the span.** Sixteen of the nineteen were certified with language
that its check could not support; none of the sixteen is wrong.

### The one candidate that needed a control: `2567e1014f`

Dropping the three spurious `GC/2.0` overrides on `vid_get`, `hw_sample` and `hw_keyoff` was landed
as "the library builds them itself". It does not build them *identically*: `.comment` differs, and
**every `R_PPC_EMB_SDA21` relocation moves two bytes**, from the instruction offset that `GC/2.0`
records to the low-halfword offset that `GC/1.2.5n` records. All three units are
`MatchingFor("GSAE01")`, so our objects are the ones that link, and a misapplied SDA21 would be a
live bug. Measured both ways at `850208fbd4`: with the overrides restored and with them dropped,
the forced link produces `main.dol: OK` and the same md5. **The linker normalises the convention;
the commit stands.** Record this as the shape to look for whenever a compiler version changes under
an object: contents can be identical while the relocation table is not.

### Class #70 re-audited: it is three classes, and only one of them is free

Every #70 row had been cleared on "prove `objdump -s` identical bytes", which cannot reach a
relocation. Re-measured at `850208fbd4`:

| sub-case | example | old check | true verdict |
| --- | --- | --- | --- |
| **(i) `@NNN` -> `@MMM` at preserved addresses** | `shader_api.h += main/model_light.h`, 33 objects | blind | **FREE — proven, not inferred** |
| **(ii) a named symbol renamed at a fixed address** | `lbl_8033527C` -> `gDREarthWarriorSpeedRows` (`8d7c8d2ff3`) | blind | free, and *intended* |
| **(iii) an extern `lbl_` reloc replaced by an own-pool `@NNN`** | `704.o` at `73abfd6123` | blind | **PRICED** — different address, tree 99.81614 -> 99.814064 |

Sub-case (i) is the one the ledger rejected rows on, and the rejection is now refuted with a
control the old check could not run. Section 13 declined three declaration homes "priced by class
#70"; re-measured at `850208fbd4` against a pristine build of it:

| rejected row | objects touched | `obj_equal` | score | forced link |
| --- | --- | --- | --- | --- |
| `shader_api.h += main/model_light.h` | 33 | 0 differ / **33 renumbered** | 99.815420 flat | **`main.dol: OK`** |
| `textrender_internal.h += GXStruct.h` | 1 (`subtitle.o`) | 0 differ / 1 renumbered | flat | — |
| `shader_api.h += camera.h` | 4 | **`.comment` only** | flat | — |

Thirty-three objects renumbered their entire literal pool and the DOL came out byte-identical.
That settles it: **a renumbering is not a cost, and the third row was never even a renumbering** —
its four objects differ only in `.comment`, a non-allocated section. The reason those three
declarations stay in their `.c` files is now no reason at all; whoever owns the declaration homes
may move them. The rule that section 13 states — "propose the include, then measure the object,
not the tree" — is right; what it must measure with is `obj_equal`, and a `RENUMBERED` line is a
pass.

Sub-case (iii) is the correction that matters in the other direction: an `extern lbl_` relocation
and an own-pool `@NNN` relocation name **different addresses**, so replacing one with the other is
never free. `73abfd6123` paid 0.002 tree points for it knowingly. Do not read #70's
"score-neutral" as covering this.

### The walk extended over the three commits that landed while this ran

`850208fbd4..9f4fb7a037`, same method, same control. `b68fd836a9` ("drop the includes and
prototypes nothing in the file needs") touches **33 objects and not one allocated byte**: 32 differ
only in `.comment` — MWCC's non-allocated browse table, which shrinks because the file declares
less — and one is a pure `@NNN` renumbering. That is the cleanest specimen of the whole audit: a
claim of neutrality that is exactly true where it matters and visibly false to a byte-comparison,
which is why the gate has to be `obj_equal` and why `.comment` has to be read as what it is.
`0c3863112e` and `9f4fb7a037` split blob symbols and change their recorded sizes, which is what
those commits are for.

### `GC/1.1` is already gone

Section 19 dropped the only two objects that declared it (`rand.c`, `exponentialsf.c`). Confirmed
at `850208fbd4`: `configure.py` contains no `GC/1.1`, and the generated `build.ninja` invokes
`GC/2.0` (781), `GC/1.2.5n` (168), `GC/1.3` (50), `GC/1.3.2` (8), `GC/1.2.5` (4) and `GC/1.3.2r`
(1) and nothing else. The two surviving mentions are not requirements: `tools/project.py`'s
`COMPILER_MAP` is decomp-toolkit's own table of every known version, and `tools/flag_sweep.py`
lists it as a probe target. **Nothing remains to retire.**

## 22. What a new `#include` actually costs, measured across the kinds (2026-08-03, A81)

Section 21 refuted the ledger's "priced by class #70" verdict on three declaration homes and
handed them off as free. This section lands them, and answers the question that refutation
raises: section 13 still says "a new `#include` is priced by default", and C70's record says the
same with a count ("7 of 9 measured adds were FREE"). A default with a counter-example in it is
not a law. So measure the whole axis instead of sampling it.

### The three handed-off rows are landed

`shader_api.h += main/camera.h, main/model_light.h` and `textrender_internal.h +=
dolphin/gx/GXStruct.h`, with the four `struct Camera` / `struct ModelLightStruct` / `struct
_GXColor` stubs they existed to support replaced by the typedefs. Over all 1013 source objects:
**0 differ / 33 renumbered**, four objects differing in `.comment` at unchanged size, forced link
`main.dol: OK` at md5 `7b955850ea4bd7ce`, every measure flat.

### The sweep: 51 include-additions, zero hard differences

Eight `.c` files spanning `src/main`, `src/track` and two DLLs, crossed with eight headers of
different content kinds, one added header per build, each object compared with `obj_equal`:
**47 EQUAL, 4 RENUMBERED, 0 hard differences**, plus two that failed to compile (a header that
needs another one first — a constraint, not a price). Not one relocation moved anywhere.

### The boundary, from synthetic probe headers

One target (`main/objhits.o`), one probe header, one construct at a time:

| the header holds | verdict |
| --- | --- |
| an `extern` object declaration | EQUAL |
| a `struct`/`typedef` | EQUAL |
| a prototype | EQUAL |
| a macro | EQUAL |
| a `static const` **scalar** | EQUAL — MWCC drops an unreferenced one entirely |
| an `enum` | renumbering only |
| an unused `static inline` function | renumbering only |
| a `static const` **array** | **PRICED**: `.sdata2` 80 -> 88 bytes and **64 of 426 `.text` relocations** retarget, `@NNN` at `.sdata2+0` becoming `@NNN` at `+8` |

So: **a new `#include` costs nothing unless the header emits an object into an allocated section,
and the only construct that does so unreferenced is a `static const` aggregate** — the same shape
section 12 identifies as the only mover, and the one the purge already bans. `@NNN` renumbering
and `.comment` growth are the two visible effects and neither is allocated or linked. The
"priced by default" wording in section 13 is replaced by this.

What this does **not** overturn, because none of it was ever an include price:

- **A SIZED extern array is still priced.** `extern char gAttractMovieAudioDmaBuffer[0x50C];`
  completes a type; that is a semantic change that happens to travel in a header.
- **The `modelEngine.c` descriptor block stays.** C71 declined its 27 externs on plausibility —
  27 new `#include`s in one file — not on price, and a free include does not make that plausible.
- **The 14 SDK/MSL/musyx file-local externs stay.** The oracle there is retail's own `nm`: it
  defines each symbol in exactly the object our source names, so the file-local `extern` is the
  original idiom.
- **The 10 pinned cross-TU type conflicts stay pinned.**

### Rows opened by the law, and the two screens that found them

**A hand-written `extern` a header already declares.** Probe: delete each of the 714 file-scope
object `extern`s in `src/**/*.c` and gate on ninja's exit code. **17 are unnecessary**; 14 are the
const lane's `lbl_<hex>` declarations and three are not — `objhits.c` restating its own header
twelve lines after including it, `mm.c` forward-declaring `gMmRegionTable` twice with two
different spellings of the same extent, and `expgfx.c` forward-declaring two `.bss` ints 1840
lines ahead of definitions that nothing uses before. All three deleted at **0 differ / 0
renumbered**: not one object changed, which is what a redundant declaration is.

**A header that reached for a forward tag because an include was believed priced.** All 66
file-scope forward tags in `include/` compile away, but that proves nothing on its own — a
`struct X*` inside a prototype self-declares the tag. A stub is a defect only when the tree's own
spelling is the typedef, and five are:

| header | the stub | tree spelling |
| --- | --- | --- |
| `pi_dolphin.h` | `extern struct RingBufferQueue gVideoFlipQueue;` — a by-value extern of an incomplete type | `RingBufferQueue`, `main/model_engine.h` |
| `rcp_dolphin_api.h` | `struct _GXColor*` in six prototypes | `GXColor` |
| `rcp_dolphin_render_api.h` | `struct _GXTexObj*`, `struct Texture*` | `GXTexObj`, `Texture` |
| `texture.h` | two inline accessors returning `struct _GXTexObj*` / `struct _GXTexRegion*`, which pushed the raw tag into six locals in `newshadows.c` | `GXTexObj` 107 sites vs `struct _GXTexObj` 9, all nine reachable from this header |
| `379_DFSH_LaserB.h`, `508.h`, `dll_0035_saveselectscreen.h` | `struct Dll81Interface`, `struct Texture`, `struct FrontendSaveSlot` | the three typedefs |

Landed in two commits at **0 differ / 76 renumbered** and **0 differ / 0 renumbered**, with
`hudMatrix` (`Mtx44` in `pi_videoinit.c` against `f32[4][4]` everywhere else) settled into
`track/intersect_hud_api.h` in the second. `zlb.h`'s `unsigned char` declarations look like the
same defect and are not one: `zlb.c` opens by typedef-ing its own `u8`/`u16` instead of including
`types.h`, which is what a self-contained zlib port does.

### The instrument note that generalises

Every verdict above was taken with `obj_equal --tree` plus the forced link, and every one of them
is invisible to `fuzzy_match_percent`, to `matched_data` and to the DOL sha1. That is the whole
reason the axis was mispriced for three sections: **a score gate reports a score-flat rewrite of
33 objects as zero, and so does `objdump -s` when the only thing that moved is a relocation.**

## 23. The `complete_units` census, and the `li`/`mr` quarter of the operation bucket (measured 2026-08-03, A82)

Two independent results. The first re-runs A75's census of units that read 100.0 everywhere and are
still `NonMatching`; the second takes §14's operation bucket at its word and finds that a quarter of
it is not an operation difference at all.

### 23a. The census, re-run from scratch

A75 closed this census at twelve members with the tree at 915 `complete_units`. At 920 it has **six**,
and only three of the six are blocked by anything a source edit could reach. The oracle is the one
§17 names: flip to `Object(Matching, …)`, force the link, read the sha1.

| Unit | Report says | Forced link says | Blocker |
|---|---|---|---|
| `main/shader_dolphin` | all 48 functions and all 7 sections 100.0 | links, sha1 FAILS | **dead-strip.** Nothing references `sWarpedRingRotAxes` (0x30) or `sWarpedRingIndMtx` (0x18); `mwldeppc` strips per symbol, `.rodata` loses 0x48, `gTexIndMtxTable` slides 0x802C1E40 -> 0x802C1DF8 and every section after 11 moves. **CURED** by arming both in `force_active`. |
| `main/gametext` | all 8 functions and all 4 sections 100.0 | **link fails** | **cross-TU pool anchor.** Its `.sdata2` is the 16-byte MWCC int->double conversion pair (`43300000 00000000`, `43300000 80000000`) at 0x803DE6F0/F8, which the carve exports as `lbl_803DE6F0`/`lbl_803DE6F8` and `gametext_tail.o` and `textrender.o` reference. Those two carves are 99.506 and 99.834, so the anchor cannot be retired until both reach 100.0 and flip with it. The pair is compiler-minted, so no source text names it. |
| `main/musyx/runtime/voice` | all 10 functions and all 5 sections 100.0 | **link fails** | **split-TU statics.** `vid_init.o` wants `vidList`, `voice_conv.o` wants `synth_last_started`/`synth_last_fxstarted`; `voice.c` defines all three `static` while `vid_init.h`/`voice_conv.h` declare them `extern` — a contradiction only the carve hides. Dropping `static` links and flips, and **costs 816 `matched_code`**: the three move from the file-local `.bss` block into the global group (§11's mixed rule), every displacement off the block base shifts by 2240, one `addi` disappears and `synthInitAllocationAids` goes 100.0 -> 99.480, tree 99.815420 -> 99.815270. **DECLINED.** The five units `vid_init`/`vid_get`/`voice_id`/`voice`/`voice_conv` are contiguous in `.text` (0x80278F0C..0x8027A4E0) and in `.sbss`, and retail's block displacements are the all-static layout, so they are one retail TU — which is exactly the merge A78 refuted on compiler invocation. Merging them would also cost a net `complete_unit`, since two of the five are already complete. |
| `main/rcp_dolphin` | `.sdata2` 14.634 | links, sha1 fails | `.sdata2` mint order only. No dead-strip, no undefined symbol, no section-size change: the DOL differs from 0x803DEB49 inside its own pool and nowhere else. §12's row, owned by the const lane. |
| `main/track/intersect_render` | `.sdata2` 91.525 | links, sha1 fails | `.sdata2` word rotation only — 63 bytes in the pool and 53 in `.text`, all SDA2 displacements. |
| `main/dlls/objects/701/701` | `.sdata2` 95.652 | links, sha1 fails | `.sdata2`, one word: retail mints `0.0f` where we mint `1.0f` first — the same shape §20 declined in `vecmath`. 12 pool bytes, 21 `.text` bytes. |

**Landed:** the `shader_dolphin` flip, `complete_units` 920 -> **921 of 1050**, every other measure flat,
`obj_equal --tree` 1013/0 differ, forced link `main.dol: OK`.

**Standing rule this adds.** The census does go stale, but not in the direction A75's framing suggests:
of six members, three are `.sdata2` rows the report already prices and one is a paid dead-strip. The
two that the report cannot see at all — `gametext` and `voice` — both fail at *link* rather than at
sha1, and both fail because **our TU boundary is not retail's**. A unit whose report is 100.0 across
the board and whose flip fails to link is a split-TU claim, not a layout bug: read the undefined
symbol list first, because it names the sibling that has to come with it.

### 23b. A quarter of the operation bucket is rematerialisation, not operation

§14 partitions every sub-100 code row by mnemonic histogram: same sequence = colouring, same multiset
= order, different multiset = operation, "which only the source text chooses". Re-derived at
`45e62d0c0e` the partition is **132 colouring / 11 order / 67 operation** over 210 rows. But **17 of
the 67 operation rows differ only by `li` against `mr`** — 15 where retail copies a live zero and we
materialise it (`Scarab_update`, `curves_advanceCollision`, `intersectModLineBuild`, `Shield_setMode`,
`textRenderStr`, `mapScreenDrawHud`, `trickyBallMove`, `trackIntersect`, `objDrawShadowCasterMesh`,
`updateEnvironment`, `hudDrawButtons`, `renderSunAndMoon`, `headDisplayDraw`, `unloadMap`,
`gameTextInitBoxTextures`) and 2 the other way (`boneParticleEffect_update`, `StaffCollision_spawn`).
Rematerialising a constant changes the opcode without changing the operation, so the histogram
mis-files the whole family.

**The decisive control is in-tree and needs no probe.** `curves_advanceCollision` has one four-line
preamble written five times, character for character:

```
pointIndices[0] = 0;
pointIndices[1] = pointIndices[0];
outputCursor[0] = (u8*)collision;
sourceOffset    = pointIndices[0];
```

Retail emits `mr` for the fourth line at all five sites. **Our build emits `mr` at four of them and
`li` at the fifth** — and at that fifth site our register assignment is already identical to retail's
(`li r29,0; mr r28,r29; mr r27,r31`), so it is not even a colouring difference. One source text, two
code generations, in one function, under one compile. Nothing the source says can select between them.

**The probes, for the record.** `Scarab_update` is the cleanest specimen in the family: the *only*
instruction that differs in the whole function is `mr r30,r31` against `li r30,0` for
`collisionDetected = bestGroundHitIndex;`, with `li r31,0` and the `stw r31` of `groundHits = NULL`
already byte-identical — MWCC's shared-constant register is demonstrably working, it just does not
reach the second variable. Five in-tree spellings (chained `a = b = 0` at the top and at the
statement's own position, reversed roles, both-literal, `+ 0`) all leave it at 99.93095, and two of
them regress the function to 99.76. A standalone lab reproducing the shape under the unit's exact
command line adds nine spellings (plain copy, reversed roles, chain, both-literal, copy-via-third,
ternary identity, comma operator, moved statement, pointer-typed source) crossed with five `-opt`
settings (`nopeephole,noschedule` / `peephole,noschedule` / `nopeephole,schedule` / `peephole,schedule`
/ `level=4`): **45 compiles, every one `li`**. MWCC's front end folds a scalar-to-scalar copy of a
compile-time constant unconditionally; the `mr` is chosen downstream.

The one construct that does defeat the fold is an *aggregate* source — `pointIndices[1] =
pointIndices[0]` gets `mr` because the operand is an array element — and that is precisely the
4-byte-aggregate respelling `docs/HACK_AUDIT.md` bans by shape. So the family has no legal lever.

**PRICED, and it is a re-classification, not a new class.** These 17 rows belong with #108/#110, not
with the operation bucket. The rule §14 should be read with: **a multiset delta made entirely of `li`
against `mr` (either direction) is rematerialisation, and rematerialisation is an allocator decision
wearing an operation's clothes** — the mirror of §15's closing sentence. Partition first, then subtract
this family, and the operation bucket that is actually worth opening is **50 rows, not 67**.

### 23c. The second way the allocator forges a multiset delta: store-to-load forwarding

`li` against `mr` is not the only opcode the allocator can invent. `beginLoadingMap`
(`main/shader.c`, 99.776, `LEN-2`, the histogram's only "T-only `lwz`") is the specimen:

```
gMapBlockOriginX = fastFloorf(characterPosition->x / gMapBlockWorldSize);
gMapBlockOriginZ = fastFloorf(characterPosition->z / gMapBlockWorldSize);
...                                     /* four stores through base + 0x8588.. */
gMapBlockOriginWorldX = gMapBlockOriginX * 640;
gMapBlockOriginWorldZ = gMapBlockOriginZ * 640;
```

Both compiles re-read `gMapBlockOriginX`, because the intervening `*(int*)(base + 0x8594) = 1;`
clobbers the register that held it — `r0` in both. Only `gMapBlockOriginZ` differs, and the whole
difference is which register received the `fctiwz` read-back at `292(r1)`: retail took `r0`, which
that same `li r0,1` then kills, so it must reload; we took `r4`, which nothing kills, so MWCC
forwards the store and the `lwz` never appears. **One register choice, two elided instructions, a
`T-only {lwz: 1}` histogram row.** The source already spells both sides identically and reads the
global at the use, so there is nothing left for it to say.

Together with §23b the rule for §14's bucket is: **before opening an operation row, ask whether the
missing opcode is one a register choice could have deleted.** A rematerialised constant (`li`/`mr`)
and a forwarded store (a vanished `lwz`) both change the multiset without changing the operation, and
neither is reachable from the source text. What survives that filter — a different addressing mode, a
different literal width, an extra store, a folded stride — is the part of the bucket that is really
asking the source a question.

## 24. The source-shaped opcode-family sweep, run to exhaustion (measured 2026-08-03, A84)

Lane A83 proved the method on ONE family — align retail's and our mnemonic streams per
function and flag every hunk that trades a single-precision opcode for its double twin —
and it paid one hit in 210 (`drawViewFinderHud`, worth 99.18072 -> 99.34538). This section
runs **every other family whose difference maps to a documented source-level fact**, and
reports the honest yield including the zeros.

**Harness.** `/private/tmp/A84_cache.py` builds one aligned-hunk mnemonic cache over all
sub-100 functions (SequenceMatcher over the normalised mnemonic streams, relocations
stripped), so a family query is a read over the cache rather than a re-scan. Population
**209 sub-100 functions in 87 paired units**; only **78** have any mnemonic-stream
difference at all, and the other 131 are pure register permutations.

**Yield per family, aligned-hunk pairing.** Every cure named in CLAUDE.md was swept:

| family | rows / 209 | verdict |
|---|---|---|
| `cmpwi` vs `cmplwi` (both directions) | **0** | the declared-width lever has NO live site |
| `andi` vs `rlwinm` (both directions) | **0** | the single-bit-clear lever has NO live site |
| `li`+`rlwimi` vs `ori`/`or`/`andc` (bitfield) | **0** | the bitfield lever has NO live site |
| `fcmpo` vs `fcmpu` (both directions) | **0** | the FP-operator lever has NO live site |
| `fmadds` vs `fmuls`+`fadds` (both directions) | **0** outside the PS islands | association lever has no live site |
| `neg`/`subf`, `srawi`/`srwi`, `mulli`/shift, `divw`/shift | **0** | no live site |
| narrow load/store WIDTH (`lwz`/`lhz`/`lbz`, `stw`/`sth`/`stb`) | **0** | the 3 apparent rows are `lwzx`-vs-`lwz`+`add` addressing, not width |
| surplus `extsb` | 3, all islands or already priced | closed |
| surplus/missing `extsh` | 4 | all four already banked (§4b, A83) |
| `bl` vs inlined body | 3 | 2 are never-touch islands; 1 is §24b below |

**The result is the finding.** Eight of the ten families are EMPTY at this frontier — not
"unsolved", *absent*. The levers CLAUDE.md names are real, and the project has already spent
them; what remains carries no instance of them. A83's one-hit-in-210 was not a low yield, it
was the ceiling. Whole-function mnemonic-multiset triage (shift-invariant, so it catches a
family that migrates across hunks) leaves **9 non-island functions** carrying any interesting
multiset delta at all, and every one is either already priced or declined below.

### 24b. Three rows worked and declined, mechanism named

**`playerCacheMoveRootHeights`** (195_Player, 97.045, NEW). Retail builds the loop's output
pointer as `li r0,12; slwi r0,r0,2; add r29,r4,r0` — the subscript scaled but **not folded**,
with the value const-propagated into the `li` by a later pass. We emit `addi r29,r4,48`. The
asymmetry inside retail's own preheader is the tell: the sibling walker `&lbl_80332F48[17]`
IS folded (`addi r30,r3,34`) because its subscript is a literal, while
`&gPlayerMoveRootHeights[moveIndex]` is not because its subscript is a variable. Our front
end copy-propagates the literal into the variable subscript and folds it; retail's did not.
**Nine spellings measured, all folded or worse**: `&a[i]` (baseline 97.045), `a + i`,
`&a[(int)i]`, `a + (int)i`, `p = a; p += i`, `p = &a[0]; p += i`, the pointer init moved into
the `for`-init, both arrays indexed in the loop body (97.023), and output indexed with the
other walker kept (92.955). `&lbl_80332F48[moveIndex + 5]` folds to retail's `+34` exactly,
proving the fold is unconditional in this unit. Pass-order artifact, not reachable.

**`textureLoad` 98.882 + `loadTextureFiles` 97.248** (main/texture.c, NEW, one mechanism).
Both are short exactly **three `b`** and nothing else, and both inline `loadTextureBank`
twice. Retail carries, per inline expansion, an orphan duplicate loop-preheader block
(`b <that copy's loop test>`) laid out at the FUNCTION TAIL, plus one `b` to skip over the
pair — 3 dead instructions before the epilogue, unreachable from anywhere. Each inline site
already carries its own inline copy of that preheader, which we match; retail simply has a
second, orphaned one. **Eight callee spellings measured**: positive-`if`-wraps-loop (95.138 /
98.416), `for` with early return (93.248 / 97.803), `for` inside positive `if` (identical),
`static` without `inline` (65.817 / 90.942 — not inlined at all), `do/while`+`break` (83.697 /
95.834), and three that are EXACTLY byte-identical to baseline (explicit trailing `return;`,
`!ptr` test, `*p` instead of `p[0]`). Inliner block-layout bookkeeping; the baseline is the
best reachable shape.

**`dll_0B_spawnEffect`** (engine/11, 98.982, NEW). Two hunks: one allocator-forged
(`mr r9,r6` vs `li r10,0` — retail copies a register that already holds zero), and one CSE
shape. Retail computes the same `*(int*)(base + off + 16)` two ways inside one loop —
`lwz; addi 16; lwzx` at the head from a cached offset, `lwz 16(r10)` at the tail from the
loop-invariant `r10 = base + off` — and we CSE both onto the second form. Same class as
`mapLoadUnloadObjects` (A83): a CSE asymmetry the source text has to state twice, not a
spelling. Banked.

### 24c. The operation bucket re-partitioned at this tip

A71's partition over the 209: **COLOURING 131 / ORDER 11 / OPERATION 67**. A83's
allocator-forged screen (the row's entire T-only/C-only delta inside
`{mr, li, fmr, addi, lis} u {lwz, lbz, lha, lfs, lfd, lwzx, lbzx, lhz, stw, extsb}`) removes
**35 of 67**; **18** more are never-touch islands (the PS bodies, `zlbDecompress`,
`pi_videoinit`, `setGQR6/7`, `modelApplyBoneTransform`/`_next`, `fn_80007F78`) — leaving
**14 real rows**, of which **11 were already banked** (152 §4b, `ObjSeq_onMapSetup`,
`ObjSeq_runBgCmds`, `subtitleUpdateAndDraw`, `voxmaps_updateActiveMap`, the `acosf` trio,
`removeButtonObject`, 332 §4b) and the 3 above are now banked too. **The operation bucket
is closed at this tip.**

**Warning for the next lane that re-partitions it.** `dll_0B_spawnEffect` reached the
OPERATION bucket only because a register permutation changed a register *reuse* pattern:
retail's `lwzx r8,r6,r3` writes a fresh register while ours writes `lwzx r5,r6,r5` over its
own index, and that shifts what the aligner pairs. Screen the bucket on the whole-function
mnemonic multiset AND read the ndiff before believing a row is an operation row — 44 of its
46 regions are plain #108 register permutations.

## 25. What the tricky `.sdata2` trade actually bought (measured 2026-08-03, A85)

A window in which `matched_code` rises and `matched_data` falls looks like a partial pool fix,
and a partial `.sdata2` fix is worth strictly less than zero (§6b). This one is not that. Both
halves of the move come from **one commit**, `3d9406bfe8` "Tricky: recover readable near-matching
source", and the data half is the priced cost of a **banned-shape removal**, not a regression.

**The measurement.** Reverting that commit's seven source/header files and its one `cflags`
line (it dropped `nodead` from `196_Tricky` in favour of the shared
`cflags_dll_noopt_noprop_noautoinline`) reproduces the earlier tree to the digit, so the commit
is the whole delta and nothing else in the window contributes:

| | tree fuzzy | `matched_code` | `matched_data` | `complete_units` | `tricky` `.text` | `tricky` `.sdata2` |
|---|---|---|---|---|---|---|
| `3d9406bfe8^` | 99.81569 | 2517640 | 1204625 | 921 | 99.937874 | **100.0** (408 B) |
| `3d9406bfe8` | 99.81612 | **2519540** | **1204217** | 921 | 99.956276 | **88.66995** (408 B) |

`+1900` code, `−408` data, `+0.00043` fuzzy, `complete_units` flat. The `−408` is the section's
**whole** contribution: `.sdata2` scores all-or-nothing, so an 88.67 % section pays zero, and
`tricky`'s unit `matched_data` is exactly `2768 − 408`.

**The mechanism, and why it is not recoverable as clean C.** `tools/banned_shapes_check.py`
names it without being asked: five baseline rows are "no longer present", and all five are
`UNCALLED_STATIC_FN` in `tricky.c` — `trickyEventTimeExpired`, `trickyApproachSpeedStep`,
`trickyRouteTurnRate`, `trickyRouteStep` and `trickyBinAngleToRadians`, none of which had a
call site. They were the only thing interning `-100000.0f`, `8.0f`, `-0.15f`, `0.05f`, `0.02f`,
`600.0f`, `0.005f`, `-2.0f`, `3.1415927f` and `32768.0f` at retail's source-text positions.
The two pools are the **same 408 bytes and the same value multiset**, identical through offset
`0x4c` and permuted from `0x50` on: a pure §10 mint-order rotation.

Per-function first-use order settles what a source edit can reach here. The two objects' pool
**value sequences agree at every one of the 96 distinct slots** — our code asks for the same
constants in the same order retail's does — while retail's *layout* puts `-100000.0f` and
`8.0f` at `0x50`/`0x54`, ahead of an `FLT_MAX` whose first live loader
(`trickySelectQueuedCommandTarget`) is an *earlier* function than their own
(`trickyUpdateCollisionAndPathState`). A slot that sits ahead of the first live function to
load it has exactly one possible minter, and §7 already named it: code that ran earlier and
that mwld stripped. So retail's layout is only reachable by putting uncalled bodies back —
the shape the checker bans and the shape this commit deleted.

**Verdict: DELIBERATE, priced, not recovered.** The trade is net positive on its own terms
(+1900 code, +0.00043 fuzzy, five banned rows retired) and the deleted bodies are five of the
`UNCALLED_STATIC_FN` reconstructions §7 adjudicated as faithful. Whether 408 data bytes are
worth five uncalled statics is the owner's decision, not a lane's; it is recorded here at
**408 `matched_data`** so the next window that sees the dip does not re-bisect it, and so that
nobody "recovers" it by re-fabricating dead code. The seven stale baseline rows the check now
reports are the visible residue and are shrunk in this lane's commit.

## 26. Brute-forcing the colouring cap: 33 571 orderings over all 131 rows (measured 2026-08-03, A85)

§14 partitions the sub-100 code frontier into **131 colouring / 11 order / 67 operation**, and
§24 closed the operation bucket, which leaves the colouring mass as the whole board. This
section runs the two source-level levers that reach a register assignment over **every** row of
it and reports the yield.

**The pruning rule in the standing brief is wrong, and it would have cost every hit here.**
"T == C length ⇒ WELDED, declaration order is inert" prunes 100 % of the colouring bucket by
construction — a pure register permutation has equal length by definition. The project's own
record already refutes it: `trickyUpdateMovementState` (99.92241, `LEN=`, colouring) is where
B31's five-round chain paid. Do not prune a colouring row on length.

**The two levers are different levers, and both are live.** The saved-GPR band is filled in two
phases — webs that never reach a loop header first, in *reverse first-definition* order, then
everything else in *declaration* order. `brute_match.py` moves the second key, `stmt_sweep.py`
the first. Neither subsumes the other: the two hit sets below are disjoint.

| axis | rows attempted | rows with anything to permute | orderings built | hits |
|---|---|---|---|---|
| declaration order (`brute_match --strategy moves`, every block, nested scopes included) | 128 | 126 | **25 335** | 3 |
| assignment-statement order (`stmt_sweep --strategy moves`, every run, every scope) | 128 | 90 | **8 236** | 4 |
| one K&R-style definition both parsers reject, swept by hand (`permsweep --mode moves`) | 1 | 1 | **529** | 1 |

Population 131 minus the three never-touch/OWNER-HOT rows = 128 attempted. **34 100 orderings
built and scored, 8 hits — a yield of one row in sixteen.**

| function | unit | axis | fuzzy |
|---|---|---|---|
| `playerState08` | `195_Player/player` | decl: `int* list` before `int i` | 99.5279 -> **99.9615** |
| `debugPrintDrawRecord` | `main/dll_80136a40` | stmt: `x0` before `y0` (x3 sites), `x1*sc` before `x0*sc` | 99.6491 -> **99.7917** |
| `trackGetIntersect2` | `main/track_dolphin` | decl: `u8 found` down 30 declarations | 99.6682 -> **99.7623** |
| `mapFillCellEntry` | `main/shader` | stmt: the `gridZ` subtraction before the `gridX` one | 99.2819 -> **99.3245** |
| `gameTextWrapLines` | `main/gametext_tail` | decl: `int charPos` to the head of the run | 98.8889 -> **98.9325** |
| `mtxRotateByVec3s` | `main/vecmath` | stmt: `z = xf->z` ahead of `x`/`y` | 98.7500 -> **98.7850** |
| `trackBuildBlockTriangles` | `main/track_dolphin` | decl (K&R): `int count, layer` down 7 | 98.3464 -> **98.3726** |
| `gameTextBuildSystemFontAtlas` | `main/textrender_run` | stmt: `ty` before `tx` | 99.0000 -> **99.0109** |

Every hit is one item moved inside one run — no construct added, no shape, no semantics
changed (`stmt_sweep` proves each permutation against the RAW/WAR/WAW relation before it is
written). Cross-axis round 2 over the eight winners converged: the axis that did not pay first
does not pay second either.

**Two things the sweep found that are not scores.**

*A K&R definition is invisible to both sweepers.* `trackBuildBlockTriangles` is written
`int f(cur, x0, ...)` with the parameter declarations below the parenthesis, and
`find_function_body` cannot see it: the driver reported it as the run's single error rather than
as a swept-and-inert row. It was then the eighth hit. **A row a tool cannot parse reads exactly
like a row a tool has cleared** — count the errors in any sweep before believing its zero.

*The sweep harness was lock-bound, not compute-bound.* Every probe of every concurrent sweep
serialised on `tools/locked_ninja.sh`'s global directory mutex, which held a ten-worker fleet at
a load average of 3.9 on a ten-core box. A probe does not need ninja: `ninja -t commands` yields
the unit's compile line once, and running it directly is byte-identical and needs no lock
(`tools/direct_build.py`, now the default path in `brute_match.rebuild`, with
`SFA_BRUTE_LOCKED_NINJA=1` to force the old one). Measured on one row: **83 s -> 1.9 s**, and
the fleet went to a load average of 15. The whole 34 100-ordering sweep would not have been
affordable otherwise, and any earlier "swept and inert" verdict taken under a time budget was
measured with 90 % of its budget spent asleep.

**Verdict.** The colouring cap is not solid, but it is thin: eight rows in 131 move, all by one
statement or one declaration, and none of them crosses 100. `matched_code`, `matched_data` and
`complete_units` are unchanged by all eight — the whole payment is fuzzy, **99.81612 ->
99.816765**. What the sweep does establish is a floor: after 34 100 orderings, the other 120
rows have no reachable ordering at all on either key, and the next lever for them is not an
ordering.

## 27. The colouring cap has ONE key, not two: statement order is an ORDER lever (measured 2026-08-03, A86)

§26 opened the colouring cap with two tools and reported their hit sets as disjoint, and the
mechanism it wrote down — "the saved band fills in two phases: webs that never reach a loop
header first, in reverse FIRST-DEFINITION order, then everything else in DECLARATION order" —
has been the standing model since. It is wrong, and the correction changes where the next lane
should point each tool.

**The controlled measurement.** Four `float` locals, each live across two calls so every one of
them needs a callee-saved home, declaration order pinned, and the four assignment statements
permuted through all 24 orders: **all 24 produce the identical assignment** `a=f31 b=f30 c=f29
d=f28`. Pin the statements instead and permute the declarations through all 24 orders and
**every one of the 24 assignments is different**. The same experiment on `int` locals gives the
same answer for the GPR band — 24 statement orders, one result. And on the construct
`stmt_sweep` actually permutes — a run of adjacent, call-free assignments — all 24 orders again
give one register assignment and differ only in the ORDER of the emitted instructions.

**The same result on the two landed hits.** Rebuild `mtxRotateByVec3s` with §26's `z = xf->z`
put back where it was: the instruction multiset is identical, no register operand changes, and
exactly one instruction (`lfs f4,20(r31)`) sits two slots away. `mapFillCellEntry` with §26's
`gridZ`/`gridX` subtraction swapped back: identical multiset, `r30` on both sides, two
instructions slid. Both of §26's statement hits are instruction-ORDER moves scored by an
alignment, not register moves.

**So:** declaration order is the ONLY source key for the register assignment; statement order
is the source key for emission ORDER. The two hit sets are disjoint because the two tools attack
two different buckets — which is worth more than the two-phase story, because it says where to
point them. `stmt_sweep` belongs on the ORDER bucket (§24c's 11 rows plus the order residual
that sits inside a colouring row), and `brute_match` is the whole colouring lever.

**The band, measured in real code.** `tools/slot_oracle.py` swaps each adjacent pair of
declarations and reads the register substitution the swap induces, which pins the
slot -> register map in `n-1` probes instead of the `O(n^2)` neighbourhood. Over the 82 rows it
could measure, adjacent slots that both own a saved register of the same class run **84
descending to 9 ascending** — the band is contiguous and monotone in declaration order, and
fills `r31`/`f31` downward. Both classes obey it; the FP band has no separate law and no second
key.

**What the residual is actually made of.** Partitioning all 209 sub-100 rows by which register
class the residual permutes (`tools/a86_reg_class_partition.py`) gives **142 colouring / 67
operation**, and inside the colouring mass only **27 rows have any FPR-only differing
instruction at all**. Of the 139
colouring rows outside the never-touch islands, **82 have a saved-band register move and 57 are
volatile-only**: their whole residual sits in `f0`-`f13`/`r0`-`r13`, so no declaration order can
reach it. Of the 82, only **9** have any saved-FPR movement. **#82 is overwhelmingly a
scratch-register class, and that is why declaration sweeps come back empty on it.**

**Caveat on the oracle, recorded so nobody over-reads it.** `slot_oracle` only pins a slot when
an adjacent swap induces a clean transposition. It logged **490** swaps that changed the object
without being one, and a sample of 60 of those did move registers — including a full six-cycle
`(r26 r31 r30 r29 r28 r27)` from one swap in `cMenuSetItems`, which is the band ROTATING because
a swap changed its membership. So "the permutation touches no declaration-owned register" (53 of
82 rows) is strong evidence of unreachability, **not a proof**, and no row should be pruned on it.

**The parse census, run explicitly.** §26's law that an unparseable row reads like a cleared row
is worth a standing check, so both parsers were run over all 139 rows: exactly **one** row either
one refuses — `trackBuildBlockTriangles`, the K&R definition §26 found by hand. `find_function_body`
now steps over K&R parameter declarations between the close paren and the body (regression-checked
against 57 stable rows: 0 block-census changes), so that row is back in the population for every
tool instead of being a permanent hand job. The other refusals are honest: 37 rows have no
reorderable assignment run and `mmFreeDeferred` has no declaration block with two items.

**A key nobody had swept: OPERAND ORDER.** If the residual is scratch registers holding unnamed
expression temporaries, the source key for it is the shape of the expression, and the smallest
edit that changes that shape is swapping the two operands of one commutative operator:

    a * b + c * d   ->  fmuls f0,f3,f4 ; fmadds f1,f1,f2,f0
    b * a + c * d   ->  fmuls f0,f3,f4 ; fmadds f1,f2,f1,f0
    c * d + a * b   ->  fmuls f0,f1,f2 ; fmadds f1,f3,f4,f0

Both the operand columns and which subexpression lands in the scratch register first move, and
neither `brute_match` (declarations) nor `stmt_sweep` (statements) can reach any of it.
`tools/operand_sweep.py` offers only provably safe sites — both operands side-effect-free atoms,
the site not inside a longer chain of its own OR of any higher-precedence class, no cast, and no
literal-first rewrite (`8 * t0` is legal C that nobody wrote in 2002) — and re-checks each
rendered variant as an exact transposition of two balanced operands before writing it.

**Read the guards, because the first version of this tool was WRONG and its hits were real.** A
`+` operand runs *through* a `*`, so taking the neighbouring atom turned `verts + j * 12` into
`(j + verts) * 12` and `gridX + gridZ * grid->sizeX` into `gridZ + gridX * grid->sizeX` — different
arithmetic that scored **better** and was applied by the tool's own gate. `(u32)x` was read as a
parenthesised operand and spliced the cast off its argument. A fuzzy score cannot tell a better
ordering from a wrong computation, so a rewriting sweep needs a semantic guard of its own and
every hit needs reading before it is landed.

## 28. The cap classes, audited against a fresh measurement (2026-08-03, A96)

Every class in §5 was carried forward from the lane that first hit it. Some of those lanes
measured; some described. This section re-measures all of them at `34c954cf62` and prices each
one, because a wrong cap description is worse than an unpriced one: it tells the next lane not to
look.

### 28a. What objdiff actually charges, per operand

The population is the **205 sub-100 functions** in `report.json` (plus the 3 that carry no
`fuzzy_match_percent` at all — the `model.c` paired-single trio). Convert each row's score to
instruction-equivalents, `loss = (100 - fuzzy)/100 * size/4`, then diff target against ours and
count what differs operand by operand:

| what differs between two aligned instructions | charged |
|---|---|
| one **register** operand | **0.05** instructions |
| one **immediate / displacement** operand | **0.01** instructions |
| the **mnemonic**, or an insert/delete | **1.00** instruction |
| the **relocation NAME** at an equal address (class #70) | **0.000** |

The evidence, not the assertion:

* **92 rows** have a residual made only of register-operand differences. `loss / (register
  operands differing)` is `0.0500` for every one of them — minimum equals maximum across counts
  from 2 to 280.
* **8 rows** have a residual made only of immediate differences. All eight are `0.0100` exactly.
* **110 of the 205** fit `0.05*REG + 0.01*IMM + 1.00*WHOLE` to the sixth decimal with the
  relocation weight at zero. **84 of those 110 carry relocation-name differences** — one carries
  174 — and the fit needs them weighted at exactly 0.000. That is the first positive control this
  project has ever had for "#70 is free"; it was previously an inference from the tool's
  documentation. **No sub-100 row anywhere has a residual made only of relocation names**, which
  is the same statement from the other side.
* The remaining 95 rows over-predict, always. `difflib` fragments an alignment where objdiff
  matches the pair and charges a fraction, so the model is a floor on those rows and never a
  ceiling — it cannot make an unreachable row look reachable.

### 28b. Why the cheapest class in fuzzy is the dearest in `matched_code`

`matched_code` is a pure threshold counter over function sizes, exactly:

    matched_code = total_code - sum(size of every sub-100 function) - sum(size of the 3 unscored)
    2 519 576    = 2 867 956  - 346 928                             - 1 452

A row losing 0.01 instruction-equivalents and a row losing 5.0 forfeit **the same bytes** — all of
them. So the ranking by fuzzy and the ranking by `matched_code` are different rankings, and #67 is
where they disagree hardest: it is the cheapest thing objdiff charges for and it is currently
holding a whole unit's 2 608 bytes out of `matched_code`. Describing it as "score-free" is what
kept it off every worklist.

### 28c. The price of each class today

Exclusive ownership: the bytes of every function whose entire scored residual is that class and
nothing else. `WHOLE`-bearing buckets are upper bounds (see the alignment caveat above); the
GPR/FPR/FRAME-only buckets have a clean alignment and are exact.

| class | functions | `matched_code` forgone | share of the 348 380 B gap |
|---|---|---|---|
| #108 GPR register permutation, exclusively | 80 | 139 544 | 40.1% |
| #82 FPR permutation, exclusively | 11 | 13 952 | 4.0% |
| operation/order only (`WHOLE`, no operand class) | 21 | 19 032 | 5.5% |
| GPR + non-frame immediate | 3 | 5 392 | 1.5% |
| **#67 frame displacement, exclusively** | **8** | **2 608** | **0.75%** |
| the never-touch islands (incl. the 3 unscored) | 8 | 6 488 | 1.9% |

### 28d. The three descriptions that did not survive, and the two names that had gone stale

1. **"#67 frame/displacement — objdiff normalises ... score-free" is false.** It is charged 0.01
   per operand. Corrected in §5.
2. **"#108 ... are WELDED" contradicts this document's own §26**, which built 34 100 orderings
   over the class and landed 8 of them, and §27, which says the cap is thin. §5's sight-list was
   never updated when §26/§27 landed.
3. **The index row for the colouring cap still stated §26's TWO-key model** that §27 refuted in
   this same file. Corrected.
4. **`fn_80007F78` is `modelRenderInterpolateRootTransform`** (96.682, 2 212 B) and **`render.o
   gap_03` is `gap_03_80006C6C_text`**, which exists only in the carve. Both were banked under
   names that resolve to nothing in the tree.

`setGQR6` re-reads **50.000** and `setGQR7` **70.000**, exactly as §5 states; those rows are
accurate. `#110`/`#113`/`#126`, array-subscript value-numbering, peephole branch-FOLD and
flow-sensitive const-prop appear in §5's sight-list and **nowhere else in `docs/`** — their
measurements live only in per-row notes in the memory topic files. §23b already re-priced the
`li`-vs-`mr` quarter of #110 at 17 rows; the rest of that group has no aggregate price and this
section does not invent one.

**Corrected in §29c (A97).** Two of those four DO appear elsewhere in `docs/`: §24b carries a full
measured entry for flow-sensitive const-prop (`playerCacheMoveRootHeights`, nine spellings) and for
the dead-tail `b`-stub class (`textureLoad` + `loadTextureFiles`, eight callee spellings). The
group as a whole is now priced — §29c attributes all 21 whole-instruction-only rows / 19 032 B —
and branch-FOLD, array-subscript value-numbering, `#113` and `#126` come out at **0 B exclusive**.

### 28e. The parameter-save-area law, applied forward: population 8, yield 0

A95's mechanism — MWCC places the first local at `8 + sizeof(the function's own incoming
parameters)`, packed by natural size — predicts a class of rows whose entire residual is a frame
displacement. Swept over all 205: **the population is exactly 8, and all 8 are `trig`.** Nothing
else in the tree has a residual made only of frame displacements. Five further rows carry a
FRAMEDISP component, and in every one of the five it is a cascade off a different frame size
inside a residual dominated by register and shape differences (`zlbDecompress`,
`trackBuildBlockTriangles`, `allocLotsOfTextures`, `expgfx_updateActivePools`,
`Checkpoint_buildControlPoints`) — none is a parameter-list shape.

The law itself reproduces: changing `float fsin16Approx(int angle)` to `short` moves `sth
r0,12(r1)` / `addi r3,r1,12` to `10(r1)` — retail's exact displacement — and adds an `extsh r0,r31`
retail does not have. Eight spellings measured at this parent, on `fsin16Approx`:

| parameter type | `fsin16Approx` |
|---|---|
| `int` (current) | **99.96970** |
| `short` / `signed short` / `s16` / `char` / `s8` | 96.81818 |
| `unsigned short` / `u16` | 95.15151 |

Every 1- or 2-byte spelling trades two 0.01 charges for one 1.00 charge and is 3.2-4.8 points
worse. **PRICED at 2 608 `matched_code`, confirmed independently of A95.** Do not re-probe the
parameter list; if this row is ever opened it will be by something that removes the `extsh`, not
by something that resizes the parameter.

## 29. The frontier ranked by BYTES FORFEITED, and the whole-instruction bucket priced (measured 2026-08-03, A97)

§28 established that `matched_code` is a threshold counter, so a row at 99.99 forfeits exactly as
many bytes as a row at 5.0. This section applies that as a worklist and then closes the one bucket
§5 named without ever pricing.

Everything below is measured at `a4e893e13e` (tree 99.818634 / `matched_code` 2 520 188 /
`matched_data` 1 195 969 / 915 of 1043), where the frontier is **204 sub-100 rows / 346 316 B**
plus the 3 permanently unscored paired-single bodies (1 452 B).

### 29a. The exclusive-class price, re-derived independently

§28c's table reproduces at this tip from a fresh script, with the register bucket split into GPR
and FPR (§28's own classifier did not split them, which is why its `REG`-only bucket read 92 rows
where §28c prints 80 + 11 + 1):

| exclusive class | functions | `matched_code` forgone | share of the 347 768 B gap |
|---|---|---|---|
| GPR permutation only | 79 | 138 932 | 39.95% |
| GPR + `WHOLE` | 34 | 58 856 | 16.92% |
| GPR + immediate + `WHOLE` | 18 | 36 192 | 10.41% |
| GPR + FPR + immediate + `WHOLE` | 7 | 23 936 | 6.88% |
| `WHOLE` only | 21 | 19 032 | 5.47% |
| FPR permutation only | 11 | 13 952 | 4.01% |
| GPR + immediate | 3 | 5 392 | 1.55% |
| frame displacement only (`trig`) | 8 | 2 608 | 0.75% |
| all remaining mixed buckets | 23 | 47 416 | 13.64% |

One row moved off the frontier between §28's parent and this one, which is the whole difference
between its 80 / 139 544 and this 79 / 138 932.

### 29b. The reframing that the byte ranking actually produces

Rank the 204 rows by objdiff's own loss, `(100 - fuzzy)/100 * size/4` instruction-equivalents:

* **149 of the 204 rows sit within 3.00 instruction-equivalents of 100.0, and they hold
  204 564 B — 59% of the entire code gap.**
* The correlation runs the *wrong* way from intuition: the biggest rows are among the closest.
  `Effect3_spawnObject` forfeits **7 796 B for 15 differing register operands** (loss 0.75);
  `trickyUpdateMovementState` forfeits **8 764 B for 34** (loss 1.70); `pauseMenuDraw` **4 564 B
  for 10** (loss 0.50); `Scarab_update` **3 476 B for one instruction** (loss 0.60).

So the honest statement of the frontier is not "204 functions are wrong" but "**149 functions are
within three instructions of exact, and they are worth 59% of the gap**". Any lever that moves a
handful of registers on a large row is worth more than a whole small row taken to 100.

### 29c. The `WHOLE`-only bucket, 21 rows / 19 032 B, attributed to the last byte

§5's sight-list bullet ("zero-weld `li`-vs-`mr`; dead-tail `b`-stubs; allocator remat; invariant-
address CSE weld; same-field-reload; peephole branch-FOLD; array-subscript value-numbering;
flow-sensitive const-prop; large-const misc") has never carried a price. It can be priced exactly,
because a row whose entire scored residual is whole instructions is a row those mechanisms own
outright. All 21 are attributed; the bucket sums to 19 032 B with nothing left over:

| row | bytes | mechanism | priced at |
|---|---|---|---|
| `Scarab_update` (262) | 3 476 | allocator remat, `mr` where we emit `li` | §23b |
| `errorThreadFunc` (dll_80136a40) | 2 776 | scheduler transposes two adjacent `addi` | §29d, NEW |
| `curves_advanceCollision` (engine/21) | 2 472 | allocator remat `li`/`mr` | §23b |
| `videoInit` (pi_videoinit) | 2 132 | `mfmsr`/`mtmsr`/`mfhid0`/`mthid0`, no intrinsic | §5 island |
| `playerStateMountBike` (195_Player) | 1 452 | mask materialised `li r0,-3; and` for our `rlwinm` | UNPRICED, owner-hot |
| `intersectModLineBuild` (track_dolphin) | 1 352 | allocator remat, `mr r4,r5` for `li r4,0` | §23b |
| `dll_98_spawnEffect` (modgfx/152) | 1 040 | same-field-reload: we forward the store, retail reloads | §29d, NEW |
| `wispBaddieProcessAnimEvent` (202/sharpclaw) | 1 000 | scheduler load-delay filler | §15 |
| `atan2fHighPrecision` (acosf) | 480 | target-unmerged dot-compare | §1 |
| `loadTextureFiles` (texture) | 436 | inliner's orphan duplicate preheader | §24b |
| `debugPrintfxy` (dll_80136a40) | 424 | address CSE: retail materialises `&text[-1]` twice | §29d, NEW |
| `babyCloudRunner_turnTowardTarget` (332) | 352 | surplus `extsh` before a narrow store | §29d, NEW |
| `playerCacheMoveRootHeights` (195_Player) | 352 | flow-sensitive const-prop into the `li` | §24b |
| `mathSinCosf` (sincosf) | 320 | parameter-home copy-back `fmr f1,f28` | §1 |
| `atan2f` (acosf) | 272 | dot-compare | §1 |
| `atan2f_fast` (acosf) | 240 | dot-compare | §1 |
| `removeButtonObject` (gameloop_buttonobj) | 220 | dot-compare, unroll-guard `srwi.` | §1 |
| `mathTanf` (MSL math_8029454c) | 148 | parameter-home copy-back `fmr f1,f28` | §1, row ADDED |
| `modelBoneTransforms_next` (model) | 72 | private-ABI island | §5 |
| `setGQR7` (model) | 8 | no `mtgqr` intrinsic | §5 |
| `setGQR6` (model) | 8 | no `mtgqr` intrinsic | §5 |

Grouped: allocator remat **7 300 B**, the never-touch islands **2 220 B**, the dot-compare and its
parameter-home cousins **1 680 B**, the inliner and const-prop rows of §24b **788 B**, the
scheduler filler **1 000 B**, the four rows first mechanised here **4 592 B**, and one owner-hot
row still unpriced **1 452 B**.

**The classes that own ZERO of it.** Array-subscript value-numbering, peephole branch-FOLD,
invariant-address CSE weld, unroll-tail-bound remat and the `#113`/`#126` large-const rows have
**no row anywhere on the frontier whose residual is exclusively theirs**. They are real compiler
behaviours and they appear as components inside mixed residuals, but their exclusive price at this
tip is **0 B**, and that — not silence — is their entry. `#110` is the allocator-remat group and is
priced above and in §23b.

**Correction to §28d.** It states that flow-sensitive const-prop, peephole branch-FOLD,
array-subscript value-numbering and `#110`/`#113`/`#126` "appear in §5's sight-list and nowhere
else in `docs/`". Two of those are wrong: **§24b already carries a full measured entry for
flow-sensitive const-prop** (`playerCacheMoveRootHeights`, nine spellings) **and for the dead-tail
`b`-stub class** (`textureLoad` + `loadTextureFiles`, eight callee spellings). Only branch-FOLD,
array-subscript VN, `#113` and `#126` were genuinely unpriced, and the paragraph above prices them
at zero.

### 29d. Eight rows worked off the byte ranking; yield 0, 33 spellings measured

Every row below was opened because of what it is worth in bytes, not what it reads in fuzzy.

* **`errorThreadFunc`** (dll_80136a40, 2 776 B, 99.95389). One instruction transposed: retail emits
  `addi r5,r3,-16256` (`rowColor`) before `addi r4,r29,76` (`rows`), we emit them the other way
  round, inside a block whose declaration order *already* matches retail's emission order. **Nine
  spellings**: three declaration permutations, declaration/initialisation split, `for`-loop form,
  `int` for the `u16`, `rows--` in the guard, statement order inside the loop body, and the stored
  value inlined as a literal. Eight are byte-identical to baseline; the ninth (`rows--` in the
  guard) is worse. **This row refutes §15's sufficiency test**: the slid instruction *is* one the
  source text names — `rows = y + 0x4c` — and it is still a scheduler slot. "The slid instruction
  is one the source names" is NECESSARY, not sufficient.
* **`dll_98_spawnEffect`** (modgfx/152, 1 040 B, 99.76923). Retail writes
  `resource->sequenceParams[1]`, **reloads it with `lha`**, and stores it to `[2]`; we re-extend the
  register with `extsh`. **Eight spellings**: no cast, `(s16)` cast, an `int` temp feeding both
  stores, a `u8*` pun on the read, a `u8*` pun on the write, and both chained-assignment
  directions. MWCC forwards the store in every one; five of the eight also delete an instruction.
  The `sth`/`lha` shape does occur in our own tree — `objfx_spawnCrystalOrbitEffects` in
  `engine/10_expgfx` has three of them — but in every case the stored value arrived **through
  memory from a float conversion**, so no register held it. With an integer register live, MWCC
  GC/2.0 always forwards. Only `volatile` defeats it, and that is banned.
* **`debugPrintfxy`** (dll_80136a40, 424 B, 99.38680). Retail materialises `text - 1` twice
  (`addi r26,r1,115` and `addi r27,r1,115`); we compute it once and copy (`mr r26,r27`). **Four
  spellings**: swapping the two statements, spelling both sides identically, spelling both as
  `&text[-1]`, and separating them with the `savedFrameBuffer` assignment. All worse. The two
  initialisers are *already* written with different syntax and MWCC still value-numbers them.
* **`babyCloudRunner_turnTowardTarget`** (332, 352 B, 98.86364). One surplus `extsh` in front of
  `sth r0,0(r28)` for `obj->anim.rotX += (yawStep >>= 3)`. **Seven spellings**: `(s16)`, `(short)`
  and `(u16)` casts on the compound right-hand side, the shift split into its own statement (with
  and without the cast), `rotX = rotX + ...`, and `s16 yawStep`. Every one is worse — the split
  costs ten instructions, the casts cost five. The A59 narrow-store rule predicts our output
  exactly (`+=` with an `int` right-hand side does not elide); retail elides anyway, and no
  spelling of the right-hand side reaches it.
* **`Effect3_spawnObject`** (engine/28, **7 796 B**, 99.96152 — the best bytes-per-probe row on the
  frontier). Fifteen differing register operands and **174 relocation-name differences weighted at
  0.000**, which is a second positive control for §28's `#70` result on a single row. The permuted
  registers are **parameter homes**: retail lands `r4→r27, r5→r28, r6→r29, r8→r30` in ABI order
  with the first local at `r31`; we land `r4→r31, r6→r30, r8→r27` with the local at `r29`.
  `slot_oracle` reports pi non-empty but **no declaration slot owning any register**, and all
  **six permutations of the three-declaration block are byte-identical**. Deleting the
  `spawnParams = spawnParamsIn` alias (which reads like scaffolding) costs 0.75 → 20.55; hoisting
  the `hasAttachedSource` computation into its initialiser costs 0.75 → 6.50. **The alias local is
  load-bearing.** Parameter homes are not reachable from the declaration list — the same wall
  §15 hit on `debugTextDrawToFrameBuffer`.
* **`newclouds_run`** (engine/7, 2 376 B, 99.94613). Retail computes the slot address into its
  final register and increments in place (`add r27,r30,r23; addi r27,r27,16`); we route through
  `r3`. **Four spellings** of the two-step address — folded into one expression, parenthesised,
  constant written first, and `cloudSlot += 4` — cost 0.32 → 41.02, 41.02, 41.02 and 4.38. The
  two-statement form already in the tree is the best reachable one.
* **`mathSinCosf` / `mathTanf`** (sincosf, MSL, 320 + 148 B). Both miss retail's `fmr f1,f28`
  parameter-home copy-back. §1 already banks `mathSinCosf` with five spellings; two more (a local
  copy of `x`, and splitting the declaration from the call) are worse or do not compile. **`mathTanf`
  is the same mechanism and is added to §1's table.**

### 29e. Two instrument notes

**A classifier that mis-buckets memory operands.** The per-row classifier A96 used for its
*narrative* (`/private/tmp/A96_classify.py`, never landed in `tools/`) decides a pair's kind with
`REG_RE.match(operand)`, which does not match `0x8(r3)`. A pair differing only in the **base
register of a memory operand** therefore reads as `IMM`. Its `REG`-only bucket comes out 40 rows
where the sound model gives 92. §28c's published table came from the *other* script
(`A96_model.py`), which splits `N(rX)` before deciding, so **the document is right and only that
one scratch script was wrong** — but any lane that reaches for it should split the displacement
first.

**A probe loop that leaves stale objects behind a clean `git status`.** A restore-by-content probe
loop that writes the source back but does not rebuild leaves the *object* holding the probe's code
while `git status` reads clean. Two of this lane's loops did exactly that (an assertion fired
mid-loop; another skipped its final rebuild), and the rows read 10.18 and 3.00 against a 1.00
baseline until `ninja all_source` was re-run. **A probe loop must rebuild after its last restore,
and a lane must re-measure the whole report before trusting any baseline it took mid-sweep.**
`git status` is not a build-state oracle.

## 30. The pure-permutation class partitioned, and the parameter-home law (measured 2026-08-03, A98)

`tools/perm_class_scan.py` (`--self-test`, 13 controls, all PASS) isolates the sub-100 rows whose
**entire** residual is a register renaming: equal stream length, 1:1 alignment, identical mnemonic
and identical operand text once register names are abstracted, and **one injective map sigma that
rewrites our whole stream into retail's**. Such a row asks the code generator for retail's
operations in retail's order and differs only in colouring, so no operation, ordering or addressing
lever can reach it. At `2a5c0e0fed` (99.818634 / 2 520 188 / 1 195 969 / 915 of 1043):

| class | what sigma moves | rows | bytes forfeited |
|---|---|---|---|
| **PARAM-HOME** | at least one register the entry block homes an argument into | **10** | **19 136** |
| **LOCALS-ONLY** | callee-saved band only, no home | **6** | **14 416** |
| **SCRATCH** | a volatile register (`r0`-`r13`) | **3** | **840** |
| | | **19** | **34 392** |

Rejected buckets, for scale: LENDIFF 49 / 79 852 B, OPERAND 49 / 74 432 B, NOTPERM 35 / 49 512 B,
NONFUNC 28 / 59 272 B, MNEMONIC 23 / 45 580 B, NONINJ 4 / 4 728 B. **The `NOTPERM` bucket is the
control that matters**: 35 rows where a single map exists site-by-site but does not rewrite the
whole stream, i.e. the verification arm fires.

### 30a. The law, from controlled compiles (GC/2.0, the real `-O4,p` cflags)

1. The callee-saved GPRs form ONE contiguous band with base `32 - N`, materialised by
   `_savegpr_<base>`. Parameters needing a home take a contiguous run of it; locals take the rest,
   **descending in declaration order** (A86's band law, reconfirmed).
2. **In the simple regime the homes are POSITIONAL**: argument register `rN` homes at `base + N - 3`,
   and the map is completely insensitive to which variable sits in which slot. Measured on a
   six-`int`-parameter probe with an asymmetric body (branches, a loop, unequal use counts) over four
   parameter-list permutations: the home is a function of the **position**, every time.
3. **In the complex regime the homes follow the VARIABLE, not the position.** On
   `Effect3_spawnObject` four different parameter-list orders — including moving `spawnFlags` to
   argument 1 and `effectId` to argument 6 — produce the **identical variable to home map**
   (`sourceObject` r26, `effectId` r31, `spawnParams` r28, `spawnFlags` r30, `extraArgs` r27). This
   **bounds §27's "param i -> f(28+i)" to the simple regime**; it is not a general law.
4. **Which end of the band each group takes flips with body complexity.** Measured on a synthetic:
   at four call-defined locals the locals sit at the TOP of the band and the parameters below it;
   adding eight switch cases to the same function moves the parameters to the top and the locals
   below. Nothing in the source selects the regime.
5. **`register` is inert.** MWCC GC/2.0 ignores the storage-class specifier for band placement
   (four probes: one parameter, one local, all locals, none — identical objects).

### 30b. `Effect3_spawnObject` — the PARAM-HOME row worked to exhaustion (7 796 B, 0.75 loss)

Every axis measured inert (home map unchanged in all of them): **7 declaration orders** of the
three-local block including A91 split forms; **4 parameter-list orders**; **5 parameter retypes**
(`u32`->`int` flags, `int`->`u32` id, `u8`->`int` modelId, and two that do not compile);
`static inline`->`static`; the inline helper **hand-expanded at all 10 call sites**; the helper
rewritten to return `void`; the `hasAttachedSource` local replaced by the repeated expression so
CSE mints the temp instead; **16 compiler flag combinations** (`-O2/3/4`, `,s`/`,p`, `-sym on`,
`nopeephole`/`noschedule`/`nostrength`/`nolifetimes`/`noglobal`/`nocse`, `-inline off/deferred`);
and **7 compiler versions** across the GC/2.x line — 1.3.2, 2.0, 2.0p1, 2.5, 2.6 and 2.7 all
reproduce our map exactly. (3.0a3/3.0a5 give an ascending map, but from a different band base, so
they differ elsewhere and are not this project's compiler.) `expr_sweep --assoc` clears **5**
operand-order rewrites here, and `slot_oracle` reports no declaration slot owning any of the four
moved registers. **PRICED 7 796 `matched_code`.**

### 30c. The tree-wide control that refutes the tempting inference

Inside the ten PARAM-HOME rows, retail's homes ascend with the argument register in **8 of 9**
judgeable rows and ours in only **3 of 9** — which invites "retail's compiler always allocates
parameter homes in argument order". **False.** `perm_class_scan.py --canon` measures it on every
function in the tree with at least two homes: **retail 1 228 of 1 471 (83.48 %) ascending, ours
1 220 of 1 472 (82.88 %)**. The regime is body-determined and we reproduce it in five sixths of the
tree; the skew inside the mismatching rows is a **selection effect**, not a compiler difference.

### 30d. Yield, and the sweeps behind the zero

**Zero bytes recovered.** `expr_sweep --assoc` over 18 of the 19 rows (`playerBuildLedgeClimbProbe`
left alone, owner-hot): **420 semantically-cleared operand-order rewrites across 16 rows, 0 hits**;
the other two rows have **nothing to sweep**, which is not the same reading as "cleared". Over 13
rows `slot_oracle` finds the moved registers declaration-owned in only **two** — `SHthorntail_update`
(slot 4 owns `r26`) and `Link_render` (slot 3 owns `r28`), one of the two moved registers each — and
`brute_match --strategy all --cross` on both (17 and 14 declarations, swaps and moves) is **inert**.
`brute_match --strategy radius2 --cross` on
`dimlavasmash_setBlockSurfaceFlags` (3 declarations, the whole neighbourhood) and
`--strategy all --cross` on `shadowVolumeBeginFrame`: inert. Targeted declaration moves and split
forms on `trickyUpdateMovementState` (the 8 764 B row: the two moved registers hold
`objectWalkGroup` and a constant `1`) and three alias/retype forms on `staff_setupSwipe`: inert.
`staff_setupSwipe`'s honest retype (`u8* swipe` -> `StaffState*`) is blocked by type visibility in
`include/main/dll/dll_00E2_staff_api.h`, i.e. a §13 cross-TU decision, not a colouring one.

**Instrument note, the same shape A97 recorded.** The first version of this lane's scanner read a
function's homes through a 40-line window with a prologue mnemonic allowlist, so a leading
`fmr f31,f1` terminated the scan and `mapSetup` came back with **no homes at all** — filing a
PARAM-HOME row as LOCALS-ONLY. The landed tool walks until the first instruction that is neither a
home nor precedes one, and is controlled by `--self-test`. **Classify the operand, not the token,
and control the parser before believing the partition.**

## 31. Statement order IS a colouring key — §27 refuted, and both order axes measured exhausted (2026-08-04, A100)

§27 concluded that "declaration order is the ONLY source key for the register assignment;
statement order is the source key for emission ORDER", from a control that pinned four
declarations and permuted four assignment statements through all 24 orders for one register
assignment. A99 then measured that in the REUSE regime (live locals outnumbering the
callee-saved band) a *declaration*-order change stops being a permutation at all, and left the
statement axis in that regime unswept. This section crosses the two and reports what the cross
actually says, which is neither lane's expectation.

### 31a. The discriminator, because neither the score nor the multiset is one

A statement move legitimately reshuffles volatile registers and slides an address base's
materialisation without touching a single named local's home: in the no-reuse control that
happens in 80 of 100 orders. A raw instruction-multiset comparison therefore reports "the
assignment moved" when nothing of the sort did. `tools/stmt_reuse_control.py` compares the
**callee-saved band signature** instead — the stream restricted to lines mentioning `r14`-`r31`,
every volatile abstracted to a placeholder — which moves if and only if a web's home moved. The
tool's `--self-test` runs the positive control that verdict needs: the same bodies swept on
*declaration* order, where the signature must move. **50 of 50 ASSIGN.** Without that arm a flat
statement-order result is indistinguishable from a blind instrument.

### 31b. Reuse is NOT what decides it — the run's SHAPE is

| regime | what it varies | 100 statement orders |
|---|---|---|
| `noreuse` 6 locals under the band | — | 0 ASSIGN (80 SCRATCH / 20 ORDER) |
| `reuse` 21 locals over the band | the allocator must host 2+ webs per register | **0 ASSIGN** |
| `stagger` 21 locals, the run's ten webs die at ten different points | live ranges change by ten different amounts | **0 ASSIGN** |
| `hetero` 20 locals, the run's eight statements have eight different SHAPES | — | **81 ASSIGN** |

So the reuse regime does not break §27's law and the live-range story behind this lane's brief is
wrong. What breaks it is that §27's control — and the first three regimes here — permute
statements that are structurally interchangeable (`ci = gT[n+i]`, eight times over). No
permutation of interchangeable statements can change which webs interfere or what the value
numberer sees. Give the run's members different shapes and the band moves.

### 31c. The real-code arm, which is the one that decides

A synthetic can only show the axis reaches the band in *some* body. `stmt_reuse_control.py
--real` permutes dependence-legal statement runs in eight sub-100 rows, rebuilds the unit,
disassembles the symbol out of the unit's own object and compares band signatures — no score
anywhere in the loop. **64 permutations, 31 ASSIGN / 33 BAND-HELD.** `debugPrintDrawRecord` moves
on 8 of 8; one reorder there takes `x0` from `r24` to `r25`, changes the per-register definition
profile (`r23` 9->5, `r25` 7->9) and even reselects instructions (`cmplwi r23,2; addi r23,r23,-2`
becomes `addi r24,rS,2`). **Statement order is a source key for the register assignment.** §26's
"the two hit sets are disjoint because the tools attack two different buckets" is the wrong
reason for a right observation.

### 31d. And both order axes are nevertheless exhausted on this frontier

Correcting the mechanism does not move the score, because the tree already sits at the optimum of
both axes. Population re-derived at `e501a44f87`: `perm_class_scan` NOTPERM 36 / NONFUNC 27 /
NONINJ 4 = **67 rows / 113 512 B** (A99's total to the byte; one row had moved between its two
buckets). 14 owner-hot, 3 banked, **12 have no reorderable assignment run at all** — which is not
the same reading as cleared — leaving 37 sweepable.

| sweep | rows | probes | hits |
|---|---|---|---|
| `stmt_sweep --strategy all --max-variants 400` (every run, every scope) | 37 | **5 717** | **0** |
| `decl_split_sweep --strategy all --apply-best` | 40 attempted, **8** with a split-enlarged neighbourhood | 503 | **0** |
| `expr_sweep --greedy` over the FPR-only rows | 12 | **381 semantically-cleared rewrites** | **0** |
| `brute_match --strategy all` on the one workable saved-FPR row | 1 | 399 | 0 |

0 build failures, 0 parse failures, 0 misparses, 0 non-zero exits other than the honest "no block
whose legal neighbourhood the split enlarges" (32 of 40 rows). Every split control that ran was
**BYTE-IDENTICAL**, so the split itself remains free. Total **7 000 orderings and rewrites, zero
bytes recovered.**

### 31e. The float band obeys the same reuse law, and #82 is confirmed unreachable by declaration

`tools/fpr_reuse_control.py` is A99's experiment with `float` locals and an FPR-aware classifier:
**9 locals under the band -> 120 of 120 PERM; 24 locals over it -> 120 of 120 NONFUNC.** The reuse
regime is not an integer-side phenomenon. And the number that matters for #82: across both
regimes, **8 085 differing FPR operands, 0 of them in `f0`-`f13`.** A declaration-order change
never touches the volatile half of the float file, so a scratch-FPR residual is not
declaration-reachable — measured, not argued.

**An instrument trap this uncovered.** MWCC saves and restores FPRs one instruction per register
in this configuration (there is no `_savefpr` helper, unlike `_savegpr`), so the prologue names
the saved *set*. Two colourings using the same set have an identical save block, and re-applying
a value map to it can never match — which makes a plain whole-stream permutation check report
**NOTPERM on every float colouring difference**. `fpr_reuse_control` excludes `stfd/lfd/psq_st/
psq_l fN,imm(r1)` from the re-application test; without that exclusion the no-reuse regime reads
30/30 NOTPERM instead of 30/30 PERM.

**And a consequence for the standing partition.** `perm_class_scan.permutation` abstracts only
`r` names, so a row differing solely in an `f` operand fails its operand-text comparison and is
filed under **OPERAND**. A99 read that bucket as frame size (#67); it is that *and* every float
colouring row in the tree. Re-censusing the 204 sub-100 rows by which register class the whole
residual touches gives LENDIFF 46 / GPR-only 86 / MNEMONIC-or-OPERAND 55 / mixed FPR+GPR 2 /
**FPR-ONLY 15 rows, 18 820 B** — of which **13 are volatile-only (16 156 B)** and only two touch a
saved FPR. (The brief carried "11 rows / 13 952 B"; the measured figure is 15 / 18 820.)

### 31f. Arithmetic corrections carried into this window

* **Informative completion is 910 of 1000, not 910 of 1005.** 1043 units; 38 `main/auto_*` are
  vacuous (`total_data` 2 342 B present, `matched_data` absent, no `total_code`, none complete)
  and 5 more report 100.0 and `complete` with no code, no data and no functions (`AX`,
  `MWCriticalSection_gc`, `OSExec`, `synth_sequence`, `synth_seq_queue`). 1005 drops only the
  auto units while 910 already has the 5 removed; the consistent pair is **910 of 1000**.
  Raw 915 of 1043 is correct.
* The FPR-only population above.

## 32. The frontier partition was float-blind, and what that voids (measured 2026-08-05, A101, at `1e25ffc15b`)

`perm_class_scan.py` abstracts `\br\d{1,2}\b` and nothing else. Float register
names are therefore literal text in its operand comparison, so every row whose
residual is a float register operand fails `REG.sub("r#", ...)` equality and is
filed under OPERAND — the bucket §29 read as frame size and displacement (#67).
`tools/fp_perm_class_scan.py` abstracts `r` AND `f` names, derives the two maps
separately (the namespaces are disjoint), and reports the old bucket beside the
new one so the re-partition reads as a cross-tab. 20 controls, including a
direct reproduction of the save-block trap below.

### 32a. The re-partition, all 205 sub-100 rows

| bucket | GPR-only classifier | float-aware |
|---|---|---|
| LENDIFF | 49 rows / 79 852 B | 49 / 79 852 |
| OPERAND | 48 / 72 616 | **30 / 48 580** |
| NONFUNC | 27 / 56 660 | **35 / 67 448** |
| NOTPERM | 37 / 53 128 | **42 / 58 820** |
| MNEMONIC | 22 / 43 988 | **23 / 46 584** |
| NONINJ | 3 / 2 152 | 3 / 2 152 |
| PERM (PARAM-HOME + LOCALS-ONLY + SCRATCH) | 19 / 34 392 | **23 / 39 352** |

**18 rows / 24 036 B were in the wrong bucket**, all of them out of OPERAND:
8 → NONFUNC, 7 → NOTPERM, 2 → PERM, 1 → MNEMONIC. The pure-permutation class
grows 19 → 23 rows / 34 392 → 39 352 B. (The same partition at the previous
tip `8e52163a24` read 206 rows with identical reclassification structure; one
MNEMONIC/OPERAND row left the population under the naming lane between the two.)

### 32b. What the OPERAND bucket actually holds, now that floats are visible

Of the 30 rows left: 16 GPR-only / 27 796 B, 5 GPR+FPR / 17 376 B, 1 FPR-only /
800 B, and **8 rows / 2 608 B with no differing register operand at all** —
those 8 are the genuine frame/displacement rows, and they reproduce §28c's
independently-derived `frame 8 / 2 608 B` exclusive class **to the byte**. So
#67's price was right; what was wrong was the rows sitting on top of it.

### 32c. The save-block trap is REAL, GENERALISES TO GPRs, and is far narrower than claimed

MWCC saves callee-saved registers one instruction per register. When both sides
save the same SET the block is byte-identical, but a whole-stream permutation
check still applies sigma to those lines and finds `stfd sigma(f31),…` ≠
`stfd f31,…`. The block declares the SET; it is not a use of the value, so
sigma need not explain it.

Measured on the real tree, the exemption moves **2 rows of 205**, and **both are
GPR rows, not float ones**: `main/texture.c textureInitGXTexObj` (356 B, sigma
= the transposition 29↔31 over an identical `stw r29/r31,…(r1)` block, 4
exempted lines, hand-verified) and `597.c SnowBike_UpdateEngineFx` (1 080 B, 8
exempted lines).

**This voids the extrapolation, not the trap.** The "30/30 NOTPERM → 30/30 PERM"
figure was measured entirely inside `fpr_reuse_control.py`, which is a pure
synthetic; it never had a real-code arm, and on real code the rate is 2/205.
"Every float colouring row in the tree sits in its OPERAND bucket" is true —
but they do not become permutations when you look at them: only 2 of the 18
float-only rows do.

### 32d. The exemption must be BANDED, or it hides real residual

The loose form — exempt any `stfd|lfd|psq_st|psq_l fN,imm(r1)` regardless of
register band or whether the line even differs — silently swallows a genuine
volatile-FPR spill displacement difference (`stfd f0,8(r1)` vs `stfd f0,12(r1)`
reads as a clean PERM). Requiring the register to be callee-saved AND the line
to be identical keeps those. Measured tree-wide the loose rule yields **21**
PERM rows against the banded rule's **23** — it is both less safe and less
sensitive.

### 32e. Verdicts this re-partition voids

* §29's reading of OPERAND as a frame/displacement bucket — right for 8 rows
  / 2 608 B, wrong for the rest of the bucket.
* Any NOTPERM/NONFUNC population count taken from the GPR-only scanner: the
  totals move 37 → 42 and 27 → 35 at this tip.
* The brief's "NONINJ 4" and "204 sub-100 rows": measured **NONINJ 3 / 2 152 B**
  and **205 rows / 342 788 B** here (206 at the previous tip).

## 33. The volatile float half: the SET is already right, only the tie-break differs (2026-08-05, A101)

### 33a. The census, defined precisely

30 sub-100 rows have a differing float operand (54 896 B); **18 are FLOAT-ONLY**
with no differing GPR (21 008 B); of those, **15 are VOLATILE-ONLY** — every
differing float operand a pair inside f0–f13 (17 564 B) — 2 saved-touching
(2 664 B) and 1 mixed (780 B). 778 differing float operands tree-wide, 626 of
them volatile-pair. (`tools/a101_fpr_census.py`.)

### 33b. `sig` cannot fail, and that is the finding

The obvious float analogue of the integer lane's callee-saved BAND SIGNATURE is
the sequence of volatile FPRs in first-write order. It is **constant by
construction**: MWCC fills the volatile half strictly top-down from the highest
register a body needs, so the sequence is `[n−1 … 0]` for essentially every
body and every axis measured with it reads INERT whether or not it moved
anything. The signature that can fail is `vsig`, the map from the VALUE (a
load's displacement and base) to the register it lands in.
(`tools/a101_volatile_fpr_control.py`.)

### 33c. What moves the volatile assignment — synthetic, with its vacuity flag

25 variants over 6 axes, each reported with how many compile BYTE-IDENTICALLY:

| axis | moves `vsig` | byte-identical (never presented a choice) |
|---|---|---|
| ORDER (statement order of independent loads) | 0 of 5 | **5 of 5** |
| ASSOC (association / term order) | **2 of 4** | 2 of 4 |
| TEMP (number of named temporaries) | 2 of 3 | 0 |
| CSE (subexpression stated once vs twice) | 0 of 1 | 0 |
| CALL (a call between the loads) | 2 of 2 | 0 |
| COUNT (simultaneously live values) | 4 of 4 | 0 |

### 33d. The real-code arm REFUTED the synthetic — record it

The synthetic says commuting a float product is absorbed by the front end and
compiles byte-identically, which would have made `expr_sweep`'s zero on float
rows a vacuity result rather than a closure. **On real code it is false.**
`tools/a101_expr_vacuity.py` replays `expr_sweep`'s own gated candidate set and
compares object BYTES: on `mtxRotateByVec3s`, **41 of 41 cleared rewrites move
the object, 0 are vacuous** (37 commute, 4 sign). The synthetic's loads were
independent and the front end canonicalised them; real bodies do not offer that.
**`expr_sweep`'s zero on the float rows is genuine.** A synthetic too uniform
cannot fail — and this one did not, until it was paired.

### 33e. The residual is a tie-break inside a CORRECT set

Volatile signature, ours vs retail, over 13 workable volatile-only rows:
**13 of 13 use the SAME volatile SET as retail**, and 6 of 13 have the same
first-write ORDER as well yet still differ in operands. Since the set is right
the pressure is right; since these are equal-length rows with no differing
mnemonic the operation sequence is right. What is left is which value the
allocator put in which register **within a set that is already correct** — the
float-side analogue of #108, and it is reached by none of the source axes that
have been measured (declaration — A100; statement order, association, operand
order, CSE — here).

### 33f. Yield

0 bytes. `mtxRotateByVec3s` (800 B / 98.785, **not** in the previous sweep's
set) worked to 13 hand-derived shapes plus 41 gated rewrites: its residual is
2.43 objdiff units and decomposes as 48 float register operands × 0.05 + 3
displacements × 0.01, i.e. **100 % volatile float colouring**. The natural
`x,y,z` load order is the one retail's addresses ascend in and it scores
*worse* (98.785 → 98.750), because objdiff charges 0.05 per register against
0.01 per displacement — a reminder that the score ranks spellings by charge, not
by correctness. `main/lightmap.c updateEnvironment` (also previously unswept):
5 cleared rewrites, inert; it is a MNEMONIC row, so expression shape was never
its key.

## 26. The zero-cost high-word knob (`| 0x1_00000000LL`) — OWNER CALL, not landed

`wispBaddieProcessAnimEvent` (`dlls/objects/202/sharpclaw`) is one spelling away from taking its
unit to **100.00000** (a linkage flip candidate). Measured, whole-unit gated, baseline verified
byte-identical first:

| spelling | fn | unit |
|---|---|---|
| `&= ~0x40LL` (HEAD before 2026-08-05) | 99.156 | 99.89016 |
| `&= ~0x40` / `&= 0xFFFFFFBF` (32-bit, gives `rlwinm`) | 99.340 | 99.91411 |
| **`= (s32)controlFlags & ~0x40LL`** — LANDED | 99.600 | 99.94795 |
| `= (controlFlags \| 0x100000000LL) & ~0x40LL` | **100.000** | **100.00000** |

Mechanism: with a `u32` LHS the widened high word is *always* the constant `0`, and the later
`activeEventIndex = 0` store CSE-binds it, hoisting the `li`. Setting any bit above 31 **before**
the AND makes the high word non-constant, so nothing binds. The knob is only zero-cost pre-AND
(`(x & ~0x40LL) | 0x100000000LL` scores baseline); De Morgan, XOR-high and `(u64)` recasts all
measure worse. So this is provably the only spelling that reaches byte-exact.

**Why it is not landed:** the landed `(s32)` form has direct precedent in matched code
(`playerStopRidingObject`, four `flags360` siblings in `player.c`), but an explicit
`| 0x100000000LL` has **no precedent anywhere in the image**, and no 2002 developer writes it. It
buys byte-exactness by encoding a compiler fact into the source, which is the shape of a match
hack even though it is not on the banned list. Landing it costs one unit flip; declining it leaves
the unit at 99.94795 and keeps the source honest.

The residual `srawi` at every `(s32)` site is a `-opt nopeephole` TU artifact — with peephole on,
the landed spelling is byte-exact to retail. That is the real fix for this whole family and it is a
TU-profile question, not a spelling one.

## 27. `tricky` pool anchors — item A is proven and byte-neutral, but parked (owner call)

The 408-byte `.sdata2` gap in `dlls/objects/196_Tricky/tricky` decomposes into five items in
`0x50..0x164`. Three were investigated to completion (2026-08-05):

- **A — `skeetla_isInWater` (line 303): SOLVED and byte-neutral, NOT landed.** Making it a plain
  `static` (emitted, dead) mints `-100000.0f, 8.0f` at retail's 0x050/0x054 and moves the first
  divergence to 0x05c. Verified against the in-tree object: all 89 retail-paired functions have
  identical instruction bytes AND identical relocation targets, every data section byte-identical,
  `jtoracle --pair` clean, unit fuzzy and `matched_code` unchanged. Three of the four call sites take
  the temp + if/else-if chain the file already uses at `tricky.c:655` and at ~24 other longhand water
  checks — evidence that retail wrote them longhand. The fourth (`trickyUpdateCircling`) needs a
  ternary chain, because retail elides both `li r0,1` there: the preceding
  `substate = ANIMOBJD2_SUBSTATE_APPROACH` (=1) leaves 1 in `r0`, and MWCC's constant CSE is
  basic-block-local, so an if/else-if chain re-materializes it (+2 instructions) while one expression
  shares the DAG. **Why parked:** a data section scores 0 until 100%, so A alone pays nothing, and its
  value is entirely contingent on B and C — which require inventing dead helper bodies. Patch preserved
  at `scratchpad/deliver/itemA_skeetla_isInWater_static.patch`.
- **D — MISDIAGNOSED, do not attempt.** `.sdata2` literals allocate in first-EMISSION order within a
  function (verified across 31 mint-bearing functions in our own object). Retail's
  `trickyAdvanceRouteTargetAhead` emits `1.5f` at +0xf6c BEFORE `-2.0f` at +0xf98, so it cannot have
  minted `-2.0f` first; that slot was interned earlier by item C's dead helper.
  `trickyAdvanceRouteTargetAhead` mints only `1.5f`. Forcing the order costs 12-13 of 63 instruction
  words and breaks a 100% function.
- **E — LANDED 2026-08-22.** Keeping the trivial wrapper `skeetla_faceMoveVector` as the stripped
  static source-order minter, while spelling the live `moveTricky` site as a direct
  `skeetla_updateFacingFromMoveVector` call, restores the tail pool order and makes `.sdata2`
  byte-exact under the current `noautoinline` TU profile. The plain-static called form is not viable
  with that profile because it leaves a real live call and drops `moveTricky` to 92.273. The landed
  form keeps the function size stable and costs only the existing near-match row
  (`moveTricky` 99.534 → 99.493) while recovering the full section data; `banned_shapes_check` reports
  no regrowth.

Also refuted: non-static `inline` behaves exactly like `static inline` (mints nothing).

**Separate, and actionable independently of the pool:** `gObjHitsScalarZero`/`gObjHitsScalarOne` are
declared `extern` in `include/main/objhits.h` and defined NOWHERE — `objhits.o` carries them as
undefined externals (the carve-only-reference latent-LINKFAIL class).

## 34. Structural respellings cannot reach the reuse-regime tie-break — NOTPERM/NONFUNC measured closed (2026-08-05, C113, at `529d615fce`)

The one lever the exhausted order axes left standing — "a structural fix RESETS colouring" — was
aimed at the NOTPERM (42 / 58 820 B) and NONFUNC (35 / 67 448 B) buckets. It resets the
allocation; it does not reach retail's answer. A structural respelling of a reuse-regime row lands
in exactly one of two states:

1. **Web-multiset-preserving -> byte-identical.** The tie-break re-runs to the same answer.
   Measured three ways on real rows: a block-scope shadow declaration of the mismatched local
   (`pauseMenuDraw` alpha) changes nothing; merging two sequential single-assignment locals into
   one reassigned variable (`pauseMenuDrawStatusPage` ty1->alpha) is **byte-identical** — MWCC
   colouring is VARIABLE-IDENTITY-BLIND, a reassigned variable's second web does not inherit the
   first web's register; a declaration-position move is inert (consistent with §31).
2. **Web-multiset-changing -> the code moves and the score drops.** Reusing a dead parameter as
   the scratch variable recolours the surrounding entry webs (-0.04); folding a single-use local
   into its consumer moves the fctiwz placement (-1.2, and moves global reads across calls —
   unsound); respelling `x += e` as an assignment breaks constant-fold chains (below).

### 34a. expr_sweep zero on the GPR side (the integer analogue of §33's float zero)

`expr_sweep --greedy` (semantic-equivalence-gated) over **41 unique rows** of the two buckets —
every row not owner-hot and not A102's: 41 scanned / 0 unscanned, ~1 000 gated rewrites, 2 vacuous
rows disclosed (`GameUI_release`, `mapBlockRender_setShader`: no parseable candidates),
**0 improvements**. The float-side zero (§33c) now has a measured integer twin.

### 34b. The `+=` / assignment fold law (probe-verified with the unit's own cmdline, `-opt nopeephole,noschedule`)

- MWCC canonicalises `x = (a-b) + x` back to accumulator-first (`add rX,rX,r0`); a NAMED addend
  (`x = w + x`) preserves source operand order (`add rX,r0,rX`) — but only while `x` is live-out.
- At a dead-after site, ANY assignment-form update folds: the pending constant chain (`x += 10`
  upstream) is substituted through and computed into a fresh scratch, deleting the in-place
  `addi`. `x += e` is the only spelling that blocks the fold — and it pins accumulator-first
  order. A retail row showing `add rX,r0,rX` with the chain intact at a dead-after site
  (`pauseMenuDraw` x2) is unreachable by every expression spelling tried (6).
- Comma-expression order inside a for-header is an ORDER key (slides insns, -0.1..-1.4 measured);
  the tree is already at its optimum there.

### 34c. Allocator facts with no source-side handle

- Retail's consecutive same-register scratch reuse (`r28` then `r28`) versus ours' spread
  (`r24` then `r30`) arises from the same web multiset and the same free pool; the pick survives
  naming, merging and shadowing.
- A parameter can lose `r31` to locals in retail (`SB_Galleon_updateFlight`: obj=r27, short
  webs=r31). The MP4 corpus shows the identical shape (`SetEnvelopMain` param=r29 under two
  locals; `HuPrcChildKill`) and its C shows NO declaration or order trick — the ranking input is
  invisible in source.

### 34d. What stays open

`blendTextures` (main/newshadows.c, 924 B, 94.48) is the one bucket row whose divergence is
mis-decomp-scale loop-nest structure, not a tie-break — a dedicated mis-decomp lane's row, not a
respelling row. `mapLoadDataFile` (8 444 B) shows per-case slwi/add temp swaps behind the MLDF
macro puns — same tie-break family as §34c. Everything else in NOTPERM/NONFUNC should be treated
as priced alongside §30's PERM residue.

## 35. The web-structure census (C114): STRUCT-REAL is measurable, unlandable by score

Method: for every sub-100 function (193 rows scanned, 0 unscanned; owner-hot and never-touch
excluded), align target/current instruction streams positionally and compare def-use edges
(each source operand mapped to the index of its defining instruction; branch operands are
labels, never registers — an early parser draft mis-read hex `f08` as an FPR and inflated the
class; fixed and re-run).

### 35a. Partition (at parent 75c6e37a74, function bytes)

- OWNERHOT (excluded)                43 rows / 74 544 B
- LENDIFF (A102's censused bucket)   29 rows / 50 356 B
- MNEM    (A102's censused bucket)   18 rows / 36 676 B
- TIEBREAK (def-use edges identical, registers renamed) 66 rows / 94 348 B
- COMMUTE-ONLY (operand swaps on commutative ops, same def multiset — peephole
  commutation downstream of register numbering, seen inside otherwise-pure FPR
  permutations: `createNewShadowDistortionTexture`, `powf`, `hudDrawMagicBar`,
  `cMenuSetItems`, `pauseMenuDraw`, `drakorhoverpad_updateMain`) 6 rows / 12 156 B
- STRUCT-REAL (def-use edges genuinely differ)          31 rows / 63 804 B

### 35b. The scoring trap (measured, 7 independent rows)

Every faithful structural fix measured REGRESSES fuzzy while converging the def-use shape,
because objdiff charges 0.05/register and 0.01/immediate: correcting an immediate or an
operand's def-site re-shuffles the downstream register permutation, and each luck-matched
register lost (-0.05) outweighs each structure cell gained (+0.01). Instances:
- blendTextures: 31/31 combination lattice of 5 derived structural edits (pa/pb add order
  tco-before-h, rdo mullw operand order width*w, red sum redA-term-first, pc base-first `+=`
  chain, loop2 rdo-in-read-arg) — all strictly below HEAD's 94.48; the all-faithful state is
  mnemonic-identical at 94.24.
- waterfx_render: retail's for-header comma order (`poolOffset += 0x1c, descriptorOffset +=
  0x20, vertexOffset += 0x40, j++`, init `j = 0` first) converges all four latch immediates
  positionally; fuzzy 99.428 -> 99.279.
- Vortex_init: dropping the `GameObject* o = obj` alias converges retail's prologue save order
  (mr r3-save before r4-save); homes recolour cyclically, 99.415 -> 98.772.
- mapProcessRomList: retail folds the ADDR16-style HA onto the runtime base
  (`(int*)(base + 0x83A8))[slot]`), ours onto the scaled index; all three faithful spellings
  (flat sum, subscript, int-first paren) regress 99.643 -> 97.9-98.2.
Landing any of these requires the WHOLE register permutation to converge at once — i.e. the
original source — not incremental score-gated steps. No wrong computation found anywhere in the
class (every divergence recomputes identical values), so no intended-regression exemption
applies.

### 35c. blendTextures reconstruction (derived, correct-direction, unlandable)

Retail's loop-1 web structure, read from the target asm: address chains add pco, tco, h, rdo in
that order for all three pointers; dst is built base-first (a `+=` chain, not a flat sum — MWCC
rotates the pointer base to the END of any single-expression pointer+int chain, and full-inline
spelling over-CSEs the whole sum into lhzx); loop-1 rdo multiplies width*w (loop 2 already
does); the red sum takes the redA term first. Retail parks wB/pixelB/redB/i/j in saved regs and
pco/tco/rdo/w/h in volatiles; every named-local vs CSE-temp respelling (offsets inline in `+=`
statements, wd-cache elimination justified by loop 2's alias-forced second width reload) moves
the saved/volatile partition but never onto retail's assignment. ~45 gated variants measured;
best faithful state 94.24 vs HEAD 94.48. The row is structure-derived but colouring-locked.

### 35d. Verdict

The frontier's opnd-only residue splits 66 TIEBREAK / 6 COMMUTE / 31 STRUCT-REAL rows, and the
STRUCT-REAL set is fully derivable from asm but unlandable row-by-row under the score gate:
this class is priced until a lane can land a whole-function colouring convergence (or the gate
learns to score def-use structure above register identity). Census data:
tools-side script left with the lane's topic file; classifications in
`aug05-C114-web-structure-census` (memory topic).

## 36. Two leads closed at mechanism level (2026-08-05)

**Tricky counterexample (2026-09-04):** the 64-bit-promotion conclusion below is
specific to the compiler used for that experiment, not evidence of original
source types. `python tools/tricky_compiler_probe.py` shows GC/1.3 emitting
`li; and` and `lis; or` from ordinary signed 32-bit masks in compound assignments;
GC/1.3.2 and GC/2.0 fold the same snippets. Unsigned masks fold in all three.
Tricky's GC/1.3 compile also reproduces retail's independent handler-array
accesses without the former combined geometry/table overlay. With signed chars,
ordinary masks, and direct calls, all 89 function lengths match and text improves
from 99.95778% to 99.97226%. No claim about Player's compiler follows from this.

The subsequent patch-cache recovery removes the Tricky-specific `nopropagation`
override: ordinary indexed access to the four cached groups and positions now
lowers to retail's base-pointer copies and fixed member displacements. With
propagation disabled, the same loops retain redundant zero-index shifts and
multiplications; explicit pointers to the array elements instead move the member
offsets into their initializers. Reproduce the distinction with
`python tools/tricky_compiler_probe.py --versions 1.3 --propagation on` and `off`.
The full TU temporarily falls to 99.822075% text while preserving all 89 retail
function offsets/sizes and every non-code section's bytes. This is a source-shape
constraint supporting normal propagation, not a claim that the full compiler
profile or remaining register assignments have been recovered.

The flame-child recovery extends indexed access across 17 spawn/retirement loops,
removing the state-base cursor helper, the duplicate flameblast placement overlay,
and an artificial single-field loop-counter struct. Retail diagnostics distinguish
state 13 (BADDIEALERT) from state 12's circling; animation 0x34 belongs to the
growl/alert/guard flame attack, not digging. The flameblast callback formerly named
`objSetAnimSpeedTo1` only sets `freeRequested`; its canonical API is now
`flameblast_requestFree`. Flameblast remains byte-exact. Tricky text temporarily
falls to 99.75482%: the changed handlers retain their mnemonic streams except
`Tricky_update`, where the plain scalar counter exposes one additional zero load.
Its text grows by four bytes; all non-code section bytes and all 58 constant-load
value sequences remain unchanged. Do not restore the fake counter struct merely
to suppress that load.

Tricky's later GC/1.3 audit removes the inherited `noauto` override as well:
the complete object SHA-256 is unchanged with the default automatic inlining.
The source-order probe now varies automatic inlining independently of deferred
emission and can move explicit inline definitions first or last. Neither change
alters any allocated section in the reverse/deferred probe. Its leading 80 pool
bytes match retail, but early water/speed literals still differ in order; moving
inline definitions does not explain them. Independent GC/1.3 fixtures also show
global `const float` scalars producing duplicate named/anonymous pool entries;
static and local const scalars retain use order, not declaration order.

The next Tricky pool audit distinguishes explicit inlining from ordinary static
functions that are automatically inlined and then dead-stripped by the linker.
GC/1.3 emits their bodies and constants; the game's GC/1.3.2 link removes the
unreferenced bodies while retaining constants used by their inlined callers.
`python tools/tricky_link_probe.py` reproduces this against the complete game,
substituting only Tricky's C object into the normal matching link inputs.

Reverse source order with deferred emission reproduces the six leading local
initializer templates without named data substitutes. Ordinary deep-water,
idle-move and facing helpers explain early water/angle constants and both water
diagnostics. The repeated acceleration/deceleration operations now use two
ordinary static helpers at eight actual call sites. All five helper bodies are
absent from the diagnostic linked ELF; all 89 retail functions remain. The
descriptor ends the TU, and water/circling messages are direct string literals.

The complete generated `.sdata2` is 404 bytes versus retail's 408: all bytes match
except the swapped `-2.0f`/`1.5f` pair at offsets 0x88/0x8c and four trailing zero
bytes. Objdiff reports 99.504944% for that pool, up from 82.04489%. All 58 retail
constant-load sequences remain equal. `.data` bytes match through 0x8eb, leaving
only five trailing zero bytes; its much lower anonymous-symbol fuzzy score is
not a byte-equality verdict. Relocated jump-table entries still depend on the
remaining text differences. The diagnostic link preserves the whole pool.
Text is temporarily 99.78016%: movement update gains two register moves, while
the pre-existing extra zero load in `Tricky_update` remains. Neither the
diagnostic link nor the strict matching build proves Tricky's C is fully exact.

The remaining pair was resolved by recovering `trickyAdvanceToSegmentEnd` from
five identical forward/reverse segment-drain loops in movement update. Its
ordinary static body is automatically inlined and stripped, emitting the reverse
step before the lookahead calculation's literals. Every retail function's code
and score are unchanged by this extraction. All 404 source pool bytes now match
retail; the normal linker supplies the final four alignment bytes. The complete
40,744-byte `.sdata2` section of the diagnostic game link is byte-identical to
the strict matching-build ELF. The link probe now reports that whole-section
comparison, in addition to checking the fate of the six static helper bodies.

Flame lifecycle consolidation replaces ten retirement copies and seven spawn
copies with the existing Tricky helpers, using canonical indexed child access.
The former movement-state/loop-index coupling in `Tricky_update` is removed:
the state is reset to `TRICKY_MOVE_WALK_WAIT`, and the retirement helper owns its
index. This removes the extra zero load without a counter struct or other
storage coercion. `Tricky_free` (480 bytes), `tricky_SeqFn` (1,168 bytes), and
`tricky_substateFlameBreath` (448 bytes) are now exact. Growl, guard and flame
also improve; `Tricky_update` has retail's length and only five register
differences. Overall text rises from 99.78016% to 99.83353%.

The approach-speed caller now reuses `trickyGetPathSpeedDelta`, and jump
preparation uses the recovered acceleration/deceleration helpers. The former
retains the retail opcode sequence with eight register differences, versus four
before extraction; the latter is byte-neutral. Broader speed-clamp substitutions
were not retained where they changed retail's conditional-assignment/ternary
branch structure. The only remaining instruction-count difference is movement
update's two additional register moves. The diagnostic link still has the exact
40,744-byte `.sdata2` section.

Shared voice and action recovery makes four more Tricky functions exact:
`Tricky_update` (8,672 bytes), `trickyGuard` (2,276), `trickyGrowl` (1,096),
and `trickyFlame` (2,224). Six guard/growl/alert gates now use the existing
voice helper. The tired-food warning reuses `trickyTryPlaySound`, including its
success result; its differently named animation exclusions are aliases for the
same IDs. Passing the selected impress sound directly removes the last update
register differences.

Seven identical approach-speed/movement pairs in flame and tunnel digging now
share `trickyApproachTarget`; tunnel digging remains exact. The two flame-action
updates share their allocation gate, callback result, animation threshold and
retirement through `trickyUpdateFlameAction`. These real call-site extractions
remove the remaining flame register differences without storage tricks. Overall
text rises to 99.84319%, with no new function-size differences and the complete
linked `.sdata2` still exact. Movement update still has two extra instructions;
the TU remains `NonMatching`.

The next target/command audit recovers `trickySetTargetPosition` across all 27
copies of its pointer-change, patch-invalidation and linked-group reset contract.
The tumbleweed caller retains its additional tracked-object-change condition.
`trickyResetCommandState` now has a normal `void` API instead of returning a
constant float zero, and 16 more command-exit copies reuse it. The old flame
exit stores through `guardPoint[0/1]` are the same union storage as the follow
state's two timers; after switching to Follow Player, the timer view is the
appropriate one. Unused pointer/reset temporaries are removed.

Target acquisition now returns success/failure directly after calling those
helpers. This resolves all 277 register differences in `trickyUpdateBaddieAlert`
(3,508 bytes), raising Tricky text to 99.92732%. A same-profile compilation of
the previous checkpoint confirms that only this function's bytes change. All
other function bytes, all non-code section bytes, SDA global offsets, and all
2,176 symbol-normalized relocations are unchanged. The linked `.sdata2` remains
exact, and movement update is still eight bytes longer than retail.

The attachment audit identifies ObjPath point 8 as Tricky's mouth position from
its carried-ball, flame-origin and particle consumers. It is now a `Vec` at
0x408, with asserted components; the joint-pose Y value at 0x414 is the mouth
yaw offset added to the horizontal flame heading, not a pitch offset. These
names are behavioral inferences, not leaked identifiers. Both public getters
and the flameblast consumer use the corrected names; flameblast remains exact.

The post-render attachment refresh is a private helper, and both ball-route
directions share a blocked/unblocked branch appender with the caller-owned
count. Render's register differences fall from 14 to 10; ball rolling retains
the retail instruction stream but rises from 52 to 84 register differences.
Overall text temporarily becomes 99.91707%. Only those two function byte ranges
change after accounting for the getter renames. All non-code section bytes,
normalized relocations and function lengths are preserved, and the complete
linked `.sdata2` remains exact. Separate route-initialization and return-valued
facing-helper experiments were not retained.

The movement audit consolidates five route-turn magnitude calculations and two
jump-facing updates, preserving their signed 16-bit and square-evaluation
semantics. The update and circling handlers share full-width yaw wrapping and
remain byte-exact. Cannonball candidate selection uses its actual indexed array,
also byte-neutrally. Helper names are behavioral inferences, not source leaks.

Jump preparation now updates the saved speed itself instead of merging that
value into the unrelated `v` temporary used by the arc calculations. Together
with the existing acceleration/deceleration helpers, this removes both extra
floating-point moves. A separate speed-convergence helper is unnecessary and
was removed. Movement update is now retail's 8,764 bytes with the same opcode
stream and 68 register differences; its entire jump-prep speed block is exact.
Only movement update's raw function bytes change, and all non-code object
sections remain byte-identical to the preceding checkpoint.

All 89 retail function lengths now agree. The full diagnostic game link has
identical addresses, sizes and bytes for every allocated non-text section,
including `.data` and its resolved jump tables. Only 234 bytes of `.text` differ;
overall Tricky text is 99.92431%. The link probe now compares every allocated
section, including size, address, missing sections and byte changes, with tests
for these distinctions. This is still `NonMatching`: the remaining register
differences must be resolved before substituting the C object in the strict DOL.

The scalar audit removes one-element count and hit-pointer arrays byte-neutrally.
It also removes `slope[1]`, introduced by `1e1d1c4deb` in place of a scalar despite
having no array or address-taking consumer. The honest scalar projection leaves
12 register differences in step adjustment, with retail's 512-byte instruction
stream. A separate projection helper and explicit delta temporaries did not
recover the retail registers and were not retained.

Jump-arc duration, elapsed time, landing-time offset and middle animation progress
now have their own meaningful locals. The dispatcher no longer couples these
values to `k`/`v` assignments embedded in zero stores and quarter-speed movement.
This preserves every instruction but changes movement's register difference
count from 68 to 72. Route ranking uses the established link/candidate capacities
without code changes. Overall text temporarily becomes 99.91013%; the full link
still has exact non-text sections and all retail function sizes, with 261 text
bytes remaining different. These exposed register differences are preferable
to retaining unsupported array storage purely for its allocation effect.

Route ranking (688 bytes) is now exact with a normal target-Z product and direct
`curve->x` accesses. Its former `curveX` cache made MWCC emit that load ahead of
the target-Z square when the product was written normally. Removing the cache
recovers the retail evaluation order without an in-place square or an artificial
storage shape.

Yaw turning (348 bytes) is also exact. The wrapped target bits now have their own
local, and the subtraction captures the current yaw for the subsequent turn
steps. This preserves the required snapshot across state-flag writes: replacing
it with fresh member reads adds two loads. Keeping a separate current-yaw load
statement moves that load before the target conversion; capturing it as part of
the subtraction reproduces the retail order and registers.

Only these two function byte ranges change. All retail lengths and linked
non-text sections remain exact, with 230 text bytes different and overall text
at 99.92039%. An explicit render-point iterator, a direct approach-radius square,
and a shared fast/slow turn-delta local were not retained: they changed retail's
offset placement, square/call order, or instruction count respectively.

The path-search dependency now exposes its evidenced pending/reached/exhausted
results and names the step argument `maxSteps`: it limits queue iterations, not
elapsed time. Every direct consumer is in Tricky. The engine implementation's
object remains byte-identical. Tricky's eight competing route searches and ninth
cached-path workspace now share their capacities with the owning state layout.
The direction probe's existing exhaustion-as-stop behavior is documented rather
than mistaken for successful path discovery.

With the status contract explicit, reusing the outer search counter to select
the final surviving candidate makes `trickyFindReachableRouteIndex` exact (468
bytes). That branch always returns, so the pass count is no longer needed. The
same counter-reuse probes before status recovery retained all four register
differences; the final code has none.

Retail's "tricky last walk group" diagnostics and the field's nonzero updates
identify the former `activeWalkGroup` as `lastWalkGroup` at 0xD0. It persists
through off-group movement. Both updates now share patch-cache invalidation,
while their full-width/16-bit comparisons remain at the call sites; forcing
those through one integer setter added a conversion and changed signedness.
Movement's bytes are unchanged. Only reachable-route search changes code, all
non-code bytes and retail lengths remain exact, and the diagnostic game link
has 222 differing text bytes. Overall Tricky text is 99.92189%.

`trickyUpdateApproachSpeed` is now exact (844 bytes). The stopping-radius input
is added into the accumulated stopping distance, rather than overwritten and
kept alive as the computed distance. The braking step and loop time step share
the initial time snapshot, then only the braking step is scaled. Ordinary
scalar assignments recover the retail registers and load order. A direct
constant-times-global expression reverses the two loads; separately assigning
the time snapshot before computing the braking step retains four register
differences. Names now distinguish the braking step, squared stopping distance,
and radius within which path-speed adjustment is considered.

Tricky's shared `RomCurveWalker` now holds three `RomCurveDef*` nodes, with
offset assertions at 0x9C/0xA0/0xA4. All stored nodes originate from the route
table or the Hermite API's curve arguments; those APIs now carry the same
types. Every rebuilt consumer object remains byte-identical. Tricky directly
accesses its typed nodes and indexed branch links, drops a redundant segment
start copy, and uses the common command-active/turning flags instead of the
misleading cannonball hide/decay aliases. Its distance locals now agree with
the distance API's `f32` return type. These changes are byte-neutral.

Only approach-speed code changes in this batch. All retail function lengths
and allocated non-text sections remain exact; the diagnostic game link has
212 differing text bytes and Tricky text is 99.92521%. Direct indexing in the
already-exact dig-tunnel advance helper retains the opcode stream but changes
11 register operands, so that separate experiment was not retained.

**Const-zero placement — `playerState19`/`1B`/`MountBike`/`ClimbWall` (player.c).** NOT a surplus
instruction: counts are identical (349/349, 409/409, 677/677). `flags360 & ~2LL` promotes a `u32` to
`long long`; the high word's zero-extension emits a dead `li rX,0`. Retail DCEs it and materialises a
fresh zero at the later `physicsActive = 0` store; our build **value-numbers that later zero onto the
dead one**, giving it a ~20-instruction live range and pushing the `lwz` chain one register up.
Two proofs: setting the consumer to a NONZERO value gives STRUC 0 (the dead zero is fully DCE-able, so
the CSE partner is the whole defect), and hoisting `physicsActive = 0;` above the clear reproduces
retail's region byte-for-byte (but puts the store in the wrong place, STRUC 4). Block separation is
independently refuted — in `ClimbWall` the store already sits after a `bne-` in another block and still
CSEs. **The `LL` is load-bearing and correct**: any 32-bit mask collapses to one `rlwinm`, and retail's
`li r0,-3; and` requires the 64-bit promotion. A repo-wide scan found four 100%-matched controls with
`~…LL` masks (`dll_19_pollCameraTarget`, `crawler_updateC`, `spittingEbaUpdateIdle`, and five sibling
player states) — every one either has no trailing zero store in the block or has the zero BEFORE the
clear. No matched precedent exists for "LL flag-clear then trailing `= 0`". Wall, no cost.

**`playerCacheMoveRootHeights` (−2 instructions).** Retail emits an unfolded `li r0,12; slwi r0,r0,2;
add r29,r4,r0` where we fold to `addi r29,r4,48`; the rest of the function is byte-identical and both
sides reach the base the same way, so base provenance is not the discriminator. 21 spellings all fold
(index arithmetic in both directions, init order, `for`-comma, `do/while`, hoisted inits, explicit
`*4`/`<<2`/`sizeof`, three base-cast forms in both operand orders, named base, `u32` and `f32*`
cursors, separate seeded index, `(&arr[i])[0]`). A scan of every built object AND the GC/2.0 refcorpus
finds the shape only under two mechanisms, neither of which can occur in a 4-iteration call-bearing
loop: an unrolled-loop remainder preheader, and a PHI-of-constants index (MP4 `MGSeqInitDraw`).
Route to the TU-profile / `mw_version` lane; further source sweeps are provably flat.
