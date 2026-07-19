# Bad-splits dossier — candidates for TU re-split / boundary surgery

Compiled 2026-07-18 from `docs/mwcc_re/RESIDUAL_HANDOFFS.md`, `docs/HACK_AUDIT.md` (policy: units
that cannot match without hacks "stay NonMatching or await a TU re-split", HACK_AUDIT.md:20-24),
`docs/mwcc_re/POOL_ORDER.md` (BLOCKED CLASS sections), `configure.py`, `config/GSAE01/splits.txt`,
and the session-memory census (`merge-group-census`, `tricky-family-3tu-map`,
`groupflip-merged-tu-unlock`). Ranked by expected value. Every entry names the evidence, the
hypothesized original TU boundary (or flag/toolchain set), and what a re-split unlocks.

Reading key — the three proven "bad split" signatures:
1. **Two same-type conversion-bias atoms inside one carve** ⇒ two original TUs (a TU mints each
   bias type exactly once). Per-bias-TYPE: u32+s32 in one carve is ONE normal TU.
2. **Duplicate pool VALUES inside one candidate pool** ⇒ a TU boundary between the duplicates
   (TU-wide literal dedup, first-creator-wins, forbids re-emission).
3. **Fused `fsubs` + UND external bias** in a retail obj ⇒ dtk split artifact: MWCC only produces
   that shape with a LOCAL mint, so dtk lifted the unit's own bias into an `auto_*_sdata2.o`
   grab-bag and rewrote the reloc (POOL_ORDER.md:643-730). The fix is always splits GEOMETRY
   (claim/redraw/merge), never a missing compiler technique.

---

## 1. ProDG toolchain island: `zlbDecompress` (pi_dolphin) + render.o `gap_03` — HIGHEST VALUE

- **Units**: `main/pi_dolphin.c` (configure.py:934, NonMatching, `cflags_dll_noopt_noloopinv`);
  `main/render.c` (configure.py:852, NonMatching, `cflags_dll_noopt`; splits.txt:16-19 — `.text`
  0x800066E0..0x80008DF4, note render.c owns no `.sdata2` split).
- **Evidence**: `mcrxr cr0; addme.` decrement idiom occurs in exactly TWO objects tree-wide and in
  0/38736 refcorpus MWCC functions; ProDG cc1 reproduces it immediately
  (RESIDUAL_HANDOFFS.md:69-77). The second hit sits in the **unclaimed** carve gap
  `gap_03_80006C6C_text` (0x58c-0x1898, ~4.8 KB of undecompiled code) between `fn_80006B1C` and
  `fn_80007F78` (RESIDUAL_HANDOFFS.md:72-73). Best MWCC attempt on zlbDecompress caps at ~76-77%
  with all ~94 divergent instructions being MWCC-vs-GCC codegen classes; plain `-O1` ProDG gets
  65.3% mnemonic-LCS with block-for-block matches on the signature runs (RESIDUAL_HANDOFFS.md:75-77).
  **Correction on record**: `fn_80007F78` itself is MWCC, NOT ProDG (RESIDUAL_HANDOFFS.md:92-93) —
  only the gap region + zlbDecompress are foreign.
- **Hypothesized re-split**: carve `zlbDecompress` out of pi_dolphin into its own unit, and the
  `gap_03` island out of render.c, both compiled by an SN ProDG / GNUPro-family GCC (flag-unreachable
  divergences pin an OLDER build than the five in-repo cc1s: mcrxr;addme. doloop, leaf LR save,
  4-byte stack alignment `stmw r14,12(r1)`, andi.-preferring andsi3 — RESIDUAL_HANDOFFS.md:77).
  Needs configure.py toolchain support (compilers exist at `build/compilers/ProDG/`; wibo runs
  cc1.exe directly, the ngccc driver is a dead end).
- **Unlocks**: the sub-97 "LOW BAND" hard cap (zlbDecompress is one of its two mechanism-attributed
  prebuilt-library members), plus ~4.8 KB of currently-uncarved, unscored `.text` in render.o. If a
  matching GCC build is sourced, near-byte match is assessed reachable. This is the only candidate
  that opens *new* code rather than relocating matched bytes.

## 2. Tricky family: 13 carves are THREE original TUs (boundaries derived to the instruction)

- **Units** (configure.py:1195-1209): `dll_80136a40` (noopt_nostrength), `skeetla` (noopt),
  `trickyfollow` (nocse_noloopinv), `mmp_cratercritter` (**nosched** — the odd one out),
  `mmp_critterspit`, `tumbleweedbush` (noprop), `animobjd2` (nocse_noprop_noloopinv), `weapone6`
  (noprop), `tricky_flameguard` (nocse_noprop), `tricky_rollroute` (noopt), `tricky_substates`
  (noprop_nostrength), `dll_00C4_tricky` (noopt), `dll_00C9_enemy` (noopt). The wildly divergent
  per-carve `-opt` sub-flags across what is provably shared TUs are themselves a mis-split symptom
  (flags were tuned per-carve to force matches across a boundary that doesn't exist in the source).
- **Evidence** (memory `tricky-family-3tu-map`, derivation quadruple-checked): the region
  0x80136A40..0x8014E1DC holds **3 sbias + 3 ubias** atoms in pool 0x803E2390..0x803E2600 ⇒ three
  TUs. (a) `dll_80136a40.o` references TWO ubias atoms (803E23A8 and 803E2400) ⇒ its carve holds
  two TUs. (b) `dll_00C4_tricky.o` references duplicate values (30.0 at 24C8 AND 2598; 15.0 at
  247C AND 25AC; 60.0 at 24F8 AND 2570) ⇒ its carve straddles a boundary. (c) No duplicates exist
  WITHIN each derived pool. (d) From 0x80148C18 on, function names are `baddie*`/`enemy` code
  sitting in tricky's carve.
- **Hypothesized original TUs**:
  - **TU-A** debug/errdisplay: `.text` 0x80136A40..0x80138908, pool 0x803E2390..23C0. A
    debug-print/error-display module unrelated to tricky.
  - **TU-B** tricky: 0x80138908..0x80148C18 (12-carve merge), pool 0x803E23C0..2558.
  - **TU-C** enemy: 0x80148C18..0x8014E1DC (= dll_00C4 tail from `Tricky_resumeAfterCommand` + all
    of dll_00C9_enemy), pool 0x803E2558..2600.
- **Blockers / status**: bare flips of TU-B members are PROVEN impossible (weapone6 at fuzzy 100
  fails mode-B: its own minted bias shifts the pool) — the merge is mandatory. A tricky-alone flip
  is blocked at the bias export (`gTrickyS32ToDoubleBias`@803E2460 is lfd-imported by 6 sibling
  DLLs; no source spelling can export a live mint — POOL_ORDER.md:122-153). The full 3-TU redraw is
  the geometry fix that dissolves that blocker (each TU mints its own biases locally). Remaining
  fn-level holes gate completion: TU-A 5 debug fns (97.7-99.4), TU-B 9 fns (98.9-99.95), TU-C's
  single hole `fn_8014C11C` was CRACKED (+956, see `banked-caps-misc`).
- **Unlocks**: TU-C redraw first = the cheapest prize (+2 complete_units / +416 B matched_data
  ceiling per the census). Full family = 13 NonMatching-or-partial carves → 3 correct units.
  Prerequisite already landed: 5 of the 6 bias atoms were mistyped `size:0x3 data:string` in
  symbols.txt and are retyped (commit 880cd0a420).

## 3. The 31-unit "bias-external" class — dtk split artifacts awaiting geometry fixes

- **Definition**: fuzzy-100/incomplete units whose retail carve has NO `.sdata2` section yet whose
  `.text` does fused `fsubs` conversions against an UND external `lbl_803Exxxx` bias — signature 3
  above. All 39 fuzzy-100/incomplete units were re-classified 2026-07-17: **31 bias-external + ~9
  global-bias-redraw**; zero flippable by non-split levers (merge-group-census:1294-1303).
- **Known members / sub-groups** (from POOL_ORDER.md:643-730 + the census blocker map):
  - *Sole importer, geometrically entangled*: `dll_01CA_dimexplosion` (bias lbl_803E4948 is its own
    displaced mint; atoms interleave `dll_01C9_dimdismountpoint`'s in the DIM grab-bag
    0x803E4860..) — assessed DEAD without a merged-TU.
  - *Genuinely shared bias ⇒ the sharers were ONE TU* (merged-TU wrapper or redraw is the only fix):
    `dll_01C6_dimcannon` + `DIM/dimwooddoor` (lbl_803E48C0, both import it); `dim2lift` +
    `dim2icicle` (bystanders complete ⇒ −1 today); `SB/dll_01E8_sbgalleon` (+ dbprotection 99.74);
    `dfbarrel` + `dfbarrelanim` (+ dfropenode) via `gRopeNodeS32ToDoubleBias`@803E4DF0 (0x68 pool
    orphaned in auto_11_803E4DE0); `drpickup` + `snowbike` (+3) via lbl_803E5B00/803E5BA4;
    `worldplanet_lighting` + `worldplanet` (lbl_803E6610; worldplanet 99.46);
    `dll_01B5_lightfoot` + `player`; `CAM/camcontrol` + `dll_b6` + `dll_bb` (lbl_803E1650 —
    span-bystanders a6/b3/b4/b7/b8/bc all complete ⇒ −2, banked); `dll_80198a00` + `mmp_gyservent`
    + `dll_0126_trigger` (BOTH biases lbl_803E40D0/40F0 shared 3 ways; pair-only merge is
    link-infeasible — proven by an actual mwld undefined-symbol failure; a byte-exact pair recipe is
    banked in merge-group-census:1170-1183 for when trigger's `beq-` CFG cap cracks);
    `tricky`/`enemy`/`weapone6` (= entry 2 above). Also on the same wall: `objfx` (imports
    lbl_803DF350..35C ⇒ objfx+expgfxresource+dll_000A_expgfx were one TU, blocked on 9 banked
    expgfx caps).
  - *Clean pure-bias emitters*: EXHAUSTED — only two ever existed (`wcearthwalker`, `waterflowwe`),
    both landed via minimal bias-claims.
- **Unlocks**: each shared-bias group is +1 ceiling but currently delta ≤ 0 because every group
  carries a sub-100 member or complete bystanders (re-costed three times, still 0 viable at origin
  10a09f5b79). **These are correct re-splits to queue behind the fn-level coloring work** — the
  census rule: land the merge the instant both members hit 100 AND the bias is local-in-both. The
  merge-gating near-100 fns are listed in merge-group-census:1330 (dll_0042 99.98, objprint_dolphin,
  cutcam, viewfinder/camTalk, objprint).

## 4. Global-bias-redraw remainder (~9-unit class, recipe CRACKED)

- **Recipe** (proven on seqobj11e/mikaladon, landed 5b7dc8f2af): a global-bias unit whose flip
  breaks the DOL from a byte-identical `.o` = (a) mwld dead-strips an unreferenced named `.sdata2`
  atom ⇒ `#pragma force_active on/reset`; and/or (b) a second same-type bias imported UND ⇒ the
  carve boundary was drawn too late ⇒ move the trailing fn(s) + a recovered uncalled-static ghost
  across the `.c` boundary and repartition splits.txt (`objdump -t` binding `l`=flips / `g`=repacks
  is the discriminator). Full mechanism: POOL_ORDER.md:563-640.
- **Landed exemplars**: seqobj11e|mikaladon (boundary `.text` 0x80152B90 / `.sdata2` 0x803E2870;
  fn_80152B90 + eight named floats + a ghost `(f32)(int)` helper moved into mikaladon.c);
  modgfxfunc03 (a 4-unit `.data` jumptable boundary redraw — dll5c/dll5d vtables moved to their true
  owners); staffAction (fn-reorder + cast-deref CSE-break); wcfloortile|arwarwing redraw (boundary
  `arwarwing_readControls`@0x8022A670); wispbaddie|newseqobj redraw (boundary 0x8014FFB4, two-sbias
  rule); arw-quartet 02A2+02A3+02A4 (FOUR sbiases ⇒ helper pairs each open the next TU; boundaries
  0x80231028/0x8023134C/0x802315EC); barrelgener (duplicates straddle `Obj_UpdateLightningCluster`
  ⇒ the generic `Obj_*` motion toolkit split out as `obj_movelib.c`, +2); skystars out of newclouds
  (boundary `drawSkyStars` 0x80093AE0 / `.sdata2` 0x803DF280, +1); camcontrol|cammodes `.data`
  redraw at the string|tables line 0x80319B58 (+1).
- **Remaining candidates** (census blocker map, merge-group-census:1126-1139 + 1228-1244):
  - `main/dll/dll_023F_dbegg.c` — fn-order + an interspersed dual-bias def-block.
  - `main/dll/dll_029B_arwingandrossstuff.c` — 3 fns to hoist + two identical add-biases
    803E7020/803E7050 both single-ref (source CSE-dedups them into one `@99`) + trailing pad ⇒
    same second-bias redraw shape as seqobj11e.
  - `main/dll/dll_3b.c` — `.bss` short 0x1010 (missing 0x1000 thread stack + 0x10 buffers; MWCC
    segregates UNREFERENCED `.bss` to section end — the buffer must be referenced in-TU). Held
    once already because the fix lowered matched_data (see `measurement-truths`).
  - `main/audio/voice_manage.c` — over-declares 0xfc0 `.bss` the carve lacks.
  - `dim2roofrub` + `dll66func0` — source over-emits float consts locally that retail refs
    externally (externalization class, cast-deref lever documented).
- **Unlocks**: ~+1 complete_unit each where the unit is otherwise 100; zero new code.

## 5. force_active mid-pool zero atoms = four interior TU boundaries (unexecuted)

- **Evidence** (merge-group-census:1084-1102): all six `force_active:` zero-atom entries in
  config.yml sit at addr ≡ 4 mod 8. The trailing-pad case (gunpowderbarrel lbl_803DBE8C) was PROVEN
  fake and landed as a claim-shrink. The four MID-pool ones are only consistent as **interior TU
  boundaries** (MWCC `.data`/`.sdata` align-8 is unconditional; an unreferenced atom at a
  non-8-aligned base is link padding between two objects):
  - `nwmammothgroup` lbl_803E5204 → TU-A 0x803E5200-04 / TU-B 0x803E5208-525C
  - `wispbaddie` lbl_803E2724 → TU-A ..2724 / TU-B 2728-2740
  - `duster` lbl_803E2A44 + lbl_803E2A64 → THREE TUs (..2A44 / 2A48..2A64 / 2A68..2A70)
  - `fxemit` lbl_803E3E44 → TU-A = single atom lbl_803E3E40 / TU-B 0x803E3E48-3E60
- **Blocker**: each needs its `.text` boundary recovered before it pays; all owning units are
  already complete, so gains come only from the split itself (structural correctness + possibly +1
  where a half can stand alone). Discriminator probe: a green `main.dol` with the force_active entry
  REMOVED proves the redraw (one build).

## 6. intersect / maketex — two mis-drawn units, fully diagnosed, cross-owner

- **Evidence** (merge-group-census:954-1082): `track/intersect.c` (configure.py:941) is TWO TUs —
  TU-A = a water-splash/ripple unit (4 fns from `objAudioFn_8006ef38`, `.text` boundary 0x8006F950,
  `.data` = exactly the two jumptables 0x8030E9B4-0x8030EA0C; owns `gWaterFxBank`), TU-B = the
  93-fn GX/screen-filter/memcard unit (`.data` 0x8030EA10-0x8030EB58, currently UNCLAIMED — every
  later symbol shifts +4). Four biases in the region (2 ubias + 2 sbias) corroborate ≥2 TUs.
  `gWaterSplashQuads`/`gWaterRipples` are extern in intersect.c but defined NOWHERE in src — the
  owning TU must define them. `maketex.o` holds TWO u32 biases ⇒ maketex+objseq is itself a redraw,
  and maketex's real `.data` is 0x8030EB58-0x8030EC00; its hand-written global jumptable
  scaffolding (retail's are scope:local minted) must be deleted for any flip — the named-jumptable
  trick maximizes fuzzy but is FATAL to a flip (score and flip pull opposite directions here).
- **Blocker**: gated on maketex's owner (one owner per .c) and on capped members (objseq 99.74,
  intersect also mints 0x20 `.sdata2` against a carve claiming none).
- **Unlocks**: +2 ceiling (both fuzzy-100/incomplete today), plus the 4-byte `.data` pad falls out
  for free (the split creates it; `section_alignments={".data":4}` is the wrong tool for interior
  pads — configure.py currently uses that knob only for the four legitimately 4-mod-8-leading
  units: fireball, cfguardian, DIMboss, nwlevcontrol).

## 7. Per-TU toolchain/flag mismatches (not boundary errors, but split-table wrongness)

- **trig.c / k_tan.c** (configure.py:1793-1808, both NonMatching, GC/1.2.5n `-O0 -opt functions`):
  two independent functions each require one peephole trait AND one no-peephole trait
  simultaneously — impossible for every in-repo compiler × flag × 436 source variants. Retail was
  built by a 1.2.5-family **peephole variant** that eliminates redundant extensions but lacks the
  `mr`→`addi` copy rewrite (RESIDUAL_HANDOFFS.md:95-143). Payoff if that build is ever sourced:
  k_tan → 100 (flip) + 6 of trig's 10 sub-100 fns → 100. BANKED as a compiler-build acquisition,
  not source work.
- **fn_801FD6B4 (main/main.c)**: redundant `frsp` + bare stfs after mathSinf ⇒ the original main.c
  TU declared `double mathSinf(double)` — a per-TU prototype-width divergence the shared header
  can't express (RESIDUAL_HANDOFFS.md:32-36). Corroborates the established rule that divergent
  `*_legacy_api.h` prototype widths are a deliberate per-TU technique, NOT bugs.
- **Whole-TU peephole/scheduling-off question — RESOLVED**: the owner-tooling question in
  RESIDUAL_HANDOFFS.md:194-199 (textrender/objseq/gameloop/objanim/debug) is answered in
  configure.py — all five already build with `cflags_dll_noopt` (configure.py:861, 868, 863, 912,
  1195), and cflags_dll_noopt's comment records this as "a per-TU compiler setting, not a
  per-function one" (configure.py:264-269). The 2026-07 pragma wave confirmed most per-TU `-opt`
  variants are load-bearing.
- **sal_dsp hwInitIrq (audio)**: the claimed evidence — hwInitIrq matching only under
  scheduling-off while TU siblings need scheduling-on, implying a differently-flagged TU sandwiched
  in the split — is **NOT present in the current RESIDUAL_HANDOFFS.md** (searched; sal_dsp builds
  plain GC/1.2.5n, configure.py:1736). EVIDENCE GAP: if real, it lives in a session log or an older
  doc revision; re-derive from the asm before acting. The adjacent audio precedent is solid though:
  the voice_conv/synth_ac/synth_adsr boundary (TWO ubias atoms ⇒ two TUs; sbias shared
  ConvertDb↔adsrStartRelease) was independently derived and landed by origin as a re-split.

## 8. newclouds head — split correct, flip blocked on a genuine wall (context for the family)

- skystars.c is split out and landed (+1). The remaining `main/newclouds.c` (configure.py:870)
  owns no `.sdata2` range in splits.txt while our TU emits a local pool whose retail home is the
  shared 0x803DF2xx carve (RESIDUAL_HANDOFFS.md:50) — the standard pool-claim surgery is the
  remaining step, but the head's 4 def atoms hit the measured **def-CSE wall** (0.0/1.0
  order-vs-CSE tension; merge-group-census:1110-1114). Not currently actionable; listed so nobody
  re-derives it.

---

## Prerequisites / hygiene that gate ALL of the above

- **symbols.txt mistype classes**: the `size:0x3 align:8 data:string` bias family is swept (362
  retyped; 22 deliberately held — 15 live-low-half incl. `axfx_reverb_std_handle_i2f_magic`, which
  is lwz-only and likely a real `u32 magic[2]`). Remaining to triage: 14 `.sdata2` atoms
  `size:0x2 align:4`, 42 `size:0x1 data:byte`. Each mistype silently breaks any claim over its
  pool. Also the `lbl_803DE9F4` two-label over-carve (retail relocs prove ONE size:0x8 object;
  symbols.txt ~15953-15954) — RESIDUAL_HANDOFFS.md:58-59.
- **Gate discipline**: pool/claim/split work is invisible to fuzzy and often to the `.o` bytes —
  gate ONLY on `ninja build/GSAE01/ok` (the tricky `const f64` probe read complete_units +1 in
  report.json while the DOL checksum FAILED). objdiff scores `.data` by symbol NAME, so a 4-byte
  layout error reads 100%.
- **~177 uncarved bias atoms** in `.sdata2` = ~177 original TUs whose pools are not carved at all
  (bias-typing sweep). The uncarved-pool vein (auto objects are scored units at 0%) remains the
  largest data prize: claiming all auto `.sdata2` ≈ +1.94 pts matched_data.
- **A multi-bias carve does NOT imply a merge**: `dll_01C1_dimsnowball` (14 biases) is a synthetic
  pool-holder, already 100% — sanity-check `.text size vs pool size` before treating any carve as a
  merge.

## Top-3 summary

| # | Candidate | Action class | Unlock |
|---|---|---|---|
| 1 | ProDG island (zlbDecompress + render gap_03) | toolchain split (configure.py + new units) | breaks a hard cap + ~4.8 KB uncarved code |
| 2 | Tricky family → 3 TUs (TU-C first) | splits/symbols redraw + merged-TU wrapper | +2 units / +416 B now; 13 carves structurally fixed |
| 3 | Global-bias-redraw remainder (dbegg, arwingandrossstuff, dll_3b, voice_manage) | cracked force_active + boundary-redraw recipe | ~+1 unit each |
