# DLL boundary audit — gResourceDescriptors vs splits.txt (Phase 1)

Forensic audit of drift-era unit boundaries against the retail descriptor
table. Reproduce with `python3 tools/dll_boundary_audit.py` (`--census`,
`--map LO HI [--syms]`, `--md`).

## Method

- `gResourceDescriptors` (retail dol .data 0x802C6300, size 0xB08): index =
  DLL id (the `dll_XXXX` filename number), entry = ObjectDescriptor*.
- Descriptor fn pointers at +0x10.. (slot count bounded by the symbols.txt
  object size, else delta to the next descriptor, else 10 = +0x10..+0x34).
  Slot order: 0 initialise, 1 release, 2 slot02, 3 init, 4 update,
  5 hitDetect, 6 render, 7 free, 8 getObjectTypeId, 9 getExtraSize.
- Object names/ids from the retail ISO: OBJECTS.bin @0xB390E90 +
  OBJECTS.tab @0xB424490 (1480 defs; name = ASCII at def+0x91, 11-char
  fixed field; handling DLL id = `>H` at def+0x50); OBJINDEX.bin
  @0xB42ECD0 (2192 `>h`, romlist type -> def index) for reachability.

## The TU model (validated)

Descriptor fns sit in **reverse slot order ascending**: getExtraSize lowest
address ... initialise highest. Helper fns precede the descriptor fns they
serve. Therefore a DLL's TU spans

```
(previous DLL's initialise end) .. (own initialise end)
```

Validated against the descriptor-carved `dll_0215_wmnewcrystal.c`:
unit = [801F943C, 801F9804), and dll 0x215's fns are 801F974C..801F9800
(initialise 801F9800 + 4 = unit end exactly; helpers 801F943C..801F974C
precede). The same model holds at every clean per-descriptor unit checked.

## Headline numbers

| metric | count (pre-surgery) | count (now, post-campaign) |
|---|---|---|
| gResourceDescriptors entries with a non-null descriptor | 704 | 704 |
| descriptors with .text fn pointers | 653 | 653 |
| **descriptors whose fn range is CUT by a unit boundary** | **132** | **1** |
| units hosting fns of 2+ DLL ids (containers and/or fragment-holders) | 129 | 85 |
| descriptors with no OBJECTS.bin def (no object names them) | 256 | 256 |
| descriptors with defs but none OBJINDEX-reachable | 0 | 0 |

The June 2026 mechanized re-split campaign (`tools/dll_boundary_resplit.py`,
see status section below) resolved 131 of the 132 cuts; the single remaining
cut (dll 0x009, MSL gamecube.c | cloudaction.c) is proven-irreducible (the
descriptor's helper gap genuinely straddles an MSL-library/DLL TU edge that
cannot be moved without breaking the MSL unit). The 85 remaining multi-DLL
units are legitimate multi-descriptor original TUs, not drift-era
cross-family containers.

Notes on the 256 no-def descriptors: most are infrastructure DLLs (partfx /
modgfx effects, cameras, FRONT menus, level-control helpers) that no object
def references — only a subset is true cut content (e.g. dll 0x107 in the
windlift complex). Every DLL that has at least one OBJECTS.bin def is
OBJINDEX-reachable, so reachability triage reduces to "has a def at all".

## Reading the cut table

`fn range` = [lowest descriptor fn, highest descriptor fn]. `TU (proposed)`
extends the fn range per the TU model: start = end of the previous
descriptor's initialise (helper gap belongs to the FOLLOWING descriptor —
verify by call direction before carving), end = own initialise end. A
boundary listed in `cutting boundary(ies)` currently splits the DLL across
the named unit pair and should be moved to a TU edge (or the units merged,
where two descriptors share one original TU — see dll_01BA/01BB note).

## Caveats before surgery on any row

1. **Interleave check**: a cut is fixable by a boundary move only when the
   two descriptors' fn ranges do not interleave. Run
   `--map` on the neighborhood first. (0x1BA/0x1BB do NOT interleave —
   the dll_01BA/01BB boundary at 801DD46C is simply wrong; real edge is
   801DDA28.)
2. **Helper-gap attribution** is by-default-following but must be verified
   by call direction (a helper called only by the PREVIOUS DLL's fns
   belongs to the previous TU).
3. **Multi-descriptor TUs are legitimate** (modgfx Effect family, CAM
   modes, FRONT). A unit hosting several complete DLLs is not a bug; only
   a boundary cutting THROUGH a descriptor's range is.
4. Slot lists with indexes >9 come from larger descriptor variants
   (ObjectDescriptor11/12/13/14) — real callbacks, same TU rules.

## Flagrant filename-vs-content contradictions (case (b))

Derived from the cut table + census; the unit's name matches NONE of the
DLLs whose fns it hosts:

| unit | actually hosts | evidence |
|---|---|---|
| main/light.c (801FB9F4-801FD398) | VFP_Block1 0x21E tail, dll_224 head — VFP-lane DLL code (vfpplatform/vfpdoorswitch/seqpoint/vfpdraghead/vfpcoreplat symbols) | not engine light code |
| main/main.c (801FD398-801FEB30) | dll_224 tail, DB_egg 0x23F fns | not engine main() |
| main/dll/CF/windlift.c | scarab 0x106 body+tail, dll_107, EndObject 0x108 (+its descriptor .data 0x803217C0), PortalSpellStone 0x10D, LanternFireFly 0x10C head | real CFWindLift (0x149) lives in DR/sandwormBoss.c 8019CCF8-8019D574 |
| main/dll/DR/gasvent.c (801A1230-801A1A60) | the MIDDLE of GunPowderBarrel 0x158 (801A0EF8-801A25E8) — nothing else | |
| main/dll/ARW/ARWarwingattachment.c (801F0B50-801F37CC) | LaserBeam 0x1FC tail, PressureSwitch 0x1FE, dll_1FF, WM_LaserTarget 0x1FD, dll_200, WM_colrise 0x201, WM_Torch 0x204, LightSource 0x206 head — 8 WM-lane DLLs, no arwing attachment | |
| main/dll/LGT/LGTdirectionallight.c | WM_Worm 0x207 tail + WM_LevelControl 0x209 head | |
| main/dll/LGT/LGTprojectedlight.c | WM_LevelControl 0x209 tail + WM_GeneralScales 0x20A (whole) | |
| dolphin/MSL_C/PPCEABI/bare/H/gamecube.c | last 3 fns (80094494-8009449C) are dll 0x009's getObjectTypeId-family stubs | DLL code in an SDK unit |

## Known-case surgery plans (Phase 2)

### 1. windlift complex (CF lane) + real CFWindLift in sandwormBoss.c

Descriptor map (from `--map 0x80184700 0x80187600`):
- 0x106 scarab [801847E8-801856C4]: head in CFguardian.c (boundary 80184930
  cuts it), body/tail in windlift.c. TU = [80184180-ish prev edge..801856C8].
- 0x107 (no def, cut content) [801859C4-80186468] in windlift.c.
- 0x108 EndObject [8018646C-80186494] in windlift.c; its descriptor IS the
  .data 0x803217C0 claimed by windlift.c.
- 0x10D PortalSpellStone [80186498-80186700] in windlift.c.
- 0x10C LanternFireFly [80186704-801871C4]: cut by windlift|CFcrystal at
  80186B94.
- 0x10B FireFlyLantern [801873C8-80187524]: cut by CFcrystal|CFBaby at
  80187524 (s3 init is first fn of CFBaby.c — off by one fn).
- real CFWindLift = dll 0x149 (defs CFWindLift, CFTreasWind)
  [8019CCF8-8019D574] inside DR/sandwormBoss.c — itself a container
  (hosts 0x148 CFGuardian tail + 0x149 + GunPowderBarrel helper, audit
  fully before carving).

### 2. GunPowderBarrel 0x158 (DR lane)

[801A0EF8-801A25E8], TU=[801A0EF8(prev edge)..801A25EC+]: spans
sandwormBoss.c tail (slot 10 fn at 801A0EF8 + helpers), ALL of gasvent.c
(801A1230-801A1A60), and cannontargetControl.c head. Sibling cut: 0x159
Blasted [801A28D0-801A2BD8] cut by cannontargetControl|gasventControl at
801A2AF8.

### 3. WM_LevelControl 0x209 / WM_GeneralScales 0x20A (LGT lane)

0x209 [801F441C-801F48BC] cut at 801F44B4
(LGTdirectionallight|LGTprojectedlight). 0x20A [801F4B4C-801F4C00] whole
inside LGTprojectedlight.c. This is part of a one-DLL-shift chain:
0x1F8 cut at 801F02F0, 0x1FC cut at 801F0B50, 0x206 cut at 801F37CC,
0x207 cut at 801F3C7C, 0x209 cut at 801F44B4.

### 4 (clean new). dll_01BA_sctotempuzzle | dll_01BB_sctotembond

Boundary 801DD46C cuts 0x1BA mid-block (between hitDetect and update);
ranges do not interleave; real edge = 801DDA28 (0x1BA initialise
801DDA24 + 4). The 01BA file header already notes "boundary fix pending".

## Surgery status (this campaign)

Re-splits landed (all conservation-EXACT, dol byte-identical; see the
per-commit forensics): cut count 132 -> 125.

| case | DLLs | outcome |
|---|---|---|
| LGT/WM | 0x209, 0x20A | dll_0209_wmlevelcontrol.c + dll_020A_wmgeneralscales.c; LGTprojectedlight.c dissolved; LGTdirectionallight/LGTcontrollight re-bounded |
| DR barrel | 0x158, 0x159 | dll_0158_gunpowderbarrel.c + dll_0159_blasted.c; gasvent.c + cannontargetControl.c dissolved |
| windlift complex | 0x106, 0x107, 0x108, 0x10B, 0x10C, 0x10D | six dll_XXXX units; CFguardian.c/windlift.c/CFcrystal.c dissolved; cfforcefield.c/CFBaby.c re-bounded |
| sandwormBoss head | 0x148 (fragment), 0x149 | dll_0148_cfguardian.c + dll_0149_cfwindlift.c (skeleton-copy); sandwormBoss.c keeps the 10-DLL tail |
| SC totem | 0x1BA | dll_01BA/01BB boundary moved 801DD46C -> 801DDA28 |

Deferred (documented, descriptor-pinned but out of this campaign's scope):
- 0x148's true TU start is inside DR/hightop.c (slot-10 callback at
  0x8019AF4C); the boundary at 0x8019B1D8 still cuts it.
- sandwormBoss.c remains a 10-DLL container (0x14A..0x157).
- The WM chain upstream of 0x209 (0x1F8 cut at 801F02F0, 0x1FC at
  801F0B50, 0x206 at 801F37CC, 0x207 at 801F3C7C) - ARWarwingattachment.c
  is an 8-DLL container.
- fn_801DD170 (sc_totempuzzle callback) sits just before dll_01BA's start;
  helper-gap attribution of [801DD170-801DD1A8) left alone (ambiguous).
- The modgfx micro-unit field (dll_64..dll_8B etc., dozens of 1-3-fn
  units cutting 0x0B2..0x0C2) and the CAM lane (0x42..0x4D) need
  campaign-scale merges, not single boundary moves.

## Mechanized surgery campaign (tools/dll_boundary_resplit.py)

The boundary surgery is now mechanized: `tools/dll_boundary_resplit.py`
consumes the TU model from `dll_boundary_audit.py` (imported as a library),
snaps every cutting boundary onto a TU edge (ts/te, min total move,
region-level monotonic brute force), derives skeleton-projection source ops
(ABSORB whole-unit merges, MOVE partial-fn nudges, CARVE single-donor
splits, address-ordered assembly, pragma-stack-balanced segments, recipe-#57
compile-error-driven decl repair, helper-last auto-retry for inline
regressions), edits splits.txt/configure.py assert-counted, and gates each
case on: full ninja green, main.dol md5 byte-identical, EXACT per-symbol
conservation (fuzzy+size by virtual address, summed matched_code) before
auto-committing. Failures revert completely and are flagged.

Usage: `--plan` to classify the live backlog; `--run [--case ID|--class X]`
to execute; `--carve UNIT` to dissolve a clean multi-DLL container into
per-descriptor units.

Campaign results (38 commits, all conservation-EXACT, dol byte-identical;
global check: 9501 fns and matched_code 1129296 identical before/after):
cut count **125 -> 66**.

- The whole modgfx/proj micro-field (0x0B2..0x0C2, 13 TUs x 3 micro-units
  each) merged into canonical `dll_00XX_<name>.c` units.
- The CAM lane 0x042/0x043/0x045 carve (pathcam/attention/camslide/
  firstperson/camstatic merged + carved at TU edges).
- DR lane fully canonical: dll_0148..dll_0159 (sandwormBoss.c dissolved
  into dll_014A..dll_0157 per-descriptor units).
- ARWarwingattachment.c dissolved into dll_01FD..dll_0204 + two edge
  fragments (dll_801F0B50.c, dll_801F33B4.c); the follow-up r801EE668 pass
  then re-bounded the WClevcontrol..dll_801F0B50 chain, fixing the
  0x1F8/0x1F9/0x1FC cuts (the carve unblocked it).
- One-DLL-shift chains fixed across SH/SC/DIM/DF/CF/MMP/FRONT-adjacent
  lanes (see `git log --grep 're-split: TU-align'` for per-case forensics).
- proximitymine quartet, dll_36/48/49/4A, door/fruit/zBomb (helper-last
  inline suppression; zBomb kept as survivor for its .data descriptor
  claim) merged.

### Flagged cases — STATUS (campaign June 2026)

The audit started at 132 cut descriptors; a long re-split campaign drove it to
32, then the June-2026 push (this section) drove it to **1 remaining cut**
(r8008EE18, proven irreducible — a descriptor that legitimately references
SDK code in a second TU). Every drift-typedef /
def-vs-header / typed-interface / inline-cascade blocker in the historical
flagged table BELOW has been RESOLVED — the prep pattern is in the per-case
`re-split: TU-align` + `resplit prep:` commits (`git log --grep 're-split:'`).

The prep recipes that cracked the historical blockers, for reuse:
- **dead drift externs in the projection** → tool now prunes any top-level
  extern/proto no kept fn body AND no retained descriptor initializer
  references (`prune_unused_externs`).
- **identical duplicate externs** ("illegal name overloading" on a redundant
  file-scope decl) → tool drops them in `reconcile_segment`.
- **return-type-on-own-line Ghidra phantoms** (`undefined4\nFUN_xxxx(...)`) →
  tool parses the real name + collapses the type line (`parse_fn_spans`).
- **moved-fn auto-inline into its owner caller** → tool's `compute_demote`
  now flags moved fns even when address-order assembly puts them in the
  owner's segment region; the regressed caller no longer vetoes the demote.
  When `dont_inline` in the donor is byte-neutral (the fn has no in-donor
  caller AND doesn't inline its own leaves), the cleaner prep is a per-fn
  `#pragma dont_inline on/reset` in the donor (byte-verified).
- **typed-interface globals** (gTitleMenuLinkInterface, gCameraInterface) →
  align the file-scope type to the donor's canonical form, spell the owner's
  uses via the equivalent cast (`(int)*p` == `(int)p->vtable` when vtable is
  the first member); byte-verify.
- **fn-vs-array load-bearing extern** (appleontree_update `u8[]` jump table) →
  declare the fn and spell the table `(u8*)fn + K`; byte-neutral, lets the
  descriptor coexist with the fn def in one TU.
- **dual struct-view of a shared global** (lbl_803A9458 LinkMenuItemDB vs
  LinkMenuItem; linkTextures u8[0x30] vs LinkTexture[6]) → block-scope the
  donor's view into its fns and drop the file-scope decl (or cast the
  struct-view accesses through a u8[] base); byte-verify.
- **dead/used objlib drift decls in a shared header** (the former vf_shared.h's
  undefined4()/undefined8() forms colliding with objlib.h in a merged TU) →
  drop the dead ones; #57-block-scope the used ones into their consumers,
  then drop from the header. Full-project .o-hash A/B gates it.
- **header decl arity drift** (anim.h dbegg `(void)` vs main.c defs) → align
  the header decl to the def (the unit is usually the only consumer).
- **descriptor-fn decl arity drift** (dll_FC_update `(void)` etc., all used
  only as `(ObjectDescriptorCallback)` casts) → align each extern to its def.

| case | DLLs | status |
|---|---|---|
| r8010847C | 0x019,0x02E,0x047-0x04D | RESOLVED (3ce84636b) |
| r801159E4 | 0x033,0x034 | RESOLVED (c202818f3) |
| r8011CD54 | 0x000,0x03C | RESOLVED (da5ec715e) |
| r8014E1DC | 0x0CA,0x0E1 | RESOLVED (775aeddb3) |
| r80161F0C | 0x0CF,0x0D2,0x0D3 | RESOLVED (ea604c844) |
| r80169360 | 0x0D7,0x0DB,0x0ED,0x0EF,0x0FF | RESOLVED (prior campaign) |
| r8017AC2C | 0x0FB,0x0FC,0x0FD,0x111,0x115,0x117 | RESOLVED (67156a840) |
| r80191F2C | 0x136,0x13B,0x13C,0x141 | RESOLVED (prior campaign) |
| r801993B0 | 0x148 | RESOLVED (79f7f619c) |
| r801A2BDC | 0x15B | RESOLVED (prior campaign) |
| r801AC248 | 0x16D,0x1C0,0x1C1,0x1C2 | RESOLVED (51a91a93e) |
| r801C5990 | 0x18F,0x190,0x192 | RESOLVED (8cb0c8a9a) |
| r801CD7DC | 0x19F,0x1A1,0x1A2 | RESOLVED (93e00ff36) |
| r801D4CD0 | 0x1AD,0x1AE,0x1B0,0x1B1,0x1B4,0x1B7 | RESOLVED (f0d42f346) |
| r801E76A0 | 0x255,0x287,0x288 | RESOLVED (87dfded25) |
| r801CFD68 | 0x1A7,0x1A8,0x1A9,0x1AA | RESOLVED (1ba617873) |
| r801F33B4 | 0x206,0x207 | RESOLVED (21fcab956) |
| r801FB9AC | 0x21E,0x224,0x22F,0x230,0x23F | RESOLVED (887fa72dd) |

### Remaining (proven-irreducible)

| case | DLLs | status |
|---|---|---|
| r8008EE18 | 0x009 | IRREDUCIBLE — descriptor legitimately references SDK code in gamecube.c |

r800C8008 (0x003,0x00F,0x014) is now RESOLVED (bcc2674e2) — see the
conservation-gate note below; the "frame/coloring cascade" was an objdiff
re-attribution artifact, the linked binary is byte-identical.

**CONSERVATION-GATE INSIGHT (r800C8008):** the resplit tool's per-symbol
fuzzy conservation check OVER-rejects when a unit's splits range shifts. When
the curves chain (a 32-fn move into objfsa) was applied, objdiff reported 244
matched_code "lost" and ~14 fns "regressed" (RomCurve_func2C 90.6→80.8, etc.)
— but main.dol md5 stayed == DOL_MD5 (7b955850...), and the regressed fns were
proven BYTE-IDENTICAL in the linked elf disasm vs the clean build. The drop is
pure objdiff re-attribution: objdiff maps a unit's symbols onto target
addresses by position, so already-partial fns in a range-shifted unit score
against neighbouring target bytes. The dol md5 is the authoritative
conservation proof (a real matched-byte change moves it); the gate now trusts
it and passes range-shift cases with the per-symbol drift logged as advisory.

**r8008EE18 (0x009) — IRREDUCIBLE, not a drift cut.** The dll 0x009
descriptor `lbl_8030F7E8` (auto_07 data) legitimately points its tail slots
(slot 11/12/13 = the getObjectTypeId/getExtraSize-family) at the THREE MSL SDK
functions `__end_critical_region` / `__begin_critical_region` /
`__kill_critical_regions` (80094494-800944A0), with its body slots pointing at
cloudaction.c's fns. The SDK fns correctly live in
`dolphin/MSL_C/PPCEABI/bare/H/gamecube.c` (a MatchingFor SDK unit) and CANNOT
move into cloudaction.c without breaking the SDK unit's link/match. The audit
flags it because the descriptor's fn-pointer span crosses the gamecube|
cloudaction boundary, but that span is a legitimate two-TU reference, not a
unit-boundary error. No conservation-preserving move exists. Leave as-is.

**r800C8008 (0x003,0x00F,0x014) — RESOLVED (bcc2674e2).** The partfx→curves
chain (df_partfx→dim_partfx, objfsa→df_partfx, curves→objfsa, a 32-fn move into
objfsa) compiles cleanly with the current tool (the old RomCurveSegmentProjection
tag-redef and illegal-name-overloading blockers are fixed). The apparent
conservation failure (~14 fns "regressing", 244 matched_code "lost") was a
FALSE ALARM: with the merge applied, main.dol md5 stayed == DOL_MD5 and the
"regressed" fns (RomCurve_func2C, func29, curves_distFn15, findByIdWithIndex)
are byte-identical in the linked elf. RomCurve_func2C's frame is -208 in BOTH
the clean and merged builds (the -160 I first saw was the retail TARGET tree
under build/GSAE01/obj — that fn was a 90.6% partial to begin with; the merge
changed nothing). The gate now trusts the dol md5; the case lands
conservation-EXACT at the binary level.

The historical fix patterns (now all proven) are above; the resplit campaign is
complete bar the one irreducible SDK-gated descriptor (r8008EE18).

## Live cut table (1 descriptor — post-campaign)

Reproduce with `--md`. After the June 2026 re-split campaign only the
proven-irreducible MSL-edge cut remains.

| dll | descriptor | fn range | TU (proposed) | cutting boundary(ies) | reach | names |
|---|---|---|---|---|---|---|
| 0x009 | lbl_8030F7E8 | 80094494-80094F60 | 80093AE0-80094F7C | 800944A0 (dolphin/MSL_C/PPCEABI/bare/H/gamecube.c \| main/dll/cloudaction.c) | n |  |

## CF-lane canonical-naming finish (June 2026)

The five remaining CF multi-DLL containers were carved into per-descriptor
units (`tools/dll_boundary_resplit.py --carve`, EXACT per-symbol conservation,
main.dol byte-identical):

| container | -> per-descriptor units |
|---|---|
| CFchuckobj.c | dll_012D_lfxemitter (0x12D), dll_0130_areafxemit (0x130), + warppad.c |
| CFforcecontrol.c | dll_010E_dieduster (0x10E), dll_0123_fuelcell (0x123), dll_0124_deathgas (0x124) |
| treasureRelated0177.c | dll_0127_dll127 (0x127), dll_0128_kttorch (0x128), dll_0129_campfire (0x129) |
| CFtoggleswitch.c | dll_011E..dll_0122 (0x11E-0x122) |
| CFBaby.c | dll_00E7,dll_00EC,dll_0109,dll_010A,dll_0119,dll_011A,dll_011B (7 descriptors) |

Trailing-fragment dispositions (the descriptor TU-end pin leaves post-init
helper tails as synthetic units):
- **warppad.c** (`8019042C-80190BD4`, ex-`dll_8019042C.c`): the transporter
  DLL (0x12C) head — `warpPadFn_8019042c`/`warpPadPlayerStandingOn`, a
  NO-RETAIL-NAME infrastructure helper TU called by dll_012C_transporter via
  external `bl` relocs (distinct TU, not inlined). Renamed after its
  `warp_pad.h` / `warpPad*` stem.
- **landed_arwing tail** (`80189610-801899B4`): `updateHitReaction`/
  `updateDamageTexture` are part of the Landed_Arwing DLL (0x11B) — called by
  `landed_arwing_update`, kept as one TU in retail (distinct global symbols,
  not inlined). Merged back into `dll_011B_landedarwi.c`.

No-descriptor / vestigial-unit dispositions:
- **CFPrisonGuard.c** (`801899B4-80189F5C`): a valid no-descriptor TU per the
  audit (no cut flagged at the `80189F5C` edge), NOT the 0x14E CFPrisonGuard
  DLL (that is canonical in DR/dll_014E_cfprisonguard.c). It hosts the
  staffactivated DLL's helper head (`staffactivated_updateLiftHeight`/
  `spawnMapEventDebris`, called by dll_011C_staffactivated's
  `staffactivated_update` via an external `bl` — a genuine cross-TU call,
  not inlined in retail) plus the `cfPrisonGuard_*` player.c gamebit-mirror
  API. **Kept as its own helper TU** — it is not a DLL (owns no descriptor),
  so it is outside the `dll_XXXX_<name>.c` namespace; merging into dll_011C
  would risk inlining its once-called 0x230B helper against the retail
  evidence of separate TUs. Name retained (matches its `cfPrisonGuard_*`
  content + `CFPrisonGuard.h`).
- **dll_15E.c**: deleted (unwired comment-only doc stub; its
  `windlift->CFcrystal->CFBaby` corridor claim is captured here and
  superseded by the windlift-complex dissolution, see surgery status above).
- **CF/dll_17A.c, CF/laser.c**: deleted (stale empty `start==end` placeholder
  units owning no .text/.data — their ranges are subsumed by
  dll_012A_cfcrate / dfppowersl respectively; the real 0x17A SpiritPrize lives
  in dll_017A_spiritprize.c, the real laser DLLs in the WC lane). `laser.h`
  KEPT (shared header used by main.h + the dfp laser DLLs); the dead
  `dll_17A.h` removed.

## Complete cut table (132 descriptors, pre-surgery — historical record)

| dll | descriptor | fn range | TU (proposed) | cutting boundary(ies) | reach | names |
|---|---|---|---|---|---|---|
| 0x009 | lbl_8030F7E8 | 80094494-80094F60 | 80093AE0-80094F7C | 800944A0 (dolphin/MSL_C/PPCEABI/bare/H/gamecube.c \| main/dll/cloudaction.c) | n |  |
| 0x003 | lbl_803112E8 | 800D5530-800D7548 | 800D5530-800D7568 | 800D6660 (main/dll/dim_partfx.c \| main/dll/df_partfx.c) | n |  |
| 0x00F | lbl_80311438 | 800D8020-800D9DC8 | 800D8020-800D9DCC | 800D8F90 (main/dll/df_partfx.c \| main/dll/objfsa.c) | n |  |
| 0x014 | lbl_803115F8 | 800E0134-800E5430 | 800D9EE8-800E5434 | 800E1B24 (main/dll/objfsa.c \| main/dll/curves.c) | n |  |
| 0x0B4 | lbl_803196D8 | 801007B8-801007EC | 801007B8-801007F0 | 801007E8 (main/dll/modgfx67.c \| main/dll/dll_68.c); 801007EC (main/dll/dll_68.c \| main/dll/dll_69.c) | n |  |
| 0x0B5 | lbl_80319720 | 801007F0-80100824 | 801007F0-80100828 | 80100820 (main/dll/dll_6A.c \| main/dll/dll_6B.c); 80100824 (main/dll/dll_6B.c \| main/dll/dll_6C.c) | n |  |
| 0x0B2 | lbl_80319768 | 80100828-8010085C | 80100828-80100860 | 80100858 (main/dll/dll_6D.c \| main/dll/dll_6E.c); 8010085C (main/dll/dll_6E.c \| main/dll/dll_6F.c) | n |  |
| 0x0B6 | lbl_803197B0 | 80100860-80100894 | 80100860-80100898 | 80100890 (main/dll/dll_70.c \| main/dll/dll_71.c); 80100894 (main/dll/dll_71.c \| main/dll/dll_AF.c) | n |  |
| 0x0B7 | lbl_803197F8 | 80100898-801008CC | 80100898-801008D0 | 801008C8 (main/dll/dll_72.c \| main/dll/dll_73.c); 801008CC (main/dll/dll_73.c \| main/dll/dll_74.c) | n |  |
| 0x0BB | lbl_80319840 | 801008D0-80100904 | 801008D0-80100908 | 80100900 (main/dll/dll_64.c \| main/dll/dll_75.c); 80100904 (main/dll/dll_75.c \| main/dll/dll_76.c) | n |  |
| 0x0BC | lbl_80319888 | 80100908-8010093C | 80100908-80100940 | 80100938 (main/dll/dll_77.c \| main/dll/dll_78.c); 8010093C (main/dll/dll_78.c \| main/dll/dll_79.c) | n |  |
| 0x0BD | lbl_803198D8 | 80100940-80100974 | 80100940-80100978 | 80100970 (main/dll/dll_7A.c \| main/dll/dll_7B.c); 80100974 (main/dll/dll_7B.c \| main/dll/dll_7C.c) | n |  |
| 0x0BE | lbl_80319920 | 80100978-801009AC | 80100978-801009B0 | 801009A8 (main/dll/dll_7D.c \| main/dll/dll_7E.c); 801009AC (main/dll/dll_7E.c \| main/dll/dll_7F.c) | n |  |
| 0x0BF | lbl_80319968 | 801009B0-801009E4 | 801009B0-801009E8 | 801009E0 (main/dll/dll_80.c \| main/dll/dll_81.c); 801009E4 (main/dll/dll_81.c \| main/dll/dll_82.c) | n |  |
| 0x0C0 | lbl_803199B0 | 801009E8-80100A1C | 801009E8-80100A20 | 80100A18 (main/dll/dll_83.c \| main/dll/dll_84.c); 80100A1C (main/dll/dll_84.c \| main/dll/dll_85.c) | n |  |
| 0x0C1 | lbl_803199F8 | 80100A20-80100A54 | 80100A20-80100A58 | 80100A50 (main/dll/modcloudrunner2.c \| main/dll/dll_87.c); 80100A54 (main/dll/dll_87.c \| main/dll/dll_88.c) | n |  |
| 0x0C2 | lbl_80319A40 | 80100A58-80100A8C | 80100A58-80100A90 | 80100A88 (main/dll/dll_89.c \| main/dll/dll_8A.c); 80100A8C (main/dll/dll_8A.c \| main/dll/dll_8B.c) | n |  |
| 0x042 | lbl_80319B58 | 801046F4-80106618 | 80103524-80106654 | 801049B0 (main/dll/CAM/attention.c \| main/dll/CAM/camslide.c); 8010509C (main/dll/CAM/camslide.c \| main/dll/CAM/firstperson.c); 80105810 (main/dll/CAM/firstperson.c \| main/dll/CAM/dll_53.c); 80105810 (main/dll/CAM/firstperson.c \| main/dll/CAM/camstatic.c); 80105E7C (main/dll/CAM/camstatic.c \| main/dll/CAM/pathcam.c) | n |  |
| 0x043 | lbl_80319B98 | 801070CC-80107AE8 | 80106654-80107AEC | 801070FC (main/dll/CAM/camshipbattle.c \| main/dll/CAM/camclimb.c); 8010747C (main/dll/CAM/camclimb.c \| main/dll/CAM/dll_59.c) | n |  |
| 0x045 | lbl_80319BC8 | 80107AEC-8010800C | 80107AEC-80108010 | 80107B4C (main/dll/CAM/dll_59.c \| main/dll/CAM/camTalk.c) | n |  |
| 0x047 | lbl_80319C88 | 8010B3F4-8010BF04 | 8010A104-8010BF08 | 8010B424 (main/dll/CAM/camcannon.c \| main/dll/CAM/dll_5F.c) | n |  |
| 0x049 | lbl_80319CE8 | 8010C064-8010CEBC | 8010BF08-8010CEC0 | 8010C0D8 (main/dll/CAM/dll_5F.c \| main/dll/CAM/dll_60.c); 8010C0D8 (main/dll/CAM/dll_5F.c \| main/dll/CAM/camdrakor.c) | n |  |
| 0x04B | lbl_80319D48 | 8010D33C-8010DAD0 | 8010D33C-8010DAD4 | 8010D36C (main/dll/CAM/camdrakor.c \| main/dll/CAM/dll_62.c); 8010D810 (main/dll/CAM/dll_62.c \| main/dll/CAM/camDebug.c) | n |  |
| 0x04D | lbl_80319DA8 | 8010DD24-8010E518 | 8010DB7C-8010E51C | 8010DD58 (main/dll/CAM/camDebug.c \| main/dll/baddieControl.c) | n |  |
| 0x019 | dll_19 | 80112D80-80113F88 | 80111D14-80113F8C | 80113504 (main/dll/baddieControl.c \| main/dll/moveLib.c) | n |  |
| 0x02E | dll_2E | 80113F9C-801159E0 | 80113F8C-801159E4 | 80115094 (main/dll/moveLib.c \| main/dll/projLib.c); 80115650 (main/dll/projLib.c \| main/dll/FRONT/POST.c) | n |  |
| 0x033 | lbl_8031A1A0 | 80115F20-801160E0 | 80115F20-8011611C | 80115FBC (main/dll/FRONT/n_rareware.c \| main/dll/FRONT/dll_39.c) | n |  |
| 0x034 | lbl_8031A304 | 801165BC-80116F84 | 8011611C-8011730C | 801166C8 (main/dll/FRONT/dll_39.c \| main/dll/FRONT/n_filemenu.c); 80116F84 (main/dll/FRONT/n_filemenu.c \| main/dll/FRONT/dll_3B.c) | n |  |
| 0x036 | lbl_8031A8D0 | 8011B5D4-8011BE9C | 8011B5D4-8011BFC8 | 8011B868 (main/dll/dll_36.c \| main/dll/dll_48.c); 8011B868 (main/dll/dll_36.c \| main/dll/dll_49.c); 8011B868 (main/dll/dll_36.c \| main/dll/dll_4A.c) | n |  |
| 0x000 | lbl_8031C020 | 8012EB24-8012FDD4 | 8011D918-8012FECC | 8012EB7C (main/dll/baddie/baby_snowworm.c \| main/dll/baddie/wall_crawler.c); 8012FCEC (main/dll/baddie/wall_crawler.c \| main/dll/baddie/dll_DB.c) | n |  |
| 0x03C | lbl_8031C1E4 | 80130620-801314C4 | 80130124-80131540 | 80130888 (main/dll/baddie/dll_DB.c \| main/dll/baddie/dll_DA.c); 80130CF0 (main/dll/baddie/dll_DA.c \| main/dll/baddie/TumbleweedBush.c) | n |  |
| 0x0C9 | gBaddieObjDescriptor | 8014D154-8014E1A4 | 80148B78-8014E1DC | 8014D164 (main/dll/sidekickToy.c \| main/dll/projswitch.c) | Y | GuardClaw,GCRobotPatr,Vambat,Firebat |
| 0x0E1 | gWispBaddieObjDescriptor | 8014F980-8014FEF4 | 8014F620-8014FEF8 | 8014F9E8 (main/dll/pressureSwitch.c \| main/dll/seqObj.c) | Y | WispBaddie |
| 0x0CA | dll_CA | 8015D5B8-8015DAC8 | 8014FEF8-8015DAE8 | 8015D7B0 (main/dll/mediumbasket.c \| main/dll/scarab.c) | n |  |
| 0x0CF | gCannonClawObjDescriptor | 80163094-801631C4 | 80162FC0-801631C8 | 801630EC (main/dll/barrel.c \| main/dll/ladders.c) | Y | CannonClaw,CannonClawO |
| 0x0D2 | gTumbleweedObjDescriptor | 80163FB0-80164F2C | 801638BC-801650D0 | 801641B0 (main/dll/waterfallControl.c \| main/dll/backpack.c) | Y | Tumbleweed1,Tumbleweed2,Tumbleweed3,Tumbleweed4 |
| 0x0D3 | dll_D3 | 80166C7C-8016758C | 801650D0-801675E0 | 80166F2C (main/dll/staffAction.c \| main/dll/treasurechest.c) | n |  |
| 0x0D7 | gKaldaChompSpitObjDescriptor | 8016980C-80169EF0 | 801696D4-80169EF4 | 80169CC4 (main/dll/wallanimator.c \| main/dll/xyzanimator.c) | Y | KaldachomSp,FireCrawler |
| 0x0DB | gMikaBombObjDescriptor | 8016B230-8016B70C | 8016B230-8016B710 | 8016B2E0 (main/dll/xyzanimator.c \| main/dll/genprops.c) | Y | MikaBomb |
| 0x0ED | gCollectibleObjDescriptor | 80171D70-80173220 | 80171D14-80173224 | 801723DC (main/dll/genprops.c \| main/dll/gfxEmit.c); 80172F14 (main/dll/gfxEmit.c \| main/dll/texframeanimator.c) | Y | CFCloudCalP,CFPickKryst,CFPowerCrys,CFPowerCrys |
| 0x0FF | gMagicDustObjDescriptor | 80173224-80173AEC | 80173224-80173F80 | 801732A4 (main/dll/texframeanimator.c \| main/dll/lightning.c) | Y | MagicDustSm,MagicDustMi,MagicDustLa,MagicDustHu |
| 0x0EF | gPushableObjDescriptor | 80175520-801769B4 | 80174438-80176FC4 | 801755CC (main/dll/dll_138.c \| main/dll/transporter.c) | Y | WCPushBlock,DIMPushBloc,DIM2IceBloc,CCboulder |
| 0x0F5 | gSidekickBallObjDescriptor | 80179738-80179EB0 | 801793A4-8017A00C | 801797A4 (main/dll/autoTransporter.c \| main/dll/sidekickball.c); 80179A2C (main/dll/sidekickball.c \| main/dll/fogcontrol.c); 80179EB0 (main/dll/fogcontrol.c \| main/dll/tFrameAnimator.c) | Y | SidekickBal |
| 0x0F9 | gProjectileSwitchObjDescriptor | 8017A350-8017A8E8 | 8017A350-8017A8EC | 8017A38C (main/dll/tFrameAnimator.c \| main/dll/screenOverlay.c) | Y | DRProjectil,ProjectileS |
| 0x0FA | gInvisibleHitSwitchObjDescriptor | 8017A8EC-8017AB20 | 8017A8EC-8017AC2C | 8017AB20 (main/dll/screenOverlay.c \| main/dll/cloudprisoncontrol.c) | Y | InvisibleHi |
| 0x0FB | gPressureSwitchFBObjDescriptor | 8017AD88-8017B3F8 | 8017AC2C-8017B5C8 | 8017ADB4 (main/dll/texScroll.c \| main/dll/dll_147.c); 8017ADB4 (main/dll/texScroll.c \| main/dll/cfguardian.c) | Y | WCTemplePre,LINK_SnowPr,LINK_UnderW,CC_Pressure |
| 0x111 | gDoorLockObjDescriptor | 8017BDAC-8017C178 | 8017BCF8-8017C294 | 8017C178 (main/dll/cfguardian.c \| main/dll/alphaanim.c) | Y | CFPowerLock,CFDoubleSwi,WCTeethBowl,DIMLever |
| 0x115 | lbl_80321428 | 8017D06C-8017D378 | 8017CF90-8017D37C | 8017D0D4 (main/dll/alphaanim.c \| main/dll/groundAnimator.c) | n |  |
| 0x117 | gAppleOnTreeObjDescriptor | 8017D818-8017E964 | 8017D818-8017EC10 | 8017E1A0 (main/dll/groundAnimator.c \| main/dll/crackanim.c) | Y | AppleOnTree |
| 0x0FC | gDllFCObjDescriptor | 8017EC10-8017EF68 | 8017EC10-8017EF6C | 8017EC94 (main/dll/crackanim.c \| main/dll/babycloudrunner.c) | n |  |
| 0x0FD | gDll14DObjDescriptor | 8017EF6C-8017F330 | 8017EF6C-8017F334 | 8017EFF0 (main/dll/babycloudrunner.c \| main/dll/dll_14D.c) | n |  |
| 0x104 | gSmallBasketObjDescriptor | 80182594-80183094 | 801814D0-80183204 | 801826E8 (main/dll/gcrobotlightbea.c \| main/dll/cfperch.c) | Y | SmallBasket,ReinforcedC |
| 0x105 | gLargeCrateObjDescriptor | 80183B44-801843BC | 80183204-801843C0 | 80184180 (main/dll/explodable.c \| main/dll/cfforcefield.c) | Y | DrakorCrate,LargeBasket,LargeCrate,LargeCrateL |
| 0x106 | gScarabObjDescriptor | 801847E8-801856C4 | 801843C0-80185868 | 80184930 (main/dll/CF/CFguardian.c \| main/dll/CF/windlift.c) | Y | GreenScarab,RedScarab,GoldScarab,RainScarab |
| 0x10C | gLanternFireFlyObjDescriptor | 80186704-801871C4 | 80186704-801871C8 | 80186B94 (main/dll/CF/windlift.c \| main/dll/CF/CFcrystal.c) | Y | LanternFire |
| 0x10B | gFireFlyLanternObjDescriptor | 801873C8-80187524 | 801871C8-80187640 | 80187524 (main/dll/CF/CFcrystal.c \| main/dll/CF/CFBaby.c) | Y | FireFlyLant |
| 0x11C | gStaffActivatedObjDescriptor | 8018A22C-8018A53C | 80189610-8018A8BC | 8018A53C (main/dll/CF/dll_163.c \| main/dll/CF/dll_165.c) | Y | LINKStaffLe,StaffAction,StaffBoostP,StaffBoulde |
| 0x11D | gTreasureChestObjDescriptor | 8018A9B4-8018ADB0 | 8018A8BC-8018ADB4 | 8018AA60 (main/dll/CF/dll_165.c \| main/dll/CF/dll_166.c) | Y | TreasureChe,MapTreasure |
| 0x11E | gMagicCaveBottomObjDescriptor | 8018ADB4-8018ADF0 | 8018ADB4-8018AFC8 | 8018ADF0 (main/dll/CF/dll_166.c \| main/dll/CF/CFtoggleswitch.c) | Y | MagicCaveBo |
| 0x124 | gDeathGasObjDescriptor | 8018BC48-8018BFBC | 8018BC48-8018C000 | 8018BC50 (main/dll/CF/CFtoggleswitch.c \| main/dll/CF/CFforcecontrol.c) | Y | deathGas,deathGasNoF |
| 0x127 | lbl_80321E58 | 8018CD64-8018CEE0 | 8018CD64-8018CEE4 | 8018CDAC (main/dll/CF/CFforcecontrol.c \| main/dll/CF/treasureRelated0177.c) | n |  |
| 0x12A | gCFCrateObjDescriptor | 8018D6E8-8018E6C0 | 8018D6E8-8018E6C4 | 8018D728 (main/dll/CF/treasureRelated0177.c \| main/dll/CF/dll_179.c); 8018D8DC (main/dll/CF/dll_179.c \| main/dll/CF/dll_17A.c); 8018D8DC (main/dll/CF/dll_179.c \| main/dll/CF/CFlevelControl.c); 8018E0A4 (main/dll/CF/CFlevelControl.c \| main/dll/CF/CFTreasSharpy.c) | Y | CFCrate,LinkF_liftg,LinkF_cog,MMP_Organic |
| 0x12B | gFXEmitObjDescriptor | 8018EC24-8018F144 | 8018E6C4-8018F148 | 8018EFE0 (main/dll/CF/CFTreasSharpy.c \| main/dll/CF/CFchuckobj.c) | Y | FXEmit |
| 0x12C | gTransporterObjDescriptor | 801914A0-801916A0 | 8019042C-80191A70 | 801916A0 (main/dll/CF/CFwalltorch.c \| main/dll/moonseedbush.c); 801916A0 (main/dll/CF/CFwalltorch.c \| main/dll/mmp_asteroid_re.c) | Y | KP_Transpor,Transporter |
| 0x136 | gWaveAnimatorObjDescriptor | 80192394-80192A64 | 80192394-80192A68 | 801923C4 (main/dll/mmp_moonrock.c \| main/dll/MMP/mmp_barrel.c) | Y | WaveAnimato |
| 0x13B | gWallAnimatorObjDescriptor | 80194408-8019483C | 80194408-801948C0 | 8019443C (main/dll/MMP/mmp_barrel.c \| main/dll/MMP/mmp_levelcontrol.c) | Y | WallAnimato |
| 0x13C | gXYZAnimatorObjDescriptor | 80194B5C-80196218 | 801948C0-801962C8 | 80195008 (main/dll/MMP/mmp_levelcontrol.c \| main/dll/MMP/MMP_asteroid.c) | Y | XYZAnimator |
| 0x141 | gLightningObjDescriptor | 801978A0-80197C54 | 801978A0-80197DA8 | 801978A8 (main/dll/MMP/MMP_asteroid.c \| main/dll/MMP/MMP_moonrock.c) | Y | Lightning |
| 0x148 | gCFGuardianObjDescriptor | 8019AF4C-8019C780 | 8019AE3C-8019C784 | 8019B1D8 (main/dll/DR/hightop.c \| main/dll/DR/sandwormBoss.c) | Y | CFGuardian |
| 0x158 | gGunPowderBarrelObjDescriptor | 801A0EF8-801A25E8 | 801A0B14-801A27B8 | 801A1230 (main/dll/DR/sandwormBoss.c \| main/dll/DR/gasvent.c); 801A1A60 (main/dll/DR/gasvent.c \| main/dll/DR/cannontargetControl.c) | Y | GunPowderBa,MetalBarrel |
| 0x159 | gBlastedObjDescriptor | 801A28D0-801A2BD8 | 801A27B8-801A2BDC | 801A2AF8 (main/dll/DR/cannontargetControl.c \| main/dll/DR/gasventControl.c) | Y | CFBlastedRo,CFBlastedWa,CFBlastedTu,DRBlastedWa |
| 0x15B | gCFForceFieldObjDescriptor | 801A39B4-801A3E98 | 801A39B4-801A3E9C | 801A39D0 (main/dll/DR/gasventControl.c \| main/dll/IM/IMicicle.c) | Y | CFForceFiel |
| 0x17E | gMMP_levelcontrolObjDescriptor | 801A66FC-801A6C24 | 801A6638-801A6C28 | 801A6778 (main/dll/IM/IMspacecraft.c \| main/dll/DIM/DIMlavaball.c) | Y | MMP_levelco |
| 0x187 | gCCqueenObjDescriptor | 801AA558-801AA694 | 801AA558-801AA734 | 801AA560 (main/dll/DIM/DIMlogfire.c \| main/dll/DIM/DIMsnowball.c) | Y | CCqueen |
| 0x16D | gIMIcePillarObjDescriptor | 801AE0EC-801AE140 | 801AE0EC-801AE144 | 801AE100 (main/dll/DIM/DIMboulder.c \| main/dll/DIM/DIMcannon.c) | Y | IMIcePillar |
| 0x1C0 | gDIMLogFireObjDescriptor | 801B07B0-801B0BE8 | 801B0670-801B0DD4 | 801B0924 (main/dll/DIM/DIMcannon.c \| main/dll/DIM/DIMlavasmash.c) | Y | DIMLogFire,DIMLogFireR |
| 0x1C1 | gDIMSnowBallObjDescriptor | 801B0DD4-801B13E4 | 801B0DD4-801B13E8 | 801B1354 (main/dll/DIM/DIMlavasmash.c \| main/dll/DIM/dimsnowball_init.c) | Y | DIMSnowBall |
| 0x1C2 | gDIMSnowBall1C2ObjDescriptor | 801B13E8-801B15D4 | 801B13E8-801B15D8 | 801B13F0 (main/dll/DIM/dimsnowball_init.c \| dolphin/TRK_MINNOW_DOLPHIN/MWCriticalSection_gc.c); 801B13F0 (main/dll/DIM/dimsnowball_init.c \| main/dll/DIM/DIMExplosion.c) | Y | DIMSnowBall |
| 0x1C7 | gDIMLavaSmashObjDescriptor | 801B3570-801B3764 | 801B3344-801B3768 | 801B3658 (main/dll/DIM/DIMlevcontrol.c \| main/dll/DIM/DIM2conveyor.c) | Y | DIMLavaSmas |
| 0x1CD | gDIM_LevelControlObjDescriptor | 801B63F4-801B69AC | 801B63F4-801B6B44 | 801B6464 (main/dll/DIM/DIM2flameburst.c \| main/dll/DIM/DIM2snowball.c) | Y | DIM_LevelCo |
| 0x1DA | dll_1DA | 801B8798-801B8B6C | 801B8798-801B8B70 | 801B8860 (main/dll/DIM/DIM2snowball.c \| main/dll/DIM/DIM2projrock.c) | n |  |
| 0x1E2 | gDIM_BossTonsilObjDescriptor | 801BE86C-801BEE64 | 801BDCF8-801BEEA0 | 801BE8F8 (main/dll/vfp_lavapool.c \| main/dll/vfp_lavastar.c); 801BEC70 (main/dll/vfp_lavastar.c \| main/dll/riverFlowRelated018D.c) | Y | DIM_BossTon |
| 0x1E7 | gDIMbossfireObjDescriptor | 801C04B8-801C0A5C | 801C04B8-801C0A60 | 801C053C (main/dll/DF/rope.c \| main/dll/DF/DFcradle.c) | Y | DIMbossfire,MMP_CraterF,CraterFlame |
| 0x175 | gDFropenodeObjDescriptor | 801C1970-801C2680 | 801C0BF8-801C26E0 | 801C1BC8 (main/dll/DF/dll_194.c \| main/dll/DF/dll_195.c); 801C1BF0 (main/dll/DF/dll_195.c \| main/dll/DF/dll_196.c); 801C1EAC (main/dll/DF/dll_196.c \| main/dll/DF/DFmole.c); 801C1F5C (main/dll/DF/DFmole.c \| main/dll/DF/DFwhirlpool.c); 801C2278 (main/dll/DF/DFwhirlpool.c \| main/dll/DF/dll_198.c) | Y | DFropenode |
| 0x177 | gDFSH_Door2SpeciObjDescriptor | 801C281C-801C2910 | 801C26E0-801C2914 | 801C2824 (main/dll/DF/dll_198.c \| main/dll/DF/dll_199.c); 801C282C (main/dll/DF/dll_199.c \| main/dll/DF/DFlantern.c) | Y | DFSH_Door2S,DFSH_Door3S,DFSH_Door4S |
| 0x178 | gDFSH_ShrineObjDescriptor | 801C2DC4-801C3614 | 801C2914-801C3618 | 801C2E68 (main/dll/DF/DFlantern.c \| main/dll/dll_19C.c) | Y | DFSH_Shrine |
| 0x179 | gDFSH_ObjCreatorObjDescriptor | 801C3B68-801C3E38 | 801C3B68-801C3E3C | 801C3BB0 (main/dll/dll_19C.c \| main/dll/dll_19E.c) | Y | DFSH_ObjCre |
| 0x17B | gDFSH_LaserBeamObjDescriptor | 801C3E3C-801C4660 | 801C3E3C-801C4664 | 801C3EB8 (main/dll/dll_19E.c \| main/dll/creator19D.c) | Y | DFSH_LaserB |
| 0x18C | gMMSH_ShrineObjDescriptor | 801C4D78-801C539C | 801C4664-801C53A0 | 801C52D8 (main/dll/laser19F.c \| main/dll/mmshrine/shrine.c) | Y | MMSH_Shrine |
| 0x18F | gECSH_ShrineObjDescriptor | 801C5E78-801C6E08 | 801C5990-801C6E0C | 801C5ED8 (main/dll/mmshrine/animobj1C0.c \| main/dll/mmshrine/torch1C1.c); 801C60B8 (main/dll/mmshrine/torch1C1.c \| main/dll/mmshrine/shrine1C2.c) | Y | ECSH_Shrine |
| 0x192 | gGPSH_ShrineObjDescriptor | 801C75A8-801C8080 | 801C70F0-801C8084 | 801C7724 (main/dll/mmshrine/shrine1C2.c \| main/dll/creator1C4.c) | Y | GPSH_Shrine |
| 0x190 | gECSH_CupObjDescriptor | 801C835C-801C8B64 | 801C835C-801C8B68 | 801C83D0 (main/dll/creator1C4.c \| main/dll/dimbarrier.c) | Y | ECSH_Cup |
| 0x195 | gDBSH_ShrineObjDescriptor | 801C9040-801C965C | 801C8B68-801C9660 | 801C91B0 (main/dll/creator1C6.c \| main/dll/scene1C7.c); 801C9544 (main/dll/scene1C7.c \| main/dll/flybaddie.c) | Y | DBSH_Shrine |
| 0x197 | dll_197 | 801C9E54-801CA714 | 801C9E54-801CA718 | 801CA5B4 (main/dll/cup1C3.c \| main/dll/explosion.c) | n |  |
| 0x199 | dll_199 | 801CACD4-801CB7A4 | 801CA9C0-801CB7A8 | 801CAD80 (main/dll/explosion.c \| main/dll/symbol.c); 801CAD80 (main/dll/explosion.c \| main/dll/dimmagicbridge.c) | n |  |
| 0x19B | dll_19B | 801CBD14-801CC728 | 801CBA98-801CC72C | 801CBD88 (main/dll/torch1CD.c \| main/dll/shrine1CE.c) | n |  |
| 0x19E | dll_19E | 801CCFA4-801CD7D8 | 801CCFA4-801CD7DC | 801CCFB4 (main/dll/shrine1CE.c \| main/dll/creator1CF.c); 801CD258 (main/dll/creator1CF.c \| main/dll/dim_tricky.c) | n |  |
| 0x19F | gTreeBirdObjDescriptor | 801CDA48-801CDBEC | 801CD7DC-801CDC78 | 801CDBEC (main/dll/dimtruthhornice.c \| main/dll/ped.c) | Y | NW_treebrid,NW_treebrid |
| 0x1A1 | gNW_mammothObjDescriptor | 801CEFB4-801CF4F0 | 801CDE70-801CF78C | 801CEFBC (main/dll/worldobj.c \| main/dll/creator1D4.c); 801CF0AC (main/dll/creator1D4.c \| main/dll/dim2conveyor.c) | Y | NW_mammothh,NW_mammothb,NW_mammothw,NW_mammothg |
| 0x1A2 | gNW_trickyObjDescriptor | 801CF7B8-801CFB04 | 801CF78C-801CFB24 | 801CF7E8 (main/dll/dim2conveyor.c \| main/dll/creator1D6.c) | Y | NW_tricky |
| 0x1A5 | gNW_levcontrolObjDescriptor | 801CFEC4-801D04E0 | 801CFD68-801D069C | 801CFF20 (main/dll/flybaddie1D7.c \| main/dll/projball1D8.c) | Y | NW_levcontr |
| 0x1A7 | gEdibleMushroomObjDescriptor | 801D155C-801D1978 | 801D0828-801D1BFC | 801D16EC (main/dll/NW/NWsfx.c \| main/dll/NW/dll_1DB.c); 801D1978 (main/dll/NW/dll_1DB.c \| main/dll/NW/dll_1DC.c); 801D1978 (main/dll/NW/dll_1DB.c \| main/dll/NW/NWmammoth.c) | Y | LINK_BlueMu,SH_whitemus,BlueMushroo |
| 0x1A8 | gEnemyMushroomObjDescriptor | 801D1D58-801D2868 | 801D1BFC-801D286C | 801D1E24 (main/dll/NW/NWmammoth.c \| main/dll/dim_boss.c); 801D1E24 (main/dll/NW/NWmammoth.c \| main/dll/dim_bossgut.c) | Y | SH_killermu |
| 0x1A9 | gBombPlantObjDescriptor | 801D2B34-801D3238 | 801D286C-801D3378 | 801D2C54 (main/dll/dim_bossgut.c \| main/dll/SH/SHkillermushroom.c) | Y | BombPlant |
| 0x1AA | gBombPlantSporeObjDescriptor | 801D3378-801D3E2C | 801D3378-801D3FF4 | 801D383C (main/dll/SH/SHkillermushroom.c \| main/dll/SH/SHrocketmushroom.c) | Y | BombPlantSp |
| 0x1AD | gSH_thorntailObjDescriptor | 801D5E8C-801D66E0 | 801D4CD0-801D6914 | 801D5ED4 (main/dll/SH/SHroot.c \| main/dll/SC/SClevelcontrol.c); 801D5F58 (main/dll/SC/SClevelcontrol.c \| main/dll/SC/SCchieflightfoot.c) | Y | SH_thorntai |
| 0x1B0 | gWarpStoneObjDescriptor | 801D7468-801D7BA4 | 801D6914-801D7BA8 | 801D7674 (main/dll/SC/SCcollectables.c \| main/dll/SC/SCanimobj.c) | Y | SH_swapston |
| 0x1AE | gSH_LevelControlObjDescriptor | 801D7BA8-801D96B4 | 801D7BA8-801D981C | 801D7C14 (main/dll/SC/SCanimobj.c \| main/dll/SC/SCtotemlogpuz.c); 801D8060 (main/dll/SC/SCtotemlogpuz.c \| main/dll/SC/SCtotembondpuz.c); 801D80F4 (main/dll/SC/SCtotembondpuz.c \| main/dll/brokecannon.c); 801D8308 (main/dll/brokecannon.c \| main/dll/SP/SPshop.c); 801D87F8 (main/dll/SP/SPshop.c \| main/dll/SP/SPshopkeeper.c); 801D8D20 (main/dll/SP/SPshopkeeper.c \| main/dll/SP/SPdrape.c); 801D8D20 (main/dll/SP/SPshopkeeper.c \| main/dll/IM/IMsnowbike.c) | Y | SH_LevelCon |
| 0x1B1 | gSH_staffObjDescriptor | 801D9B1C-801DA608 | 801D9B1C-801DA8C4 | 801D9BDC (main/dll/IM/IMsnowbike.c \| main/dll/DR/DRearthwalk.c) | Y | SH_staff |
| 0x1B4 | gSH_EmptyTumbleWObjDescriptor | 801DAFA4-801DAFDC | 801DAFA4-801DB098 | 801DAFDC (main/dll/DR/DRearthwalk.c \| main/dll/CR/CRsnowbike.c) | Y | SH_EmptyTum |
| 0x1B7 | gSC_MusicTreeObjDescriptor | 801DC230-801DC8D0 | 801DBFA0-801DC8D4 | 801DC310 (main/dll/CR/CRsnowbike.c \| main/dll/DR/DRcloudrunner.c) | Y | SC_MusicTre,SC_BirchTre |
| 0x1BA | gSC_totempuzzleObjDescriptor | 801DD424-801DDA24 | 801DD170-801DDA28 | 801DD46C (main/dll/SC/dll_01BA_sctotempuzzle.c \| main/dll/SC/dll_01BB_sctotembond.c) | Y | SC_totempuz |
| 0x1BD | gPaymentKioskObjDescriptor | 801DF304-801DF4A8 | 801DF110-801DF4AC | 801DF43C (main/dll/VF/platform1.c \| main/dll/VF/draghead.c); 801DF43C (main/dll/VF/platform1.c \| main/dll/VF/lavaflow.c); 801DF43C (main/dll/VF/platform1.c \| main/dll/DB/DBrockfall.c) | Y | SC_paypoint,SPWell |
| 0x1EC | gSB_ShipGunObjDescriptor | 801E341C-801E3D14 | 801E341C-801E3D30 | 801E34C0 (main/dll/DB/DBstealerworm.c \| main/dll/TREX/TREX_levelcontrol.c) | Y | SB_ShipGun |
| 0x1ED | gSB_FireBallObjDescriptor | 801E4288-801E45A8 | 801E4288-801E45AC | 801E42F8 (main/dll/TREX/TREX_levelcontrol.c \| main/dll/TREX/TREX_trex.c) | Y | SB_FireBall |
| 0x287 | gSPScarabObjDescriptor | 801E8EA4-801E9324 | 801E8EA4-801E9328 | 801E8EE0 (main/dll/DR/DRpushcart.c \| main/dll/DR/DRCloudball.c) | Y | SPScarab |
| 0x288 | gSPDrapeObjDescriptor | 801E9328-801E97D8 | 801E9328-801E97DC | 801E9344 (main/dll/DR/DRCloudball.c \| main/dll/DR/DRsimplehuman.c) | Y | SPDrape |
| 0x255 | gSnowBikeObjDescriptor | 801ECDD8-801EE054 | 801E991C-801EE088 | 801ECEC4 (main/dll/DR/DRcradle.c \| main/dll/DR/DRpulley.c); 801ECF94 (main/dll/DR/DRpulley.c \| main/dll/DR/DRhalolight.c); 801ED428 (main/dll/DR/DRhalolight.c \| main/dll/BW/BWalphaanim.c) | Y | CRSnowBike,CRSnowClawB,CRSnowClawB,CRSnowClawB |
| 0x1F9 | gWM_ObjCreatorObjDescriptor | 801EF360-801EFF78 | 801EF360-801EFF7C | 801EF3A8 (main/dll/WC/WClevcontrol.c \| main/dll/WC/WCbeacon.c); 801EF3A8 (main/dll/WC/WClevcontrol.c \| main/dll/WC/WCpressureSwitch.c) | Y | WM_ObjCreat |
| 0x1F8 | gWM_GalleonObjDescriptor | 801F01BC-801F06D4 | 801EFF7C-801F06D8 | 801F02F0 (main/dll/WC/WCpressureSwitch.c \| main/dll/WC/WCdial.c); 801F02F0 (main/dll/WC/WCpressureSwitch.c \| main/dll/WC/WClaser.c) | Y | WM_Galleon |
| 0x1FC | gLaserBeamObjDescriptor | 801F0AE4-801F15E0 | 801F0AE4-801F160C | 801F0B50 (main/dll/WC/WClaser.c \| main/dll/ARW/ARWarwingattachment.c) | Y | WM_LaserBea,ECSH_LaserB |
| 0x206 | gLightSourceObjDescriptor | 801F33B4-801F3C28 | 801F33B4-801F3C2C | 801F37CC (main/dll/ARW/ARWarwingattachment.c \| main/dll/LGT/LGTpointlight.c) | Y | LINKPoleFla,WM_WallTorc,HangingLigh,PoleLight |
| 0x207 | gWM_WormObjDescriptor | 801F3C2C-801F3F14 | 801F3C2C-801F3F18 | 801F3C7C (main/dll/LGT/LGTpointlight.c \| main/dll/LGT/LGTdirectionallight.c) | Y | WM_Worm |
| 0x209 | gWM_LevelControlObjDescriptor | 801F441C-801F48BC | 801F3F18-801F48C0 | 801F44B4 (main/dll/LGT/LGTdirectionallight.c \| main/dll/LGT/LGTprojectedlight.c) | Y | WM_LevelCon |
| 0x21E | gVFP_Block1ObjDescriptor | 801FB9AC-801FBAC4 | 801FB9AC-801FBAC8 | 801FB9F4 (main/dll/VF/dll_021E_vfpblock1.c \| main/light.c) | Y | VFP_Block1 |
| 0x224 | dll_224 | 801FD378-801FD4A4 | 801FD270-801FD4A8 | 801FD398 (main/light.c \| main/main.c) | n |  |
| 0x23F | gDB_eggObjDescriptor | 801FE118-801FF880 | 801FE118-801FF884 | 801FEB30 (main/main.c \| main/dll/anim.c) | Y | DB_egg |
| 0x230 | gChukaObjDescriptor | 80205F48-80206470 | 80205F40-80206474 | 8020637C (main/dll/anim.c \| main/dll/baddie/chuka.c) | Y | DFP_wallbar |
| 0x22F | gDfpfloorbarObjDescriptor | 8020647C-8020692C | 80206474-80206968 | 8020652C (main/dll/baddie/chuka.c \| main/dll/baddie/chukachuck.c) | Y | DFP_floorba |
| 0x232 | gSfxplayerObjDescriptor | 80207C24-80208094 | 8020768C-80208098 | 80207CE4 (main/dll/TrickyCurve.c \| main/dll/sfxplayer.c) | Y | DFP_RotateP |
| 0x235 | gDfptargetblockObjDescriptor | 80208660-80208FD8 | 80208508-80208FDC | 802086C4 (main/dll/door.c \| main/dll/fruit.c); 80208B70 (main/dll/fruit.c \| main/dll/zBomb.c) | Y | DFP_TargetB,DFP_TargetB |
| 0x260 | gProximityMineObjDescriptor | 8021122C-80211C20 | 802110F8-80211C24 | 802113F8 (main/proximitymine.c \| main/proximitymine_update.c); 80211A10 (main/proximitymine_update.c \| main/proximitymine_init.c) | Y | CRDropBomb,ProximityMi |

## Per-unit census (units hosting fns of 2+ DLL ids)

Reproduce with `--census`. A multi-DLL unit is only a problem when a
descriptor's range CROSSES its edge (see cut table); several complete DLLs
in one unit can be a legitimate multi-descriptor TU.

```
main/dll/CAM/camdrakor.c                                2 dlls: 0x049:lbl_80319CE8, 0x04A:lbl_80319D18
main/dll/CAM/dll_5B.c                                   3 dlls: 0x044:lbl_80319BF8, 0x046:lbl_80319C28, 0x048:lbl_80319C58
main/dll/CF/CFBaby.c                                    7 dlls: 0x0E7:CCeyeVines, 0x0EC:InfoPoint, 0x109:lbl_803218E8, 0x10A:Fall_Ladder, 0x119:coldWaterCo, 0x11A:DRDebrisGir, 0x11B:Landed_Arwi
main/dll/CF/CFchuckobj.c                                2 dlls: 0x12D:LFXEmitter, 0x130:AreaFXEmit
main/dll/CF/CFforcecontrol.c                            3 dlls: 0x10E:DieDuster, 0x123:fuelCell, 0x124:deathGas
main/dll/CF/CFtoggleswitch.c                            5 dlls: 0x11E:MagicCaveBo, 0x11F:MagicCaveTo, 0x120:TrickyGuard, 0x121:LINKF_InfoT, 0x122:CCTestInfot
main/dll/CF/treasureRelated0177.c                       3 dlls: 0x127:lbl_80321E58, 0x128:KT_Torch, 0x129:CampFire
main/dll/CR/CRsnowbike.c                                2 dlls: 0x1B4:SH_EmptyTum, 0x1B6:SC_levelcon
main/dll/DB/DBrockfall.c                                3 dlls: 0x142:FElevContro, 0x143:FEseqobject, 0x144:lbl_80327BA8
main/dll/DB/DBstealerworm.c                             4 dlls: 0x1E8:SB_Galleon, 0x1E9:SB_Propelle, 0x1EA:SB_ShipHead, 0x1EB:SB_ShipMast
main/dll/DF/DFcradle.c                                  2 dlls: 0x174:CCriverflow, 0x1E7:DIMbossfire
main/dll/DF/rope.c                                      4 dlls: 0x1E3:DIM_BossGut, 0x1E4:MAGICMaker, 0x1E5:DIM_BossSpi, 0x1E6:DIMbosscrac
main/dll/DIM/DIM2conveyor.c                             2 dlls: 0x1C8:DIMBridgeCo, 0x1C9:DIMDismount
main/dll/DIM/DIM2flameburst.c                           4 dlls: 0x1CA:DIMExplosio, 0x1CB:DIMWoodDoor, 0x1CC:DIMMagicBri, 0x1CE:dll_1CE
main/dll/DIM/DIM2projrock.c                             6 dlls: 0x1DA:dll_1DA, 0x1DB:dll_1DB, 0x1DC:DIM2IceFloe, 0x1DD:DIM2Icicle, 0x1DE:DIM2LavaCon, 0x1DF:lbl_80325928
main/dll/DIM/DIM2snowball.c                             8 dlls: 0x1CD:DIM_LevelCo, 0x1CF:dll_1CF, 0x1D0:DIM_tricky, 0x1D1:DIMTruthHor, 0x1D5:DIM2Conveyo, 0x1D6:dll_1D6, 0x1D7:DIM2SnowBal, 0x1D8:DIM2PathGen
main/dll/DIM/DIMExplosion.c                             4 dlls: 0x1C2:DIMSnowBall, 0x1C3:DIMGate, 0x1C4:DIMIceWall, 0x1C5:DIMBarrier
main/dll/DIM/DIMboulder.c                               4 dlls: 0x169:IMIceMounta, 0x16A:CRrockfall, 0x16B:DIMMagicLig, 0x16C:lbl_80323740
main/dll/DIM/DIMcannon.c                                9 dlls: 0x16D:IMIcePillar, 0x16E:IMAnimSpace, 0x16F:IMSpaceThru, 0x170:IMSpaceRing, 0x171:IMSpaceRing, 0x172:LINKB_levco, 0x173:LINK_levcon, 0x1BE:DIMLavaBall, 0x1BF:DIMLavaBall
main/dll/DIM/DIMlavaball.c                              6 dlls: 0x17E:MMP_levelco, 0x17F:MSBush, 0x180:MMP_asteroi, 0x181:MMP_trenchF, 0x182:MMP_moonroc, 0x183:MMP_gyserve
main/dll/DIM/DIMlavasmash.c                             2 dlls: 0x1C0:DIMLogFire, 0x1C1:DIMSnowBall
main/dll/DIM/DIMlevcontrol.c                            2 dlls: 0x1C6:DIMCannon, 0x1C7:DIMLavaSmas
main/dll/DIM/DIMlogfire.c                               4 dlls: 0x184:DIMAnimShar, 0x185:CCgasvent, 0x186:CCgasventCo, 0x25B:MSPlantingS
main/dll/DIM/DIMsnowball.c                              5 dlls: 0x187:CCqueen, 0x188:CClightfoot, 0x189:CCSharpclaw, 0x18A:CCpedstal, 0x18B:CClevcontro
main/dll/DR/DRcloudrunner.c                             3 dlls: 0x1B7:SC_MusicTre, 0x1B8:SC_totempol, 0x1B9:SC_Cloudrun
main/dll/DR/DRearthwalk.c                               3 dlls: 0x1B1:SH_staff, 0x1B2:SH_staffHaz, 0x1B3:SH_Beacon
main/dll/DR/DRpushcart.c                                2 dlls: 0x284:SPFruitSmal, 0x286:SPShopKeepe
main/dll/DR/DRsimplehuman.c                             2 dlls: 0x288:SPDrape, 0x289:SPitembeam
main/dll/DR/hightop.c                                   2 dlls: 0x126:TrigPnt, 0x145:CloudPrison
main/dll/IM/IMicicle.c                                  6 dlls: 0x15B:CFForceFiel, 0x15D:CFSlideDoor, 0x15F:CFAttractor, 0x162:CFMagicWall, 0x164:CFLevelCont, 0x166:CFbrokenGra
main/dll/IM/IMspacecraft.c                              2 dlls: 0x167:SpiritDoorL, 0x17D:DIM2_barrel
main/dll/MMP/MMP_asteroid.c                             5 dlls: 0x13C:XYZAnimator, 0x13D:ExplodeAnim, 0x13E:DIMBossIceS, 0x13F:TexFrameAni, 0x140:fogControl
main/dll/MMP/MMP_moonrock.c                             3 dlls: 0x132:WaterFallSp, 0x133:sfxPlayer, 0x141:Lightning
main/dll/MMP/mmp_barrel.c                               5 dlls: 0x136:WaveAnimato, 0x137:AlphaAnimat, 0x138:GroundAnima, 0x139:HitAnimator, 0x13A:VisAnimator
main/dll/SH/SHrocketmushroom.c                          2 dlls: 0x1AA:BombPlantSp, 0x1AB:BombPlantin
main/dll/TREX/TREX_levelcontrol.c                       2 dlls: 0x1EC:SB_ShipGun, 0x1EE:SB_CannonBa
main/dll/TREX/TREX_trex.c                               11 dlls: 0x1ED:SB_FireBall, 0x1EF:SB_CloudBal, 0x1F0:SB_KyteCage, 0x1F1:SB_SeqDoor, 0x1F2:SB_CageKyte, 0x1F3:SB_MiniFire, 0x1F4:CF_Lamp, 0x1F5:generalscal, 0x1F6:DIMFlag, 0x1F7:SB_ShipGunB, 0x285:SPShop
main/dll/TrickyCurve.c                                  2 dlls: 0x231:DFP_ForceAw, 0x232:DFP_RotateP
main/dll/VF/platform1.c                                 2 dlls: 0x1BC:SC_totemstr, 0x1BD:SC_paypoint
main/dll/WC/WClaser.c                                   3 dlls: 0x1F8:WM_Galleon, 0x1FA:WM_seqobjec, 0x1FB:dll_1FB
main/dll/alphaanim.c                                    3 dlls: 0x112:BossDrakor_, 0x113:CAMERAnewse, 0x114:IMMultiSeq
main/dll/anim.c                                         12 dlls: 0x229:DFP_LevelCo, 0x22A:DFP_ObjCrea, 0x22B:DFP_Torch, 0x22C:lbl_803298D0, 0x22D:DFP_seqpoin, 0x22E:DFP_DoorSwi, 0x230:DFP_wallbar, 0x23F:DB_egg, 0x240:GCRobotBlas, 0x241:DrakorEnerg, 0x242:DBstealerwo, 0x243:DBHoleContr
main/dll/baddie/Tumbleweed.c                            5 dlls: 0x031:lbl_8031C5D0, 0x03F:lbl_8031C5F8, 0x040:lbl_8031CC10, 0x041:lbl_8031CDB8, 0x2C0:FrontFox
main/dll/baddie/dll_003E_dummy3e.c                      2 dlls: 0x03D:lbl_8031C2B4, 0x03E:lbl_8031C300
main/dll/baddieControl.c                                12 dlls: 0x019:dll_19, 0x04D:lbl_80319DA8, 0x04E:lbl_80319E08, 0x04F:lbl_80319E38, 0x050:lbl_80319E68, 0x051:lbl_80319E98, 0x052:lbl_80319EC8, 0x053:lbl_80319EF8, 0x054:dll_54, 0x055:lbl_80319F58, 0x056:lbl_80319F88, 0x057:lbl_8031A01C
main/dll/barrel.c                                       2 dlls: 0x0CF:CannonClaw, 0x0D0:Grimble
main/dll/cfguardian.c                                   4 dlls: 0x0FB:WCTemplePre, 0x10F:MMP_Bridge, 0x110:KT_RexDoorP, 0x111:CFPowerLock
main/dll/cfprisonuncle.c                                6 dlls: 0x0FE:MagicPlant, 0x100:TrickyWarp, 0x101:TrickyGuard, 0x102:StayPoint, 0x103:CurveFish, 0x118:Duster
main/dll/crate2.c                                       2 dlls: 0x233:DFP_Statue1, 0x234:DFP_PerchSw
main/dll/creator1C4.c                                   3 dlls: 0x192:GPSH_Shrine, 0x193:GPSH_ObjCre, 0x194:GPSH_Scene
main/dll/creator1D6.c                                   3 dlls: 0x1A2:NW_tricky, 0x1A3:NW_animice1, 0x1A4:NW_ice1
main/dll/cup1C3.c                                       2 dlls: 0x196:DBSH_Symbol, 0x197:dll_197
main/dll/debug/dimenu.c                                 4 dlls: 0x037:lbl_8031ACF8, 0x038:lbl_8031ADA4, 0x039:lbl_8031ADD0, 0x03A:lbl_8031ADF8
main/dll/df_partfx.c                                    3 dlls: 0x004:lbl_80311378, 0x00F:lbl_80311438, 0x016:lbl_80311340
main/dll/dim_partfx.c                                   8 dlls: 0x003:lbl_803112E8, 0x026:lbl_80310FB8, 0x028:lbl_80310F38, 0x029:lbl_80310E88, 0x02A:lbl_80310FE0, 0x02B:lbl_80311038, 0x02C:lbl_803110D8, 0x02D:lbl_80311100
main/dll/dimmagicbridge.c                               2 dlls: 0x199:dll_199, 0x19A:dll_19A
main/dll/dll_00F3_flameblast.c                          4 dlls: 0x0F0:MMP_WarpPoi, 0x0F1:InvHit, 0x0F2:iceblast, 0x0F3:flameblast
main/dll/dll_017A_spiritprize.c                         2 dlls: 0x178:DFSH_Shrine, 0x17A:SpiritPrize
main/dll/dll_66.c                                       11 dlls: 0x0AB:lbl_80319378, 0x0AC:lbl_803193C0, 0x0AD:lbl_80319410, 0x0AE:lbl_80319460, 0x0AF:lbl_803194A8, 0x0B0:lbl_803194F8, 0x0B1:lbl_80319548, 0x0B3:lbl_80319598, 0x0B8:lbl_803195E8, 0x0B9:lbl_80319638, 0x0BA:lbl_80319688
main/dll/foodbag.c                                      21 dlls: 0x07C:lbl_80315010, 0x07D:lbl_80315238, 0x07E:lbl_80315304, 0x07F:lbl_80315444, 0x080:lbl_80315528, 0x081:lbl_80315750, 0x082:lbl_80315978, 0x083:lbl_80315C84, 0x084:lbl_80315F84, 0x085:lbl_80316000, 0x086:lbl_80316030, 0x087:lbl_80316220, 0x088:lbl_80316440, 0x089:lbl_80316630, 0x08A:lbl_80316708, 0x08B:lbl_80316930, 0x08C:lbl_80316B3C, 0x08D:lbl_80316C20, 0x08E:lbl_80316C70, 0x08F:lbl_80316E0C, 0x090:lbl_80316FD4
main/dll/gameplay.c                                     40 dlls: 0x011:lbl_80311BE0, 0x017:lbl_80311900, 0x02F:Carryable_funcs, 0x058:lbl_803137D8, 0x059:lbl_80311D88, 0x05A:lbl_80311E0C, 0x05B:lbl_80311E80, 0x05C:lbl_8031210C, 0x05D:lbl_8031231C, 0x05E:lbl_8031262C, 0x05F:lbl_80312770, 0x060:lbl_803128C4, 0x061:lbl_803129A8, 0x062:lbl_80312BB4, 0x063:lbl_80312CF8, 0x064:lbl_80312E38, 0x065:lbl_80312F78, 0x066:lbl_80313394, 0x067:lbl_803135A4, 0x068:lbl_803137B4, 0x069:lbl_80313880, 0x06A:lbl_80313A1C, 0x06B:lbl_80313AB0, 0x06C:lbl_80313AD0, 0x06D:lbl_80313C10, 0x06E:lbl_80313CA0, 0x06F:lbl_80313E78, 0x070:lbl_8031403C, 0x071:lbl_80314268, 0x072:lbl_80314490, 0x073:lbl_803146B8, 0x074:lbl_803148FC, 0x075:lbl_80314930, 0x076:lbl_80314960, 0x077:lbl_80314990, 0x078:lbl_80314AD0, 0x079:lbl_80314BB0, 0x07A:lbl_80314C90, 0x07B:lbl_80314DE4, 0x0A3:lbl_80313184
main/dll/genprops.c                                     19 dlls: 0x0C6:AnimDummy, 0x0C7:DIM2RoofRub, 0x0C8:DepthOfFiel, 0x0DB:MikaBomb, 0x0DC:MikaBombSha, 0x0DD:GCbaddieShi, 0x0DE:baddieInter, 0x0E2:sword, 0x0E3:projball, 0x0E4:FlameThrowe, 0x0E5:fox_shield, 0x0E6:ReStartMark, 0x0E8:checkpoint4, 0x0E9:setuppoint, 0x0EA:sideload, 0x0EB:siderepel, 0x0F7:dll_F7, 0x125:curve, 0x25A:StaticCamer
main/dll/groundAnimator.c                               2 dlls: 0x115:lbl_80321428, 0x116:WM_Column
main/dll/lightning.c                                    2 dlls: 0x0EE:EffectBox, 0x0FF:MagicDustSm
main/dll/mmp_asteroid_re.c                              3 dlls: 0x12E:LaserTurret, 0x12F:NWCallOFEld, 0x131:CF_DoorLigh
main/dll/mmp_moonrock.c                                 2 dlls: 0x134:texscroll2, 0x135:texscroll
main/dll/mmshrine/shrine.c                              2 dlls: 0x18D:MMSH_Scales, 0x18E:MMSH_WaterS
main/dll/mmshrine/shrine1C2.c                           2 dlls: 0x18F:ECSH_Shrine, 0x191:ECSH_Creato
main/dll/modelfx.c                                      4 dlls: 0x023:lbl_80310C60, 0x024:lbl_80310D20, 0x025:lbl_80310D80, 0x027:lbl_80310DE8
main/dll/modgfx.c                                       14 dlls: 0x00B:lbl_8030FCA8, 0x00C:projgfx_funcs, 0x00D:playerShadow_funcs, 0x00E:lbl_80310604, 0x018:boneParticleEffect_funcs, 0x01A:lbl_80310638, 0x01B:lbl_80310670, 0x01C:lbl_80310808, 0x01D:lbl_803108A0, 0x01E:lbl_803109B8, 0x01F:lbl_80310A20, 0x020:lbl_80310A78, 0x021:lbl_80310B50, 0x022:lbl_80310BD8
main/dll/objfsa.c                                       3 dlls: 0x010:lbl_803114B0, 0x012:lbl_803114D8, 0x014:lbl_803115F8
main/dll/pickup.c                                       13 dlls: 0x09D:lbl_80318240, 0x09E:lbl_80318468, 0x09F:lbl_80318690, 0x0A0:lbl_803188B8, 0x0A1:lbl_80318AE0, 0x0A2:lbl_80318D08, 0x0A4:lbl_80318D28, 0x0A5:lbl_80318DD0, 0x0A6:lbl_80318E20, 0x0A7:lbl_80318EC8, 0x0A8:lbl_80319008, 0x0A9:lbl_80319148, 0x0AA:lbl_80319354
main/dll/pressureSwitch.c                               2 dlls: 0x0DF:Hagabon, 0x0E0:SwarmBaddie
main/dll/projball1D8.c                                  2 dlls: 0x1A5:NW_levcontr, 0x1A6:SH_tricky
main/dll/savegame.c                                     9 dlls: 0x091:lbl_8031719C, 0x092:lbl_8031723C, 0x093:lbl_80317468, 0x094:lbl_80317504, 0x095:lbl_803175C8, 0x096:lbl_803177F0, 0x097:lbl_8031788C, 0x098:lbl_80317AD4, 0x099:lbl_80317B74
main/dll/scarab.c                                       4 dlls: 0x0CB:dll_CB, 0x0CC:ChukChuk, 0x0CD:IceBall, 0x0CE:dll_CE
main/dll/screenOverlay.c                                2 dlls: 0x0F9:DRProjectil, 0x0FA:InvisibleHi
main/dll/screens.c                                      3 dlls: 0x09A:lbl_80317BB8, 0x09B:lbl_80317DE0, 0x09C:lbl_80318014
main/dll/shrine1CE.c                                    3 dlls: 0x19B:dll_19B, 0x19C:dll_19C, 0x19D:dll_19D
main/dll/tFrameAnimator.c                               2 dlls: 0x0F6:Area, 0x0F8:LevelName
main/dll/wallanimator.c                                 2 dlls: 0x0D6:KaldachomMe, 0x0D7:KaldachomSp
main/dll/xyzanimator.c                                  3 dlls: 0x0D8:PinPonSpike, 0x0D9:Pollen, 0x0DA:PollenFragm
main/light.c                                            7 dlls: 0x21E:VFP_Block1, 0x21F:VFP_Platfor, 0x220:VFP_DoorSwi, 0x221:VFP_seqpoin, 0x222:VFPDragHead, 0x223:VFP_corepla, 0x224:dll_224
main/main.c                                             4 dlls: 0x225:VFP_flamepo, 0x226:VFP_lavapoo, 0x227:VFP_lavasta, 0x228:VFPSpPl
main/sky.c                                              2 dlls: 0x005:lbl_8030F414, 0x006:lbl_8030F4AC
```
