# The data axis — the pool side was reopened, then worked to a close

> **STATUS 2026-08-03.** The correction below reopened this axis by proving `.sdata2` is scored by
> BYTES; that reopening has since been worked out. The pool model, the frontier classification and
> the price of every remaining row now live in `docs/priced_classes.md` **sections 8-13** — start at
> its **Index of the measured laws**. All 31 sub-100 data sections are classified there (18
> intra-function, 13 cross-function) and every one is adjudicated: pure statement or use motion
> reaches none of them, and the one construct that does reach them is the banned shape (§12/§12b).
> What is still authoritative *here* is the method — how to tell an artifact from a real difference,
> and the stop-rules. Read this file for the screens; read §8-13 for the verdicts.

> ## ⚠️ CORRECTION 2026-08 — the central premise below is WRONG, and it was measured wrong twice
>
> This document asserted that a sub-100 `.sdata2` is an *artifact* of anonymous `@N` symbols failing
> to pair. **That is false. `.sdata2` is scored by BYTES, not by names.** Three measurements, any one
> of which refutes it:
>
> 1. **600 units** have an entirely anonymous `@N` `.sdata2` and score **fuzzy 100.0**. `audio_sfx`
>    is the clean exhibit: our side all `@N` and *local*, retail's all `lbl_*`/named and *global*,
>    retail even carrying two symbols at 0x0c/0x0e that we do not emit at all — **100.0**.
> 2. **All 48** sub-100 `.sdata2` sections have genuinely **differing bytes**. Zero are
>    byte-identical. Anonymity is not doing any work in any of them.
> 3. The differences are frequently **pool ORDER**, which is initialized data and therefore real.
>    `track/intersect_render`, the worked proof in §1, holds the *same* constants in a *different
>    sequence* — retail `3f490fdb bf000000` at 0x50 with the int→double magic at 0x60, ours
>    `3f490fdb 4b800000` at 0x50 with the magic at 0x90.
>
> **Consequence: sub-100 `.sdata2` is a real, live, source-addressable class** (emission order —
> see `sdata2-emission-order-law-w57`), not a closed artifact. It must not be screened out as
> "anonymous-pool blindness". The banned construct remains banned: recovering pool *order* is a
> source-shape question, and never a licence to define named `.sdata2` constants.
>
> **How the error survived:** the original screen used `missing == section size exactly` as its
> signature. That test cannot distinguish "the section did not pair" from "the section's bytes
> differ", because both zero the whole section. A later classifier of mine then hard-coded
> `anon @N ⇒ SCORE-BLOCKED` and propagated the premise into a tree-wide census. **Neither instrument
> ever compared the bytes.** Always diff `objdump -s -j <section>` before calling a data difference
> an artifact.
>
> Retained below and still correct: the `.bss`/`.sbss` order results (§1 corollary), the
> `gap_*` exclusion rule, the binding-carries-no-information result, the `.sbss2` and `284`
> stop-rules, and the over-claimed-extent class.

# (original) The data axis — CLOSED

`matched_data` measures data-**symbol pairing**, not pool contents. Every remaining shortfall in
the tree has been classified, and none of it is a missing constant. This file exists so the axis
is not re-mined: read it before spending a build on a data score.

The axis produced exactly **one** real content recovery (`player_SeqFn`, +8232 bytes, a retype
of `obj->extra`). Everything else measured as a tooling artifact or a TU-boundary artifact.

---

## 1. The law: pool-pairing blindness is SECTION-granular

objdiff pairs data symbols **by name**. Our compiler emits pool constants as anonymous `@N`
symbols; the splitter carves the retail side as named `lbl_8XXXXXXX`. Those can never pair.

The sharpened form — and the part that was not previously written down:

> **A data section containing ANY unpairable anonymous symbol scores ZERO as a unit,**
> **regardless of how many of its named symbols are byte-perfect and name-identical.**

This is why partial data scores are rare: sections tend to be all-or-nothing.

### Worked proof — `track/intersect_render.c`

`total_data 452 = .rodata 216 + .sdata2 236`. `.rodata` scores **216/216**; `.sdata2` scores
**0/236**. The single variable that separates them:

| section | named syms | anonymous `@N` | score |
|---|---|---|---|
| `.rodata` | 2 | **0** | 216/216 (100%) |
| `.sdata2` | 13 | **40** | 0/236 (0%) |

Byte-level decomposition of the 236, comparing our object against the retail carve:

| bytes | population | status |
|---|---|---|
| **51** | 13 constants our source already names (`sApertureColorBlack`, `sDistortKColor0/1/2`, `sColorFilterKColor0/1/2`, `sMoonFxTint`, …) | byte-identical **and** name-identical on both sides — **still scores 0** |
| **76** | 18 anonymous `@N` pool floats vs the splitter's `lbl_803DEExx` | byte-identical, unpairable by construction |
| **109** | 27 entries where pool **order** diverges: doubles land at different offsets (size 4v8 / 8v4), and retail holds 5 entries at `+0x5c/0x6c/0x6e/0x8c/0x94` we never emit | genuine divergence — TU-boundary artifact, do not reconstruct |

**127 of 236 bytes are already byte-correct and score zero purely for pairing reasons.** The 51-byte
row is the exhibit: identical name, identical size, identical bytes, zero score.

An earlier, weaker proof of the same law: `engine/5` had three genuinely missing `.sdata2`
constants (`0.55f`, `10800.0f`, `86400.0f`). Replacing the stand-ins with literals made the pool
contents *exactly* match — 44 slots / 41 distinct on both sides, nothing absent either way.
**`matched_data` did not move: 600/776 before, 600/776 after.**

### Corollary — objdiff is ORDER-BLIND: the pend-cluster theorem

> A **zero-filled** section (`.bss`, `.sbss`) whose only defect is symbol *order* **already scores
> 100**, because permuting symbols across uniformly zero bytes changes nothing observable.
> So for `.bss`/`.sbss`, "order is the last defect" and "section < 100" are mutually exclusive.

⚠️ **Scope, corrected.** This holds for the **zero-filled** sections only. It was originally written
as "objdiff pairs data symbols by name and is blind to order", generalised to all data sections —
that mechanism claim is **wrong** (see the correction at the top of this file). In an *initialized*
section (`.data`, `.sdata`, `.sdata2`) order changes bytes, so order is fully visible there and is a
live defect class. The `.bss` result below stands on its own measurement.

So a screen of the form *"fix the order wherever the section is fully pairable and order is the sole
remaining difference"* enumerates an **empty set** — not in a given unit, but anywhere. Do not build
that screen again.

Confirmed empirically on `dlls/engine/7`: its `.bss` holds a genuine permutation — retail
`gNewCloudLayerTextures@0x00 / gNewClouds@0x10`, ours exactly reversed, same names and sizes — and
the section reads **fuzzy 100.0**.

⚠️ The tree-wide run originally cited here classified 47 sections as "blocked by anonymous `@N`".
**That classification is withdrawn** — those 47 are real byte differences, mostly pool order, and
are the reopened class described in the correction at the top. What survives from that run is only
its `.bss`/`.sbss` half: no zero-filled section anywhere in the tree is order-defective, and the
two genuine non-pool defects it surfaced (`intersect` `.sbss` naming, `engine/60` `.sbss` extent)
were both fixed — `90cabeaf76`, `6e7b713c49`.

This does **not** make `.bss` emission order worthless: it is what makes a unit *link*
byte-identical, which is the criterion for a `NonMatching → MatchingFor` flip. The point is only
that its payoff is **linked byte-identity, never `matched_data`** — so never gate a pend fix on a
report.json delta, and treat any data gain that appears after a pure reorder as an attribution
error.

---

## 2. Two gates that were tried and refuted — do not re-try either

### Naming is not the gate (measured null)

All 12 `lbl_803DEExx` in `intersect_render`'s `.sdata2` were renamed to the identifiers our source
already used. The retail object was confirmed **re-carved** with the new names
(`sApertureColorBlack`, global, 4 B at `+0`), and `report.json` was rebuilt fresh — the first run
read a **stale** report and would have been read as a null for the wrong reason.

Result: `matched_data` stayed at exactly **216/452**. Naming a byte-identical constant on both
sides buys nothing while anonymous symbols remain in the section.

### Retail-side binding carries ZERO information (splitter artifact)

The tempting second hypothesis is `static`: retail `.sdata2` is 57 global / 1 local, ours is
0 global / 54 local. It is wrong twice over.

1. `.rodata` scores **216/216 with the same mismatch** — our two symbols are `l`, retail's are `g`.
2. The splitter emits **every** retail data symbol global, including unambiguous file statics:

   | section | retail global | retail local |
   |---|---|---|
   | `.data` | 59 | 0 |
   | `.sdata` | 57 | 0 |
   | `.sdata2` | 57 | 0 |
   | `.rodata` | 2 | 0 |

De-`static`-ing a unit to chase this would be optimizing against a tool artifact — the data-axis
twin of the `@N`-vs-`lbl_` trap CLAUDE.md already warns about. It also makes the source *less*
plausible. Don't.

---

## 3. Taxonomy — every classified vein, and why none is workable

| class | signature | verdict |
|---|---|---|
| **Anonymous-pool pairing** (section-granular) | `missing == section size` exactly; section holds `@N` symbols | Artifact. Fixing it requires our source to *define named `.sdata2` constants* — the **banned pool-reconstruction construct**. Closed on principle. |
| **Jump-table naming** (`.data` only — NOT a pool analogue) | a `.data` section whose unpaired symbols are all `switch` jump tables — retail `jumptable_8XXXXXXX`, ours `@N` — with identical sizes, identical order, and **byte-identical section contents** | Artifact. ⚠️ **Corrected**: this is *not* "the `.data` analogue of the pool class" — the pool class is not a pairing failure at all (see the correction at the top). `.data` and `.sdata2` are scored differently, and `engine/2` is the **only** unit tree-wide where `.data` holds `@N` and scores under 100; 117 other units hold `@N` in `.data` and score 100. Verified benign the only way that counts: `objdump -s -j .data` is byte-identical on both sides and relocation counts match 265/265. C cannot name a compiler-generated jump table, so nothing is actionable. Never rank it. |
| **Over-claimed extent absorbing inter-TU padding** | `symbols.txt` claims more bytes than the source object emits, and the surplus reaches exactly to where the **next TU's** section begins | Real, correctable — trim the claim to the atom's true extent. The surplus becomes a `gap_*` filler, which objdiff skips. ⚠️ The retail carve's size is generated **from** the claim, so "the retail object says N bytes" is **circular** — decide from access width, neighbouring atom sizes, and the section range instead. Landed: `engine/60`, `6e7b713c49`. |
| **Merged-TU duplication** | equal distinct constant counts, retail merely holding more copies; our side always *smaller* | TU-boundary artifact. `objects/202` is 421→127 slots at 119 distinct on both sides. Leave it. |
| **Pool-order TU artifacts** | same value multiset, different offsets; size 4v8 / 8v4 shifts | TU-boundary artifact per CLAUDE.md. Leave the unit `NonMatching`; do not reconstruct the pool. |
| **Unowned `gap_*` bytes** | splitter-emitted `gap_NN_8XXXXXXX_section` symbols marking bytes no symbol owns | Not ours to define. Exclude from every screen — counting them manufactures a phantom gap. |
| **Cross-symbol reach through an adjacent base** | `displacement_oob_check` reports typed reads past a symbol's claimed size; the over-reach lands **inside a correctly-claimed neighbour** | Faithful, not a defect. Retail addresses the sibling through the same base. **Correcting the size would overlap a correctly-carved symbol.** Decline. |
| **Splitter attribution artifact** | the OOB screen fires on the **retail** object but not on ours, for `.text` that is byte-identical | Not a real access and not a divergence — the splitter attributed a same-page address to a preceding symbol plus displacement. Nothing to fix; the code already matches. Decline. |
| **Genuine content** | our side missing *distinct values* the retail side has | The only real class. Exactly one instance found tree-wide (`player_SeqFn`, +8232 B, a retype — not an added constant). |

Of 25 non-`auto_` data-losing units, **13 have `missing == .sdata2` size exactly**, every one with an
overwhelmingly anonymous pool: `intersect_render` 236/236 (13 named / 40 anon), `engine/5` 176/176
(0/41), `DIMSnowHorn` 144/144 (2/33), `BossDrakor` 120/120 (0/27), `DR_LaserCan` 100/100,
`engine/19` 96/96, `CFGuardian` 88/88, `SH_thorntai` 80/80, `DFropenode` 76/76, `engine/69` and
`DIM_BossTon` 64/64, `engine/24` and `sincosf` 32/32.

#### Worked proof — jump-table naming, `dlls/engine/2` `.data`

1904 B at fuzzy **53.5865 %**. 21 of its 32 symbols pair perfectly. The 11 that do not are all
switch jump tables — retail `jumptable_8030EF58…`, ours `@1433…` — with **identical sizes on every
one** (80/208/204/28/44/72/28/44/64/60/48) in identical order. The arithmetic settles it:

```
named symbols  1016 bytes (21 syms)
jump tables     880 bytes (11 syms, anonymous on our side)
named fraction  1016/1896 = 53.5865 %
reported .data            = 53.5865 %
```

Every named byte matches; the section loses 880 B purely because they cannot pair by name. The
unit's whole deficit resolves to two sections — `.data` 1904 + `.sdata2` 184 = 2088, and
16296/18384 = 88.642 % — of which only the 184 B `.sdata2` (retail 43 symbols vs our 38, with real
size disagreements) is genuinely attackable.

### The under-claimed-size discriminator: are the bytes past the claim UNOWNED?

The last two rows above are the ones that look **exactly** like a real defect in tool output, so
classify with this test before touching `symbols.txt`. `tools/displacement_oob_check.py` reports
typed reads landing past a symbol's claimed size. That is a real fix class *only* when the bytes
past the claim belong to nobody:

- **Unowned bytes ⇒ genuinely under-claimed; correctable.** The sky-RGBA case: five `.sbss`
  objects claimed `size:0x1`, the bytes after them unowned, and the splitter minting 3-byte
  `gap_*` fillers **derived from the bad claim** (no `gap_` entry exists in `symbols.txt`, so the
  fillers are an output of the error, never evidence for it). Proven by **layout** — at 4 bytes
  every symbol lands on its exact retail address — with `.text` byte-identical and the DOL
  bit-identical.
- **Owned bytes ⇒ cross-symbol reach; decline.** Every over-reach in the current population lands
  inside a correctly-claimed neighbour, so the axis has **no upside by construction, not by bad
  luck**. Worked survey (5 distinct symbols; note the tool's hit count is **accesses, not
  symbols** — 70 source-side hits were 2 symbols, 194 retail-side hits were 4):

  | symbol | claimed | max read | pad to next | lands inside |
  |---|---|---|---|---|
  | `gObjFxCrystalSparkleTbl` | 0x1e | +0x110 | 2 | `gObjFxHitPulseTbl` |
  | `lbl_802C1D50` | 0x18 | +0x50 | 0 | `lbl_802C1D68` |
  | `RunQueue` | 0x100 | +0x6e4 | 0 | `DefaultThread` |
  | `CommandList` | 0x3c | +0xcc | 4 | `Curr` |
  | `gWritePos` | 0x4 | +0x8 | 0 | `gReadCount` |

**Corroborating the carve itself — the reloc standard.** When a base is read past its end, ask
whether retail *independently relocates* the symbol the read lands in. It does for
`gObjFxPulseVariantTbl` and `gObjFxHitPulseTbl` (their own `ADDR16_HA`/`LO` pairs at `0x18ea` /
`0x191a`), and **a single merged table could never produce those** — so the carve is confirmed and
a size correction is affirmatively wrong, not merely unnecessary. Check our relocations against
retail's at the same `.text` offsets too: matching there means our cross-reach spelling is
faithful, however odd it reads in C.

**And distrust the headline.** This axis was briefed as "a table claimed at one entry, read at
seven-plus" — inverted. The table is correctly sized; its *siblings* are read through its base.
Run the tool's own `control` mode first (it self-builds a paired probe) and read the w82 record —
this screen was once ~88% false positives before it was fixed — **even when the instrument comes
recommended.** Applying that brief mechanically would have put an overlapping size claim into
`symbols.txt`.

---

## 4. Two standing stop-rules

### `.sbss2` remains unpartitioned; native initializers can emit it

As of `733eb4a0aa`, `.sbss2` has no per-source spans in
`config/GSAE01/splits.txt`. The 56-byte retail block remains an anonymous carve.
This is an unresolved layout constraint, not a restriction imposed by the C
compiler and not proof that the original source declared external constants.

The GC/1.3 follow-up replaces four external zero-color loads with ordinary
`GXColor fogColor = {0, 0, 0, 0}` initializers in `tex_dolphin.c` and
`intersect_render.c`. Each TU emits two four-byte anonymous `.sbss2` constants
with eight-byte section alignment. All raw function bytes remain identical;
the four load relocations now refer to native constants instead of external
symbols. Every previously allocated data section and named data-symbol position
is unchanged. This disproves the earlier claim that these zero-word loads could
only be written as externs.

It does **not** prove retail pool placement. The compiler's local constant order
and section alignment do not reproduce the four existing address labels in the
unpartitioned retail block. Neither TU gains a matched-data span from this
change, and both remain NonMatching. The strict retail checksum therefore does
not validate placement of these new source constants. Resolve the layout from
independent evidence before assigning `.sbss2` splits or claiming a linked match;
do not insert padding or named constant anchors to manufacture the order.

The same source pass types the projected-shadow channel's six seven-word tables
as three stages of `GXTevColorArg` inputs and `GXTevScale` values. Native structure
initializers replace the stack-offset-named word-copy buffers and their casts.
The original table bytes and all their consumers' instruction bytes are retained.

### The `284` precedent — if the DOL moves, stop

Symbol re-partitioning that leaves the DOL byte-identical is safe bookkeeping (`object.c`). Changes
that genuinely re-lay pool words change the DOL (`284`). **DOL SHA-256 identity is the gate**;
`matched_data` is only a hint. A data "win" that moves the DOL is a regression wearing a score.

---

## 5. The screens, in run order

Run these before touching anything. The order is load-bearing — it was established by getting it
wrong (checking size before duplicate inflation misclassified `objects/202` and contradicted a
confirmed peer result).

1. **`missing == section size`?** If the shortfall equals a whole section's size exactly, it is the
   section-granular pairing artifact. Stop — nothing below will change the verdict.
2. **Distinct-values screen**, with precedence
   **missing distinct values → duplicate inflation → size → order.** A merged TU is *always* smaller
   on our side, so size alone cannot distinguish it from a content defect. Trust `.sdata2` verdicts
   above `.data`/`.sdata` ones: those carry relocation targets, so a "missing value" there may be an
   address word rather than a constant.
3. **Ownership** — does the address fall inside this unit's span in `splits.txt`? Check the *section*
   is partitioned at all before asking which unit owns it (see `.sbss2` above). Exclude `gap_*`.
4. **DOL identity** — `shasum -a 256 build/GSAE01/main.dol` before and after. Plus per-function
   `tools/unitfuzzy.py --all` equality on the whole radius for `NonMatching` units, where unit-level
   metrics and DOL identity cannot see a per-function regression.

### Gate traps that fired on this axis

- **`report.json` is not rebuilt by the default ninja target.** Build it explicitly
  (`ninja build/GSAE01/report.json`) before reading a score, and compare its mtime against the object
  you just rebuilt. A stale report reads as a clean null.
- **The retail object re-carves from `symbols.txt`.** After a rename, confirm the new name is
  actually present in `build/GSAE01/obj/...` before concluding anything from a pairing measurement.
- **`tools/autogen_data_triage.py` regenerates tracked files** (`docs/orig/autogen_data_triage.{md,csv}`)
  despite a read-only docstring. Check `git status` after running it.

---

## Attribution

- Section-granularity law, `intersect_render` decomposition, both refutations, the `.sbss2`
  construction fact, the `engine/5` null, the 25-unit census and the screen precedence fix:
  measured in this lane.
- `objects/202` merged-TU confirmation and the `engine/0` constant audit: Lane B.
- Peer commits: `d440ea21bc` (independently landed the same 12 `intersect_render` `.sdata2` names —
  worktree edits converged byte-identically, nothing to commit), `d40663374d` and `b5d4da6c62`
  (this lane's `intersect` naming batches).

## See also

- `CLAUDE.md` — the banned pool-reconstruction construct, and why it keeps being re-introduced.
- `docs/priced_classes.md` §8-13 — the verdicts this file's screens feed into: the mint-order
  model, the mover, the crutch oracle and the cross-TU declaration laws. Its **Index of the
  measured laws** is the entry point.
- `docs/purge_campaign_audit.md` — the three sensor blind spots, and why a data loss can read as
  `+0.000000` on every score axis.
- `docs/source_shape_levers.md` — the code-shape axis; its data section points here.
- `docs/rename_safety.md` — the rename gate and the stale-object race.
- `docs/splits.md` — how the splitter carves retail objects from `symbols.txt`.
