# Inlining `.sdata2` constants (the "data-split")

How to turn an `extern f32 lbl_XXXXXXXX;` placeholder into a plausible inline
literal (`0.5f`) that the owning unit actually **owns** — moving a read-only
constant out of the shared auto data pool and into the unit's own section so it
becomes byte-identical and **linked**, not just fuzzy-matched.

Related: [`splits.txt`](splits.md), [`symbols.txt`](symbols.md),
[`lbl_` naming spec](/tools/lbl_naming_spec.md),
[Live-Debugging Workflow](live_debugging_workflow.md).

## The mental model (read this first)

A float/double literal in C is **not** a PPC immediate. MWCC materialises it as a
constant in `.sdata2` and loads it with `lfs fN, sym@sda21(r0)`. So a value like
`225.0f` always lives *somewhere* as data; the only question is **who owns that
data**:

- **Auto pool (default, un-split):** the constant sits in an auto-generated blob
  (e.g. `build/GSAE01/asm/auto_11_803DECE0_sdata2.s`) and every unit that needs it
  references it as `extern f32 lbl_803E3C30`. The target object emits **no**
  `.sdata2` of its own — the load is an *external* `R_PPC_EMB_SDA21` relocation.
- **Owned (split):** the source file writes the value inline (`225.0f`), MWCC
  emits it into the **unit's own** `.sdata2`, and `splits.txt` gives that unit the
  matching DOL address range. dtk then carves the constant out of the auto pool
  and into **both** the target and source objects as local anonymous data.

"Inlining an `lbl_`" means performing that auto → owned move. It is a
**data-split**, not a find/replace. This is the finished state — units like
`worldplanet.c` / `objlib.c` already look this way.

## The trap: fuzzy match is blind to this

`fuzzy_match_percent` compares **object files with normalised relocations**. It
cannot tell a *local* constant load from an *external pooled* one — both are just
`lfs fN, …@sda21`. So if you naively replace `lbl_803E3C44` with `3.0f` and change
nothing else:

- the report still says **100%** — but you have merely added a *redundant* local
  copy of a constant that also still lives in the auto pool;
- the target object still references the pooled symbol, so nothing actually
  matched the DOL better;
- `metadata.complete` does not change.

**"It still says 100%" is not proof.** The real signals are:

1. `matched_data` / `total_data` on the unit (exact-byte data comparison), and
2. `metadata.complete == true` after the object is flagged `Matching` (a real
   hash-check against the DOL), and
3. an explicit `.sdata2` byte diff between the source and target objects.

## Workflow

### 1. Find the block and its values

```sh
# value of one constant
grep -A3 '\.obj lbl_803E3C44,' build/GSAE01/asm/auto_11_*_sdata2.s
# who references each address (must be ONLY your unit's functions — see step 2)
grep -rl 'lbl_803E3C44@sda21' build/GSAE01/asm/main/
```

The auto `.s` lists each constant with its address, size, and value
(`.float 3`, `.string …`, etc.). Distances often reveal the role — e.g. `225 =
15²`, `14400 = 120²` are squared thresholds.

### 2. Confirm the range is exclusively yours

A unit can only own a **contiguous** range, and every address in it must be
referenced **only** by that unit (or be dtk-owned filler like the conversion
bias). Map each `@sda21` reference to its containing function:

```sh
# each 'lbl_803E3Cxx@sda21' -> which .fn it sits inside
awk '/^\.fn /{fn=$2} /lbl_803E3C[0-9A-F]{2}@sda21/{print fn": "$0}' \
  build/GSAE01/asm/main/dll/CF/CFtoggleswitch.s
```

If a sibling unit references an address inside your intended range, you cannot
cleanly own it — stop at that boundary (see *Shared constants* below). Auto-split
`.s` files bundle many handlers, so "referenced by another file" often just means
"referenced by another function in the same original object" — check the `.fn`,
not the filename.

### 3. Claim the range in `splits.txt`

Add a `.sdata2` line to the unit's entry (end address is exclusive):

```
main/dll/dll_011F_magiccavetop.c:
	.text       start:0x8018AFC8 end:0x8018B7B0
	.sdata2     start:0x803E3C30 end:0x803E3C78
```

### 4. Inline the literals in source

Replace every `extern`+reference with the literal value and delete the `extern`
decls. Inline **all** floats in the claimed range — including ones that were
already named (`gMagicCaveTopFadeMax` → `100.0f`) and ones already inline
(`10.0f`). Edit byte-wise if the file carries SJIS (`python rb/wb`, latin-1).

### 5. Fix ordering (the part that actually bites)

MWCC emits `.sdata2` **floats in first-use order**, and that order must reproduce
the retail **address** order. Two forces move first-use order:

- **Function order.** Constants are emitted across the whole TU in compile order.
  objdiff matches functions *individually*, so function order is invisible to the
  code match — but it drives constant emission order. If a function that is early
  in the source first-uses a constant whose retail address is late, that constant
  gets hoisted to the front of `.sdata2` and everything mismatches. Reorder the
  functions to retail order (compare against the `.fn` order in the target asm).
- **Type/alignment grouping.** 8-byte doubles are emitted **after** the 4-byte
  floats regardless of use order. The int→double conversion bias
  `0x4330000080000000` (auto-emitted by `(f32)(int)` casts) therefore lands last;
  you do not write it, but it must be inside the claimed range.

### 6. Flip to `Matching` and verify

In `configure.py`, change the object from `NonMatching` to `MatchingFor("GSAE01")`
(or `Matching`). Then:

```sh
rm -f build/GSAE01/src/main/dll/<unit>.o && ninja      # EXIT must be 0
# exact-byte .sdata2 compare, source vs target:
diff <(build/binutils/powerpc-eabi-objdump -s -j .sdata2 build/GSAE01/src/.../<unit>.o | sed 1,3d) \
     <(build/binutils/powerpc-eabi-objdump -s -j .sdata2 build/GSAE01/obj/.../<unit>.o | sed 1,3d) \
  && echo IDENTICAL
```

`Matching` makes the build hash-check the object against the DOL, so a clean
`ninja` (with `main.dol: OK`) is the real proof. Confirm in `report.json` that the
unit has `matched_data == total_data` and `metadata.complete == true`.

## Non-shared vs shared constants

- **Non-shared** (only your unit's functions use it): inline it, as above. The
  value still exists — as a unit-owned literal instead of a pool entry. This is
  the common, faithful case.
- **Shared** (a single pooled address referenced by *different* decomp units):
  only **one** unit can own that address. In retail each TU emitted its **own**
  copy of a literal — so genuine cross-TU sharing at one address is mostly a
  decomp-pooling artifact. When you split the range to its rightful owner, any
  co-referencing unit must either keep the `extern` or (more faithfully) get its
  **own** inline copy at its **own** address. You do **not** "inline it everywhere
  into one shared definition." Truly shared `const` globals referenced by symbol
  are a different thing and stay defined once.

## Other gotchas

- **Generic zeros stay generic.** Per the [naming spec](/tools/lbl_naming_spec.md),
  a multi-role `0.0f` should not be *named* (`gXxxZero` is unwanted) — but it can
  still be **inlined** to a literal `0.0f`, which removes the naming question
  entirely.
- **dtk mis-labels the double bias.** `0x4330000080000000` at an 8-byte slot is
  disassembled as a size-3 `.string "C0"` + a `-0.0` float. That's one 8-byte
  double, not two constants.
- **Vestigial `symbols.txt` names are harmless.** After inlining, the named
  entries at those addresses are no longer referenced by name; the build stays
  green. Clean them up opportunistically, but it isn't required for the match.
- **A data-split can expose latent bugs.** The ordering work in step 5 surfaces
  function-order problems the per-function code match happily hides — treat a
  mismatch there as a real signal, not noise.

## The `.text` half: codegen must byte-match too (bounce it off the data)

Inlining a constant is **not** data-only — it can change `.text`. The per-function
fuzzy match normalises this away, so a unit reads 100% while its `.text` is *not*
byte-identical, and the `Matching` flip then shifts the DOL. Treat `.text` and
`.sdata2` as **two independent byte checks that constrain each other**: build the
`.o` and `diff -s` *both* sections against the target `.o`. Two forces move
`.text`:

- **Function order.** The source must list functions in the retail `.fn` order
  (see step 5). Wrong order shifts every branch offset even though each function
  matches individually. Read the target order from the retail `.o` symbol table
  (`objdump -t … | sort`).
- **Commutative-op operand order.** For `field = field OP const` (add/mul), MWCC
  canonicalises a **compile-time-known** constant to the *front*
  (`fmuls f1,const,field`), but retail — compiled with the value unknown — is
  *field*-first (`fmuls f2,field,const`). Inlining the literal regresses the op.
  The fix keeps the literal inline: **write the compound assignment**
  (`field *= 0.015625f`, `field += 15.0f`) — MWCC does *not* canonicalise the
  compound form, so it emits field-first and matches. This is the common case.
  - Division/subtraction aren't commutative, so a plain inline literal is fine.
  - Last resort for a value that must be a *runtime-unknown* memory load:
    `*(f32*)&namedconst`. It forces a load (field-first) but emits in a separate
    declaration-order stream from the inline pool, so it fights the `.sdata2`
    order — avoid unless a compound rewrite can't express it.
  - Only the **`field = field OP const` accumulator** shape canonicalises. When
    the constant is genuinely first in the expression — `0.005f * timeDelta + x`
    (an `fmadds`), `0.13f * y`, `const + field` inside a cast — retail is *also*
    const-first, so the plain inline literal already matches; don't "fix" it.
- **A literal to a `double` param becomes an 8-byte `lfd` double.** If a call arg
  inlines to a double const (`.sdata2` grows, `lfd` instead of `lfs`), the callee
  prototype in the TU has that parameter typed `double`; type it `f32` and the
  literal loads as a single (`lfs`). An `extern f32` *variable* hid this (it
  loads `lfs` then promotes), so it only surfaces once you inline the literal.

The bounce in practice: inline everything → `diff` both sections → a `.text`
regression on an arithmetic line means "rewrite as compound assignment"; a
`.sdata2` order mismatch means "fix function/first-use order." Iterate until both
are `IDENTICAL`, *then* flip to `Matching`.

## Worked examples — `dll_0127` / `lightsource` (compound-assignment fixes)

`dll_0127`: 3 exclusive floats (`1.0` render arg, `10.0` compare, `0.015625`
sway multiplier). Inlining `scale = scale * 0.015625f` regressed the `fmuls` to
const-first; `scale *= 0.015625f` restored field-first. Reordered to retail
function order; both sections identical → complete (24/24 data).

`lightsource`: 80-byte range mixing `render`/`update`/`init` constants.
`b->fxTimer + 15.0f` and `b->sparkSpawnTimer + 5.0f` both needed `+=`; everything
else inlined as plain literals. Complete (80/80 data).

## Worked example — `magiccavetop` (commit `ad84d1a5`)

Moved 16 `.sdata2` floats (`225 … 10.0`) + the conversion bias out of the auto
pool into `dll_011F_magiccavetop.c`.

| Step | fuzzy | data | linked/complete |
|---|---|---|---|
| Baseline (`extern lbl_`) | 100% | pooled (unowned) | **not linked** |
| Naive inline only | 100% | still pooled + redundant local copy | not linked |
| Inline + claim `.sdata2` range | 100% | **15/16** — `FadeMax` misordered | no |
| + reorder `init` after `update` | 100% | **72/72 byte-identical** | no |
| + flip to `MatchingFor` | 100% | 72/72 | **`main.dol: OK`, complete ✓** |

`FadeMax` (100.0) was hoisted to the front because `magiccavetop_init` first-used
it while sitting *before* `magiccavetop_update` in the source; retail compiled
`init` last. Reordering the function fixed the `.sdata2` order with the code match
untouched.

## Quick reference — the loop that worked

1. `grep` the auto `.s` for the block's addresses + values.
2. `awk` the target asm to confirm every address is yours (by `.fn`, not filename).
3. Add the `.sdata2 start:… end:…` line to `splits.txt`.
4. Inline every float in the range; delete the `extern` decls.
5. Match retail **function order** so first-use order == address order.
6. `NonMatching` → `MatchingFor("GSAE01")` in `configure.py`.
7. `ninja` (EXIT 0, `main.dol: OK`); `diff` the source vs target `.sdata2`;
   confirm `matched_data == total_data` and `complete == true`.
