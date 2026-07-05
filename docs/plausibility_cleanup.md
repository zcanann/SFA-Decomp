# Plausibility Cleanup Playbook

How to take an **already-matched** unit (`fuzzy_match_percent == 100`) and make the
C read like plausible 2002 Rare source — dropping decomp scaffolding, typing raw
pointers, extracting shared structs, and moving compiler knobs out of the file —
**without losing a single byte of the match**.

The full flow is **two phases**, and they belong together:

- **Phase 0 — inline the unit-owned constants** (data-split). This isn't cosmetic: it's
  what *unlocks* the cleanup. While a constant is loaded from the shared `.sdata2` pool,
  MWCC needs the register-pinning scaffolding (the `f32 zero` trick, temp-splits) to
  match; once the constant is a literal the unit owns, MWCC reuses loads on its own and
  the scaffolding falls away (§4). "Now that things are inlined, it falls into place" is
  the whole reason this playbook exists.
- **Phase 1 — the byte-neutral cleanup** (§1–§10 below).

Phase 0 is *not* byte-neutral (it changes which unit owns the data and can flip a unit to
`complete`), so it has its own mechanics and its own success signal — see below and
[data-split inlining](data_split_inlining.md). Do Phase 0 first, then Phase 1.

Related: [`CLAUDE.md`](/CLAUDE.md), [data-split inlining](data_split_inlining.md),
the MP4 reference decomp (`reference_projects/marioparty4`).

---

## Definition of done — what "finished" means

A unit is *finished* when all six hold. The catch: only some are per-file; the rest are
**cross-cutting** (shared headers, other units, the global symbol map), and a unit can be
"as finished as it can be on its own" while these wait on a commons change.

1. **Fully linked** — `metadata.complete == true`, `MatchingFor`, data byte-matched (Phase 0
   done). *Per-file.*
2. **No matching hacks** — no `f32 zero` trick, no launder that exists only to bend codegen
   (keep + comment the ones that are the faithful original). *Per-file (§1–§5).*
3. **Data resolved** — unit-owned constants inlined; shared-pool `lbl_` *named*, not raw.
   Inlining is per-file; **naming a shared `lbl_` is cross-cutting** (it's one symbol used by
   many units).
4. **A dedicated companion header** — `include/main/dll/<unit>.h` declaring the unit's structs
   and *all* its public functions, so consumers `#include` it instead of re-declaring (and
   the definer includes it, so decl is checked against definition). Retire duplicate decls in
   other headers by pointing them at this one. *Per-file to create; light cross-cutting to
   wire up existing consumers.* (Precedent: `dll_00F2_iceblast.h`.)
5. **No consuming externs** — every called symbol comes from a real header (§10). Engine/core
   symbols already have headers; **DLL-to-DLL helpers and shared globals are cross-cutting**
   (promote to a shared header + fix every unit that re-declares it, reconciling signatures —
   see §10 and the `vecRotateZXY`/`timeDelta` cases).
6. **Nothing unnamed** — no `fn_XXXXXXXX`, `unkNNN`, `p1`, `tmp`; shared data named. Names you
   can derive from code/cross-refs/MP4 are per-file; an opaque symbol that needs live
   observation (Dolphin, `live_debugging_workflow.md`) or a **global rename** (e.g.
   `objRenderFn_8003b8f4`, 327 refs → the symbol map) is cross-cutting — best-effort or defer.

**Naming is the pacing item and it gates 5 and 6:** you can't properly export `fn_80138F90`
(externed `int(void)`, really `s16(u8*)`, *called with no args*) until you know what it is.
So "finished" is really an integrated RE pass; drive the per-file criteria to done, and
batch the cross-cutting ones (shared-header promotions, global renames) as their own changes.

---

## Prime rule: the match is truth, and you must re-prove it after every edit

`report.json`'s `fuzzy_match_percent` is the only authority (per `CLAUDE.md`). Every
transformation here is meant to be **byte-neutral**: the emitted object file is
identical, and only whitespace / comments / names / *types that don't change codegen*
move. Whitespace and comments never affect codegen; renames and type changes usually
don't, **but you verify, you don't assume.**

Three mantras:

1. **Test every change in isolation.** One transform, one rebuild, one match check.
   Batching edits means a regression tells you nothing about which one broke it.
2. **A regression is information, not failure.** If a "cosmetic" change drops the
   match, you just discovered a *load-bearing* quirk — that quirk is the faithful
   original. Revert and keep it (often with a one-line comment saying why).
3. **Load-bearing ≠ ugly-forever.** Sometimes the quirk can be re-expressed (a raw
   offset → a typed field is byte-neutral). Sometimes it can't (a store order). Learn
   which by measuring.

---

## The verification loop (run this after EVERY edit)

```sh
# rebuild just this unit's source object + the report (NEVER touch build/GSAE01/obj — read-only)
rm -f build/GSAE01/src/main/dll/<unit>.o \
  && ninja build/GSAE01/src/main/dll/<unit>.o \
  && ninja build/GSAE01/report.json
```

Check the number:

```sh
python3 -c "
import json
r=json.load(open('build/GSAE01/report.json'))
for u in r['units']:
    if '<unit>' in u['name']:
        for f in u['functions']:
            p=f.get('fuzzy_match_percent')   # use .get(): a regression can DROP the key entirely
            ok = p == 100.0
            print(f'  {str(p):>7}  {f[\"name\"]}' + ('' if ok else '  <-- REGRESSED'))
"
```

A **missing** `fuzzy_match_percent` is a regression, not a pass — a function that
gets inlined away (or otherwise stops being emitted) simply vanishes from the report
rather than scoring < 100. That's why the snippet uses `.get()` and treats non-`100.0`
(including `None`) as a failure. Always confirm the *expected set* of functions is all
present and all 100.

Supporting tools:

- **`python3 tools/function_objdump.py <unit-path> <symbol>`** — the target asm.
  Read the prologue to see which local lives in which register (`stw r31,..` saves,
  `mr r29,r3` = first param, `lwz r30,0xB8(r29)` = a field load into a saved reg).
  This is how you reason about declaration-order / register-allocation constraints.
- **`clang-format --dry-run --Werror <file>`** — silent == the file is style-clean.
- **`ninja` (full) → `EXIT=0`** — required before any commit (`CLAUDE.md`).

### When a change regresses: bisect

If a multi-line change drops the match, split it and test halves independently. Real
example from `iceblast`: reordering a 7-line store block regressed to 97.8%. Bisecting
showed the `vec.pos[...]` order was strongly load-bearing (97.9%) while the `vec.dir[...]`
order barely mattered (99.96%) — two different findings hidden in one edit.

---

## Phase 0 — inline the unit-owned constants first (this unlocks the cleanup)

A float/double literal is not a PPC immediate; MWCC materialises it in `.sdata2` and
loads it. An un-owned constant sits in the shared auto pool and the unit references it as
`extern f32 lbl_803EXXXX`. Turning that into an inline literal the unit *owns* is the
"data-split" — mechanics in [data_split_inlining.md](data_split_inlining.md) (it edits
`splits.txt`; its success signal is `matched_data` / `metadata.complete`, **not**
`fuzzy_match_percent`, which is blind to it). Why it belongs here: the inline literal is
what lets MWCC drop the §4 scaffolding.

**The ownership gate — inline a constant only if your unit references it ALONE.** This is
the rule that decides which `lbl_` you can retire and which must stay `extern`. A constant
used by many units lives in the shared pool; inlining it just adds a *redundant* local
copy while the retail object still points at the pool — no data matched, and you've made
the unit's data *worse*. Check every candidate:

```sh
# how many units reference this constant? 1 = yours to inline; >1 = shared, keep the extern
for lbl in $(grep -oE 'extern f32 lbl_[0-9A-Fa-f]+' src/main/dll/<unit>.c | grep -oE 'lbl_[0-9A-Fa-f]+'); do
  echo "$(grep -rl "${lbl}@sda21" build/GSAE01/asm/ | wc -l)  $lbl"
done
# value of an exclusive one (to write the literal): grep -A1 '.obj lbl_XXXX,' build/GSAE01/asm/auto_*_sdata2.s
```

Worked example — `weapone6.c` has 22 `extern f32 lbl_803E2xxx`, but only **3** are
unit-exclusive (`13.0`, `0.03`, `0.65`); the other 19 (`0.0` alone is shared by ~21 units)
are pool constants that **stay `extern`**. So "the file is still full of `lbl_`" is the
*correct* end state here — most of them are not yours to inline. Inline the 3, leave the
19. Don't confuse "an extern remained" with "a step was skipped."

`char lbl_XXXX[]` / non-`f32` `lbl_` are data arrays and tables with real addresses — never
inline candidates; leave them.

---

## Cleanup catalog — byte-neutral transforms (Phase 1)

Most of these were applied to `dll_00F2_iceblast.c` / `dll_00F3_flameblast.c` and
verified at 100%. They are the default moves; apply the ones that fit, verify each — and
note (§10) that the right answer is sometimes "no change."

### 1. Type the object parameter → delete the cast noise

Callback params are often `int* obj` / `u8* obj` with `((GameObject*)obj)->anim.…`
repeated everywhere. Retype the param and drop every cast:

```c
void foo_update(int* obj) { ... ((GameObject*)obj)->anim.rotZ = ...; }   // before
void foo_update(GameObject* obj) { ... obj->anim.rotZ = ...; }           // after
```

Safe because pointer→pointer with the same target offsets is identical codegen. The
integer casts callees want (`ObjHits_*(int obj)`) become `(int)obj` / `(u32)obj` and
compile the same. Assignments from `void*` sources (`Obj_GetPlayerObject()`,
`obj->extra`, `obj->childObjs[0]`) need **no** cast.

> House-style caveat: `int* obj` is itself the dominant *signature* style (survey below).
> Retyping to `GameObject*` is a deliberate readability upgrade for the cleanup phase —
> confirm it's wanted, then be consistent within the file.

**Callback entry points retype in isolation; internal helpers do not.** If the function
is called from *within the same TU* (a `fn_XXXXXXXX` helper, say), retyping its `obj`
parameter is **not** a one-file-neutral edit you can verify alone:

- The mismatch is a hard **error**, not a warning — MWCC emits
  `illegal implicit conversion from 'int *' to 'struct GameObject *'` at each call site,
  and `-maxerrors 1` aborts the build before you get a match number.
- So the helper **and every caller** must be retyped in the *same* edit, then verified as
  a set. Change the helper's signature, fix all `helper(obj, …)` call sites, rebuild once.

### 2. Raw pointer arithmetic → typed struct fields

```c
((f32*)obj)[9]  = 0.0f;               // → obj->anim.velocityX = 0.0f;
((f32*)obj)[10] = -3.0f;              // → obj->anim.velocityY = -3.0f;
vecRotateZXY(&vec, (f32*)((char*)obj + 0x24));  // → vecRotateZXY(&vec, &obj->anim.velocityX);
```

Map the offset with the struct's `STATIC_ASSERT(offsetof(...) == 0x..)` lines
(`include/main/objanim_internal.h` is the anim layout). Same address + same width =
same load/store. `CLAUDE.md` rule: *distrust raw derefs — the original was a typed field.*

### 3. Pointer launder → plain cast (when equivalent)

```c
def = *(IceblastPlacement**)&obj->anim.placementData;   // before
def = (IceblastPlacement*)obj->anim.placementData;        // after
```

Both just reinterpret a pointer value → identical codegen. **But** the `*(int*)&ptr`
launder is *load-bearing* when it forces a `cmpwi` (int) null-test instead of `cmplwi`;
don't collapse those (`CLAUDE.md` width-discipline note). Verify.

### 4. Remove register-allocation scaffolding once constants are inlined

Decomp often carries crutches that pin a value in a register: a `f32 zero;` written via
a side-effect (`if (cur <= (zero = 0.0f))`), or a `f32 tmp = state[0];` that splits a
web. Once **Phase 0** has inlined the unit-owned constants, MWCC frequently reuses loads on
its own, so these crutches can become plain literals (this is the payoff of doing Phase 0
first — on a unit still loading from the pool the scaffolding often stays load-bearing):

```c
f32 zero; f32 cur = state[0];
if (cur <= (zero = 0.0f)) { ...; x = zero; ... }   // before
if (state[0] <= 0.0f)     { ...; x = 0.0f; ... }   // after — if it still matches
```

**Verify each removal — but don't assume they're all load-bearing.** In practice the
crutch often *is* removable: MWCC reuses a single `0.0f` load across several stores on
its own (materialising a float constant into a register and reusing it is **not** the
same optimisation as common-subexpression elimination, so it happens even under
`-opt nocse` / `opt_common_subs off`). Distinguish two separate things:

- **the crutch in the C** (the `f32 zero` / temp) — usually removable, verify;
- **the compiler flag/pragma** (`opt_common_subs off`, §9) — a separate knob that may
  still be required. Removing the *flag* from `iceblast` dropped it to 95.9% even with
  clean C; removing the `f32 zero` *crutch* was byte-neutral. Don't confuse the two.

### 5. Merge declaration and initialization

Split `T x; ... x = expr;` folds into `T x = expr;` — **but declaration order sets
saved-register homes** (`CLAUDE.md`: first-declared → highest reg) and initializer
evaluation order follows declaration order. So:

- Preserve the **relative order** of any locals that live in callee-saved regs
  (`r31, r30, …` — the ones `stw`'d in the prologue and read after a call).
- A local can't merge if its initializer isn't valid at the declaration point — e.g.
  `iceblast`'s `path` must be declared *first* (to claim `r31`) but its load
  `player->childObjs[0]` must stay *guarded* by the `player != NULL` check, so it
  stays split. Merge the rest around it.

Check the prologue with `function_objdump.py` before and confirm identical after.

### 6. Rename locals / params to intent

`state` → `timer` when the extra block is only a countdown; `p` → `def` for a placement
pointer (match the family's word — grep siblings). Pure token rename, always byte-neutral.

### 7. Expand one-liner functions

Repo style (and the `.clang-format`) is **no one-liner functions** — even
`int foo_getExtraSize(void) { return 0x4; }` becomes the 4-line Allman form. This is
whitespace-only. Let `clang-format -i` do it.

### 8. Extract a shared anonymous struct into a `_struct.h`

If the file declares an anonymous `struct { … } x;` that appears identically in sibling
files, lift it to a named type in a shared header (precedent: `mtxbuildarg_struct.h`).
Anonymous → named with identical layout is byte-neutral.

```sh
# find every file with the same shape before naming it
python3 - <<'PY'
import glob,re
pat=re.compile(r's16\s+\w+\[3\];\s*s16\s+\w+;\s*f32\s+\w+\[4\];')
for f in glob.glob('src/**/*.c',recursive=True):
    if pat.search(re.sub(r'\s+',' ',open(f,errors='replace').read())): print(f)
PY
```

`iceblast` did this: the `{ s16 dir[3]; s16 pad; f32 pos[4]; }` `vecRotateZXY` input
block (shared by `pushable`/`flameblast`/`wmobjcreator`) became `VecRotateZXYArg` in
`include/main/dll/vecrotatezxyarg_struct.h`. Header guard style
`MAIN_DLL_<NAME>_STRUCT_H_`, `#include "types.h"`. Only edit the *one* file you own to
use it; note the others can adopt it later (one owner per `.c`).

### 9. Move codegen pragmas out of the file into `configure.py`

In-file `#pragma peephole/scheduling/opt_common_subs off` are really **per-TU compiler
settings**. The build already models them as `-opt` flag lists
(`cflags_dll_noopt`, `cflags_dll_nopeep`, …). Map and move:

| in-file pragma | compiler flag |
| --- | --- |
| `#pragma peephole off` | `-opt nopeephole` |
| `#pragma scheduling off` | `-opt noschedule` |
| `#pragma opt_common_subs off` | `-opt nocse` |
| `#pragma opt_propagation off` | `-opt nopropagation` |
| `#pragma opt_loop_invariants off` | `-opt noloopinvariants` (alias `noloop`) |
| `#pragma dont_inline on` | `-inline off` |

(The table is not exhaustive — MWCC has more `-opt` sub-flags. If you hit an
`opt_<name> off` pragma that isn't listed, the flag is almost always `-opt no<name>`;
confirm it by rebuilding and diffing the object, and add it here. `opt_loop_invariants`
is ON by default at `-O4`, so disabling it TU-wide is an unusually dangerous
scope-widening — re-verify every function after the move.)

Define (or reuse) a named list next to the others in `configure.py` and point the
`Object` at it:

```python
cflags_dll_noopt_nocse = [*cflags_base, "-opt", "nopeephole,noschedule,nocse"]
...
Object(MatchingFor("GSAE01"), "main/dll/<unit>.c", cflags=cflags_dll_noopt_nocse),
```

Editing `configure.py` auto-reconfigures on the next `ninja`. **Verify the exact flag
equivalence** — `-opt nocse == opt_common_subs off` was confirmed byte-identical, but a
new mapping you introduce must be proven with a rebuild. Check the live command:
`ninja -t commands build/GSAE01/src/main/dll/<unit>.o | tr ' ' '\n' | grep -A1 opt`.

**⚠ Scope-widening — the trap.** In-file pragmas are often scoped to *some* functions
(`#pragma X off` … `#pragma X reset` around one or two), leaving the rest of the TU on
the compiler defaults. A `cflags` flag applies to the **whole unit** — so moving a
per-function pragma to a flag turns it *on for functions that previously compiled with
it OFF*. That is **not** guaranteed byte-neutral. After the move, verify **every**
function of the unit, not just the ones that had the pragma. (It usually survives —
those passes are typically inert on the simple accessors — but you must confirm, not
assume.) This is the single most likely way this step silently regresses.

**`dont_inline on` → `-inline off`.** Two gotchas: (a) it needs its own named list
(e.g. `cflags_dll_noopt_nocse_noinline`) — the existing `cflags_dll_*` don't cover it;
(b) `-inline off` must come *after* the base `-inline auto` and win by last-flag-order
(appending it in a `[*cflags_base, …, "-inline", "off"]` list does this). Semantic
caveat for the commit message: this converts a per-function "don't inline *this helper*"
into a TU-wide "inline nothing" — byte-neutral today, but it will suppress a future
small static helper. `dont_inline` is frequently **load-bearing**: dropping it entirely
let MWCC inline a large helper into its callers, and those callers *lost their match
score outright* (see the missing-score note above).

Trade-off to state in the commit: the codegen requirement is no longer visible in the
`.c`. That's the house convention here, so it's the right call — but it's why the flags
must be discoverable (named list + comment).

### 10. Replace file-local `extern`s with a proper `#include` — where a real home exists

The top-of-file `extern` block usually has stragglers the big extern-cleanup pass left
behind. Some can be replaced by including the header that already declares the symbol;
**many legitimately can't**, and forcing them is worse than leaving them.

**Import** (delete the local extern, rely on the `#include`) only when the symbol is
declared in a **curated API header** — `objhits.h`, `objlib.h`, `game_object.h`,
`gameplay_runtime.h`, `objanim_internal.h`, `vecmath.h`, … It's often already included
transitively (e.g. `game_object.h` pulls in `objanim_internal.h`), so the local extern is
simply **redundant**. Find the real home:

```sh
# real prototype (exclude the per-subsystem *_shared.h dumps and comments)
grep -rn "void MySym(" include/ | grep -v "_shared.h"
```

**Keep the local extern** when the symbol only appears in:

- a per-subsystem `*_shared.h` **extern-dump** (`player_80295318_shared.h`, `wm_shared.h`,
  …) — those are per-DLL scratch collections, not APIs; including one in an unrelated unit
  is wrong, and they frequently disagree on the signature (some declare
  `Obj_FreeObject` returning `int`, others `void`);
- the catch-all `engine_shared.h` (1298 lines; pulls in audio/sky/effects) — too heavy to
  include for one global. `timeDelta` lives here, and **137 units keep it local — that IS
  the house style**;
- an unnamed `fn_XXXXXXXX`, or a symbol with **conflicting signatures** tree-wide and no
  single canonical header (e.g. `vecRotateZXY`).

Two traps that make this deceptive:

1. **Implicit declaration hides a missing prototype.** In C89, deleting an extern for a
   function with *no* real declaration still **compiles and can score 100%** — MWCC
   implicitly declares it `int f()`. Green build ≠ proper import; it may be an undeclared
   call. Only remove an extern when a real prototype exists in an included header (verify
   with the grep above, not by "it still built").
2. **Creating a canonical home is cross-cutting, not local.** A symbol may *deserve* a
   real header (`vecRotateZXY` belongs in `vecmath.h` — it's defined in `vecmath.c`), but
   adding it there is a redefinition error for every unit that both includes that header
   and carries its own local extern with a different signature (`-maxerrors 1` aborts).
   Promoting a symbol means touching all those units — out of scope for a per-file cleanup.

**"Defined in a `.c`" ≠ "has an includable header."** Every one of these functions is
defined *somewhere* — that's never the question. The question is whether the defining
module *publishes a header* for it. Engine/core symbols do (`getTrickyObject` →
`gameplay_runtime.h`); DLL-internal helpers usually don't — they're declared at each call
site via a local extern, by convention. Grepping the tree for the symbol tells you which:
if the only hits are the definition and one consumer's extern, there is no header.

### The proper-export path (when you *do* want to import a header-less symbol)

When a symbol is defined in a real `.c` but has no header, you can create one — this is a
bounded, per-symbol change, distinct from trap #2 (promoting into a *shared* header that
many units already re-declare):

1. **Create a minimal companion header** for the defining module (precedent:
   `dll_801b1d84.h`, `dll_80136a40.h`) — guard `MAIN_DLL_<NAME>_H_`, `#include "types.h"`,
   declare just the export(s) a consumer needs.
2. **Reconcile the signature.** Hand-recovered externs often disagree with the definition
   (`f32*(s16*)` vs the real `void*(u8*)`). Pick the definition's truth, and prefer
   `void*` for a generic object pointer — MWCC rejects `s16* → u8*` as a hard **error**,
   but `anything* → void*` is legal, so `void*` lets every caller pass its own pointer type
   with no cast. Since the definer is often `NonMatching`, aligning its param to `void*` is
   free (the body just casts to `GameObject*` anyway).
3. **Include the header in both** the definer (so decl is checked against definition) and
   the consumer; drop the consumer's extern. Verify the consumer still 100% and the definer
   still builds.

Not every extern qualifies even then: `fn_80138F90` is defined `s16 fn_80138F90(u8* obj)`
but flameblast externs it `int(void)` and *calls it with no arguments* — importing the
real prototype is a "too few arguments" error and changes the call's codegen. That one
**stays** a local extern.

Worked result (iceblast / flameblast): most stragglers were "keep" (`timeDelta`,
`vecRotateZXY`, `fn_*`); the already-importable symbols were already imported. The one
genuine win was `trickyGetQueuedPathParticlePos` — header-less, single-consumer, so a fresh
`dll_80136a40.h` + `void*` reconciliation retired the extern cleanly. Don't manufacture
churn, but do take the bounded proper-export when a header-less symbol has a real home.

### 11. Publish a dedicated companion header (the unit's own API)

The flip side of §10: a finished unit *exports* a header
`include/main/dll/<unit>.h` declaring its structs and **all** its public functions, so
other files import it rather than re-declaring. Follow the precedent
(`dll_00F2_iceblast.h`): guard `MAIN_DLL_<NAME>_H_`, include what the declarations need
(`main/game_object.h` for `GameObject` params), move the unit's `typedef struct`s into it,
declare every callback. Then:

- the **definer** includes its own header (so the compiler checks each declaration against
  its definition);
- **retire duplicate declarations elsewhere** — family/descriptor headers often re-declare
  a class's callbacks with Ghidra-style signatures (`int a, int b, …`); replace those with
  an `#include` of the new header and delete the dupes.

All declaration-only → byte-neutral; verify the definer and every consumer still build and
hold their match. Worked example: `iceblast` published `dll_00F2_iceblast.h` and the
transporter-family header `dll_00EF_pushable.h` (which had re-declared 7 of its callbacks,
missing `update`/`init`/`IceblastPlacement`) now includes it.

---

## Load-bearing: measure before you "tidy" these

These *look* cosmetic and routinely **regress**. Never reorder/rewrite them on aesthetic
grounds without the verification loop:

- **Statement / store order.** With `noschedule`+`nopeephole`, the compiler emits stores
  in *source order* — so source order **is** the retail order. `iceblast` must write
  `velocityX, velocityZ, velocityY` and `pos[1],pos[2],pos[3],pos[0]` in exactly that
  order. "Fixing" it to natural order dropped to 95.9%.
- **Declaration order** (§5) — register homes.
- **Control-flow shape.** The `if (a && (x=…)) { … } else { return; }` form emits a
  specific branch layout (including a dead `else`-return branch). Flattening it to early
  returns changes the branches. Keep the shape that matches.
- **Pragmas / `-opt` flags** (§9) — each was verified necessary.

When a quirk is load-bearing **and** can't be re-expressed, leave it and add a short
comment. It is the faithful recovery, not a mistake to fix.

---

## Match house style — survey, don't invent

Before "improving" a signature or spelling, check what the corpus already does and match
the majority. Read matched **siblings** in the same family and the **MP4 reference**.

```sh
# e.g. what do *_update signatures look like across the DLLs?
grep -rhoE "void [A-Za-z0-9_]*_update\((GameObject|int|void|u8) ?\*+ ?[a-z]+\)" src/main/dll/*.c \
  | sed -E 's/[A-Za-z0-9_]*update/NAME_update/' | sort | uniq -c | sort -rn
```

Findings that came out of such surveys (keep these — they're house style, not warts):
`int* obj` params (121 vs 3 `GameObject*`); hex `return 0x4;` in `getExtraSize`
(not `sizeof`); the `pad0[0x19 - 0x0]` `[hi - lo]` padding idiom; `p1..p4` for
unused pass-through render args; `def` for the placement param.

Two rules of thumb for applying a survey:

- **Family precedent beats the global survey.** Within a family (e.g.
  pushable/iceblast/flameblast), match the already-cleaned sibling even where it diverges
  from the corpus-wide majority. `iceblast` retyped `obj` to `GameObject*` for the cleanup
  phase, so `flameblast` should too — consistency within the family reads better than
  conforming each file to the global `int*` count.
- **A survey tells you what to *write*, not a mandate to *rewrite*.** If a file already
  uses a clean, byte-neutral spelling that happens to be the minority (e.g.
  `return sizeof(FlameblastState);` instead of `return 0x14;`), **leave it** — it's more
  readable and churning it buys nothing. Only reach for the majority form when you're the
  one choosing a fresh spelling.

---

## Hard compiler limits (this is a C89 MWCC)

Don't reach for modern C — it won't compile:

- **No designated initializers, no compound literals.** `x = (T){.a=1, .b=2};` and
  `T x = {.a=1};` are C99 → `expression syntax error`. Plain positional aggregate init
  (`T x = {1, 2};`) compiles but initializes in **declaration order**, which usually
  breaks a load-bearing store order — so it's rarely a win anyway.
- Declarations go at the **top of a block** (C89), not interleaved with statements.

---

## Formatting: `.clang-format`, per file

A repo-root `.clang-format` (4-space, full Allman, left pointers, no one-liners, 120 col,
`ReflowComments: false`) is calibrated to house style. Apply **per file you're touching**,
not tree-wide:

```sh
clang-format -i src/main/dll/<unit>.c
```

- Do **not** blanket-run over `include/` — headers are legacy 2-space/K&R and would
  churn massively; format a header only deliberately, per file.
- Never run it over SJIS-bearing files (edit those byte-wise).
- To freeze a delicately hand-aligned block (a `#define` table, an offset-annotated
  struct), wrap it in `// clang-format off` … `// clang-format on`.
- Formatting is whitespace/comments only → never affects the match.

---

## Commit workflow

- One owner per `.c`. Branch off `main`; **rebase + full `ninja` `EXIT=0` before every
  commit**; commit only when asked (`CLAUDE.md`).
- One logical cleanup per commit. Subject like
  `dll_00F2 iceblast: <what> (byte-neutral)`; body notes what stayed load-bearing and
  that the unit is still 100%.
- Never rebuild/delete `build/GSAE01/obj/...` (retail target objects are read-only).

---

## Worked reference: `dll_00F2_iceblast.c`

The end-to-end example this playbook was distilled from (each was its own verified,
byte-neutral commit): removed `f32 zero`/`f32 cur` scaffolding → typed `obj` as
`GameObject*` and dropped ~20 casts → raw velocity offsets to `anim.velocityX/Y/Z` →
launder to cast → `state`→`timer` → expanded one-liners → moved three pragmas to
`cflags_dll_noopt_nocse` in `configure.py` → merged decls with initializers (kept `path`
split) → extracted `VecRotateZXYArg`. Held at 100% the whole way; the odd store orders
and one split declaration were proven load-bearing and left as the faithful original.
