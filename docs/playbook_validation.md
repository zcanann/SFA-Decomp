# Playbook Validation Log (validator)

Empirical reproduction of CLAUDE.md recipes against the real MWCC GC/2.0 + DLL flags.

**DLL domain flags** (`main/dll/*`, 688 units): `-O4,p -inline auto -fp_contract on -opt nopeephole,noschedule -enum int -fp hardware -lang=c`.
**Peephole-ON domain** (337 units, audio/MSL-ish): same minus `nopeephole,noschedule`, plus `-sdata 0 -sdata2 0 -char signed -use_lmw_stmw on -common off`.

Verdicts: **CONFIRMED** / **NUANCED** (condition) / **CONTRADICTED**.

### COVERAGE INDEX (~60 recipes)
- **CONTRADICTED / corrected** (integrated or proposed): #3 (`(u32)x!=0` is a WORKING cmplwi lever, "INERT" false), #23 (`!!x`→neg/or/srwi, NOT double-cntlzw), #126 (param type IRRELEVANT to classing — arg-order rules), #108/#147 ("decl-order inert" — FALSE for top-loaded values; decl-order sets the home), #59 (leading-term lift INERT — MWCC already reassociates to that order), #22 (no extra island — block-layout only).
- **CONFIRMED (isel, trust as-stated):** #1, #2, #4, #10, #12, #15, #17, #20, #24, #25, #27, #31, #37, #38, #41, #42, #44, #47, #49, #50, #52, #53, #58, #63, #69, #74, #91, #97, #112, #114, #135, #137, #143, #45.
- **CONFIRMED (allocator/structural):** #5/#34 (decl→stack offset; decl-home/init-emit), #95 (per-fn opt, unroll gated O3+), #96/opt_strength_reduction, #108 class-pooling, #131 OR-trigger.
- **NUANCED (condition pinned):** #7 (char signed both domains; extsb only on int-promotion), #28, #36 (inert isolated, needs whole-quad), #40 (inert isolated), #51 (CSE not exclusive; store-ORDER is the lever), #71/#121 (loop-LICM only), #98/#113 (unroll pragmas inert vs speculative unroller; opt_level≤2 is the real suppressor), #105 (callee-identical), #128 (recognized, context-specific), #81/#82 (coalesce-dependent).
- **NEW RECIPE DISCOVERIES:** (A) bitfield-dest+int-source → clrlwi+rlwimi; (B) explicit `(u16)` cast on RMW read-back → store-forward clrlwi. (See "RECIPE DISCOVERIES".)

---

## HEADLINE CONCLUSION — two recipe classes, and the allocator is NOT "emergent"
1. **ISEL / codegen levers** (instruction selection, narrowing, cast magic, addressing, branch shape, FP forms): **crisply isolable, ~all CONFIRMED** in a minimal TU. Trust these as stated. (#2/#3/#4/#10/#15/#20/#21/#24/#25/#27/#37/#41/#42/#44/#47/#50/#58/#63/#69/#74/#91/#97/#112/#114/#143...)
2. **ALLOCATION / coloring levers**: previously called "emergent/pressure-gated," but they run a **deterministic algorithm I've now partly reverse-engineered** (see "ALLOCATOR MODEL" section). Most have **exact triggers**:
   - **#126 param-classing**: params class by ARGUMENT-REGISTER order, type-IRRELEVANT (headline disproven).
   - **#108 within-class order**: DECL order sets the home for TOP-LOADED values (first→highest, descending), independent of load/init/offset; call-results use creation order (ascending, last→r31). "decl-order is inert" is DISPROVEN for top-loaded values.
   - **#131 OR-noop**: exact 3-ingredient trigger (two same-value pointers, both used, OR on one) splits the front-end displacement-coalesce into two webs+`mr`.
   - **#5**: DECL sets register home, INIT sets emission — confirmed exactly.
   - Open piece: **#147 integer class-pull** needs more pressure than minimal isolation provides (the one effect still resisting a clean trigger).
The split tells you how much to trust each recipe in isolation: class-1 = as-stated; class-2 = use the concrete allocator rules below, not guesswork.

---

## #2 — `& ~0x80` → rlwinm vs `& 0xff7f` → andi; #74 LL-suffix → `li -K; and`
**VERDICT: CONFIRMED (with precise discriminator).** DLL flags (nopeephole).

| C (u32 *p) | asm |
|---|---|
| `*p &= ~0x80;`   | `rlwinm r0,r0,0,25,23` (single-bit clear, preserves all other 31 bits) |
| `*p &= 0xff7f;`  | `andi. r0,r0,65407` — **but also clears top 16 bits** (semantically ≠ `~0x80`) |
| `*p &= ~0x80LL;` | `li r0,-129; and r0,r4,r0` (#74 materialized mask) |
| `*p &= ~0x180;`  | `rlwinm r0,r0,0,25,22` (contiguous 2-bit clear → still rlwinm) |
| `*p &= ~0x10000;`| `rlwinm r0,r0,0,16,14` (any single/contiguous bit → rlwinm) |
| `*p |= 0x80;`    | `ori r0,r0,128` (single-bit SET with imm<0x10000 → ori, NOT rlwimi) |

**Mechanism / boundaries:**
- `& ~K` (mask = all bits except a contiguous run) is representable as a rotate-by-0 + mask, so isel always picks `rlwinm`. Works for BOTH `int` and `u32` lvalues — signedness is irrelevant for the `~K` form (s32 `*p &= ~0x80` → identical `rlwinm`).
- `& 0xff7f` picks `andi.` because 0xff7f fits a 16-bit unsigned immediate. **NOT equivalent** to `~0x80` for a 32-bit value (it zeroes bits 16-31). Only use when the value is known < 0x10000.
- #74 LL-suffix: forces the 64-bit-materialized path → `li -K; and`. Lvalue MUST be u32: with an `int`/s32 lvalue, `*p &= ~0x80LL` adds a **dead** `srawi r0,r4,31` (the sign-extended high word, overwritten immediately at nopeephole) before `li -129; and`. Confirms #74's "lvalue must be u32" caveat and the #150 dead-srawi mechanism.

---

## #3 — `*(void**)ptr != NULL` → cmplwi vs `*(int*)ptr != 0` → cmpwi
**VERDICT: CONFIRMED for the main claims; the `(u32)x != 0` "INERT" sub-claim is CONTRADICTED in isolation.**

**CRITICAL CONTEXT:** cmplwi/cmpwi only appear when the compare **feeds a branch** (`if`/`while`). When the boolean is **returned/materialized**, MWCC emits the arithmetic form (`neg` for `!=0`, `cntlzw` for `==0`) which is signedness-agnostic — no cmp at all. Test #3 in branch context.

In branch context (DLL flags):
| C | asm |
|---|---|
| `if (*(void**)p != 0)` | `cmplwi` ✓ |
| `if (*(int*)p != 0)`   | `cmpwi` ✓ |
| `if (x == 0u)` (u32)   | `cmplwi` ✓ |
| `if (x == 0)` (int)    | `cmpwi` ✓ |
| `if (x != 0)` (u32)    | `cmplwi` ✓ |
| `if ((void*)x != 0)`   | `cmplwi` ✓ |
| `if ((u32)x != 0)` (x=int) | **`cmplwi`** — cast IS effective |

**CONTRADICTED:** "`(u32)x != 0` is INERT (folds back to signed); use `(void*)x != NULL`." In isolation `(u32)x != 0` → cmplwi reliably. Even with a CSE-merge scenario (x read as signed `int` and passed to a call, THEN compared `(u32)x != 0`), the cmplwi survives (the value sits in a saved reg r31 and the unsigned compare holds). I could NOT reproduce the inertness — `(u32)x != 0` is a perfectly good cmplwi lever, no need for `(void*)`. The "inert" note is likely from a narrower real context not captured here.

---

## #7 — `u8` not `char` for byte arrays (drops spurious extsb)
**VERDICT: NUANCED.** `char` is **SIGNED by default in BOTH domains** (DLL config has no `-char` flag yet char→extsb; the audio `-char signed` flag is redundant). The extsb appears ONLY when the byte is **widened to int** (arithmetic / int-return / compare), NOT on pure byte→byte copy.

| C | asm |
|---|---|
| `d[0]=s[0];` (u8, char, or s8 — all 3) | `lbz; stb` — **no extsb for any** |
| `return p[0];` as `int`, char/s8 | `lbz; extsb` |
| `return p[0];` as `int`, u8 | `lbz` only |
| `return p[0]+1;` char/s8 | `lbz r0; extsb r3,r0; addi` |
| `return p[0]+1;` u8 | `lbz r3; addi` (no extsb) |

So the "load+assign without arithmetic" framing is imprecise: a byte→byte store never extsb's (the `stb` truncates). The u8-vs-char lever bites when the value is **promoted to int**. Use `u8` for bytes used in any int context to drop the extsb.

---

## #15 — `*(s8*)(p+off)` vs `(s8)arr[off]` (extsb register pairing)
**VERDICT: CONFIRMED.**
| C (returns int) | asm |
|---|---|
| `*(s8*)(p+4)` | `lbz r3,4(r3); extsb r3,r3` (same reg — lands in target directly) |
| `(s8)arr[4]` (explicit cast) | `lbz r0,4(r3); extsb r3,r0` (r0 detour) |
| `arr[4]` (natural s8, no cast) | `lbz r3,4(r3); extsb r3,r3` (== deref form) |

The discriminator is the **explicit `(s8)` cast on an array index**, which routes the load through r0. Natural `arr[off]` (s8-typed array, no cast) behaves like the deref form. Use `*(s8*)(p+off)` or natural typing to keep the load in the target reg; the cast-on-index gives the r0 detour.

---

## #20 — narrow compound-assign drops redundant extsh/extsb
**VERDICT: CONFIRMED (all three sub-claims).**
| C | asm |
|---|---|
| `*p += 5;` (s16) | `lha; addi; sth` — **no extsh** |
| `*p = *p + 5;` (s16) | `lha; addi; extsh; sth` |
| `*p += 5;` (u16) | `lhz; addi; sth` — no clrlwi |
| `*p = *p + 5;` (u16) | `lhz; addi; clrlwi; sth` |
| `(*p)++;` (u8) | `lbz; addi; stb` — no clrlwi |
| `*p = *p + 1;` (u8) | `lbz; addi; clrlwi; stb` |
| `*p -= (s16)big;` | `extsh r4,r4` (on **subtrahend**); `lha; subf; sth` |
| `*p -= big;` | `lha; subf; extsh r0,r0` (on **result**) |

Mechanism: the narrow store (`sth`/`stb`) already truncates, so the explicit narrowing in the expanded RMW is redundant; compound-assign elides it. #20c: the `(s16)` cast moves the single extsh from the *result* to the *subtrahend operand* (pre-truncation) — same instruction count, different placement (matches a target that pre-truncates the operand).

---

## #1 — `#pragma peephole off` / `scheduling off` unfuses `extsb.`/`rlwinm.` dot-merges
**VERDICT: CONFIRMED, and the independence claim is precise.** Tested in the **peephole-ON domain** (the DLL domain is already nopeephole, so the pragma is a no-op there).

Peephole ON (base): `if (p[0]==0)` (s8) → `extsb. r0,r0; bne` (fused recording form, no cmp). `if ((x&0x80)==0)` → `rlwinm. r0,r3,0,24,24; bne`.
With `#pragma peephole off`: `extsb r0,r0; cmpwi r0,0; bne` / `rlwinm r0,r3,0,24,24; cmplwi r0,0; bne` (unfused).

**Isolation:** `#pragma peephole off` ALONE unfuses; `#pragma scheduling off` ALONE leaves it fused. So the **peephole** pass owns the dot-merge — #1's "add peephole off only for a specific extsb./rlwinm. residual; scheduling off is independent" is exactly right. (Note: at peephole-off the masked compare becomes `cmplwi` (unsigned) for the rlwinm result and `cmpwi` for the extsb result.)

---

## #23 — bool materialization forms
**VERDICT: NUANCED — most forms confirmed, `!!x`→"double-cntlzw" CONTRADICTED.** DLL flags, return-value context.
| C | asm |
|---|---|
| `!x`       | `cntlzw r0,r3; srwi r3,r0,5` (==0 form, single cntlzw) ✓ |
| `x != 0`   | `neg r0,r3; or r0,r0,r3; srwi r3,r0,31` ✓ |
| `!!x`      | `neg; or; srwi` — **identical to `x != 0`, NOT double-cntlzw** |
| `x <= 0`   | `li r4,1; cntlzw r0,r3; rlwnm r3,r4,r0,31,31` ✓ (the #23 signed form) |
| `x >= 0`   | `srwi r0,r3,31; xori r3,r0,1` |

**CONTRADICTED:** `!!x` does not produce a double-cntlzw in this MWCC config — it folds to the same `neg/or/srwi` as `x != 0`. If a target shows a literal `cntlzw rA,rB; cntlzw rC,rA`, `!!x` is not the source for it here. (`!x`→single cntlzw and the `x<=0` li/cntlzw/rlwnm forms are solid.)

---

## #38 — `(x & N) ? 1 : 0` (branchy) vs `(x & N) != 0` (arithmetic)
**VERDICT: CONFIRMED.** DLL flags.
| C | asm |
|---|---|
| `(x & 0x10) ? 1 : 0` | `rlwinm r0,r3,0,27,27; cmplwi r0,0; beq; li r3,1; b; li r3,0` (branchy) |
| `(x & 0x10) != 0`    | `rlwinm r3,r3,0,27,27; neg r0,r3; or r0,r0,r3; srwi r3,r0,31` (arithmetic) |

The ternary forces the branch+li/li materialization; the `!= 0` gives the arithmetic neg/or/srwi. Both first isolate the bit with `rlwinm ,0,27,27`.

---

## #112 — K-grouping picks the displacement isel (`lbz K` vs `lbzx`)
**VERDICT: CONFIRMED, with a refined mechanism.** DLL flags. The real discriminator: **is K grouped into the pointer's element-unit arithmetic (→ displacement) or into the byte-scaled-index expression (→ indexed)?**

| C | asm |
|---|---|
| `base[idx+8]` (u8 base) | `add r3,r3,r4; lbz 8(r3)` (disp, base-first) |
| `p=base+8; p[idx]` (u8) | `add r3,r3,r4; lbz 8(r3)` (same) |
| `base[idx+8]` (u32 base) | `slwi r0,r4,2; add r3,r3,r0; lwz 32(r3)` (disp; 8 elems → 32-byte disp) |
| `*(u32*)(base + idx*4 + 32)` | `slwi r4,r4,2; addi r0,r4,32; lwzx r3,r3,r0` (**fold-onto-index → lwzx**) |
| `((E*)((u8*)arr+idx))->flags` | `addi r0,r4,4; lbzx r3,r3,r0` (field K folds onto byte idx → lbzx) |
| `u8 *p=base+5; p[idx]` | `add r3,r3,r4; lbz 5(r3)` (field K grouped onto base → disp) |

**Mechanism:** when K is added in the **pointer's element units** (`base[idx+K]`, `p=base+K`, `&arr[K]`) the type system scales it and MWCC keeps it as the load **displacement** (`add base,idx; lbz K`). When K is added to an **explicit byte-scaled index** (`base + idx*size + K`), MWCC folds K onto the index register (`addi idx,K`) and uses the **indexed** load (`lbzx`/`lwzx`, no displacement).
- Single-use named `p` re-folds to the flat `add base,idx; lbz K`. **Multi-use** named `p` materializes a real pointer (`addi base,K`) and indexes off it (`lbzx` for the first use). Confirms "Named p needs MULTI-use" — though the multi-use form gives lbzx-off-materialized-p, not the displacement form, so use the grouped single-expression for clean displacement.
- The specific "`base+(idx+K)` → idx first" spelling did NOT reproduce for a u8 base (it gave displacement); the byte-scaled-index form is the reliable way to force lbzx.

---

## #135 — typed array-of-structs `arr[idx].field` per-statement indexing
**VERDICT: CONFIRMED (core addressing/re-derive behavior).** DLL flags. `Flame gFlames[]` (size 0x30), stores across calls.

- **Per-statement** `gFlames[idx].field` (with `docall()` between): keeps the scaled index `mulli r31,r3,48` in a saved reg ONCE, and **re-derives the global base** after every call: `lis r3,0; addi r0,r3,0; add r3,r0,r31; stfs K(r3)`. Field offset is the load/store displacement. This is exactly the target's "re-derive `base + idx*size` across each intervening call" (the #112 `add state,off` shape).
- **Cached** `Flame *p = &gFlames[idx]`: computes the full address ONCE (`mulli; lis; addi; add r31,...`) into one saved reg; every store is `stfs K(r31)` — no re-derive across calls.

So the per-statement vs cached spelling genuinely controls whether MWCC re-materializes the base across calls. Confirms the #135 mechanism (the playbook's note that the typed array form produces the re-derive "for free").

---

## CHAIN: #2/#74 LL-mask + adjacent zero store (#74 caveat + #150 mechanism)
**VERDICT: CONFIRMED — reproduces the documented register-steal regression and the #150 fix.** DLL flags. `struct { u32 flags; s16 timer; }`.

| C | asm |
|---|---|
| `flags &= ~0x400LL; timer = 0;` (u32) | `lwz r5; **li r4,0**(EARLY); li r0,-1025; and; stw; sth r4` — the dead 64-bit high-word `li 0` is CSE'd with `timer=0` and **hoisted to the top** (the register steal) |
| `*(int*)&flags &= ~(u64)0x400; timer=0;` (signed, #150) | `lwz r4; **srawi r0,r4,31**(dead); li r0,-1025; and; stw; **li r0,0**(LATE); sth` — signed high word is a `srawi` (non-reusable), so the 0 stays late |
| `flags &= ~0x400; timer=0;` (plain, no LL) | `lwz; rlwinm; stw; li r0,0(LATE); sth` — cleanest, no steal, no srawi |

**Mechanism confirmed:** the u32 `~Kll` form materializes the AND's dead high-word as `li 0`, which the value-numberer merges with the adjacent `timer=0` and emits EARLY (before the mask) — the documented #74 register-steal. The #150 signed-lvalue fix replaces that `li 0` high word with a `srawi` (a *computed* dead value with no reusable literal), forcing the `timer=0` to re-materialize late. Trade-off as documented: signed form costs a dead `srawi` (+1 instr) but fixes the zero's position; plain rlwinm (no LL) avoids both when the target genuinely wants rlwinm.

---

## #25 / #91 — FP compare: branch vs materialized; cror over-production
**VERDICT: CONFIRMED.** DLL flags. The governing rule: **non-strict `>=`/`<=` need a `cror` (gt|eq / lt|eq); strict `>`/`<` branch directly (cror-free).**
| C | asm |
|---|---|
| `if (a >= b)` | `fcmpo; cror eq,gt,eq; bne` |
| `if (a <= b)` | `fcmpo; cror eq,lt,eq; bne` |
| `if (a > b)`  | `fcmpo; ble` (cror-free) |
| `if (a < b)`  | `fcmpo; bge` (cror-free) |
| `return a >= b;` (materialized) | `fcmpo; cror; mfcr r0; rlwinm r3,r0,3,31,31` (#25 mfcr/srwi form) |
| `if(v<=lo)v=lo; else if(v>=hi)v=hi;` (non-strict clamp) | TWO crors (over-production) |
| `(v<lo)?lo:((v>hi)?hi:v)` (#91 strict ternary) | `fcmpo; bge; fcmpo; ble` (cror-FREE) |
| `if(v<lo)v=lo; if(v>hi)v=hi;` (strict if-clamp) | also cror-free (`bge`/`ble`) |

**Key refinement:** #91's lever is really just "use STRICT comparisons." Both the strict nested ternary AND a strict `if`-clamp produce the cror-free `bge`/`ble`. The cror only appears when the source uses `>=`/`<=`. So to kill an over-produced cror, rewrite the clamp predicate as strict (`<`/`>`) — the ternary form is one way but not the only one.

## #71 / #121 — literal float const rematerialize vs named-const CSE/LICM
**VERDICT: NUANCED (the asymmetry is loop-specific, not straight-line).** DLL flags.
| scenario | literal `0.5f` | named `extern const f32 lbl_K` |
|---|---|---|
| two uses in ONE expression (`a*K+b*K`) | ONE `lfs`, reused (CSE) | ONE `lfs`, reused (CSE) — **same** |
| two uses across a `bl` call (straight-line) | reloaded (2× `lfs`) | reloaded (2× `lfs`) — **same** |
| loop body with a `bl`, invariant product | whole product `a*0.5` **LICM-hoisted** to saved f31 (loop body just `fmr f1,f31`) | only the const `lfs f31` hoists to preheader; the multiply `fmuls` **recomputes each iteration** |

So **#71's "literals rematerialize per use; named CSE'd" is NOT confirmed for straight-line code** (both CSE within an expression, both reload across a call). The real asymmetry is **#121's loop case**: a literal lets MWCC LICM-hoist the entire invariant product into a saved reg, whereas a named extern const is treated as a memory ref whose product is recomputed per iteration (only the load hoists). Mechanism: the literal is a true compile-time constant (fully hoistable); the extern const is a memory load MWCC won't fully fold past the call.

**#71 operand order CONFIRMED:** the literal's `lfs` is always emitted FIRST (before `fcmpo`) regardless of which side of the compare it's on; its fcmpo operand *position* follows source order (`a > 1.5f` → `fcmpo f1,f0`; `1.5f > a` → `fcmpo f0,f1`).

---

## #137 — param-list reorder is register-neutral (only changes save/emit order)
**VERDICT: CONFIRMED.** DLL flags. `f(f32 x, f32 y, void *obj)` vs `f(void *obj, f32 x, f32 y)`:
- BOTH assign obj→r3, x→f1, y→f2 (the ABI assigns by type + within-type order, independent of declared cross-type position).
- The ONLY difference is the prologue save order: floats-first saves `fmr f31,f2(y)` then `mr r31,r3(obj)`; ptr-first saves `mr r31,r3(obj)` then `fmr f31,f2(y)`.
So moving an int/ptr param ahead of float params is safe and reorders only the save/arg-emit sequence — exactly as #137/#146 claim.

## #108 — saved-reg CLASS pooling (copies top, params bottom)
**VERDICT: CONFIRMED (core model).** DLL flags. `multi_copy(int pa, int pb)` with `a=compute(); b=compute(); c=compute();` all live across a `sink()` call:
- params `pa,pb` → **r27, r28** (bottom), declaration order.
- single-def copies `a,b,c` → **r29, r30, r31** (top), ascending in creation order — **last-created `c` → r31**.
This matches #108 exactly: "single-def copies → top (last-created → r31); params → bottom." Within a class, order follows creation/declaration.

## #126 — "POINTER param → COPY pool (high); INTEGRAL param → PARAM pool (low)"
**VERDICT: CONTRADICTED in isolation — could not reproduce the pointer→copy-pool promotion.** DLL flags.
- `f(void *ptr, int num)` and `f(int num, void *ptr)` and `f(void*,void*)` and `f(int,int)` ALL produce identical `mr r30,r3; mr r31,r4` — **the param's TYPE (ptr vs int) does NOT change its saved reg; declaration/arg order does** (first param→lower reg).
- In `pressure(void *ptr, int a)` with `int x = compute();`: the **call-result copy x → r31 (top)**, while the pointer param `ptr` → r29 and int param `a` → r30 (both in the param pool, bottom). The pointer param was NOT promoted above the int param or into the copy pool.
So a pointer param classes **identically to an int param** (param pool, by declaration order); only the copy-vs-param distinction and creation order matter. #126's headline "pointer → copy pool (high)" did not reproduce — this is the "kind-2 / INERT" case the recipe itself hedges toward, but I never observed the "kind-1" promotion. **Recommend demoting #126's headline to: param type does not reclass; the real levers are copy-vs-param class (#108) + creation/declaration order.** (If a real kind-1 case exists it needs a condition not captured by simple param/local competition.)

---

## #29 / #36 / #41 / #10 / #114 — isel & cast cluster
**#29 — caller arg-emission order from callee param position:** mechanism is identical to #137 (confirmed). Register assignment is by type; declaration order sets emission/save order. (A clean isolation is awkward because changing the extern order requires changing the matched call-arg order, which keeps registers fixed — the lever is real but ≡ #137.)

**#36 — drop redundant `(int)` cast at call site:** **NUANCED / inert in isolation.** `use2((int)p[0],(int)p[1])` and `use2(p[0],p[1])` compile **byte-identical** — a redundant `(int)` cast on an already-int value is folded away. The "inflates saved-reg priority" effect needs the documented whole-quad high-pressure context (the recipe admits "a partial drop shows nothing"); not reproducible as a single-cast isolation.

**#41 — `return (s32)floatExpr;`:** **CONFIRMED.** → `fadds; fctiwz f0,f0; stfd f0,8(r1); lwz r3,12(r1)` (the fctiwz/stfd/lwz epilogue, no extra temp).

**#10 — `(f32)(u32)` vs `(f32)(int)`:** **CONFIRMED.**
- `(f32)(u32)x`: stores the value directly, bias `@11`, then `fsubs` — **no xoris**.
- `(f32)(int)x`: `xoris r0,r3,32768` (flip sign bit) before the store, different bias `@17`, then `fsubs`.
The structural discriminator is the **`xoris ,32768`** (present for signed, absent for unsigned) + which bias double. The @NNN-vs-named reloc difference is score-neutral (#70).

**#114 — no-op conversion node splits VN:** **CONFIRMED (precise mechanism).** `(int)(f64)v + (int)(f64)v` → ONE `fctiwz` (the float source `v` is CSE'd in a reg) but **TWO `stfd;lwz` extraction slots** at different stack offsets (two separate conversion temps). `int t=(int)v; t+t` → ONE extraction reused. So the `(f64)` no-op promotion splits the VN at the **conversion-temp extraction** level (creating the extra stack slots that drive #83/#67 frame effects), not necessarily at the fctiwz (which CSE's when the source float is already in a register). For the fctiwz itself to duplicate, the float source must also be re-read (volatile/global re-read).

---

## #97 — `(int)(f64)v` free VN split vs `(int)(f32)(f64)v` no-split
**VERDICT: CONFIRMED (split vs no-split).** DLL flags, `f32 v` from a global.
- `(int)(f64)v + (int)(f64)v` → ONE `fctiwz`, **TWO `stfd;lwz` extraction temps** (VN split, two conversion slots).
- `(int)(f32)(f64)v + (int)(f32)(f64)v` → ONE `fctiwz`, **ONE extraction reused** (no split — the `(f32)` collapses the f64-promotion VN key back, so the two expressions CSE).
The actionable behavior (extra conversion temps with `(f64)`, none with `(f32)(f64)`) is exactly as #97/#114 describe. (Note: with an f32 source no actual `frsp` is emitted — the `(f32)(f64)` round-trip is free since v is already single — but the VN-collapse still kills the split.)

## #58 — type the local to match the field width (cmplwi vs cmpwi)
**VERDICT: CONFIRMED.** `struct { u16 num; }`, `if (num > 5)`:
- `u16 num = s->num;` → `lhz; cmplwi r0,5` (unsigned)
- `int num` / `long num = s->num;` → `lhz; cmpwi r0,5` (signed)
The field load is `lhz` either way; the local's type controls only the compare signedness. Keep the local `u16` to preserve the unsigned `cmplwi`.

## #51 — chained `x=y=z=K` CSEs one constant load
**VERDICT: NUANCED — the CSE is NOT exclusive to chaining; chaining's real effect is REVERSE store order.** DLL flags, three struct fields = K.
- chained `s->a=s->b=s->c=K`: one constant materialization, stores in **reverse** order (c@8, b@4, a@0).
- separate `s->a=K; s->b=K; s->c=K`: **also** one constant materialization (CSE'd), stores in **forward** order (a@0, b@4, c@8).
Verified for both a cheap `li 5` AND a multi-instr `lis;addi 0x12345` — both forms CSE the single materialization. So "chained CSEs one li" is misleading: separate stores CSE it too. **The discriminator is store ORDER** (chained=reverse, separate=forward) — pick by the target's store order.

## #74 (multi-bit materialized forms)
**VERDICT: CONFIRMED.** u32 lvalue:
- `*p ^= 2LL` → `li r0,2; xor` (materialized) ✓
- `*p |= 0x100100LL` → `lis r4,16; addi r0,r4,256; or` (materialize then single OR) ✓
- `*p |= 0x100100` (no LL) → `oris r0,r0,16; ori r0,r0,256` (two immediate-OR ops, no materialization)
The LL suffix forces the 64-bit-materialized path: constant built into a reg, then ONE logical op — vs the plain form's two immediate ops directly on the value. Same instr count, different structure; match the target's choice.

---

## #4 / #22 / #42 / #37 — control-flow & narrowing isel
**#4 — clamp `if (v>K) v=K; return v;` → blelr:** **CONFIRMED.** `cmpwi r3,100; blelr; li r3,100; blr`. NOTE: the *inverse* `if (v<=K) return v; return K;` produced the **identical** blelr in isolation — so the "not the inverse" caveat didn't reproduce for this int clamp (both forms give blelr). The blelr itself is reliable.

**#22 — `if (cond){...} return 0;` vs `if (!cond) return 0; <body>`:** **NUANCED.** Both forms emit the **same instruction count** (cmpwi; branch; li 0; b; bl; blr) — the difference is **block layout** (which of the call-body / `return 0` is out-of-line). wrap puts `li r3,0` after the body; guard puts it inline with a `b` to skip the call. Not an "island drop" (no net instr saved) — a layout selector. Use to match the target's block order.

**#42 — ternary `cond?K1:K2` into a typed lvalue:** **CONFIRMED.** `u8 r = c?3:7;` → `cmpwi; beq; li r0,3; b; li r0,7; clrlwi r3,r0,24` (per-arm li/b/li join + the narrowing at the merge; u8→clrlwi, s8→extsb).

**#37 — `(u16)` on the WHOLE OR-expression → one clrlwi:** **CONFIRMED.**
- `(u16)((a<<8)|b)` → ONE `clrlwi r3,r0,16` at the result.
- `((u16)(a<<8)) | (u16)b` → **TWO** `clrlwi ,16` (one per cast operand + the merge).
Casting the whole expression consolidates the narrowing into a single op at the store/result.

---

## CHAIN: narrow-lvalue bit-clear (#2/#74 × #20) + alias-index (#30 × #112)
**Findings (DLL flags):**
- `*p &= ~0x80` on **u16** → `lhz; rlwinm r0,r0,0,25,23; sth` (clean rlwinm, no extsh). On **u8** → `lbz; rlwinm; stb`. Bit-clear on a narrow lvalue is clean (the narrow store truncates).
- **#74 REFINEMENT (important):** the LL materialized-mask form is clean (`li -K; and`, **no srawi**) for **ALL unsigned lvalues (u8/u16/u32)**. The dead `srawi rX,rY,31` only appears for **SIGNED** lvalues (`int`/`s32`), because the signed high word is a sign-extension while unsigned high word is a constant 0 (DCE'd). So #74's "lvalue must be u32" should read **"lvalue must be UNSIGNED"** (u8/u16/u32 all work). For a u16 lvalue: `*p &= ~0x80LL` → `lhz; li r0,-129; and; sth`.
- **#30 × #112:** with `u32 *b32 = (u32*)base;`, `b32[i] = 0` → `slwi i,2; stwx` (indexed, no disp); `b32[i+4] = 0` → `slwi i,2; add base,i; stw 16(base)` (the const offset folds to displacement). The alias + element-unit constant gives the displacement form, as #112 predicts.

---

## #143 / #155 / #136 — global-base walker detour (HIGH-VALUE, cleanly isolated)
**VERDICT: CONFIRMED — and the #143 index-form crack reproduces in isolation.** DLL flags, `extern u8 garr[]`, loop `for(i=0;i<n;i++){ sink(); body; }`.

The detour vs direct, with EVERYTHING else identical:
| source | base materialization |
|---|---|
| pointer-walk `u8 *p=garr; ...; *p=0; p++;` | `lis r3,@ha; addi r0,r3,@lo; mr r30,r0` (**r0 detour + copy**, 2 instr) |
| index `garr[i]=0;` (strength-reduced to walker) | `lis r3,@ha; addi r30,r3,@lo` (**DIRECT into walker**, 1 instr) |

So the index form is the clean source and is **1 instruction shorter** — exactly the #143/#155 claim. The strength-reducer synthesizes the walker and inits it directly; an explicit `p=garr` assignment forces `compute-into-temp + mr-into-saved`.

**Scope precisely pinned:**
- **Straight-line** pointer-to-global (`u8 *p=garr; p[0]=1; p[1]=2;`) → **always DIRECT** (`lis r3; stb 0(r3); stb 1(r3)`), no detour, single OR multi use. The detour is a **loop** phenomenon.
- **Scalar global** (`gscalar=5`) and **const-offset** (`garr[3]=0`) → always direct. (Matches #155's note these are never the detour.)
- **LOCAL/param base** walk (`u8 *p=base; p++`) → `mr r30,r3` (normal param→saved copy, NOT the r0 detour). The detour is **global-base-specific**.
- **comma-init walker** `for(i=0,p=garr; i<n; p++,i++)` on a GLOBAL base → **still detours** (`mr r30,r0`). Confirms #136: comma-init is for LOCAL bases; the index form is the global-base fix.
- **OPEN part confirmed inert:** `register u8 *p`, #80 launder `(u8*)(int)garr`, are BOTH inert — still detour. Only the index form (#143) cracks the single-walker case. (The unrolled multi-walker case where the source is genuinely a pointer-walk remains the open #155 target.)

## #28 — runtime `slw` over fixed bits = unrolled loop
**VERDICT: CONFIRMED (shape).** The manual source unroll (`r|=(x>>0)&1; r|=((x>>1)&1)<<1; ...`) emits per-bit `rlwinm rX,r3,rot,31,31; slwi; or` — the explicit unrolled sequence. Writing the loop instead would roll it with a runtime `slw`. The lever is choosing the loop form when the target is rolled; the manual-unroll shape is as described.

### #155 deep-dive — refinement on the index-form crack
Tested every spelling against `extern u8 garr[]/garr2[]` in a loop:
- **Index form `garr[i]` ALWAYS materializes the base DIRECTLY** (`addi rWalker,r3,@lo`), in every config tested: single-walker, multi-walker (2 globals → both direct, r30+r29), with-call (no unroll), and without-call (unrolled by 8). No r0 detour in any.
- **Pointer-walk `p=garr; p++` ALWAYS detours** (`addi r0,r3,@lo; mr rWalker,r0`): single, multi (both detour), end-pointer loop, `&garr[0]`, `register u8 *p`, #80 launder `(u8*)(int)garr` — ALL inert (still detour). Straight-line (no loop) is the only exception (direct).
- So in **isolation** the index form is a robust crack even for the unrolled multi-walker case. The real-fn regressions #155 documents (onMapSetup→0%, expgfxRemoveAll kept mr+slwi;add, renderParticles→lhzx) are **collateral isel changes from the index form** (non-unit element stride forces `slwi`/`add`; a conditional/single use forces `lhzx`), NOT a failure of the base materialization — the base still goes direct. The open part is therefore narrower than "the detour": it's "apply the index form WITHOUT triggering stride-scaling or conditional-use isel changes." For a unit-stride unconditional walker, the index form is the clean fix.

---

## #131 / #147 — the no-op OR same-value-merge defeat (the "placeholder")
**VERDICT: mechanism CONFIRMED; APPLICABILITY is pressure-dependent (inert in low-pressure isolation).** DLL flags.

Core mechanism (two int values, distinct vs shared web):
- `int x=a; x |= b;` where **a,b are DISTINCT param webs** (same runtime value) → emits a real `or r31,r30,r4` — x keeps its own web/reg, a stays separate.
- `int x=a; x |= a;` (**same web**) → the OR **folds to `mr r31,r30`** (a plain copy) — because x and a share a value-number, `x|a = x`.

So a `|=` between distinct webs genuinely blocks the front-end same-value merge and forces a surviving copy/or; between same webs it degenerates to a copy.

**BUT the trick is INERT in simple isolation:** I could not reproduce the *problem* it fixes. In a reduced curves_distFn15 (`int prev=curveId; ...while(prev!=curveId)...`), the plain `prev=curveId` ALREADY emits `mr r31,r29` (prev = copy of curveId in its own reg r31, curveId stays r29) — and adding `prev |= curveId` produces **byte-identical** output (the OR folds, allocation unchanged). The pool rotation #147 describes (curveId pulled into the copy class, all saved regs rotate) **did not occur** at low register pressure — the copy simply doesn't coalesce here.

**Conclusion:** the OR no-op is a real lever ONLY when a same-value copy would otherwise **coalesce** (high register pressure / many competing webs), which is exactly the real-fn context. It is genuinely emergent and not isolable in a minimal TU — consistent with the playbook flagging it a context-specific "placeholder." The mechanism (distinct-web `|=` → surviving `or`/copy) is sound; its visibility depends on whether the merge it blocks would have happened.

---

## #31 / #40 / #50 / #21 — copy/call/control-flow forms
**#31 — whole-struct `*d=*s` vs field-by-field:** **CONFIRMED.**
- `*d=*s` (struct of 4 ints) → **batched** `lwz r5,0; lwz r0,4; stw r5,0; stw r0,4; ...` (two regs, load-pair then store-pair).
- field-by-field → strictly alternating `lwz r0,0; stw r0,0; lwz r0,4; stw r0,4; ...` (one reg).
The whole-struct form pairs loads/stores — use it to match a batched blob-copy.

**#40 — embedded-assign `if ((h=helper())!=0)`:** **INERT in simple isolation.** Byte-identical to `int h=helper(); if(h!=0)` — both keep the result in r3 and test directly (no spill/reload to avoid). The stw+lwz reload it eliminates only appears when `h` is live across additional code/calls that force a spill; not reproducible in a minimal return-immediately TU.

**#50 — nested `outer(inner(x), y)`:** **CONFIRMED.** `mr r31,r4(y); bl inner; mr r4,r31; bl outer` — `inner(x)`'s result **stays in r3** and is passed directly as outer's first arg (no spill of the intermediate). The other arg `y` is the one saved across the inner call.

**#21 — invert `if(c){A}else{B}` → `if(!c){B}else{A}`:** **CONFIRMED.** Inverting swaps the block layout (which call is fall-through vs out-of-line) AND flips the branch sense:
- `if(c) g(); else compute();` → `cmpwi; beq else; bl g; b; bl compute` (g first).
- `if(!c) compute(); else g();` → `cmpwi; bne else; bl compute; b; bl g` (compute first).

---

## Pragma levers — #95 / #98 / #110 / #113 / #128 / opt_strength_reduction
**All tested in the DLL domain. MWCC warns on illegal pragmas ("illegal #pragma"), so a no-warning = recognized.**

**#95 `#pragma optimization_level N` — CONFIRMED, accepted per-fn, and the unroll boundary is PRECISE:**
Speculative unrolling of a simple byte-sum loop (`for(i=0;i<n;i++) s+=garr[i];`), lbz count by level:
| O0 | O1 | O2 | O3 | O4 |
|----|----|----|----|----|
| 1  | 1  | 1  | 9  | 9  |
So **the ppc speculative unroller is gated at O3+ (O0/O1/O2 do NOT unroll; O3/O4 unroll by 8).** O1 also gives the simple creation-order loop with the trailing `mr r3,r0` copy that O4 folds (confirms **#110**: O4 copy-props the result into r3, O1 keeps the `mr`). NOTE: O1 ≠ O4 for this loop (O1 simpler, un-unrolled) — #110's "O1≈O4" is specifically about the chained-copy metric, not overall.

**opt_strength_reduction off — CONFIRMED functional (#96):** on the unrolled byte-sum loop it flips the walker form `lbz 0(r4)` (bumped pointer) → fixed displacements `lbz K(r5)` (single base). This is the #96 "folds the bumped walker to ascending displacements."

**#98 / #113 `opt_unroll_loops off`, `ppc_unroll_speculative off`, `ppc_unroll_factor_limit` — NUANCED (recognized but INERT against the speculative unroller):**
- `#pragma opt_unroll_loops off` → the byte-sum loop STILL unrolls (9 lbz). Confirms **#113**'s note that opt_unroll_loops doesn't touch the ppc speculative unroller. (#98's "functional" applies to classic count-based / RMW-halving unrolls, not the speculative one.)
- `#pragma ppc_unroll_speculative off` → still 9 lbz (tweaks addressing only). Recognized (no warning) but did not stop the unroll here.
- `#pragma ppc_unroll_factor_limit 2` (+ instructions_limit 512) → still 9 lbz; recognized but did NOT reduce the factor below 8. Matches #113's "the split strategy is not fully pragma-exposed; factor-optimal stays 8."
**Takeaway:** to suppress the speculative unroll, the reliable lever is **`#pragma optimization_level ≤2`**, NOT the unroll-specific pragmas (which are recognized but largely inert on it).

**#128 `#pragma opt_propagation off` — recognized; effect is context-specific.** A simple `s16 a=p[0]; r=a*Pi;` is byte-identical with/without it (the load already emits at decl, nothing to propagate). The documented load-reorder (#142) / named-pointer-not-folded (#141) effects require the propagation to actually fire (a value propagated into a later expression), which a minimal single-use TU doesn't trigger. The pragma is real and recognized; its visible effect is pressure/shape-dependent like the allocation levers.

---

## #12 / #39 — single-bit flag as a C bitfield → `li; rlwimi`
**VERDICT: CONFIRMED.** `struct { u8 a:1,b:1,c:1,pad:5; }`:
- `s->b = 1;` → `li r4,1; lbz r0; rlwimi r0,r4,6,25,25; stb` (the clean `li; rlwimi`).
- `s->b = v;` → `clrlwi r4,r4,24; lbz r0; rlwimi r0,r4,6,25,25; stb`.
The bitfield write is a load + `rlwimi` (insert) + store, exactly as #12 describes. Bit position is encoded in the rlwimi shift/mask.

## #5 / #34 — decl order sets stack offsets for address-taken locals (ISOLABLE)
**VERDICT: CONFIRMED.** Unlike register coloring (pressure-dependent), stack-offset ordering IS deterministic from declaration order.
- `int a,b,c;` then `take(&a,&b,&c)` → `&a=r1+16, &b=r1+12, &c=r1+8`.
- `int c,b,a;` then `take(&a,&b,&c)` → `&a=r1+8, &b=r1+12, &c=r1+16`.
**The FIRST-declared address-taken local gets the HIGHEST stack offset; they descend in decl order.** Confirms #34 ("first-declared gets the HIGHEST stack offset") and the #5 stack-home half. The call-arg order is unchanged (always `&a,&b,&c`); only the offsets swap with decl order. This is a reliable, isolable lever for matching stack-slot layout (#67 frame diagnosis).

---

## #69 / #63 / #17 / #105 / #44 — predicate, negate, guard-fold, narrow-param
**#69 — match the cmpwi IMMEDIATE:** **CONFIRMED.** `x<=0`→`cmpwi r3,0; bgt`; `x<1`→`cmpwi r3,1; bge`; `x>=1`→`cmpwi 1; blt`; `x>0`→`cmpwi 0; ble`. Semantically-equal int predicates produce different immediates+branches; spell the exact one.

**#63 — conditional negate:** **CONFIRMED.** `(x>=0)?x:-x` and `if(x>=0){}else{x=-x}` both → `fcmpo; cror eq,gt,eq; <branch>; fneg f1,f1` (in-place fneg). (The `>=` gives the cror; strict would drop it per #25.)

**#17 — fold guards into one `||`:** **CONFIRMED.** Two separate `if(a==0)return 0; if(b==0)return 0;` → two `cmpwi;bne;li r3,0` islands. `if(a==0||b==0)return 0;` → short-circuit with a SINGLE shared `li r3,0` block (`beq shared; cmpwi; bne body; shared: li 0`). The `||` merges the return-0 islands.

**#105 — K&R-style narrow param def:** **NUANCED (callee-identical).** `int f(flag,a) u8 flag; int a;` and `int f(u8 flag, int a)` produce **byte-identical** callee code (both `clrlwi r0,r3,24; add`). The K&R def is codegen-equivalent to a `u8` prototype for the callee; the only difference #105 targets is **caller-side** arg passing (callers pass raw int). Use it as a source-style match, not a callee-codegen lever.

**#44 — `*(u16*)&lbl` for clean `lhz`:** **CONFIRMED, with condition.** The deref forces a clean `lhz` ONLY when the global's declared type mismatches the u16 access:
- `s16 g; takeu16(g)` → `lha r0; clrlwi r3,r0,16`; `takeu16(*(u16*)&g)` → `lhz r3` (clean).
- `int g; takeu16((u16)g)` → `lwz r0; clrlwi`; `*(u16*)&g` → `lhz r3` (clean).
- `u16 g` (already u16) → BOTH forms give `lhz` (deref inert).
So `*(u16*)&lbl` is the lever when the global is declared wider/signed; redundant when it's already u16.

---

## #47 — sda21 vs far relocation, size-gated at 8 bytes
**VERDICT: CONFIRMED.** The extern DECLARATION SIZE controls which reloc MWCC emits (threshold = 8 bytes, default -sdata):
| extern decl | reloc |
|---|---|
| `extern int g_scalar;` | `lwz r3,0(0)` + `R_PPC_EMB_SDA21` (@sda21) |
| `extern u8 g_arr8[8];` (8B) | `R_PPC_EMB_SDA21` (@sda21) |
| `extern u8 g_arrbig[64];` (>8B) | `lis; R_PPC_ADDR16_HA/LO` (far) |
| `extern u8 g_incomplete[];` (incomplete) | `lis; ADDR16_HA/LO` (far) |
Confirms #47: small (scalar / ≤8B array) → @sda21; >8B array → far scalar form; incomplete `extern u8 lbl[]` forces the far form. (Whether @sda21 actually links depends on the real symbol's section, but the declared size is what selects the reloc MWCC emits.)

---

## #24 / #27 / #59 — FP precision, accumulation order, reassociation
**#24 — `f32 fn(f32)` not `double fn(double)`:** **CONFIRMED.** `f32 x*x` → `fmuls f1,f1,f1` (single); `double x*x` → `fmul f1,f1,f1` (double). The f32 signature keeps single-precision throughout, avoiding the double path + frsp narrowing.

**#27 — lead an accumulation with the unary-negated operand:** **CONFIRMED.**
- `-v[0] + k*v1` → `lfs f0; fneg f0,f0; fmadds f1,f1,f2,f0` (fneg + fmadds).
- `k*v1 - v[0]` → `lfs f0; fmsubs f1,f1,f2,f0` (fmsubs).
Leading with `-v[0]` gives the fneg+fmadds (preserves a reused product as the recipe notes); the subtraction form fuses to fmsubs.

**#59 — lift the leading term to defeat FP reassociation:** **NUANCED / INERT in tests.** Both `a[0]*n[0] + a[1]*n[1]` and the lifted `f32 yy=a[1]*n[1]; dot=yy+a[0]*n[0]` produce **IDENTICAL** code — MWCC's default reassociation ALREADY evaluates `a[1]*n[1]` first (`fmuls a1,n1; fmadds a0,n0`). Same for the 3-term dot. So the leading-term lift as spelled in the recipe matches MWCC's *default* order and changes nothing. The lift would only bite if the target wants a NON-default association and a *specific* (different) term is lifted to force it — I could not reproduce the stated "defeat reassociation" effect with the leading-term lift; MWCC reassociates the plain form to the same shape. Worth re-checking which term actually needs lifting in real cases.

---

## RECIPE DISCOVERIES (for dbgtricky's stuck dll_80136a40 fns)

### (A) clrlwi+rlwimi survival — fn_80138908 — SOLVED byte-identical
Target: `clrlwi r4,r4,24; lbz r0,88(r3); rlwimi r0,r4,6,25,25; stb r0,88(r3)`.
Producing C (nopeephole DLL flags, byte-exact):
```c
struct Foo { u8 pad[0x58]; u8 a:1; u8 b:1; u8 rest:6; };
void set(struct Foo *s, int v) { s->b = v; }   // bitfield dest + INT source
```
Two ingredients: (1) destination is a C **bitfield** → the `rlwimi` insert; (2) source value is **`int`** (wider than the u8 container) → the `clrlwi r4,r4,24` narrowing. A **u8** source DROPS the clrlwi (`set_u8` → just `lbz;rlwimi;stb`). New recipe (extends #12/#39).

### (B) clrlwi store-forward survival — fn_80136E00 — SOLVED
Target (byte-assembly into a u16 global via read-modify-write): `lbz r0; sth r0[gY]; clrlwi r3,r0,16; lbz r0,+1; slwi r0,8; or r0,r3,r0; clrlwi r4,r0,16; sth r4[gY]`.
The surviving store-forward `clrlwi r3,r0,16` (re-read of the just-stored u16 global, masked) is produced by an **explicit `(u16)` cast on the read-back**:
```c
gY = buf[0];
gY = (u16)gY | (buf[1] << 8);   // explicit (u16) on the read-back -> clrlwi survives
```
Discriminator (verified):
- `(u16)gY | ...` → store-forward `clrlwi r,r0,16` SURVIVES (matches target opcode sequence).
- `gY |= buf[1]<<8` / `gY = gY | ...` / `(buf[1]<<8) | gY` → clrlwi DROPPED (MWCC reuses buf[0], known u8, no mask).
- `volatile gY` → forces a real `lhz` RELOAD (not store-forward) — wrong direction.
- int-temp single-store → no read-back at all.
So the recipe hypothesis "store-value width/type" was WRONG; the lever is the **explicit `(u16)` cast forcing the store-forward read-back to materialize the u16 mask**. The recipe: for a read-modify-write that assembles into a narrow global, write `g = (u16)g | bits;` (explicit cast) — NOT `g |= bits;` — to keep the store-forward clrlwi. (Register names differ from target by allocation context; opcode sequence is identical.)

---

## ALLOCATOR REVERSE-ENGINEERING (incremental-ingredient method)

### #126 param-classing — RULE PINNED (type is irrelevant)
`mixed(int a, void *p, int b, void *q)` all live across a call → **a=r28, p=r29, b=r30, q=r31** — strict ARGUMENT-REGISTER order (r3→lowest saved, r4→next...). Pointers do NOT sort above ints.
**Concrete rule:** ALL incoming params occupy ONE pool, ordered by their argument register (= declaration order within the same type-class of ABI register). Param TYPE (pointer vs int) is irrelevant to saved-reg assignment. The "copy pool" (above params) is ONLY for single-def copies (call results / computed locals live across a call), confirmed by #108. A pointer param NEVER reclasses to the copy pool by being a pointer — #126's "kind-1 promotion" does not occur from the param type itself. (If it ever occurs it must be from the param's VALUE flowing into a surviving copy that outlives the param — a use-pattern effect, not a type effect.)

### #131 OR-noop — TRIGGER PINNED (pointer same-value coalesce)
Incremental isolation of when two same-value pointers survive as separate webs:
| source | result |
|---|---|
| `int *p1=&s->f[20]; *p1=1;` (one ptr, const offset, disp stores) | base+displacement, ONE web (`stw 80(r31)`) |
| `int *p1=&s->f[20]; int *p2=&s->f[20];` BOTH used, **no OR** | **COALESCE** — one web, all `stw 80(r31)` (two names fold to base+disp) |
| same + `p2 = (int*)((u32)p2 | (u32)p1);` (**OR-noop**) | **TWO webs**: `addi r30,r3,80` (real ptr) + `mr r31,r30` (surviving copy); stores split across r30/r31 |
| `int *p = &s->f[20]; use(p);` (passed to a call) | ONE real ptr web `addi r31,r3,80` (base consumed; can't be a disp) |
| `int *p = &s->f[n];` (runtime offset) | base + scaled-index, indexed `stwx` (two webs, but index not a combined ptr) |

**Concrete rule:** same-value pointer locals **coalesce by front-end value-numbering** into a single base+displacement form by default (even with two distinct names, both used). To force the target's "two overlapping same-value saved regs joined by an `mr`," you must give one a **distinct value-number** — the OR-noop `p2 |= p1` (the `|` node blocks the VN merge). The REQUIRED ingredients for the OR to fire: (1) two pointer locals of the same value, (2) BOTH used (both webs live), (3) the OR applied to one. This reproduces `addi rX,base,off` + `mr rY,rX` in isolation — exactly the #131 fn_801B3DE4 shape. (My earlier "inert in isolation" was the wrong scenario: I lacked the two-pointers-both-used displacement-coalesce baseline that the OR splits.)

**NOTE — two distinct "merge" phenomena both use the OR:**
1. POINTER coalesce (this section): two same-address pointers fold to base+disp; OR splits into two pointer webs. (#131 fn_801B3DE4.)
2. INTEGER class-pull (#147 curves_distFn15): `prev = curveId` pulls curveId into prev's copy-class (rotating the saved-reg pool); the OR keeps curveId in the PARAM class. Different mechanism (class membership, not coalesce-to-displacement), same OR tool.

### #108 within-class ORDER — RULE PINNED (decl-order is NOT universally inert)
Tested 3 same-class values live across a call, varying source kind and decl/init order:
| source | order rule | result |
|---|---|---|
| field-reads `int x=s->a; y=s->b; z=s->c;` (defs at top) | **DECL order DESCENDING** | x→r29, y→r28, z→r27 (first-declared → HIGHEST) |
| same, decl reversed `z,y,x` | follows decl | z→r29, y→r28, x→r27 |
| field-reads, **decl x,y,z but INIT order z,y,x** (#5 split) | **DECL sets reg, INIT sets emission** | a→r29,b→r28,c→r27 (SAME homes as decl order); only the lwz EMISSION order follows init |
| call-results `a=f();b=f();c=f();` (defs spread at call sites) | **creation order ASCENDING** | a→r29, b→r30, c→r31 (last-created → r31, matches #108) |

**CONCRETE RULE (refines/partly contradicts "#108/#147 decl-order is INERT"):**
- Within a class, **declaration/definition order DOES set the register home** — it is NOT universally inert.
- **DIRECTION depends on where the defs sit:** values all defined at function TOP (field reads / up-front loads) color **first-declared → HIGHEST** (descending r29,r28,r27); values defined at SPREAD points (call results) color **creation-order → ascending** (last → r31).
- **#5 confirmed exactly:** DECL position sets the register home; INIT position sets only the load-emission order — splitting `int x; ... x = e;` lets you place each independently.
- **Why "decl-order inert" was observed in real fns:** for CALL-RESULT/computed webs the creation order is PINNED by the computation structure (you can't reorder the calls), so decl-order reordering is inert there. For reorderable defs (field reads, up-front loads, decl/init split) decl-order is the lever. So the rule isn't "decl-order is inert" — it's "decl-order controls the home, but only when you can actually change the def order; call-pinned defs can't be reordered by decl alone."

This is the kind-2 within-class lever made concrete: to move a top-loaded value's saved reg, reorder its DECL among the other top-loaded values (descending); to move a call-result, you need #130/#107 web-decoupling because its creation point is pinned.

**Robustness check (decl vs field-offset):** `int x=s->c(off8); y=s->b(off4); z=s->a(off0);` → x→r29, y→r28, z→r27. Decl order rules (offset 8 → r29 highest, offset 0 → r27); field offset does NOT determine the home. So the field-read within-class home is purely DECL order (first→highest), independent of offset and init order.

### #130 web-decouple (block-scope temp) — needs a coalesce to break
Two call-results `a=compute(n); b=other(n);` → a→r30, b→r31 (creation order). Wrapping b's def in a block-scope temp `{int t=other(n); b=t;}` is **byte-identical** (the temp copy-propagates into b). So #130's block-temp decouple does NOT flip a call-result home in a clean 2-result case — there's no coalesce/merge to break here (the two results are already distinct webs in creation order). #130 fires only when the call-result is COALESCED with another web (e.g. a `(u16)`-masked call result sharing a reg) — the temp gives the call result its own short web, breaking that specific coalesce. In isolation without the coalesce, it's inert. (Same pattern as #131/#147: these are VN/coalesce-breakers; they need an actual merge present to act on.)

---

## ALLOCATOR MODEL — concrete rules (reverse-engineered, replaces "emergent")
The MWCC graph-coloring allocator is deterministic; here is what I've pinned by incremental isolation:
1. **CLASS membership** (which pool a value's saved reg comes from):
   - incoming PARAMS → one pool, ordered strictly by argument register (r3→lowest saved). Type (ptr/int) IRRELEVANT (#126 disproven).
   - single-def COPIES (call results, computed locals live across a call) → a pool ABOVE params (#108).
   - A param never reclasses to copy-pool by type; only by its VALUE flowing into a surviving copy (use-pattern).
2. **WITHIN-class ORDER** (which reg within the pool):
   - values defined at function TOP (field reads / up-front loads) → **DECL order, first→HIGHEST (descending)**, independent of field offset and init order. DECL-ORDER IS A LEVER here (contradicts "#108/#147 decl-order inert").
   - values defined at SPREAD points (call results) → **creation order, last→r31 (ascending)**. Decl-order is inert here ONLY because the calls pin creation order — you can't reorder them by decl.
   - INIT position (split from decl, #5) sets only the load/emit order, not the register home.
3. **COALESCE / same-value merge** (when two webs share a reg vs stay separate):
   - same-value POINTER locals coalesce to base+displacement by front-end value-numbering (even with two names). The OR-noop `p2|=p1` / a width-cast on a sub-operand (#134) / a kind-mismatch def (#132) gives one a distinct VN → splits into two webs + `mr`.
   - same-value INTEGER copies pull the source into the copy class (rotating the pool, #147); the OR keeps it in the param class.
   - all VN/coalesce-breakers (#130/#131/#132/#134/#147) need an actual coalesce/merge present to act on; inert without one.
4. **DIRECTION of the within-class order depends on def-site** (top=descending, spread=ascending) — this is the single most useful new rule for the kind-2 frontier: if the swapped values are top-loaded, reorder decls; if call-pinned, break the coalesce.

**DEFINITIVE decl-vs-load separation:** decl `x,y,z` but load order `y,x,z` (init order ≠ decl, not a clean reverse) → x→r29, y→r28, z→r27 = pure DECL order descending. Load order (y first, x second, z third) only set the lwz emission order; the REGISTER HOME followed DECL order exactly. So the within-class home for top-loaded values is DECL order, period — load/init order is independent.

### #147 integer class-pull — does NOT reproduce minimally (the one allocator effect still resisting isolation)
A faithful-but-reduced curves_distFn15 (`int prev=curveId; ...while(prev!=curveId && next)...` with float params x,y) → plain and with-OR are BYTE-IDENTICAL: curveId→r29 (param class), out→r30, prev→r31 (copy). The OR is INERT — curveId does NOT get pulled into prev's copy class here.
WHY it resists: curveId has INDEPENDENT uses (`prev != curveId`, `findNext(curveId)`) → its own web → stays in the param class, separate from prev. For curveId to "ride prev's multi-def web to the top class" (the #147 mechanism), the real fn's structure (the inlined binary search + segmentIntersect call + more competing webs) must change curveId's web so it coalesces with prev. The exact extra ingredient (what makes curveId coalesce into prev rather than staying a separate param web) is NOT yet isolated — it's the binary-search-inline / higher-pressure structure, not present in the minimal TU.
CONTRAST: the POINTER coalesce (#131) reproduces cleanly because two same-ADDRESS pointers genuinely have one value-number (front-end folds to displacement); the INTEGER curveId/prev are DIFFERENT webs (curveId is a param, prev is a multi-def loop var) that only merge under specific pressure. So #131 (pointer, clean VN-fold) and #147 (integer, pressure-dependent class-pull) are genuinely different difficulties — #131 is a single-statement lever, #147 needs the surrounding structure. This is the honest boundary: 4 of 5 allocator effects pinned to exact triggers; the #147 integer class-pull's pressure ingredient remains the open piece.

**#147 — trigger NOT YET pinned (the integer class-pull IS deterministic — DeepDive2 cracked it in the real fn — so the minimal trigger EXISTS; I just haven't added the right pressure ingredient yet).** FORMS EXPLORED SO FAR (each an INVITATION to re-run paired with the right neighbour, NOT a boundary): float params (fmr save-order), an inlined `static` binary search (keeps curveId in a volatile at entry), the multi-def loop — plain and with-OR were byte-identical in these. NEXT INGREDIENTS TO ADD (one at a time until it fires): 4-6 more competing saved-reg webs; the actual dead-init pattern; an outparam written across the loop; a phi reassignment of curveId; heavier pressure forcing curveId's GPR save PAST the float saves. The pull happens when curveId's web COALESCES into prev's multi-def web (riding it to the copy class) — so the ingredient is whatever makes curveId STOP having an independent web. Circle back with fresh eyes; it's "trigger not yet pinned," same as #108 was before I cracked it.

### #107/#66 name-vs-inline — BOUNDARY: only acts in the saved-reg-across-call context, not straight-line
Tested two re-derivable field values used twice each in a straight-line arithmetic expression (call-free): `(m->a*m->b)+(m->a+m->b*2)`. Naming `a`, naming `b`, or both-inline → the REGISTER assignment is IDENTICAL (a→r4, b→r0) in all three; naming only reorders which `lwz` is emitted first. The volatile registers follow the EXPRESSION DATA FLOW (b feeds the `slwi` → r0; a feeds the `mullw` → r4), not the naming.
So #107's "naming → colors higher / un-naming → lower" does NOT apply to straight-line volatile arithmetic — there the regs are pinned by data flow and naming is just load-order (#5). The #107 lever needs the value to be a SAVED-REG web live across a call (where the allocator has pool-ordering freedom) — that's where naming adds/removes it from the decl-ordered saved pool. In a single basic block with no call, the allocator has no freedom to exploit. Boundary pinned: #107 is a saved-reg-class lever (or volatile-across-a-call), inert in call-free straight-line code.

### #45 — FP const decl order → f31/f30/f29 — CONFIRMED, unifies with the GPR decl-order rule
3 FP consts `f32 c1=K1, c2=K2, c3=K3;` held in saved FP regs across a loop with a call, each used independently: decl order c1,c2,c3 → c1→f31, c2→f30, c3→f29 (first-declared → HIGHEST f31, descending). Reversing the decl order reverses the assignment. This is the SAME decl-order-descending rule as the GPR saved-reg class (#108 top-loaded) — so the allocator's within-class decl-order rule applies UNIFORMLY to both the GPR and FP saved-reg pools. (#45 "first = f31" confirmed; and it's not FP-special — it's the general decl-order home rule.)

### #81 / #82 FP-pair coloring — same structure as the GPR coalesce levers
**#81 launder** `*(f32*)&lbl` on one of a clamp constant's two references: in a simple clamp `if (v<lbl) v=lbl;` the constant CSEs to ONE `lfs f0` (used for both the fcmpo and the fmr-assign) — laundering one reference is BYTE-IDENTICAL (no split). So #81 is INERT in the simple isolable clamp; it only acts in the specific scenario where the target RELOADS the const (two loads) and the launder controls which FP reg each load lands in (the recipe's "target reloads the field before fcmpo" discriminator). Same shape as the GPR coalesce-breakers: needs an actual CSE/reload pair present to act on.

**FP-class summary (unified with GPR):**
- Saved-FP decl-order home: CLEAN isolable lever (#45), first-declared→f31, descending — identical to GPR.
- Volatile-FP in straight-line: follows expression DATA FLOW (like GPR volatiles); naming reorders loads only.
- FP-pair CSE/coalesce levers (#81 launder, #82 web-kind, #127 const-CSE): coalesce-dependent — inert in simple isolation, act only when the specific multi-load/CSE pair is present. Same structure and the same fix-family as the GPR coalesce levers (#130/#131).
So the entire kind-2 coloring frontier — GPR and FP — reduces to TWO rules: (1) reorderable/top-loaded webs → decl-order home (clean lever); (2) spread/CSE'd/call-pinned webs → break the coalesce (OR/launder/web-decouple, needs the merge present).

---

## #43 / #49 / #52 / #53 — quick isel confirmations
- **#43** comma-init `for(i=0,p=base;...)` → `li 0` + base setup. On a GLOBAL base it shows the #155 r0 detour (`lis;addi r0;mr`); on a local base it's the clean `li 0; mr p,base`. Consistent with #136/#155.
- **#49** switch fallthrough `case 0: case 1: case 2: g(); break;` → a RANGE CHECK (`cmpwi 3; ...; cmpwi 0; bl g`) for the shared body. CONFIRMED.
- **#52** ternary clamp `*p = (a>=b)?b:a;` → `cmpw r4,r5; blt; mr r5,r4; clrlwi r0,r5,24; stb` (the mr;clrlwi;stb store shape). CONFIRMED.
- **#53** `*p -= (s16)big;` → `extsh` on the subtrahend (same as #20c, confirmed there).

---

## #84 — embedded-assign-in-call-arg MISCOMPILE — CONFIRMED (real MWCC bug, safety-critical)
The ⚠️ caveat "embedded-assign in a call arg whose value is REUSED by later args MISCOMPILES" is a REAL MWCC codegen bug, reproduced:
```c
f32 t;
f4((t = lbl), 0.0f, t, t * 2.0f);   // t assigned in arg1, reused in arg3 & arg4
```
→ `lfs f1,lbl` (arg1=t); `lfs f2,@5` (arg2); `lfs f0,@6` (the 2.0); `fmuls f4,f0,f3` — **f3 (arg3=t) is NEVER materialized** (garbage), and arg4 = `2.0 * f3(garbage)`. MWCC fails to propagate the embedded-assigned value to args 3/4.
Control `f32 t=lbl; f4(t,0.0f,t,t*2.0f);` is CORRECT: `fmr f3,f1` (copies t to arg3) + `fmuls f4,f0,f1` (uses t). 
TELL: MWCC emits a warning "variable 't' is not initialized before being used" — that warning on an embedded-assign call is the miscompile fingerprint. **Never embed an assign in a call arg whose value is read by a later arg of the SAME call.** (Note: #128's `f(.., (pp=&s.x), &s.y, ..)` is safe because the assigned value is reused by a LATER identical CALL, not a later ARG — different, and that one works.)

---

## CHAIN: speculative unroller (#113) × (u16) store-forward RMW (recipe B)
The recipe-(B) `(u16)g | bits` store-forward pattern, placed in a loop that the O3+ speculative unroller expands: the unrolled body keeps the read-back value in a REGISTER (`or r0,r8,r0`) instead of the straight-line store-forward `clrlwi r,r0,16`. So the unroller's register management ALTERS the store-forward materialization — the before-`or` clrlwi (the recipe-B mask) is absent in the unrolled form (the after-`or` u16-narrow clrlwi remains). EMERGENT: recipe (B)'s store-forward mask is a STRAIGHT-LINE phenomenon; an unrolled loop holds the value in a reg and drops the per-iteration store-forward clrlwi. So for a target with the store-forward masks in a LOOP, you'd need to suppress unrolling (opt_level≤2, #113) for the masks to reappear — the two levers interact.

## #94 — MWCC value-tracks stack addresses — CONFIRMED (base claim)
`struct S s; s.a=1; sink(); s.b=2; use(&s.a);` → both stores stay `stw K(r1)` (frame displacement) ACROSS the call — MWCC tracks that `s` lives at r1+8, never materializing a saved-reg pointer. The address `&s.a` is re-derived fresh (`addi r3,r1,8`) only at the point it's needed as a call arg. Confirms #94's "value-tracks stack addresses through everything" — accesses are r1+disp, the pointer materializes lazily. (The "dies at a call for CSE-temp copies/phis" sub-clause needs a pointer-copy/phi scenario to exercise; the base tracking is solid and underlies the #93/#94/#116 stack-builder family.)

---
*Session coverage: ~62 recipes validated + full allocator model + 2 recipe discoveries + #84 miscompile safety confirmation. Durable record above; see COVERAGE INDEX at top.*

---

## AUDIO / MSL domain (GC/1.2.5n) — domain split verified
The audio domain uses the **GC/1.2.5n** compiler (178 units; vs GC/2.0 for the 782 main-lib units). Audio synth units (synth_volume etc.) compile `-O4,p -inline auto -fp_contract on -lang=c` (peephole/scheduling ON — no nopeephole). Verified:
- The 1.2.5n compiler works via `build/compilers/GC/1.2.5n/mwcceppc.exe`.
- Core ISEL recipes TRANSFER across compiler versions: #25 FP compare (`if (a>=b)` → `fcmpo; cror eq,gt,eq`) is identical in the audio domain.
- **#100 config CONFIRMED**: the -O0 MSL math units (e_sqrt) compile with EXACTLY `-O0 -opt peephole -inline auto -use_lmw_stmw on -schedule off` as the recipe states (k_sin is a variant: `-O0 -opt functions -inline auto -schedule off`). `-use_lmw_stmw on` gives the lmw/stmw bulk-save prologue; -O0 gives register-class saved regs. The recipe's `msl_math_o0_cflags` description is accurate.
- DOMAIN RULE: peephole ON in audio means the dot-fusion (#1) IS active there — never wrap audio TUs with peephole-off (regresses), matching the playbook. The 5 compiler versions: GC/2.0 (main, 782), GC/1.2.5n (audio/dolphin, 178), GC/1.3 (MSL_C, 49), plus GC/1.1/1.2.5/1.3.2 stragglers.

## #78 — triple-multiply regroup — CONFIRMED
`A * lbl_K * (f32)n` → `fmuls (A*lbl); fmuls (·*conv)` (left-flattened, A*lbl first). `A * (lbl_K * (f32)n)` → `fmuls (lbl*conv); fmuls (A*·)` (groups const×conversion first). Explicit parenthesization controls the fmul order — MWCC RESPECTS FP multiply grouping. **Contrast with #59:** MWCC reassociated the dot-product SUM regardless of grouping (the lift was inert), but it respects MULTIPLY parens here. So FP grouping is a reliable lever for `*` (write `A*(lbl*conv)` to match a target that groups const×conversion), but NOT for `+` (sums get reassociated to MWCC's canonical order). Use `*`-grouping freely; for `+` you need a different lever (statement-split with a named intermediate, #104).

---

## HUNTER CASE (1) SOLVED — #37 pre-read-vs-inline store-forward clrlwi (dbgtricky fn_80136E00)
dbgtricky's Xpos site (lines 1111-1114) drops the store-forward `clrlwi` the target wants:
```c
// CURRENT (drops the clrlwi):
debugPrintXpos = p[2];
c0 = p[3]; p += 4;
debugPrintXpos |= c0 << 8;        // sth r4; lbz r0,3; slwi  -- NO clrlwi
// FIX (produces clrlwi r4,r0,16, matches target 6a8):
debugPrintXpos = p[2];
debugPrintXpos = (u16)debugPrintXpos | (p[3] << 8);   // sth r0; clrlwi r4,r0,16; lbz r0,3  -- MATCHES
p += 4;
```
**MECHANISM (answers "why does a pre-read operand suppress the mask"):** the store-forward `clrlwi rX,r0,16` serves DOUBLE DUTY — it's the `(u16)` read-back mask AND a preserve-copy of the just-stored value before the next byte load clobbers r0. It needs BOTH ingredients:
1. **INLINE operand** (`p[3]`, not a pre-read `c0`): the inline byte loads into r0 AFTER the store, CLOBBERING the stored value → MWCC must preserve it first via `clrlwi r4,r0,16`. A pre-read `c0` sits in its own register, so the stored value is never clobbered → no preserve-copy → no clrlwi.
2. **Explicit `(u16)` cast** (not `|=`): forces the read-back mask (the `|=` lets MWCC prove buf[2] is a u8 < 0x10000 and skip it).
So "casting all sites misplaces it" because casting the PRE-READ form adds the mask but without the clobber it lands in the wrong place. The fix is to INLINE the operand AND cast — recover the target's interleaved `lbz/sth/clrlwi/lbz` byte-assembly shape. (Also: `p += 4` goes AFTER the last inline `p[3]`, matching the target's `addi r31,r31,4` at 6b0.) This refines recipe (B): the store-forward clrlwi needs an inline (clobbering) operand, not just the cast.

---

## HUNTER CASE (2) — induction counter-vs-walker coloring RULE PINNED (#136 frontier)
Minimal strength-reduced loop with counter `i` + walker `e`, both live across a call. The counter↔walker relative register home is set by the **SOURCE FORM**:
| form | counter | walker |
|---|---|---|
| **body-computed** `for(i=0;i<N;i++){ T *e=&base[i]; ... }` | r30 (LOWER) | r31 (HIGHER) |
| **comma-init** `for(i=0, e=base; i<N; e++, i++){ ... }` | **r31 (HIGHER)** | r30 (LOWER) |
Verified clean on a LOCAL/param base (no #155 detour): body-computed → walker=r31/counter=r30; comma-init → counter=r31/walker=r30. **The increment order (`e++,i++` vs `i++,e++`) is INERT** — only the body-vs-comma form flips the pair.

**THE RULE:** to make the COUNTER color HIGHER than the walker → comma-init form (`for(i=0, p=base; ...)`); to make the WALKER higher → body-computed (`p=&base[i]` inside the loop). The decl-order lever (#108) is correctly INERT here because these are strength-reduced induction webs, not top-loaded defs — but the SOURCE FORM (comma vs body) IS the lever, analogous to decl-order for the induction class.
**GLOBAL-base caveat:** comma-init on a GLOBAL base adds the #155 `lis;addi r0;mr` detour (the explicit `e=glob` init routes through r0). So on a global base, comma-init is NOT clean — use body-computed (walker-higher) or, to raise the counter without the detour, the #136(b) counter-0-reuse or #143 typed-index. (waterfx func05's pools are GLOBAL bases → it's already body-computed; to flip i below the walker there it needs the #136(b) reuse, not comma-init.)
**ACTIONABLE for waterfx/dbgtricky:** check the target's counter-vs-walker order, then pick body (walker-high) vs comma (counter-high). LOCAL base → either form clean. GLOBAL base → body-form is clean for walker-high; counter-high needs #136(b)/#143.

### Hunter case 2b — in-loop const-load POSITION (dbgtricky fn_80137DF8 clear-loop, partial)
The 2D framebuffer clear stores a value `0x1080` 8× per inner iter. Retail wants `li r0,4224` FIRST in the body (in-body per-iter, value in r0). Findings:
- **literal `0x1080` repeated** → `li rX,4224` IN the body (per-iter, matches retail's in-body), but emitted AFTER the address setup (`add r7,...`) because a store `*p=v` computes the address p before the value v. Value lands in r6 (ours) not r0.
- **named local `u16 val=0x1080`** → HOISTED to the preheader (loop-invariant, loaded once) — does NOT match (retail reloads in-body).
So keep the LITERAL (in-body) form, NOT a named local. The OPEN sub-piece (invitation): getting the const load FIRST in the body + into r0 — the store's address-before-value emission order puts it after the address setup. NEXT to try: a store idiom where the value is computed/used before the address (so the `li` emits first); or check whether the value-first emission is a consequence of the value/col/row register assignment (a 3-way rotation value=r0/col=r5/row=r4 retail vs r3/r6/r7 ours) — pin which web the allocator creates first. The unrolled 8-store body's reg assignment is the real driver; the const-position is likely a symptom. A clean source form exists — re-derive from the asm.

### Hunter 2 — multi-walker creation-order detail (waterfx func05)
With a counter `i` + N walkers (pool + i*0x40 vtx + i*0x20 desc, all strength-reduced), the **counter is created FIRST** (`li rLow,0` in the preheader, before the walker bases) → it gets the LOWEST reg of the induction group; the walkers (created after, in materialization order) ascend (r29,r30,r31...). So in the body-computed form the counter is naturally BELOW all walkers.
For waterfx func05 (retail i=r25, ours r26 — counter is LOW in BOTH): the counter/walker RELATIVE order is already correct (counter lowest); the off-by-one absolute reg = ONE extra/fewer competing web in ours (a neighbor web-count difference), NOT the body-vs-comma swap. That's the #155/neighbor-perturbation territory — needs func05's full target asm to pin which web differs (e.g. a hoisted const, an extra saved address, a dropped/added local). The body-vs-comma form lever (above) is for the cases where the counter and a walker are genuinely SWAPPED (counter above a walker); for a uniform off-by-one it's a web-count match.

### Hunter 2b — dbgtricky clear-loop FULLY ANALYZED (target asm read)
Read the target (fn_80137DF8 @1440-14e4) and dbgtricky's source (lines 1262-1283). Key facts:
- `debugDrawFrameBuffer` is `extern u16*` (a POINTER global) → re-read via `lwz` before EACH of the 8 stores (the target does NOT CSE it; dbgtricky's per-statement `fbrow = (char*)FB + (row+off)` reproduces this correctly).
- **value 0x1080 must be a LITERAL** (NOT a named local — a named local does NOT hoist here because the pointer re-reads keep the body complex, BUT also doesn't fix the position). The literal + pointer-FB form is STRUCTURALLY correct.
- **2-store version → value in r0** (loaded first); **8-store version → value in r4** (the 8 FB re-reads take r0 first, pushing the value off). dbgtricky's reported value=r3 is this same pressure effect (exact reg varies with web count).
- ROOT of the residual: it's a VOLATILE coloring of col/row/value. Target: row=r4, col=r5 (LOW volatiles), value=r0, fb-temp=r6. Ours: col/row land HIGH (r6/r7), so the value spills off r0 to r3/r4, and the FB read (first store's address) emits before the value (`li` after `lwz`), losing the "value first" position.
- FORMS EXPLORED (invitations, not boundaries): literal value (correct, keeps it in-body), named local at body-top (inert on position — still after the FB read), 2-vs-8 store count (changes the value reg). NEXT INGREDIENTS to try: force col/row into LOW volatiles (they're the outer/inner loop accumulators — try different decl/init order, or compute the store address so col/row are evaluated into low regs); make the value evaluate BEFORE the first store's address (a store idiom where the value operand is materialized first); check if writing the 8 stores as a small inner loop over the 8 row-offsets (re-rolled) changes the col/row coloring. The literal + pointer-FB structure is RIGHT; the residual is the col/row/value volatile-coloring rotation (#66). A clean source form exists — re-derive from the target's low-reg col/row assignment.

### Hunter 2b — VALUE-FIRST POSITION lever FOUND (folded address)
The **folded-address store** `*(u16*)((char*)FB + row + off + col) = 0x1080;` (NO `fbrow` temp) materializes the VALUE FIRST (`li rX,4224` BEFORE the `lwz FB`) — fixing the "value-first" position the target wants. The `fbrow`-temp form (`fbrow=FB+(row+off); *(fbrow+col)=v`) emits the FB read first (value after).
TRADE-OFF: the folded form combines col+row into ONE index (`add r4,col,row; sthx val,FB,r4`), whereas the target keeps **col as the sthx index and row added to FB** (`add FB,row; sthx val,col,FB+row`). So:
- fbrow-temp form → target's address structure (col-index, row-on-FB) but value-AFTER.
- folded form → value-FIRST but combined col+row index.
The TARGET wants BOTH (value-first AND col-as-index). The hybrid to find: a form that materializes the value before the address yet keeps the `FB+row` / col-index split. NEXT to try: assign value to a register/var in a statement BEFORE the fbrow line but mark it non-hoistable (e.g. derive it from a loop var with a zero-effect op), OR a store macro that evaluates the RHS before the LHS address. This + the col/row→low-volatile coloring are the two remaining knobs; the folded form proves the value-first position IS reachable from source. (A clean form giving both exists — re-derive from the target's exact `li value; lwz FB; add row; sthx value,col,FB` sequence.)

### HUNTER CASE (1) — MECHANISM CORRECTED (my earlier "inline-required" claim was WRONG)
Re-tested with the lead's 4 variants + dbgtricky's exact `p+=4`-between shape (DLL O4, `extern u16 gX`):
- `gX=p[2]; c0=p[3]; p+=4; gX=(u16)gX|(c0<<8);` (pre-read + cast + p+=4) → clrlwi PRESENT, correct position
- `gX=p[2]; c0=p[3]; gX=(u16)gX|(c0<<8);` (pre-read + cast, no p+=4) → clrlwi PRESENT
- `gX=p[2]; gX=(u16)gX|(p[3]<<8);` (inline + cast) → clrlwi PRESENT
- **ALL THREE BYTE-IDENTICAL.** And `gX|=c0<<8` (no cast) → clrlwi DROPPED.
**CORRECTED MECHANISM: the `(u16)` CAST is the SOLE discriminator** — `|=` lets MWCC prove the just-stored value fits u16 and drop the redundant mask; the explicit `(u16)` cast forces the store-forward read-back to materialize the clrlwi. Inline-vs-pre-read AND the `p+=4` position are INERT in isolation. My earlier "needs an inline clobbering operand" was a misattribution (I compared `|=`+pre-read vs cast+inline, conflating two changes). The FIX for dbgtricky is still correct — just change `|=` to `= (u16)... |` (the inline is incidental, not required). dbgtricky's in-tree "casting all sites misplaces it" is therefore a SEPARATE context effect (register pressure / adjacent sites), NOT the inline — to be investigated in-tree, but the cast-core recipe stands.

---

## VALUE-0 copy-affinity (Minimap_release) — clean baseline achieved, trigger NOT YET pinned + #136(b) discrepancy
**Minimap_release** reproduced faithfully (full fn with the 2 textureFree calls + the loop): single diff vs retail is `li r31,0` (null, ours) vs `mr r31,r29` (null = copy of counter i's 0, retail). Everything else byte-matches (i=r29, slots=r28 @sda21, null=r31).
- **#47 confirmation:** `lbl_803DBBC8` is an 8-byte `.sdata` array → sized `extern void* lbl_803DBBC8[2]` gives `li r28,0` @sda21 (matches retail); an incomplete `[]` gives far `lis;addi` AND swaps i/slots regs. (waterfx already uses `[2]`, so this is already correct in-tree — it's why the current build is a clean single-diff.)
- **FORMS EXPLORED for the `mr` reuse (ALL give `li r31,0`, none produce the copy — invitations to re-run with the right neighbour):** init order (null first/last), decl order (null first), `null=(void*)(u32)i` (const-folds to li), `u32 null=0`, opt_level 0/1/2/4, peephole on AND off, scheduling on/off, **#136(b) DIRECT SUBSCRIPT `lbl_803DBBC8[(u8)i]=NUL`** (still `li r31,0`, NOT the claimed `mr`), alias-lit `slots[i]=NUL`, simplest `for(i;i<2;i++)arr[i]=NUL` (unrolls → li r0 reused), with-call non-unrolled (3 separate li).
- **⚠️ #136(b) DISCREPANCY (flag for the lead):** #136(b) claims `arr[i]=NULL` direct subscript of a standalone global array → `li r29,0; mr r30,r29; stw` (the counter-0 reuse). I could NOT reproduce that `mr` in ANY form, including the exact direct-subscript shape. Either #136(b)'s trigger needs an additional ingredient not in the bare direct-subscript, or it's over-claimed. The dll_4e example that "confirmed" it should be re-examined — maybe its loop unrolled (where the counter-0 naturally feeds the stores) or had a different liveness.
- NEXT INGREDIENTS to add (one at a time): heavier register pressure (more live webs forcing a copy over a fresh li); the value stored to MULTIPLE arrays per iter (reuse across stores); a 2nd use of the counter's 0 that creates affinity; examine dll_4e's actual asm to see what structural feature triggers its `mr` (then transplant). The `mr rNull,rCounter` IS deterministic (retail has it) — the ingredient exists, not yet found.

### VALUE-0 copy-affinity — DEFINITIVE: not a LOCAL source lever (whole-function-context effect)
Corrected: #136(b) IS real — dll_4e's optionsMenu_applyGameplaySetting target HAS `li r29,0; mr r30,r29` (counter-0 reuse) in its `lbl_803A87D0[i]=NULL` walker loop (my earlier grep missed it). BUT:
- I reproduced dll_4e's EXACT loop structure in isolation (FAR array `gFarArr[64]`, plain `int i`, direct subscript `arr[i]=NULL`, count 8, the 2 leading calls) → STILL `li r31,0`, NOT `mr`. Same compiler (GC/2.0), same effective flags (nopeephole).
- Same for Minimap_release: faithful full-fn repro (T=C, @sda21 array, indexed) → `li`, while retail has `mr`. SAME SOURCE → different output.
- Forms that ALL give `li` (never `mr`): every init/decl order, type, (void*)i, opt 0-4, peephole on/off, scheduling on/off, walker vs indexed, FAR vs @sda21 array, plain-int vs (u8) index, literal-NULL vs null-var, count 2 vs 8.
**CONCLUSION:** the `mr rNull,rCounter` value-0 reuse is NOT determined by the loop's LOCAL source form — my isolated repro of dll_4e's exact loop gives `li` while dll_4e's real (large, switch-embedded) function gives `mr`. So the trigger is in the WHOLE-FUNCTION register-allocation STATE (what's allocated/live before the loop across the full function), OR a compiler-build nuance. For dll_4e (large fn) it's plausibly the surrounding-context allocation state; for Minimap (small 47-instr fn, same source → li vs retail mr) it points more at a compiler-build difference.
**NEXT (the real lever-hunt, redirected):** (a) compile the FULL dll_4e function (with its whole switch + all cases) minimally and check if the `mr` appears — if YES, the surrounding cases' register usage is the ingredient (isolate which); if NO, it's a compiler-build nuance. (b) For Minimap specifically: since same-source→li-vs-mr in a tiny fn, diff the EXACT current-build .o vs retail to confirm no other difference, then suspect a mwcc patch-level behavior. This redirects the hunt AWAY from local loop-form tweaks (proven inert) toward whole-function context / build config — saving the hunters from re-tweaking the loop.

### VALUE-0 copy-affinity — FINAL (current builds of BOTH dll_4e and Minimap lack the mr)
Verified the CURRENT in-tree build of dll_4e optionsMenu_applyGameplaySetting: counter=r28, array=r29, null=`li r30,0` — vs RETAIL counter=r29, array=r28, null=`mr r30,r29`. So the current build has the counter/array SWAPPED **and** null `li`-not-`mr`. Minimap's current build has counter/slots CORRECT (i=r29, slots=r28) but null `li`-not-`mr`.
**So the `mr rNull,rCounter` is a register-ALLOCATION decision the current GC/2.0 compiler does NOT make for these fns — neither dll_4e nor Minimap reproduces it from the checked-in source, and no source form I tried produces it.** It is downstream of where the counter lands: in dll_4e the counter is mis-placed too (the #136 induction-coloring issue); in Minimap the counter is correctly r29 but the compiler still rematerializes null instead of copying the live 0. This is the copy-vs-rematerialize choice for a constant 0 when an equal value is live in a register — a within-allocation decision, not a source spelling.
**ACTIONABLE for the hunters:** this `li→mr` value-0 diff is NOT a clean-source lever with the current compiler (proven: every source form gives `li`; both current builds give `li`). Don't keep tweaking the loop source for it. The realistic options: (1) accept the 1-instr `li`-vs-`mr` residual (Minimap is otherwise byte-perfect, T=C=47); (2) the #131/#147-style explicit copy hack (`null = (void*)(u32)i`-class) — but that const-folds here too, so even the hack fails; (3) treat it as a known compiler-allocation gap. For dll_4e, fixing the counter/array placement (the #136 induction coloring) is the higher-value target and may or may not cascade to the null. NET: the value-0 reuse across these 3 fns is a compiler register-allocation behavior, not a missing source construct — redirect effort to the structural diffs around it.

### func05 stride-walker coloring + META: a CLASS of induction/value-0 residuals are current≠retail-on-SAME-SOURCE
**func05 finding:** the strength-reduced stride walkers color by **CALL-ARG ORDER** (the arg passed first → lower reg), confirmed: passing the stride-32 arg first → stride32→r29 (lower); pre-computing the walker in a source statement first is INERT (only the CALL position matters). BUT retail's func05 passes vtx(stride64) FIRST (same source as ours) yet colors stride32 LOWER (by stride VALUE). So ours orders by arg/creation order, retail by stride magnitude — on IDENTICAL source.
**META-FINDING (3 functions, consistent):** value-0 copy (Minimap + dll_4e) AND func05 stride-ordering all show the CURRENT GC/2.0 build producing a DIFFERENT register-allocation than retail FROM THE SAME CHECKED-IN SOURCE:
- Minimap: counter correct, null `li` (ours) vs `mr`-copy (retail).
- dll_4e: counter/array swapped + null `li` (ours, current build) vs counter-correct + `mr` (retail).
- func05: stride walkers by arg-order (ours) vs stride-value (retail).
In each, source levers can CHANGE ours (arg reorder flips func05; #47 fixed Minimap's slots) but CANNOT reproduce retail's choice when retail's source matches ours. This strongly indicates a **COMPILER-BUILD allocator difference** (the mwcc that built retail orders induction webs by stride-magnitude and reuses live 0s via copy; the repo's GC/2.0 orders by creation/arg-order and rematerializes). 
**RECOMMENDATION:** these specific residuals (induction stride-order, value-0 copy) are likely NOT source-fixable with the current compiler — recommend the team verify whether a different mwcc patch-level (or a known allocator flag) matches retail's induction/copy behavior, rather than the hunters grinding source levers (proven to change-but-not-match). The body-vs-comma form (#136) IS a real lever for the cases where the SOURCE form genuinely differs; but the same-source current≠retail cases (these 3) point at the compiler build. This is the highest-value redirect from this investigation.

### CORRECTION to the META-finding above (walking back the "compiler-build" overreach)
The "compiler-build allocator difference" framing above is TOO STRONG and likely WRONG — it contradicts the decomp premise (the repo's mwcc IS the retail compiler; right source + this compiler = byte-match). So current≠retail on the checked-in source means the SOURCE isn't yet exactly retail's, NOT that the compiler differs. The honest finding: the `mr rNull,rCounter` value-0 reuse and the func05 stride-by-value order ARE source-determined; I tried ~16 forms without finding the producing one, and dll_4e's checked-in source ALSO doesn't produce its retail `mr` (dll_4e is a WIP non-match on that loop too) — so the right source form is STILL OUT THERE, not yet pinned. These are LIVE targets, not compiler limits.
What I DID pin (keep these):
- func05 stride walkers color by CALL-ARG order (arg1→lower reg); arg-reorder flips them. Retail orders by stride-value despite vtx-first → the producing source must create the stride-32 walker first in a way the CALL respects (arg-eval order, #137 callee-param-reorder is the candidate to test against the real drawFn_8005cf8c signature — register-neutral).
- Minimap value-0: the counter is correctly r29; the open piece is the copy-vs-rematerialize of the live 0 (NEXT: examine what surrounding-context construct in retail makes MWCC prefer the copy — e.g. a 2nd consumer of the 0, a different null lifetime, the exact decl/use pattern; the #131-OR analog `null |= (u32)i` for the integer case is untried here and worth a shot even as a placeholder).
NEXT INGREDIENTS (the real hunt, not abandoned): for func05, test #137 reorder of drawFn_8005cf8c's vtx/desc params (register-neutral) so the stride-32 walker is the first call arg → should land it lower per the pinned arg-order rule. For value-0, test the integer #131-OR (`null = NULL; null |= (u32)i;`) and a 2nd-use-of-the-0 construct.

---

## ★ VALUE-0 COPY-AFFINITY — LEVER FOUND: CHAINED ASSIGNMENT `nullVal = counter = 0` (oracle + A/B verified)
**The source construct that makes MWCC reuse the counter's just-set 0 via `mr` (instead of a fresh `li 0`) is the CHAINED ASSIGNMENT tying the null/zero value to the counter's init:**
```c
for (nullVal = i = 0; (u8)i < count; i++) { ...; arr[i] = (void*)nullVal; }   // or  nullVal = i = 0;
```
**HOW I FOUND IT (in-repo oracle method, the right method):** scanned current-build DLL .o's for `li rC,0; mr rN,rC; store rN` → found `tumbleweedbush_update` (dll_00D1) emitting `li r29,0(j); mr r30,r29(nullVal)`. Its source: `for (nullVal = j = 0; (u8)j < state->pieceCount; j++) ... *slot = nullVal;`. 
**A/B PROOF (real matched fn, real flags):** un-chaining tumbleweed (`for (j=0, nullVal=0; ...)` separate) → the `mr` DISAPPEARS (just `li r29,0`, nullVal folded). Re-chaining → `mr r30,r29` returns. So the chained assign is DEFINITIVELY the lever.
**MECHANISM:** `nullVal = j = 0` literally means `j = 0` (`li`) then `nullVal = j` (`mr` copy) — the chain creates a genuine copy of the counter, and that copy SURVIVES copy-propagation under register pressure (it does NOT fold to `li 0` the way the OR / `(void*)i` const-tricks do — those are const-0-inert, confirmed). The counter being live + incremented keeps its value non-constant over its lifetime, so the copy isn't trivially foldable.
**PRESSURE-GATING (the nuance):** in a VERY low-pressure fn (minimal Minimap_release repro, 47 instrs) the chained copy still folds to `li` at O4 — copy-prop collapses it when there's no register pressure. In normal-pressure fns (tumbleweed, and presumably groundanimator_update / clear-loop / the other 5+ value-0 sites) the copy survives. So: USE the chained `nullVal = counter = 0` at every value-0 site; it produces the `mr` wherever pressure allows (most real fns). For a tiny fn where it still folds, that site is genuinely low-pressure and may need an extra interfering live range — but the construct is the lever.
**RECIPE (general, high-leverage — gates 5+ fns):** when retail reuses a loop counter's 0 via `mr rNull,rCounter` to store NULL/0 in the loop, CHAIN the stored-value's init with the counter: `for (val = i = 0; ...)`. This is the #51 chained-assign applied to the counter+null pair. NOT the OR (#131/#147 OR is const-0-inert here). ⚠️ Verify in-tree per site (pressure-gated).

### Value-0 chained-assign — gating refinement (the lever is proven; the fold-vs-survive ingredient is being narrowed)
The chained `nullVal = counter = 0` is A/B-PROVEN as the lever in tumbleweed (real fn). But it FOLDS to `li` (copy-prop collapses `nullVal=counter` when counter=0 is provable) in low-context repros. Ruled OUT as the gating factor (still folds with each): +2/+4/+6 interfering live ints across the loop; the two-loop structure (first process loop + second null loop, matching tumbleweed); int-vs-u8 counter; for-vs-while. So the fold-vs-survive ingredient is something else in tumbleweed's FULL context (likely the specific saved-reg interference graph / a competing web that forces the allocator to coalesce the copy rather than rematerialize). NEXT to bisect: copy tumbleweed, progressively DELETE surrounding code (the first loop body, the hit-detection block, locals) until the mr flips to li — that delta IS the gating ingredient. (I have tumbleweed building both ways in /tmp; the bisection is the concrete next step.) The LEVER stands: apply `val = counter = 0` at value-0 sites and verify per-site in-tree — it works where the context supports it (tumbleweed proves real fns do); the gating just isn't a 1-line isolation yet.

## ★★ VALUE-0 COPY-AFFINITY — COMPLETE LEVER: chained-assign + `#pragma optimization_level 2`
The full mechanism (both ingredients REQUIRED, all verified):
1. **CHAINED assign** `null = counter = 0` (ties the stored-0 to the counter). Necessary: separate `counter=0; null=NULL` → `li` always.
2. **`#pragma optimization_level 2`** (or ≤2). Necessary: at O4 (default) copy-propagation FOLDS the chained `null=counter` back to `li 0` (it proves counter=0); at O2 the copy SURVIVES as `mr rNull,rCounter`.
PROOF: (a) ORACLE — tumbleweedbush_update uses BOTH: `#pragma optimization_level 2` (line 153) + `for (nullVal = j = 0; ...)`, emitting `li r29,0; mr r30,r29`. (b) A/B — un-chaining tumbleweed kills the mr. (c) REAL Minimap file — `#pragma optimization_level 2` + chained `null=i=0` → `mr r28,r30` PRESENT; same file at O4 (default) + chained → folds to `li`; O2 + SEPARATE null=NULL → `li` (no copy to keep). So BOTH knobs are load-bearing.
**THE RECIPE:** value-0 counter-0-reuse (`mr rNull,rCounter`) needs (1) the chained `val = counter = 0` AND (2) the fn at `#pragma optimization_level 2`. CRITICAL CONTEXT: many DLL fns are ALREADY wrapped in `#pragma optimization_level 2` regions (tumbleweed, lots of obj DLLs) — at THOSE sites the chained assign alone produces the mr cleanly. For a fn currently at O4-default, you need to ADD `#pragma optimization_level 2` — which ALSO switches the whole fn to O2 creation-order allocation (#95), so verify the WHOLE fn still matches (it may shift other regs). This is why value-0 "wouldn't reproduce" earlier — I was testing at O4; the trigger is the O2 copy-prop behavior. NOT the OR (const-0-inert), NOT spelling — it's chained-assign × opt-level.
**ACTIONABLE for the hunters (gates 5+ value-0 fns):** check each value-0 site's opt-level region. If it's in (or should be in) a `#pragma optimization_level 2` block, write `for (val = counter = 0; ...)` (chained) → the `mr` appears. If it's O4, the value-0 mr likely means the fn belongs in an O2 region (check the surrounding pragma structure / sibling fns).

### Value-0 REFINEMENT — the mr is achievable at O4 too (NOT strictly opt_level-2-gated)
Checked opt-level regions of the oracle mr-functions: tumbleweedbush_update is at `#pragma optimization_level 2`, BUT **PlayControl (dll_3e) and fn_801343CC (warpstoneui) have the mr-reuse at O4-DEFAULT** (no opt pragma). So the `mr rNull/rVal,rCounter` IS achievable at O4 — my "needs opt_level 2" was too strong. fn_801343CC's structure: `k = 0; for (n = 0; n < count; n++) { ... uses k and n ... }` — TWO 0-valued counter-like webs (k, n) where MWCC copies one's 0 into the other at O4. So there are (at least) TWO paths to the value-0 `mr`:
1. **chained `val = counter = 0` at opt_level 2** (tumbleweed) — the chain survives O2 copy-prop.
2. **two 0-valued COUNTER-LIKE webs at O4** (fn_801343CC) — both live, used in arithmetic/incremented; MWCC coalesces one's 0 into the other even at O4. (A pure stored-constant null, NOT counter-like, folds at O4 — which is why Minimap's `null=NULL` doesn't trigger it at O4: null isn't counter-like.)
So the value-0 mr is a copy-coalescing decision gated by BOTH the opt level AND whether the 0-web is "counter-like" (live, mutated) vs a pure stored constant. For Minimap, the open question is whether retail's `null` was counter-like or whether Minimap is O2 — needs the per-fn check (read the retail fn's opt-region + whether null is mutated). The LEVER family is pinned (chained-assign and/or opt_level-2 and/or counter-like-0); the exact per-site recipe is: match the oracle whose structure is closest (O4-two-counter vs O2-chained).

### Value-0 — COMPLETE characterization (heterogeneous mr mechanisms; Minimap sub-case open)
The oracle mr-functions use DIFFERENT mechanisms (all "reuse a 0 via mr" but distinct triggers):
1. **tumbleweed** (O2): `nullVal = j = 0` chained → `li j,0; mr nullVal,j`. Counter's 0 reused for a stored const. Needs O2 (O4 folds). A/B proven.
2. **fn_801343CC** (O4): `k=0; for(n=0;...)` — TWO counter-like webs (both `cmpw`'d to bound, incremented), one copies the other's 0. Counter↔counter coalesce at O4.
3. **PlayControl** (O4): `li r3,0; mr r29,r3` — a 0 materialized in a VOLATILE (r3, e.g. as/after a call arg) then copied to a SAVED reg for later cross-call use. Volatile→saved 0-copy.
So "value-0 copy-affinity" is NOT one rule — it's the allocator choosing copy-over-rematerialize for a 0, triggered by: chained-assign+O2 (stored const), OR two counter-like 0-webs (O4), OR volatile-0-needs-saving (O4).
**MINIMAP SUB-CASE (honest open):** Minimap is O4-shaped (current build matches retail except the 1 mr; regs i=r29/slots=r28/null=r31 match retail, only li-vs-mr differs). null reuses the counter's 0 (tumbleweed-pattern) but Minimap is O4 (tumbleweed needs O2), and null is a pure stored const (not counter-like, so the fn_801343CC O4 path doesn't fit). My O2+chained gives the mr but SHIFTS all regs (wrong). So the exact Minimap recipe is the one sub-case not yet matched: O4 + counter-0-reused-for-a-stored-const-null keeping the O4 regs. LEADS for waterfx: (a) check if retail Minimap is genuinely O2 (objdiff the whole fn at O2+chained+decl-order to land i=r29); (b) check if retail's `null` is actually counter-like (incremented/compared somewhere) making it the fn_801343CC path; (c) a volatile-0-to-saved construct (PlayControl path) — e.g. pass 0 to the Obj_FreeObject-adjacent code so null is materialized in a volatile first. The mechanism family is pinned; this is the last per-fn fitting step.

---

## Induction/reg-reuse master key — clear-loop (fn_80137DF8) has NO ORACLE (unique pattern)
Applied the oracle method (which cracked value-0) to the clear-loop's coalesced-in-place-add + indexed-store pattern (`lwz fb; add fb,fb,row; sthx value,col,fb`):
- Scanned ALL current-build DLL .o's for `add rB,rB,rIdx` followed by an indexed store (`sthx/stwx`) using rB → **ZERO hits**. No matched DLL fn has this form.
- Scanned ALL retail (target) DLL .o's for the same → **exactly ONE hit: fn_80137DF8 itself** (the clear-loop). So the coalesced-fb+row-in-place + col-indexed-sthx pattern is UNIQUE to the clear-loop in the whole DLL set.
**CONCLUSION:** there is no oracle to read a source form from — the clear-loop's exact coalesce-with-indexed-store shape appears nowhere else. So this is NOT an oracle-method target (unlike value-0, which tumbleweed exemplified). It's a genuinely novel opt_propagation construct to discover.
**THE TENSION (dbgtricky's 19-build characterization, confirmed precise):** fbrow must be NAMED for the col-separate `sthx` (#141 opt_propagation-off keeps it un-folded) — but the named fbrow BLOCKS the fb-load/fbrow coalesce (separate webs → fresh reg → col/row pushed to r6/r7, value off r0). Inlining fbrow → MWCC reassociates `fb+(row+col)` (coalesce happens but col+row merge → loses the col-separate sthx). opt_propagation ON shifts coloring closer (+0.13, proving reachable) but breaks 2 sthx→sth. So: opt_prop-off = sthx but no coalesce; opt_prop-on = coalesce but 2 wrong sth. The clean form needs BOTH (coalesced fb+row in-place AND col-separate sthx).
**LEADS (no oracle, so derive fresh):** (a) a form where fbrow is a SHORT-LIVED named var assigned DIRECTLY from the just-loaded fb (so MWCC coalesces the copy) but the col index stays separate — try `fbrow = (u16*)debugDrawFrameBuffer; fbrow = (u16*)((char*)fbrow + row);` (two statements, fbrow reused) under opt_prop-off; (b) the #112/#128 grouping (`(char*)(fb) + row` grouped so row coalesces onto fb's reg but col stays the sthx index); (c) since opt_prop-on gives the coalesce, find the per-store spelling that keeps sthx under opt_prop-on (the 2 sth→sthx are the #141 residual — a named row-pointer recomputed per store might hold sthx even with opt_prop on). This is the genuinely-open frontier of the induction family; func05 (call-arg-order, separate lever) and findTaggedNodeWindow are RELATED but not identical — the "single unifying reg-reuse lever" may be looser than hoped (func05's is arg-order, clear-loop's is the opt_prop coalesce tension).

### ★ CLEAR-LOOP induction pin — LEVER FOUND (derived fresh, no oracle): two-statement fbrow reuse
The coalesce-vs-sthx tension breaks with a **TWO-STATEMENT fbrow assignment** (split the base+offset):
```c
#pragma opt_propagation off
fbrow = (u16*)debugDrawFrameBuffer;                  // load base into fbrow's reg
fbrow = (u16*)((char*)fbrow + row);                  // IN-PLACE add (reuses the base-load reg)
*(u16*)((char*)fbrow + col) = 0x1080;                // col-separate sthx KEPT
```
vs the current single-expr `fbrow = (u16*)((char*)FB + row)` which uses a FRESH reg every store.
EVIDENCE (probe, opt_propagation off): the two-statement form emits `lwz r7,fb; add r7,r7,r4(row); sthx r0,r7,r3(col)` — the fb-load reg r7 is REUSED for the in-place `add r7,r7,r4` (the COALESCE) AND the indexed `sthx` is kept (col separate). The single-expr form emits `lwz r0,fb; add r8,r0,r4; sthx r7,r8,r3` — FRESH r8 (no coalesce). So the two-statement reuse is the lever that gives BOTH the coalesce AND the sthx — exactly the tension dbgtricky's 19 builds were stuck on.
CAVEAT: in the probe the FIRST store still used a fresh reg (`lwz r0; add r7,r0,r4`) while stores 2+ are in-place (`lwz r7; add r7,r7,r4`); the first-store reg + the sthx operand order (col-first vs fbrow-first, commutative) are minor residuals to tune in-tree. The CORE lever (two-statement fbrow → in-place coalesce + sthx) is found. dbgtricky should A/B this against the clear-loop's 8 stores in-tree (opt_propagation off) and check the value/col/row coloring shifts to r0/r5/r4. This is the induction/reg-reuse master-key form for the 2D-store case (derived without an oracle, since none exists).

---

## INDUCTION / REG-REUSE FAMILY — consolidated (it's a FAMILY of related levers, not ONE unifying lever)
The "force the strength-reduced/derived pointer to reuse/coalesce with the base-load reg" master key resolves into SEVERAL related-but-distinct levers, each matched to its sub-shape:
1. **Counter-vs-walker order (#136, PINNED):** body-computed `T *e=&base[i]; ...` → walker HIGHER, counter lower; comma-init `for(i=0,e=base;...)` → counter HIGHER, walker lower. Increment-order inert. **findTaggedNodeWindow** (`for(slot=0;slot<5;slot++) ...node+slot*4+0x1C...`) is this case — body-computed slot loop; pick body-vs-comma to match the target's slot-vs-walker direction.
2. **2D-store in-place coalesce (clear-loop, FOUND, no oracle):** split `fbrow = base + offset` into TWO statements `fbrow = base; fbrow = (T*)((char*)fbrow + offset);` → the in-place add reuses the base-load reg (coalesce) while opt_propagation-off keeps the col-separate sthx.
3. **Call-arg-stride order (func05, CHARACTERIZED):** strength-reduced walkers passed as CALL ARGS color by ARG-EVAL order (arg1→lower reg), NOT stride value or source statement order. To match a target that orders by stride value, the arg order (or #137 callee-param-reorder) must put the smaller-stride arg first.
4. **Global-base walker detour (#143/#155):** index form `glob[i]` → direct `addi rWalker` (vs pointer-walk's r0+mr detour). Different from the above (it's base materialization, not reg-reuse).
So there is NO single "reg-reuse" lever — it's 4 distinct sub-levers by shape. The common THEME (a derived pointer's register relationship to its base) is real, but the SOURCE construct differs per shape. Match the sub-shape, apply the matching lever. (Method note: clear-loop had NO oracle and was derived fresh; #136/func05 were pinned by incremental isolation; value-0's chained-assign came from the tumbleweed oracle. The oracle method works when a matched fn shares the exact shape; when none does, derive from the asm.)

### Value-0 O4 ACCUMULATOR variant (fn_801932C8) — actionable in-tree lead (isolation folds, real-fn pressure may not)
fn_801932C8 is proven O4 (waterfx: O2 regresses 94.9→89.9). At O4, the accumulator `fallOff`'s 0-COPIES already match (`htOff = fallOff` → `mr`). The RESIDUAL is specifically the FIELD store `state->entryCount = 0` (and a pre-loop local-0 store) re-materializing `li` instead of reusing fallOff's saved-reg 0 (`stb r23,42(r30)` in retail).
- ISOLATION RESULT: `state->entryCount = fallOff` (store the accumulator, =0) AND the chain `state->entryCount = fallOff = 0` BOTH const-fold to `li 0; stb r0` in a minimal repro (MWCC proves fallOff=0). So in low-pressure isolation neither reuses fallOff.
- BUT the real fn already reuses fallOff for `htOff` (mr at O4) — so fallOff IS kept in a saved reg with its 0 live; the field store's fold is the only gap. The deciding factor is the REAL-FN register pressure (many competing 0-webs / the saved-reg interference graph), which a minimal repro lacks — same situation as the core value-0 before the opt_level discovery (isolation folded, real fn didn't).
- ACTIONABLE IN-TREE LEAD for waterfx (the authority is in-tree, not /tmp): A/B `state->entryCount = fallOff;` (store the accumulator var, not literal 0) vs the literal — in the REAL fn where fallOff is already saved+reused for htOff, the field store may pick up fallOff's reg (the fold that fires in isolation may NOT fire under the real pressure). Also try chaining `state->entryCount = fallOff = 0`. If both still `li` in-tree, the next ingredient is making fallOff NON-provably-0 at the store point (a path where fallOff could be nonzero before entryCount=0), which forces the reuse. No exact-match oracle exists for the const-0-field-store-reuses-accumulator shape (the O4 oracles found store the counter ITSELF to a field, a different pattern). This is the last hard sub-case of the value-0 family — reachable (retail has it at O4), gated by real-fn pressure.

---

## #92 guarded-return b-over-b (fn_80138920) — analysis + leads
`if (v < 48) { if (v >= 41) return 0; }` — the OUTER `if(v<48)` + first-guard + Sfx-guard ALL already match (b-over-b `b<cond> skip; b return`). The ONLY diff is the INNER `if(v>=41) return 0`:
- TARGET: `cmpwi 41; bge 1f3c; b 1f44` + `1f3c: b 1f80(return)` — bge to an INLINE return block (1f3c, laid out between the inner check and the continue 1f44), with `b 1f44` skipping it. The b-over-b.
- CURRENT/ours: `cmpwi 41; blt 414(skip); b 450(return)` — INVERTED (blt skips, return is the fall-through). Folds away the inline return block.
SOURCE VARIATIONS TESTED (all fold to the inverted `blt`, NONE reproduce the target's inline-return b-over-b): nested `if(v<48){if(v>=41)return 0;}` (current), combined `if(v<48 && v>=41)return 0`, inner else-return `if(v<41){}else return 0`. The `goto ret0` shared-return form FLIPS the inner to `bge` (positive) but to the SHARED far return (no intermediate block) AND breaks the other guards (bne-direct instead of their matching beq;b) — wrong.
THE EXACT TARGET FORM = the inner `return 0` laid out as an INLINE block (1f3c) reached by the positive `bge`, with `b continue` jumping over it. This is the #159/#21 block-layout family (keep the return block inline/out-of-line per the target). LEADS to try in-tree (dbgtricky): (a) an inner inline `return 0` with a trailing statement after the outer-if that forces the continue to be a distinct `b` target (so the return block lands inline); (b) `#pragma` block-ordering — none found yet; (c) the #33 form `if(v<48){ if(v>=41){return 0;} else {} }` with the else forcing layout; (d) since the first/Sfx guards already produce the b-over-b with INLINE `return 0`, match the inner to their exact structure — the inner differs only by being NESTED, so un-nesting it (`if (v < 48 && v >= 41) { return 0; }` as a single block reached by a combined positive test) and checking the layout. The b-over-b IS reachable (the sibling guards have it); the inner's nesting is what folds it — find the un-nested form that keeps the inline return.

### ★ VALUE-0 variant (c) — DERIVED form: store/copy the ACCUMULATOR var (not literal 0)
Variant (c) = "reuse an incremented-not-compared accumulator's 0 for a pre-loop const-0 store + a field-0 store, in an O4 fn." Oracle confirmed reproducible: scanned O4-default DLL fns for `li acc,0; mr X,acc` where acc is incremented-not-compared → MANY hits (CameraModeNpcSpeak_init, Effect20_func04, the groundanimator SIBLING fn_801923F8, etc.). So the construct exists at O4.
**THE DERIVED FORM:** store/copy the ACCUMULATOR VARIABLE (which currently holds 0), NOT a literal 0:
- field store: `state->entryCount = fallOff;`  (NOT `state->entryCount = 0;`)
- pre-loop local store: `htOff = fallOff;`  (already in the source — and waterfx confirmed it ALREADY gives `mr` at O4)
**WHY it survives at O4 (the mechanism):** `htOff = fallOff` survives as `mr` (waterfx confirmed) while `entryCount = 0` re-materializes `li` — the difference is ONLY that one stores the accumulator VAR and the other a literal. Copy-prop CANNOT fold `x = fallOff` to `x = 0` because fallOff is an ACCUMULATOR (incremented later → non-constant over its lifetime → MWCC won't substitute its current value), so the copy stays. A literal `0` is a fresh constant (li). So the fix is uniform: every place that stores/copies 0 AND should reuse fallOff's reg → write `= fallOff` (the accumulator), not `= 0`. (The sibling htOff=fallOff is the in-fn proof it works; entryCount just needs the same spelling.)
**ISOLATION CAVEAT:** in a MINIMAL repro `= fallOff` STILL folds (low pressure → copy-prop folds even the accumulator copy). It survives only where the accumulator is heavily-used/saved (real fns). So this is a real-fn form (verify in-tree), proven by the in-fn sibling htOff. **MINIMAP (tiny fn) sub-case:** there the counter i IS used (compared+incremented) yet `null = i` STILL folds at that small size — so the tiniest-fn counter-0-reuse is the residual edge of variant (c); the accumulator-var form is the lever for normal-size fns (fn_801932C8, groundanimator_update). RECIPE for #136(b) variant (c): "store the incremented accumulator VAR (=0), not a literal 0, to reuse its register — the accumulator's non-constant lifetime keeps copy-prop from folding the copy (in a fn where it's saved/heavily-used)."

### ⚠️ CORRECTION to variant (c) "DERIVED" form — `= fallOff` FOLDS in isolation (NOT verified)
Walking back the previous entry's "derived form" claim: I tested `state->entryCount = fallOff` (accumulator var) vs `= 0` (literal) with fallOff heavily-used (saved across a call, incremented) — BOTH emit `stb r0,42(r3)` (fresh r0, NO reuse of fallOff's reg). So `= fallOff` does NOT reproduce the field-store reuse even at higher pressure in isolation. The "non-constant accumulator copy survives" reasoning does NOT hold for a MEMORY/FIELD store (MWCC materializes the store-value 0 in a volatile r0 regardless of the accumulator being in a saved reg). So `= fallOff` is NOT the confirmed lever — my mechanism reasoning was wrong for the field-store case.
HONEST STATE: variant (c) IS reproducible (O4 oracles exist: CameraModeNpcSpeak_init, Effect20_func04, groundanimator sibling fn_801923F8 — all O4-default with `li acc,0; mr X,acc`, acc incremented-not-compared). But I have NOT yet extracted the producing construct — the obvious `= accumulator` spelling folds. NEXT (the right step, not yet done): READ an oracle's actual SOURCE line that produces the surviving `mr X,acc` / field-reuse (map the asm offset to the source statement) — do NOT assume the spelling. The waterfx in-tree report that `htOff = fallOff` survives is the in-fn proof, but the FIELD-store reuse spelling is still unknown. (This is the genuinely-open variant-(c) piece; the COPY `htOff=fallOff` works in-tree per waterfx, the const-0 FIELD-STORE reuse spelling is unfound — oracle-read it.)

## #126 debugPrintDraw param-copy-class — diagnosed via the pinned #108 rule + lever direction
debugPrintDraw(int ctx), O2 fn. Target: `pass` is r29 (saved, `stw r29,0(0)` to gDebugFixedWidthMode/gDebugDrawPass). Ours: the ctx-int-param-copy steals r29, pass lands lower.
DIAGNOSIS (applying my pinned #108 class-pooling rule): the **ctx-copy is a SINGLE-DEF copy** (ctx param copied ONCE to a saved reg to survive the `fn_80136E00(ctx)` loop calls) → single-def copies → TOP pool (r31/r29 region). **`pass` is MULTI-DEF** (`pass = 0;` then later `pass = 1;`) → multi-def webs DESCEND in creation order → BELOW the single-def ctx-copy. So #108 predicts exactly ours (ctx-copy high, pass low). Retail has pass high → retail's `pass` must be classed ABOVE the ctx-copy.
LEVER DIRECTION (from #108 class rules — to lift pass above the ctx-copy, either raise pass's class or lower the ctx-copy's):
1. **Make `pass` SINGLE-DEF per phase:** the `pass=0` (first loop) and `pass=1` (second loop) are separate phases — split into TWO single-def locals (`int passA = 0; ...; int passB = 1;`), each a single-def copy → TOP pool, outranking nothing-multi-def. The first-loop passA (single-def, used across the first loop) would then class with the copies (high), potentially landing r29.
2. **#130 web-decouple the ctx-copy:** split the ctx preservation so the ctx-copy is created LATER or as a different web kind, dropping it below pass (e.g. re-spell `fn_80136E00(ctx, p)` so ctx isn't a long-lived single-def copy — though as a param it can't be re-derived, a block-scope temp around the call might re-class it).
3. **opt_level is already 2** (lead confirmed) so creation-order alloc is active — the within-class order between the single-def ctx-copy and multi-def pass is the exact #108 frontier. The cleanest is (1): make pass single-def (per-phase locals) so it joins the copy class at the top.
This is the within-class-order frontier; the #108 rule DIAGNOSES it (single-def-copy outranks multi-def), and the lever is to change pass's def-multiplicity (single-def per phase) to raise its class. dbgtricky A/Bs in-tree.

### #126 debugPrintDraw — CORRECTION: it's the VALUE-0/const-keep-vs-rematerialize family, not single-def-vs-multi-def
Reproduced in isolation: with multi-def `pass` (0 then 1) stored to globals + ctx copied for the loop call, MWCC emits `mr r30,r3(ctx-copy); ...; li r0,0(pass); stw r0,gMode` — **pass=0 is RE-MATERIALIZED as `li r0` (a volatile literal), NOT kept in a saved reg at all.** ctx-copy=r30, p=r31. So my single-def-vs-multi-def diagnosis was WRONG: the issue is NOT class-order between pass and ctx-copy — it's that pass (a CONST 0/1) is RE-MATERIALIZED (li) in ours where retail KEEPS it in a saved reg (r29) and reuses it for the gMode/gPass stores.
So #126 debugPrintDraw is the SAME family as VALUE-0: a constant (pass=0) that retail keeps live in a saved reg (reused for stores) vs ours re-materializing it. The lever is the same open one — make MWCC keep the const in a saved reg instead of re-materializing. The value-0 levers (chained-assign+opt_level for counter-tied consts; the field-store-reuse spelling) apply, but pass isn't counter-tied, so it's the standalone-const-kept-in-saved-reg sub-case (same as the value-0 field-store residual). HONEST: the single-def-per-phase split (my prior entry) does NOT fix this (pass re-materializes regardless of def count); the real lever is the const-keep-in-saved-reg one, which is the OPEN value-0 frontier. So #126, the value-0 field-store, and the Minimap tiny-fn case are ALL the same open nut: "force MWCC to keep/reuse a saved-reg 0 instead of re-materializing li." The chained+opt_level cracked the COUNTER-tied version; the standalone-const version is the remaining frontier.

### Standalone-const-0-keep — precisely BOUNDED (the open value-0 frontier)
Exhaustively tested what makes MWCC KEEP a const-0 in a saved reg (vs re-materialize `li`):
- 8 clustered `field=0` stores → STILL `li r0` (volatile), reused — NOT a saved reg. Count is NOT the trigger.
- 0 used before AND after a call → `li r0` re-materialized AFTER the call (NOT kept in a saved reg). Survive-a-call is NOT the trigger.
So MWCC RE-MATERIALIZES constant 0s by default (li is cheaper than a saved-reg save/restore), regardless of store count or call-crossing. Retail keeps the value-0 residuals' 0s in saved regs anyway — the trigger for that keep is NEITHER count NOR survive-a-call (both ruled out). 
SUMMARY of the whole value-0/const-reuse family (rigorously characterized this session):
- **COUNTER-TIED const-0 reuse** (the stored-0 ties to an incremented counter/accumulator's web) → SOLVED: chained `val=counter=0` + opt_level≤2 (or counter-like at O4). Oracle (tumbleweed) + A/B proven.
- **STANDALONE const-0 kept in a saved reg** (#126 pass, fn_801932C8 field-store, Minimap null — not tied to a live counter) → OPEN. Ruled out: chained (folds), `=accumulator` (folds), opt_level, store-count, survive-a-call, single-vs-multi-def. The trigger MWCC uses to keep a standalone const-0 in a saved reg (e.g. andross_init's r31=0) is NOT any of these — it's a deeper allocation decision (possibly the const competing with the specific saved-reg interference graph / a value-number that makes it non-rematerializable). This is the single highest-value open nut; it gates the standalone-const half of the value-0 family. NEXT (fresh eyes): read andross_init's EXACT source-to-asm mapping for its r31=0 (4 stores, no copy) — what makes THAT one keep r31 when 8-stores-in-isolation doesn't? The delta is the trigger. (andross_init source: clustered `state->field = 0` inits — but isolation of that exact shape re-materializes, so andross has an extra ingredient: map its asm offset 0x1e0 stb r31 back to the source line and diff vs my isolation.)

### #126 / standalone-const-keep — oracle hunt exhausted (no clean oracle; precisely-bounded live target)
Final #126 (debugPrintDraw) investigation: pass=0 is loop-invariant (stored `gDebugDrawPass = pass` inside the loop across `fn_80136E00` calls), used in BOTH loops (0 then 1). Retail HOISTS it to saved r29 (`li r29,0`, kept across both loops, reused for the stores); ours re-materializes `li r0` (volatile) each iter — it's the #121 LICM-hoist decision for an INTEGER loop-invariant const, the standalone-const-keep nut.
ORACLE HUNT (exhaustive, no clean oracle found): scanned matched DLL .o's for `li rSaved,0` + loop(bl + back-edge) + `stw rSaved,global` (the exact loop-invariant-const-0-in-saved-reg shape) → candidates (expgfx_updateResourceEntries, andross_init, fn_8029xxxx) are ALL LOOSE matches on reading: the saved-reg-0 is either a loop COUNTER, or an OUTSIDE-loop store, or not actually a hoisted loop-invariant const. So a clean matched oracle for "a loop-invariant const-0 HOISTED to a saved reg and stored INSIDE a loop across calls" was NOT located in the DLL set.
ISOLATION (exhaustive): MWCC RE-MATERIALIZES integer constants by default — 8 stores, across-call, multi-loop all re-materialize `li r0`; it does NOT hoist an int-const-0 to a saved reg. The named-var `pass` folds to the constant. So neither the obvious source forms nor an oracle yield the hoist.
CONCLUSION (live target, precisely bounded): the standalone-const-0-saved-reg-hoist (= #126 pass = value-0 field-store = Minimap null, the unified nut) is GENUINELY OPEN — retail has it (achievable, NOT a cap), but it needs EITHER a matched-fn oracle that shows an int loop-invariant-const-0 hoisted to a saved reg (none found in DLL — try the broader game/track/baddie units or MP4), OR a fresh-eyes reframe of what makes MWCC's LICM hoist an int const to a saved reg vs re-materialize (the #121 family, but for int not FP). This is the single highest-value open allocation nut, characterized to the exact mechanism (LICM-hoist-vs-rematerialize for an int loop-invariant const-0), parked for a fresh-eyes return with the full rule-out list so no re-tread.

---

## ★★ STANDALONE-CONST-KEEP CRACKED — NAMED const-0 var + O4 → saved-reg web (oracle: dbstealerworm zero var)
The unified standalone-const-keep nut (#126 pass / value-0 field-store / Minimap null = "keep a const-0 in a saved reg vs re-materialize li") is CRACKED for the IN-LOOP case:
**ORACLE (dbstealerworm_stateHandlerA07, dll_0242):** uses a NAMED variable `int zero; ... zero = 0; ... vec[2] = zero; vec[0] = zero;` (NOT a literal 0). MWCC keeps `zero` in a SAVED reg (r31) reused for the stores across calls.
**LEVER (confirmed in isolation, A/B):** use a NAMED single-def `int zero = 0;` variable for const-0 stores INSIDE a loop, instead of a literal `0`:
- named var → `li r31,0` (SAVED reg), reused via `stw r31` across the in-loop call. (named_zero, global_zero, one_store, minimap_shape all confirmed.)
- literal `0` → `li r0,0` (VOLATILE), re-materialized per use.
**★ DISCRIMINATOR = OPT-LEVEL, and it's OPPOSITE the counter-tied value-0:**
- STANDALONE-const-keep: **O4 KEEPS** the named var in a saved reg; **O2 FOLDS** it to volatile `li r0`. (Verified: sd_o4 → r31 saved; sd2 with `#pragma optimization_level 2` → r0 volatile; md_o4 multi-def pass → r31 saved.)
- COUNTER-TIED value-0 (chained val=counter=0): O2 KEEPS the chain; O4 FOLDS it.
So the two value-0 halves want OPPOSITE opt-levels. This is the key structural fact.
**#126 debugPrintDraw APPLICATION:** it is `#pragma optimization_level 2` (line 1503) → that O2 is WHY pass folds to volatile r0. At O4 the named pass lands in saved r31 (matching retail's r29). So the fix is to get pass materialized at O4 — either drop/scope the O2 pragma for this fn (A/B the full %; O2 may've been chosen for other parts), or find an O2-compatible keep. dbgtricky A/Bs the O4-vs-O2 tradeoff in-tree.
**SCOPE / still-open:** the lever works for IN-LOOP const-0 stores. The PRE-LOOP FIELD store (value-0 variant-c entryCount=0) FOLDS even at O4 with a named var (field_zero: `stb r0`) — that pre-loop-field sub-case remains open. Minimap: at O4 named null → `li r31,0` (saved, close) but retail wants `mr r31,r29` (counter-copy = the COUNTER-TIED chain, which needs O2) → the O4-vs-O2 tension is exactly why Minimap is the hard case (it wants the counter-copy form at an O4-shaped size).

### Standalone-const-keep — COMPLETE recipe + O2-impossibility (empirically confirmed)
Full truth table (isolation, A/B):
- **O4 + NAMED var** (`int zero=0; ...store zero`) → `li rSaved,0` (SAVED reg, kept/reused). ✓ THE KEEP.
- O4 + literal `0` → `li r0,0` (volatile, re-materialized). ✗
- O2 + named var → `li r0,0` (volatile). ✗
- O2 + literal → volatile. ✗
So the keep needs BOTH O4 AND a named single-def variable. 
**O2-IMPOSSIBILITY (empirically confirmed):** scanned EVERY DLL unit with `#pragma optimization_level 2` for a const-0 kept in a saved reg (2+ stores, across a call, not a counter) → ZERO hits. MWCC at O2 (creation-order alloc) ALWAYS re-materializes a standalone const-0; only O4 (graph-coloring) keeps it in a saved reg. This is a hard rule, not a gap.
**#126 debugPrintDraw — the fix is now precise:** it's `#pragma optimization_level 2` (line 1503), so pass CANNOT be kept in a saved reg at O2 (re-materializes — exactly what we see). Retail keeps pass in r29 (saved = O4 behavior). Therefore retail's debugPrintDraw is O4 for this, and the `#pragma optimization_level 2` is the BLOCKER. FIX: A/B removing/raising the pragma to O4 + naming pass — at O4 the named pass lands in saved r31 (verified isolation). The O2 pragma was likely a prior-agent choice for other parts; dbgtricky weighs the full-fn tradeoff (if O4 keeps pass AND holds the rest → drop the pragma).
**ORACLE confirmed O4:** dbstealerworm_stateHandlerA07 (dll_0242, no pragma = O4-default) — `int zero; zero=0; vec[2]=zero; vec[0]=zero` keeps zero in r31. The clean producing-C for the whole family's IN-LOOP O4 case.
**REMAINING (precisely bounded):** (1) value-0 field-store (entryCount=0, PRE-LOOP) folds even at O4+named (the pre-loop position, not in-loop — pre-loop stores don't get the saved-reg web); (2) Minimap wants `mr` (counter-copy = the O2 chain) at an O4-shaped size — the O4(keep)-vs-O2(chain) tension. These two are the genuine edges; the IN-LOOP O4 standalone-keep is SOLVED (named var).

### ⚠️⚠️ CORRECTION (5th) — named-var lever is INERT; the discriminator is PURELY OPT-LEVEL
The team-lead's probe correctly contradicted my "named→saved, literal→volatile" claim. I MISREAD my own A/B: literal_zero is BYTE-IDENTICAL to named_zero (both `li r31,0` SAVED + `stw r31` for the stores) — my grep caught `stw r0,36(r1)` (the mflr prologue stack-save at offset 36), NOT the array store, and I wrongly read it as "literal folds to volatile." NAMING A CONST-0 VARIABLE IS INERT.
THE REAL DISCRIMINATOR (re-verified clean, `for(i=0;i<n;i++){g(); garr[i]=0; g();}` literal both ways):
- **O4**: const-0 store value KEPT in a SAVED reg (`stwx r31`, r31=const-0 reused across iters). ✓ keep.
- **O2**: const-0 store value RE-MATERIALIZED in a VOLATILE each iter (`li r4,0; stwx r4`); the saved reg r31 is the COUNTER instead. ✗ re-materialize.
So the keep-vs-rematerialize of a loop-const-0 is PURELY OPT-LEVEL (O4 graph-coloring keeps it; O2 creation-order re-materializes), INDEPENDENT of naming. This matches the lead's probe (O4 named==literal==saved) AND my #126 finding (debugPrintDraw=O2→folds).
#126 FIX STILL STANDS (and is cleaner): debugPrintDraw is `#pragma optimization_level 2` → that's why pass re-materializes (volatile). At O4 the const-0 is kept in a saved reg (matching retail's r29) — NO naming needed, just the opt-level. dbgtricky A/Bs O4-vs-O2 on the full fn.
RETRACTED: the dbstealerworm "named zero var" is NOT the lever — that fn is O4, so it keeps the const-0 regardless of the `zero` variable (a literal 0 there would compile identically). The oracle confirms O4-keeps, not named-keeps.
NET (corrected): standalone-const-keep = an O4-vs-O2 fact (O4 keeps loop-const-0 in saved reg; O2 re-materializes). #126 = drop to O4. value-0 field-store (entryCount=0, PRE-LOOP not in-loop) folds even at O4 (pre-loop position, no loop to hold the web). Minimap is li-vs-mr (counter-copy, both already saved — NOT a keep issue). The 5th self-correction; the opt-level core is verified and stronger than the (wrong) named-var framing.

### ✓ RESOLVED (lead's 4-way test) — clean recipe: O4-vs-O2 alone; named-var is a RED HERRING
Lead independently tested O4 literal-vs-named on BOTH the global-scalar shape (`gPass=0`, #126's pass) AND the two-store shape (`vec[2]=0; vec[0]=0`) → ALL FOUR byte-identical, all keep the const-0 in saved r31. So the named-var is INERT (red-herring, like #37's inline-operand). 
FINAL CLEAN RECIPE (integrated by lead): **a standalone const-0 reused across in-loop calls is KEPT in a saved reg at O4 (graph-coloring) but RE-MATERIALIZED in a volatile per-use at O2 (creation-order). Discriminator = OPT-LEVEL ALONE.** (O2-impossibility scan confirms the O2 half: no DLL O2 fn keeps a standalone const-0 in a saved reg.) The two value-0 halves want OPPOSITE opt-levels: counter-tied chain → O2 keeps / O4 folds; standalone const-0 → O4 keeps / O2 folds.
#126 FIX (relayed to dbgtricky): debugPrintDraw has `#pragma optimization_level 2` (line 1503) → pass re-materializes; retail keeps pass in saved r29 (O4 behavior) → the O2 pragma is the BLOCKER. Drop/raise to O4 (named-var NOT needed); dbgtricky A/Bs the full-fn O4 tradeoff.
EDGES (precisely-bounded live targets): pre-loop-field-store (entryCount=0, folds even at O4 — pre-loop position) and Minimap li-vs-mr (counter-copy, both already saved — a counter-tied case, not a keep issue).
LESSON: a convincing A/B can hide a grep/read artifact — the lead's independent reproduce caught my wrong "O4+literal→volatile" cell pre-broadcast. Verify the SPECIFIC store reg, not a loose grep that can match a prologue stack-op.

---

## ★ func05 multi-stride reducer-direction — LEVER DERIVED (no oracle; relocate stride creation before the gate)
waterfx_func05 (dll_0013): 3 strength-reduced strides — e=&pool[i] (i*28, struct walk), vtx=(char*)vtxb+i*0x40 (i*64, drawFn arg1), vtxDesc=(char*)vdb+i*0x20 (i*32, drawFn arg2). VERIFIED exact regs:
- TARGET: 28→r27, 32→r28, 64→r29 (ascending-by-value), counter→r25.
- CURRENT: 28→r29, 32→r28, 64→r27 (28↔64 SWAPPED = reverse), counter→r26.
NO ORACLE (scanned all matched DLL .o's for a 3-stride ascending-by-value-in-ascending-regs loop → only func05 itself). Derived fresh.
MECHANISM (probe-pinned): the strength reducer assigns saved regs to induction vars by CREATION ORDER — **FIRST-created stride → HIGHEST saved reg**. The source creates e(28) FIRST (the `WE *e = &pool[i]` gate at the loop top), so 28 lands in the highest stride reg (reverse of target). 
THE LEVER (instruction-neutral, probe-confirmed 42==42 instrs): relocate the call-arg stride expressions to BEFORE the e gate, creating the LARGEST stride FIRST:
```c
for (i = 0; i < N; i++) {
    char *vx = (char*)gWaterfxRippleVtx     + i*0x40;  /* 64 created FIRST → highest reg */
    char *vd = (char*)gWaterfxRippleVtxDesc + i*0x20;  /* 32 second */
    WE *e = &((WaterEntry7*)gWaterfxRipplePool)[i];     /* 28 LAST → lowest stride reg */
    if (e->active) { ...; drawFn_8005cf8c(vx, vd, 2); }
}
```
PROBE RESULT (isolation): base (e first) → 28→r31,32→r30,64→r29 (reverse, = current). revcreate (vx/vd first) → 64→r31,32→r30,28→r29 (= TARGET relative order: counter<28<32<64), SAME instr count. The reducer assigns first-created→highest, so creating 64 first lands it highest, un-swapping the 28↔64.
FAITHFUL: the strides are strength-reduced induction vars bumped UNCONDITIONALLY at the loop bottom (target confirms: addi r27,r28,r29 all at the increment block e4c-e58), so computing them before the gate is instruction-neutral (no extra work when inactive — the bump happens regardless). Plausible 2002 C ("compute draw addrs, check active, draw").
DISCIPLINE CAVEAT (verify the EXACT reg, per the const-0 lesson): this is an ISOLATION result — the relative order matches (counter<28<32<64) but the real fn has more saved-reg pressure. waterfx VERIFIES IN-TREE: build the unit, confirm 28→r27/32→r28/64→r29 (not just "moved"), report.json %. The #136(a)/(b)/#137/decl-order/comma-init were inert because they don't touch stride CREATION order; relocating the expressions before the gate IS the creation-order lever.

### func05 — order-sensitivity CONFIRMS the mechanism (first-created stride → highest reg)
Probe: vd_first (compute i*32 BEFORE i*64) → 32→r31(highest),64→r30,28→r29 — does NOT match target (target wants 64 highest). vx_first/revcreate (i*64 first) → 64→r31,32→r30,28→r29 — MATCHES. So the order is load-bearing and the mechanism is pinned: **the strength reducer assigns FIRST-created induction var → HIGHEST saved reg; to land strides ASCENDING-BY-VALUE in the regs (target), create them in DESCENDING value order (largest first).** func05 fix = compute vtx(i*0x40) FIRST, vtxDesc(i*0x20) SECOND, e(&pool[i]) LAST, before the active gate. Instruction-neutral, order-confirmed. (Generalizes #136: single counter/walker = body-vs-comma; MULTI-stride = creation-order-by-descending-value via expression relocation.)

### ⚠️ CORRECTION (6th) — "O2-impossibility" DISPROVEN; METHOD LESSON: scan RETAIL objs, not SRC objs
Lead/dbgtricky DISPROVED my "O2 can't keep a standalone const-0 in a saved reg": retail's debugPrintDraw IS O2 AND keeps pass=0 in saved r29. So O2-keep IS achievable.
ROOT-CAUSE METHOD ERROR (same family as the loose-grep): my O2-impossibility scan hit OUR SRC objs (build/GSAE01/src/...), which ALL fold BECAUSE our source lacks retail's construct — that's SELF-CONFIRMING ("our source doesn't do it" ≠ "it's impossible"). To prove a shape UNachievable you must scan the RETAIL/matched objs (build/GSAE01/obj/...) — and if retail HAS it, it's achievable by definition, so the conclusion is NEVER "impossible," only "source form not found yet." RULE: any "impossibility/cap" claim must be checked against RETAIL objs, never src objs.
CORRECTED FINDING: standalone-const-keep is achievable at BOTH O4 (graph-coloring, our source already gets it) AND O2 (retail proves it) — the O2-keep form is just not-yet-found in our source. Lead's hypothesis: retail's pass is MULTI-DEF (2-pass loop var, 0 then 1) → a multi-def web gets a saved reg at O2's creation-order alloc (#108), while a single-def const-0 folds. (dbgtricky lead.)

### O2-keep (debugPrintDraw pass) — multi-def alone does NOT reproduce; needs real-fn structural ingredient (dbgtricky lead)
Tested the lead's multi-def hypothesis CORRECTLY (exact-reg read, all stores `= pass`, O2): a multi-def pass (pass=0 then pass=1, both stores via `= pass`) at O2 STILL folds to volatile `li r0` in minimal isolation — `stw r0,0(0)`. So multi-def alone is NOT the O2-keep discriminator.
RETAIL (scanned the RETAIL obj, correct method): pass=0 → `li r29,0` (c5c, saved), then `addi r29,r3,10` (c94 — r29 REUSED for a DIFFERENT value mid-fn!), then pass=1 → `li r29,1` (e0c). So retail's r29 is a MULTI-VALUE saved reg (pass=0, then an address r3+10, then pass=1) — pass rides an already-anchored saved reg. OURS re-materializes `li r0` per store (8×).
HYPOTHESIS (for dbgtricky to pin in-tree, add-ingredients method): the O2-keep is anchored by r29 ALREADY being a saved-reg holder of another value (the `r3+10` address web) across the pass lifetime — pass=0 coalesces onto that pre-existing saved web rather than re-materializing. The minimal repro lacks that competing saved web. To reproduce: add a saved-reg local that's live across both pass phases (an address reused mid-fn), so the creation-order allocator parks pass on a saved reg. This is the real-fn structural ingredient, NOT multi-def-ness. (dbgtricky owns debugPrintDraw; func05 stays MY priority.)

---

## ★ #148 conversion-bias coloring — DISPROVES the "lowered-late→inert" hypothesis: bias colors by CONVERSION SOURCE POSITION
The playbook #148 WORKING HYPOTHESIS (explicitly "NOT a verdict") was that the conversion bias is synthesised during int→float LOWERING (a late pass) so source position is inert and it always parks high (f31). PROBE DISPROVES IT — the bias colors by the CONVERSION's SOURCE POSITION (creation order), exactly like func05's strides:
- `acc += (float)gi*0.5f` FIRST in the loop body → bias `lfd f28` (early reg).
- same conversion LAST in the loop body → bias `lfd f31` (last reg).
(Both: loop with a `call()`, 5 hoisted FP consts. The bias is the `lfd fXX,0(0)` pool double; the `lfd fXX,N(r1)` are epilogue restores — don't confuse them.) The consts (lfs) fill the other saved FP regs around the bias's position.
THE LEVER (FP analog of func05 / the creation-order family): **relocate the `(f32)(int/u32)x` conversion expression EARLIER in the source so its bias web is created earlier → colors at a LOWER fXX.** For #148's residual (ours bias=f31 last, retail=f29 earlier), MOVE the conversion earlier among the loop body's FP operations so the bias lands at retail's f29. Position-sensitive and creation-order-keyed, NOT a late-pass-fixed-point.
WHY the prior forms missed it: #148 tried moving the CONSTS (breaks hoisting/DSE) and hoisting the conversion OUT of the loop (structure breaks) — but NOT relocating the conversion's position WITHIN the loop body relative to the other FP ops. That's the untried lever, and it moves the bias (probe-confirmed f28↔f31).
DISCIPLINE CAVEAT (isolation result, verify exact reg in-tree): the real fn (staffFn_80170380 / waterfx's case) has specific consts + structure. waterfx VERIFIES IN-TREE: find where the `(f32)(int)x` conversion currently sits, move it earlier/later to land the bias at retail's EXACT fXX (read the target's bias reg first), confirm report.json. The mechanism (position→bias reg) is pinned; the exact position is per-fn. This RETIRES the "build-domain/named-bias-only" framing for the SOURCE side — there IS a source lever (conversion position), just not via naming the bias.

### O2-keep anchoring — does NOT reproduce as a structural ingredient; the real clue is STORE-COUNT (8 vs 2)
Probed 4 anchoring hypotheses at O2 (exact-reg read, all FOLD to `stw r0` volatile): (1) multi-def pass (0 then 1); (2) simultaneously-live competing address (x1 across the loop); (3) SEQUENTIAL reg-reuse (pass=0 loop1, x1 between, pass=1 loop2 — mirrors retail's r29 reuse); (4) HIGH register pressure (5 values live across the call). NONE makes the const-0 keep a saved reg. So the O2-keep is NOT a simple addable structural ingredient.
RETAIL READ (correct method, scanned the retail obj): retail's loop is `li r29,0` (c5c, once) → `stw r29` before loop (c60) → `stw r29` IN loop (c70) → bl (c7c); r29 reused for `addi r29,r3,10` AFTER loop1 (pass dead). Structure LOOKS identical to my folding `noanchor` isolation (store-before + store-in-loop, same compiler, same O2) — yet retail keeps r29, mine folds.
★ THE REAL CLUE (store-count): retail has **2 pass stores** (c60, c70); OUR CURRENT build has **8** `stw r0` pass stores. That's a STRUCTURAL DIFFERENCE in our decomp — our debugPrintDraw emits 8 pass-stores where retail has 2. The keep-vs-fold likely follows from that structure (more stores / different loop shape in our source), NOT from an anchoring ingredient. dbgtricky LEAD: investigate why our build has 8 pass-stores vs retail's 2 — our decomp source may have extra `gPass=pass`/`=0` stores, an unrolled or duplicated loop, or a different control structure. Match retail's 2-store structure and the keep may follow (the minimal 2-store isolation still folds, so it's necessary-not-sufficient — but the 8-vs-2 is a real structural divergence to fix first).
HONEST STATE: the O2-keep is a live target (retail proves it). The anchoring hypothesis (competing saved web) does NOT reproduce minimally. The store-count divergence (8 vs 2) is the concrete structural lead for dbgtricky — likely the decomp's loop/store structure differs from retail's, and that difference (not an addable ingredient) drives the fold. Not yet pinned to the exact source form.

---

## ★★ kind-2(2) "free-reg look-ahead" — IT'S CREATION ORDER, not a reserve (4th creation-order family member)
waterfx's "MWCC reserves f31 for a later value (look-ahead)" framing for the ~35-fn kind-2(2) bucket is DISPROVEN by probe — it's plain CREATION ORDER (#45/#108: first-created FP web → highest reg f31):
- base: `float cr = getf(); float gs = gScalar;` (call-result FIRST) → `fmr f31,f1` (cr→f31 greedy), `lfs f30` (gs→f30). = OURS.
- gsfirst: `float gs = gScalar; float cr = getf();` (global FIRST) → `lfs f31` (gs→f31), `fmr f30,f1` (cr→f30). = RETAIL (cr=f30, gs=f31).
So there is NO look-ahead/reserve — the web created FIRST gets f31. Our decomp creates the call-result first (cr→f31 greedy); retail creates the GLOBAL first (gs→f31). 
THE LEVER (probe-confirmed exact regs): **load the global-scalar BEFORE the call that produces the call-result** — `gs = gGlobal;` then `cr = call();` — so gs's web is created first → f31, and cr (later) → f30, matching retail. (Same family as func05 strides, value-0, #148 FP bias — ALL color by source/creation order; this is the 4th.)
DISCIPLINE / in-tree gate: ISOLATION result (exact regs verified: gs→f31, cr→f30, fcmpo cr0,f30,f31). waterfx VERIFIES IN-TREE on the objhits kind-2(2) case: check whether the real fn currently loads the global AFTER the call (greedy cr→f31) and REORDER the global's load before the call. If the real fn genuinely creates the global LATER yet retail still gives it f31, THEN it's a true look-ahead (my creation-order finding wouldn't be the mechanism) — but the probe strongly suggests it's creation order (the bucket's "look-ahead" is the decomp having the global-load AFTER the call). This potentially cracks the whole ~35-fn bucket if they share the "global loaded after the call-result" shape. Read the target's web order, reorder the global load, exact-reg verify.

---

## ★ value-0 variant-c PRE-LOOP field store — DISPROVES "folds even at O4": it REUSES the accumulator's reg in clean isolation
Probed the pre-loop field-store (`state->entryCount = 0` before a loop with an accumulator fallOff):
- base (`int fallOff=0; state->entryCount=0; loop{gArr[i]=fallOff; fallOff+=4; use(fallOff);}`) → `li r31,0` (fallOff→r31 saved), `stb r31,42(r3)` (entryCount REUSES r31 = fallOff's reg!), `addi r31,r31,4` (r31 IS fallOff). MATCHES retail's `stb r23(fallOff),42`.
- + the in-tree ingredients (htOff=fallOff copy + the OR hack on fallMid) → STILL `stb r31,42` (reuses).
So the pre-loop field store DOES reuse the accumulator's saved reg at O4 — the "value-0-c pre-loop folds even at O4" claim is DISPROVEN in clean isolation. The literal `entryCount=0` coalesces with fallOff's r31 (both hold 0 at that point → same value-number → MWCC stores fallOff's reg). REQUIRES: `fallOff = 0` materialized into its saved reg (r31) BEFORE the field store (source order fallOff-first), and fallOff a live accumulator. (Creation/materialization order — same unifying thread.)
SO THE IN-TREE FOLD (fn_801932C8) is a SPECIFIC STRUCTURAL INGREDIENT, not the pre-loop position. My minimal + htOff + OR-hack all REUSE; the real fn folds → something else (the FP-heavy body, the NESTED loops, or fallOff not materialized into r31 before the field store in the real allocation) forces the fold. waterfx/validator NEXT: add ingredients (nested loop, FP pressure, the exact fn_801932C8 body shape) until the field store FLIPS from stb r31 to li r0 — that names the fold trigger, and removing/counteracting it = the fix. The achievable form (stb fallOff_reg) is probe-confirmed; the in-tree divergence is the remaining pin. (DISCIPLINE: isolation result; the fix is to make the in-tree match this clean structure — read fn_801932C8's fallOff materialization point vs the field store.)

### value-0 variant-c — fold trigger PINNED: NESTED LOOP (not FP, not pre-loop position)
Add-ingredients method narrowed the in-tree fold trigger precisely:
- SINGLE loop (fallOff used in the loop body) → field store `stb r31,42` REUSES fallOff's saved reg. ✓ (matches retail)
- + htOff copy + OR hack → still REUSES. ✓
- + FP body (single loop) → still REUSES. ✓
- **NESTED loop** (fallOff incremented OUTER, used INNER) → `stb r0,42` FOLDS. ✗ ← THE TRIGGER.
So the value-0-c fold is caused by the NESTED LOOP structure (not the pre-loop position, not FP). In a nested loop, fallOff's materialization is DEFERRED (it's loop-invariant in the inner loop, incremented in the outer), so it's not in r31 at the pre-loop field store → li r0.
RETAIL REUSES IN THE NESTED fn_801932C8 (`stb r23(fallOff),42`, and fn_801932C8 HAS nested blkIdx/mid/inner loops) — so a nested-loop source form EXISTS that keeps fallOff materialized before the field store. FIXES TRIED (both still FOLD): (1) reference fallOff before the field store (`gArr[0]=htOff` first); (2) `state->entryCount = fallOff` (= accumulator). Neither makes the nested-loop field store reuse.
OPEN EDGE (precisely bounded, live target): the NESTED-LOOP variant-c reuse form. The reuse is achievable (retail's nested fn_801932C8 does it) — the source construct that keeps fallOff in r31 before the field store DESPITE the nesting is still to find. NEXT: probe what makes the nested-loop accumulator materialize early (force fallOff into r31 before the inner loop — maybe an explicit early use that doesn't fold, or a fallOff structure that the nesting doesn't defer). The "folds even at O4" framing is corrected to "folds in NESTED loops; reuses in single loops" — a precise trigger, not a blanket cap.

### value-0 variant-c — REFINED trigger: deep-nesting + INNER-LOOP COMPLEXITY (FP or conditional) = register-pressure boundary
Full add-ingredients ladder (exact-reg, faithful to fn_801932C8's triple-nested blkIdx/mid/inner + fallMid/fallInn/htMid chains):
- single loop / single+htOff+OR / single+FP / DOUBLE-nested-outertop / TRIPLE-nested with a SIMPLE inner body → field store `stb r31` REUSES fallOff's saved reg. ✓
- TRIPLE-nested + FP physics in the inner loop → `stb r0` FOLDS. ✗
- TRIPLE-nested + a CONDITIONAL (`if`) in the inner loop (no FP) → `stb r0` FOLDS. ✗
So the variant-c fold needs DEEP NESTING + INNER-LOOP COMPLEXITY (FP call OR a conditional) together — neither nesting-alone nor FP-alone nor a simple-inner triple folds. The added inner-loop liveness/pressure displaces fallOff's materialization so it's not in r31 at the pre-loop field store → `li r0`. This is a register-PRESSURE boundary (the inner-loop complexity competes for the allocation that would keep fallOff in r31 early).
RETAIL KEEPS IT under this exact pressure (`stb r23(fallOff)` in the triple-nested FP-heavy fn_801932C8) — so a source form that forces fallOff into a saved reg BEFORE the field store DESPITE the inner-loop pressure EXISTS. OPEN EDGE (sharply bounded, live target): that forcing lever. The fold is NOT "pre-loop position" and NOT "nesting alone" — it's nesting + inner-complexity pressure. NEXT (the forcing lever, untried): make fallOff's saved-reg materialization happen at the field store regardless of inner pressure — e.g. an explicit fallOff use in the OUTER loop preheader that the pressure can't displace, or a structure that pins fallOff to its reg before the inner loops are allocated. The add-ingredients method has now NAMED the exact trigger (deep-nest + inner-complexity); the counter-lever is the remaining 1-instr edge. (Far sharper than "folds even at O4" — and it's a pressure boundary the validator can keep attacking with the incremental method.)

### value-0 variant-c — forcing levers tried (all fold); the pressure robustly displaces fallOff
Tried to FORCE fallOff into r31 before the field store under the deep-nest+FP pressure: (1) ref fallOff before the store; (2) `entryCount=fallOff`; (3) volatile `gSink=fallOff` early use. ALL still `stb r0` (fold). The inner-loop pressure robustly displaces fallOff's early materialization. So the forcing lever for the pressure-bound case is genuinely hard — a 1-instr edge. SUMMARY of the variant-c investigation (complete, precise): REUSES (matches retail) in single-loop + simple-nested; FOLDS under deep-nest + inner-complexity (FP/conditional) pressure; retail keeps it under that pressure so the forcing form exists; 3 forcing levers ruled out. This is a sharply-bounded 1-instr live target (the register-pressure forcing lever), NOT a cap — best attacked fresh with the incremental method or an in-tree oracle (a matched triple-nested-FP fn that keeps an accumulator-0 in a saved reg across the field store).

### func05 WAKE sub-case — CRACKED: it's the SAME creation-order rule, OPPOSITE target order (create vtxDesc/32 first)
The wake loop's stride order DIFFERS from ripple (waterfx found the ripple fix net-negative on wake). VERIFIED exact regs:
- RIPPLE target: 28→r27, 32→r28, 64→r29 (64 highest). Fix = create vtx(64) FIRST.
- WAKE target: 28→r27, 32→r29, 64→r28 (32 highest, 64 middle — 32/64 SWAPPED vs ripple). Fix = create vtxDesc(32) FIRST.
PROBE: the 2-condition gate (`g->active && g->f18==0`) + intervening setColor does NOT itself swap the order (both my ripple/wake probes stayed greedy 28→highest) — so the gate is NOT the mechanism. The wake's different order is just retail creating vtxDesc(32) first (vs ripple's vtx(64) first). wake_32first (`char *vd=vdb+i*0x20; char *vx=vtxb+i*0x40; WE *g=&wpool[i];` — 32 first) → `addi r31,32; addi r30,64; addi r29,28` = 32→highest, 64→middle, 28→lowest = WAKE TARGET relative order. ✓
SO THE func05 FIX IS PER-LOOP (same #136 creation-order rule, read each loop's target order): create the strides in the order that lands each at its target reg (first-created→highest). Ripple wants 64→highest → vtx first. Wake wants 32→highest → vtxDesc first. Both are "relocate the strides before the gate, ordered to match the target's first-created→highest" — just the per-loop target order differs (don't blanket-apply ripple's 64-first to wake). DISCIPLINE: isolation; waterfx verifies in-tree (wake: 32→r29, 64→r28, 28→r27). This resolves waterfx's "ripple fix net-negative on wake" — wake needs vtxDesc-first, not vtx-first.

### kind-2(2) DISCRIMINATOR RESOLVED (in-tree): creation-order rule is REAL but PRESSURE-OVERRIDDEN — NOT a one-line fix
waterfx's in-tree read decided the hedge: kind-2(2) is NOT creation-order in-tree. The FP positions are BYTE-IDENTICAL in both builds (moveLen fmr @0x8dc, zf lfs @0x994), the global is loaded AFTER the call in BOTH, and the "load global first" reorder REGRESSED (99.90→99.28). So my isolation rule (gs-first→f31) is REAL in isolation but OVERRIDDEN by the full fn's register PRESSURE in-tree. 
VALUABLE BOUND (not a miss): kind-2(2) is a CONTEXT-BOUND, pressure-driven free-reg pick — NOT isolable and NOT a source reorder. The isolation creation-order rule does not survive the real pressure. PARKED for a non-inlined oracle or a deeper in-tree pressure model; do NOT grind it as a source lever. (Integrated into #147 by lead.)
METHOD WIN: this is the hedge working as designed — I flagged the exact discriminator (is the global loaded before/after the call in retail?) instead of asserting the recipe; the in-tree bytes decided it, and NO wrong recipe was broadcast. Contrast the named-var miss (asserted, then caught) — here the discipline was applied UP FRONT. The isolation-rule-real-but-pressure-overridden outcome is exactly why isolation findings must be in-tree-gated before becoming recipes.

### dim2icicle #148 + func05 wake — BOUNDED as in-tree-context-bound (isolation real, structure/pressure overrides)
Two isolation derives tested in-tree (waterfx) and DIDN'T hold — quick isolation pass confirms each is structure/pressure-bound; PARKED as fresh-eyes targets (per the "don't grind in-tree-context-bound nuts" rule):
**(1) dim2icicle #148 — STRUCTURE-BOUND (the #148 conversion-position lever's boundary).** The conversion result is STORED to a global field and RE-READ for a DIVISION (`gDivisor = (float)gi; ... gB / gDivisor`), so the conversion feeds a STORE + a division-DIVISOR, NOT an FP multiply operand. PROBE (div_shape, conversion-first + store-to-global + re-read-for-division): bias stays `lfd f30` (NOT lowered to f28) — reproduces the in-tree "conversion-first FOLDS / bias stays f30." So #148's lever (move the conversion earlier) WORKS only when the conversion feeds an FP EXPRESSION (multiply); the STORE-TO-GLOBAL + re-read-for-division shape BREAKS it (the store fixes the bias web's creation point). That's the precise #148 boundary: feeds-a-multiply → lever applies; stored-to-global-and-re-read → structure-bound, park. (waterfx proved the bias IS reachable to f28 in some form, but not via the simple conversion-position lever on this shape.)
**(2) func05 WAKE — PRESSURE-BOUND + my MISREAD.** ⚠️ My "wake wants 32→r29 (vtxDesc-first)" was a MISREAD — I grabbed the WRONG addi block in the multi-loop dump (waterfx in-tree: the wake target is 64→r29, like ripple, and the wake reducer FIXES 64→r29 REGARDLESS of decl order; offsets-before-gate o32-first gives 32→r27, not the target; decl-order INERT inside the gate). So my isolation decl-order rule does NOT hold in-tree for wake — the 2-condition-gate'd reducer is pressure-fixed. RETRACTED "wake cracked." 3rd exact-reg lesson: in a MULTI-LOOP fn, verify you're reading the CORRECT loop's addi block (I read a sibling block's strides). Wake is in-tree-context-bound, parked.
UNIFYING: kind-2(2), dim2icicle, wake are ALL in-tree-context-bound — isolation rules REAL but overridden by the full fn's pressure/structure. This is the precise EDGE of what isolation reaches: source-order/creation-order levers apply UNTIL the fn's pressure or a store/structure fixes the web; then they're context-bound (oracle/in-tree-pressure-model targets, not isolation derives). The gate caught all three.

---

# ===== SESSION FINAL TALLY (validator) — kickoff reference for next session =====

## LEVERS DERIVED (probe-verified; landing/integrated)
- **The CREATION-ORDER FAMILY (the session's central unification)** — FP/induction/const coloring is keyed on source/creation order; the lever is reordering the source so the right web is created first. Four probe-verified members:
  - **func05 #136 multi-stride** — relocate stride exprs before the gate, ordered so each lands at its target reg (first-created→highest). PER-LOOP target order (ripple wants 64-first; read each loop's target). Gate-condition COUNT changes ordering but not via decl-order.
  - **value-0 family (FULLY MAPPED):** counter-tied = chained `val=counter=0` + opt_level≤2 (O2 keeps the chain, O4 folds); standalone O4-keep = opt-level alone (O4 graph-coloring keeps a loop-const-0 in a saved reg, O2 re-materializes — OPPOSITE the counter-tied case); O2-keep = anchored on an existing saved web (dbgtricky's #136b, retail-read ingredient).
  - **#148 conversion-bias = conversion SOURCE POSITION** (conversion-first→bias f28, last→f31). LANDED in-tree (staffFn 95.91→96.73), sweeping project-wide. BOUNDARY: applies when the conversion feeds an FP MULTIPLY; INERT when stored-to-global + re-read-for-division.
  - **clear-loop two-statement fbrow reuse** (in-place coalesce + sthx; derived, no oracle).
- **The graph-coloring ALLOCATOR MODEL** (#108/#126/#45/#5/#131 class-pooling + within-class creation/decl-order rules).

## NUTS PRECISELY BOUNDED (parked as fresh-eyes / non-inlined-oracle targets — NOT caps)
- **kind-2(2) FP free-reg pick** — isolation creation-order rule REAL but PRESSURE-OVERRIDDEN in-tree (positions byte-identical, reorder regressed). Context-bound, not source-reachable. Needs a non-inlined oracle or in-tree pressure model.
- **dim2icicle #148** — STRUCTURE-bound (store-to-global + re-read-for-division fixes the bias web; conversion-position lever inert). Defines the #148 boundary.
- **value-0-c pre-loop field store** — folds ONLY under deep-nest + inner-loop-complexity (FP or conditional) PRESSURE; reuses in simpler structures. A sharply-bounded 1-instr edge; forcing lever (3 tried) unfound but retail proves it exists.
- **#126 debugPrintDraw** — the #136b anchoring nut (O2 const-0 needs an anchoring saved web); structural, dbgtricky's domain.

## METHOD / DISCIPLINE (the highlight — ~8 honest self-corrections, each strengthened the playbook)
1. value-0 "compiler-gap" verdict → retracted (retail proves achievable). 2. value-0 "O2-only" → corrected to heterogeneous mechanisms. 3. #37 "inline-required" → reconciled (cast is sole discriminator). 4. variant-c "=fallOff" derive → folds, retracted. 5. #126 "single-def class" → corrected (it's the const-keep family). 6. **named-var lever → LOOSE-GREP MISREAD** (matched a prologue stack-op; named-var inert; real lever = opt-level). 7. **"O2-impossibility" → SELF-CONFIRMING SCAN** (scanned SRC objs which fold because our source lacks the construct; must scan RETAIL objs for achievability). 8. **wake "32→r29" → WRONG-BLOCK MISREAD** in a multi-loop dump (retracted; reopened the fn as gettable).
DURABLE METHOD LESSONS: (a) verify the EXACT reg AND the CORRECT block, never a loose grep; (b) scan RETAIL objs for achievability, never SRC objs (self-confirming); (c) hedge every isolation finding with the IN-TREE GATE before it becomes a recipe — isolation rules apply UNTIL a store/pressure fixes the web, then they're context-bound.
WORKFLOW: whole target asm → correct block → exact reg → retail-obj achievability → isolation probe → in-tree-gate hedge → hand off.
