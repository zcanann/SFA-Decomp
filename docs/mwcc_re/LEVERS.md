# Matching levers, derived from the decompiled passes

Each lever below is backed by a specific code path in `recovered/Scheduler.c` /
`recovered/Coloring.c` (addresses cited), not by black-box correlation. This is
the "what to change in the C, and why it works" index. Use it to TRIAGE a stuck
function before permuting blindly.

## How MWCC actually picks a register (Coloring.c)
The pipeline per register class is: build interference graph → coalesce copies →
**Simplify** (build a stack) → **Select** (assign) → spill-or-apply, iterated.

1. **Register = lowest free register in the class mask, assigned in stack order.**
   `Color_Select` (0x508900) starts from the class's usable-register bitmask
   (`GetAllocRegMask` 0x4fe4d0), clears each bit used by an already-colored
   *interfering* neighbor, and takes the **lowest remaining bit**. There is no
   "preference" heuristic beyond lowest-free. So a register only differs from the
   target because (a) the web is colored at a different point in the stack, or
   (b) a different set of neighbors is already colored (different interference).
   **[VALIDATED 87/87 byte-exact — see VALIDATION.md.]**

   1a. **Volatile vs saved is a two-tier mechanism (validated).** The primary mask
   is VOLATILES ONLY (GPR: r0,r3–r12; FPR: f0–f13). A web gets a **saved register
   only when the primary mask is empty** — i.e. it interferes with *every*
   volatile (classically: live across a call, or across the whole function). Then
   the fallback (`GetReservedReg` 0x4fe470) hands out saved regs from a pool
   ordered **r31, r30, r29 … descending**, by a rotating counter. Consequences:
   - To put a value in a saved register, make it **live across all volatiles**
     (across a call). To keep it in a volatile, shorten its range so it doesn't.
   - **Which** saved register (r31 vs r30 vs …) follows the **order webs reach the
     fallback** = creation/coloring order ⟹ this is the real mechanism behind the
     CLAUDE.md "declaration order sets saved-register homes" fact. The first
     long-lived value gets r31, the next r30, and so on.

2. **Stack/color order = web creation (index) order, low-degree-first.**
   `Color_Simplify` (0x508a20) scans webs in **web-index order**
   (`for i in [webStart,webEnd)`) and removes every web with `degree < k` each
   pass. Web index == creation order == the order values are first materialized in
   the IR ≈ **source order of first def/use**. This is the real mechanism behind
   the CLAUDE.md "declaration order sets saved-register homes" fact: reordering
   local decls reorders web creation, which reorders the stack, which can change
   the lowest-free-register outcome. It is NOT cosmetic — it only moves a register
   if it changes the stack position relative to an interfering web.

3. **To change a register you must change interference or creation order — not
   spelling.** `degree` (web+0x12) = count of simultaneously-live neighbors. Two
   values share/avoid a register based purely on whether their live ranges
   overlap. Levers that work: shorten/extend a live range (derive a typed local
   early and let the source die; or keep a value live across a call to force a
   saved reg); reorder first-use; change whether two values are live at once.
   Levers that DON'T: renaming, casts, parenthesization (unless they change
   liveness or CSE — see ValueNumbering below).

4. **Spill choice is STRUCTURAL (web index), NOT cost-weighted.** *(Corrected — the
   earlier "min degree/spillCost" was wrong.)* The web's `+0xc` ("spillCost") is
   **always 0** — the web is `bzero`'d at creation (0x57b470 → 0x440b80) and `+0xc`
   is never written. So the ratio `degree/+0xc` is `+Inf` for every web; the
   min-ratio search never updates and **the first parked web wins**. Parked is
   built by prepend over webs in index order, so its head is the **highest-index**
   high-degree web — that's what gets optimistically removed first. There is **no
   usage×loop-depth weighting**. Consequence: a register divergence on a non-
   spilling function is decided by **interference degree + web index (creation
   order)**, full stop — not by any cost you can tune. If decl/creation order is
   inert (e.g. a param with a fixed index), and the visible degree matches, the
   divergence is **interference-bound from the rest of the function** (recover the
   real liveness elsewhere) or genuinely irreducible (bank it, per AGENTS.md).
   *(The interference graph itself: degree = web+0x18 = popcount of the triangular
   bit-matrix row built in 0x57b470 from the per-block live sets; web+0x12 = a
   working copy of it. To move a register, change what's simultaneously live.)*

4a. **Web index = IR-definition order (the saved-register tie-break, completed).**
   Web numbers are assigned sequentially by `0x4fe552` (`web = webEnd[class]++`) in
   the order values are numbered = the order they're DEFINED in the post-optimization
   instruction stream. With no spillCost (lever 4), this index IS the coloring/Select
   order, so when two saved-lived webs compete for r31 vs r30, **the one defined
   earlier in the IR gets the lower index → r31**. Verified across two functions
   (matcher-2 InitAllMessageQueue: loop3-base vs counter; matcher-3 fn_800A3AF0:
   param-saved-copy vs LICM-hoisted `&global`). The catch: **IR-definition order is
   set by front-end passes (LICM hoisting a loop-invariant address before the loop,
   param materialization point), NOT by C declaration order** — exhaustively
   confirmed inert. So a saved-register swap between two such webs whose only
   difference is IR-definition order is **interference/index-bound and irreducible
   from plausible C** with the currently-decompiled passes → BANK with the index
   analysis as proof. (A future decomp of the front-end web-numbering/LICM ordering
   is the only thing that could turn this into a lever; matcher-3 showed de-hoisting
   the invariant or materializing the param earlier always adds an instruction or
   makes the web volatile, so it diverges.)

## How a copy / `mr` survives or dies (Coloring.c coalescer)
5. **A copy is coalesced (the `mr` disappears) iff its move is on a coalesce list
   with the descriptor flags set.** `Color_Coalesce` (0x508c10) walks
   `0x5e9b00 / 0x5e99c4 / 0x5e98f4`; a move coalesces only when its RegInfo
   descriptor (0x4d0150) has bit1 (`+0x24 & 2`) and matches the class, then it
   propagates value-identity (web+0x4) so src and dst become one web ⇒ one
   register ⇒ the copy is dead (dropped in `Color_Apply` 0x5087d0). A surviving
   `mr` means the move was never made eligible upstream — because src and dst
   **interfere** (both live at the copy) or have incompatible class. This is the
   blog's Wall A exactly: keep a value alive in a *second* register past the copy
   point and the two webs interfere, so the `mr` survives. Killing the source
   right after the copy makes them non-interfering ⇒ coalesced ⇒ no `mr`.

## A copy / `mr` has THREE independent ways to die (don't confuse them)
5a. **Propagation (`IroPropagate.c` 0x470060, EARLIEST — `opt_propagation`).** A
   `x = y` / `x = const` is folded away (uses of x → y/const) unless a side is
   **volatile or ADDRESS-TAKEN**, or types mismatch (`IsPropagatable` 0x4709f0).
   To KEEP a copy, make a side address-taken (`&x`) / volatile / type-straddling —
   that blocks propagation so the copy survives downstream. This is the mechanism
   under the CLAUDE.md "typed-local / distrust raw derefs" idiom.
5b. **Value-number fold (`ValueNumbering.c` 0x509010 — the blog's pass).** A copy
   `dst = src` is DELETED iff `dst` and `src` carry the **same value number** at
   the copy point (`valTab[cls][web]` equal; 0x5090f2 → `Instr_Delete`). It
   SURVIVES iff their value numbers DIFFER. This is *earlier* and *different* from
   the coalescer (lever 5, which is interference-based at coloring time). The blog's
   `e14 |= e` no-op worked here: it gave the second value a distinct value number so
   the copy survived. Clean-C control: to KEEP a copy, ensure the two sides aren't
   value-identical at that point (a genuine recompute / intervening def); to KILL
   one, make them the same value (reuse, don't recompute).
5c. **CSE materialization/hoisting is `IroCSE.c` (0x46a360) — RULE DECODED.**
   IroCSE is forward available-expression dataflow. The temp lives at the FIRST
   AVAILABLE occurrence (the def the later use is replaced with); it is NOT
   anticipation-hoisted to a dominator where it wasn't computed. Crucially:
   - A **memory-load expression is KILLED by any intervening call/aliasing store**
     (`IroCSE_KillStmt` 0x46aaa0). Two uses with a call between → recomputed each
     side → **VOLATILE, short range**. Two uses with no clobber between → second
     replaced, temp at the first occurrence (if that's before a call → **SAVED**).
   - A **register local caching the load is NOT a memory expression**, so a call
     does not kill it → it survives across the call → hoisted into a saved reg.
   So: to keep a recomputed-each-side / volatile shape, leave the value as a
   DIRECT memory load at each use (killable); to force a single hoisted/saved
   copy, cache it in a local. And the temp's position follows the FIRST load in
   program order — order operands so that first load lands where the target wants
   it (e.g. after the dividend, not at block-top).

## Compare operand order (front-end form)
5d. **`cmplw`/`cmpw` operand order follows the LHS *form*.** A plain variable LHS
   (`modResult == (n-1)`) emits `cmplw r0,r7`; an assignment-expression LHS
   (`(modResult = …) == (n-1)`) flips it to `cmplw r7,r0`. (Validated closing
   PlayControl's last region.) So if only the compare operands are swapped and
   nothing else, check whether the target wrote a plain read vs an inline
   assignment on the compare's LHS — split an `&&` chain into nested ifs to turn
   an inline-assignment compare back into a plain-read compare.

## Commutative operands & evaluation order (InstrSelection / IroLinearForm)
*(Derived empirically — compile probes, not yet line-decoded.)*
9a. **Operand order = source order.** `a*b` → `fmuls fd,fa,fb`; `b*a` → `fmuls fd,fb,fa`.
   The left source operand is the first instruction operand. (Verified across
   fmuls/fadds with reg/reg, reg/mem, computed/computed operands.)
9b. **Constants canonicalize to the 2nd operand.** `5+a` and `a+5` both emit
   `addi r3,r3,5`. So a literal never lands first; don't try to match a "const-first"
   shape — it doesn't exist.
9c. **Eval order follows operand order, NOT declaration order.** `float e=a+b;
   float l=a-b; return l*e;` computes `l` (the left mult operand) *before* `e`.
   So to reorder two sub-expression computations, reorder them within the
   *expression that consumes them*, not their declarations.
9d. **Commutative ops are value-numbered commutatively: `a*b == b*a`.** A redundant
   `b*a` is CSE'd to an existing `a*b` (e.g. `w=(1-r)*s; w + s*(1-r)` → `fadds f0,f0`).
   So the surviving op keeps the FIRST occurrence's operand order, and swapping a
   *later* occurrence's source has no effect — change the FIRST occurrence (or break
   the CSE) to move the order.
9e. **An instruction whose only diff is operand registers (`fmuls f0,f1` vs `f1,f0`)
   for IDENTICAL source is a REGISTER-ALLOCATION difference, not an operand-order
   one.** Which logical operand occupies fa vs fb follows coloring; it resolves when
   the register divergence does. Don't chase it as a separate "canonicalization" bug.

## Instruction order (Scheduler.c)
6. **`#pragma scheduling off` ⇒ instruction order is InstrSelection emission
   order.** The dependency DAG is still built (`Sched_AddInstrDeps` 0x508100) but
   the ready-list reorder is bypassed. So under `scheduling off`, to match an
   ordering you match the *emission* order (InstrSelection), not a schedule.
7. **`scheduling on` ⇒ ready-list by critical-path priority** (longest weighted
   dependency chain; `Sched_AddDep` 0x5084f0 propagates `priority = max(priority,
   weight + dep.priority)`). To match a scheduled block, match its dependency
   structure: data deps (per-register def/use), memory deps (load-after-aliasing-
   store via `MayAlias` 0x511fc0), and call/barrier ordering.
8. **r2 and r13 are invisible to scheduling and allocation.** `Sched_AddInstrDeps`
   (0x50815d) skips GPR operands r2 (SDA2) and r13 (SDA), and r0-as-literal-zero.
   Don't expect deps or register pressure from SDA-based accesses.

## Conversion staging temps (stack frame / slot layout)
9. **Int→float and float→int staging temps (8-byte `stw/stw/lfd` and
   `stfd/lwz` slots) are allocated fresh per conversion and NEVER freed by
   default** — slots ascend, frames grow, and no retail function reuses a
   staging slot unless the original source triggered freeing (below). A
   mismatch that is ONLY `stwu -N` + shifted `stw r0,K(r1)`/`lfd`/`stfd`
   offsets (instruction stream otherwise identical) is this lever, not a
   missing local.
   - **Free trigger (validated by probe grid + 2 full matches):** a compound
     assignment on a local inside a branch (`if (d > 0x8000) d -= 0xffff;`),
     or an `if/else if` chain that reassigns a variable which later feeds an
     int→float conversion. Either switches the temp pool into freeing mode:
     all earlier conversion temps are released and reused **LIFO** (slots
     descend on the next statement, frame shrinks).
   - **Fresh spelling:** `d = d - 0xffff;` for in-branch clamps, and a
     ternary (`d = (d < -K) ? -K : ((d > K) ? K : d);`) for the else-if
     clamp. Statement-level compounds on integer loads (`a -= (u16)s16field`)
     are inert; a compound whose RHS contains a conversion temp (u16 cast of
     an f32 field) is a trigger.
   - **Both directions occur in retail:** most targets are fresh (respell
     compounds/else-ifs to explicit/ternary: DR_CloudRunner_stateHandler04,
     arwarwing_updateFlightPhysics 100%; fn_802ABFBC, fn_802BCA10,
     CameraModeArwing_update improved), but some targets DO reuse slots
     (fn_802ABAE8, fn_802AC32C: original kept the compound spelling — mixed,
     per-site work; check the target's slot sequence first: ascending = fresh,
     descending-reuse = compound).
   - The same mechanism shows up in FPR temp choice (a freed f0 reused where
     the target picks the next fresh fN) — same triggers apply.

## Inlining (CInline.c)
10. **A call is auto-inlined (`-inline auto`) iff: callee body is available in
   THIS TU + ≤30 statements + ≤1024 cost units + not `dont_inline` + not recursive**
   (`InlineSizeOK` 0x55c2e0, `CanInlineCall` 0x55c350).
   - **Extra `bl`/RELOC to a `fn_` the target inlined** ⟹ the callee is in a
     DIFFERENT `.c` in our split but was in the SAME TU originally. FIX = move the
     callee into the same `.c` (a split/file-org fix, not a code fix). A trivial
     accessor called-not-inlined is the classic "wrong TU" tell.
   - **Target calls where we inline** ⟹ callee just over 30 stmts / 1024 cost, or
     the original had `#pragma dont_inline on`.

## Triage recipe for a stuck function
- **Wrong register, same shape** → interference/creation-order problem (levers
  1-3). Recover the real live ranges: typed local derived early vs raw derefs
  scattered late (the param-inversion case). Reorder decls only to change which
  web is created first among *interfering* webs.
- **Extra/missing `mr` or reused vs duplicated register** → coalescer (lever 5).
  Decide whether the target keeps the value live in a second register (interfere,
  `mr` survives) or not (coalesce, no `mr`).
- **Wrong instruction order** → check the pragma. `scheduling off`: it's emission
  order (InstrSelection), stop blaming the scheduler. `scheduling on`: match the
  dependency DAG (lever 7).
- **Spill where target has none (or vice-versa)** → usage/loop-depth profile
  (lever 4), not a spelling change.

## Still upstream / to confirm
- `spillCost` (web+0x0c) and `regsNeeded` (web+0x10) sources — read RegisterInfo.c
  (0x4d0150) and InterferenceGraph.c (0x57b680) next to pin them.
- The coalesce-eligibility flags (desc+0x24) are set during web/move building —
  locate where to know precisely when a copy is made coalesceable.
