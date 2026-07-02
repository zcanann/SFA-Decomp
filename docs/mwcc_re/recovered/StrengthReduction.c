/* ============================================================================
 * RECOVERED: mwcceppc.exe (GC/2.0)  TU = StrengthReduction.c   band 0x571730-0x572e90
 * ----------------------------------------------------------------------------
 * Disassembly: docs/mwcc_re/disasm/StrengthReduction.c.objdump.txt
 * Anchored by assert string "StrengthReduction.c" @ .data 0x5d0920 (only fn
 *   0x571730 carries the two assert sites: lines 0x3a2 / 0x3a6). The other 16
 *   funcs are inferred-same-TU (all callees stay inside the band).
 *
 * THE PRIZE (for #112): this is the BACKEND, PCode-level strength reducer. It is
 * NOT the Iro (IR-level) SR — it lives late in .text next to Coloring/Scheduler/
 * InterferenceGraph (0x508/0x57b), operates on machine-instruction nodes, and
 * decides the address-computation SHAPE that #112 is all about:
 *   walker-pointer  vs  base+displacement  vs  scaled-index (Xx) form,
 *   and whether to materialize a new IV register + `addi` increment per loop.
 *
 * ENABLE GATE (confirms the frontier lever): the whole pass is skipped unless
 *   the global flag *(int*)0x5e9714 != 0.  That flag = `opt_strength_reduction`.
 *   `#pragma opt_strength_reduction off` (or -Ono_strength) => 0 => pass no-ops,
 *   so the ISEL-default address forms survive untouched. This is WHY the pragma
 *   is a reliable #112 lever (see LEVERS + frontier fn_80137DF8 / dll_1CE cases).
 *
 * CONFIDENCE: control-flow, struct offsets, and the enable gate are read直 from
 * the binary (HIGH). galloc=0x440ce0, arena begin/end 0x56e0b0/0x440bf0, PCode
 * node kinds 0x3c/0x3f/0x89 and opcode tags are cross-checked against Coloring.c
 * / ValueNumbering.c. Inferred names marked [inf]. Where the exact semantic of a
 * node-field is not 100% pinned it is flagged RETRACTABLE.
 * ==========================================================================*/

/* ---------------------------------------------------------------------------
 * Environment / globals (all VA, image base 0x400000)
 * ------------------------------------------------------------------------- */
extern int   gDoStrengthReduce;   /* 0x5e9714  = opt_strength_reduction flag   */
extern int   gTempCount;          /* 0x5e9b14  running #virtual regs (RegisterInfo)*/
extern int   gTempCountSnap;      /* 0x5e2b98  snapshot at pass entry            */
extern u32  *gDefBits;            /* 0x5e2ba0  per-pass def bitvector (galloc'd) */
extern u32  *gUseBits;            /* 0x5e2b9c  per-pass use bitvector (galloc'd) */
extern void *gChanged;            /* 0x5e98cc  "IR changed" flag (fn0x571730)    */
extern void **gRegDefLists;       /* 0x5e9a70  reg -> list of defining instrs    */
extern void **gRegUseLists;       /* 0x5e9a94  reg -> list of using instrs       */
extern void **gInstrTable;        /* 0x5e966c  packed (instr,def) table (stride 10)*/
extern void **gInstrTable2;       /* 0x5e972c  packed instr table #2 (stride 10) */
extern void **gBlockTable;        /* 0x5e9a4c  block table (stride 0x20)         */

extern void *galloc(int n);       /* 0x440ce0  compiler arena allocator          */
extern void  ArenaPush(int);      /* 0x56e0b0  [inf] scoped-arena begin          */
extern void  ArenaPop(void);      /* 0x440bf0  [inf] scoped-arena end            */
extern void *AllocInstr(int,...); /* 0x4dd4d0  new PCode node (also used by SR)   */
extern void  DeleteInstr(void*);  /* 0x4dd120                                     */
extern void  SpliceInstr(void*,void*); /* 0x4dd0a0                               */
extern void  Assertion(int line, char *file); /* 0x463760                        */

/* ---- the PCode INSTRUCTION node (offsets from the accesses in this TU) ------
 * (matches the node shape used across Coloring/ValueNumbering)                 */
typedef struct Instr {
    /* +0x00 */ struct Instr *next;    /* next instr in block                    */
    /* +0x04 */ int           index;   /* packed-table row index (*5, into 0x5e966c/972c) */
    /* +0x08 */ void         *block;   /* owning block / list-head for splice    */
    /* +0x14 */ int           attr;    /* attribute bits (0x1,0x9,0x6, 0x20000000)*/
    /* +0x18 */ s16           dstReg;  /* operand-0 register (destination)       */
    /* +0x1a */ s16           f1a;
    /* +0x1c */ s16           f1c;     /* SR-emitted node: 0xffff sentinel       */
    /* +0x1e */ s16           f1e;     /*                  0xffff sentinel        */
    /* +0x20 */ s16           opcode;  /* OPCODE TAG (the isel node kind)         */
    /* +0x22 */ s16           nOperands;
    /* +0x24 */ struct Operand operands[1]; /* each 0xc: [+0]=kind [+1]=class    */
    /* --- fields used by the address/IV forms (union-ish over the base type) -- */
    /* +0x28 */ s16           useReg;  /* the IV/index register this node reads   */
    /* +0x34 */ s16           baseA;   /* candidate base register #1             */
    /* +0x3e */ int           constK;  /* the CONSTANT (stride / displacement)    */
    /* +0x40 */ s16           baseB;   /* candidate base register #2             */
    /* +0x4a */ int           f4a;     /* shift-form: nonzero => reject          */
    /* +0x56 */ int           f56;     /* shift-form: must equal 31-shift        */
} Instr;

/* ---- the per-loop SR CANDIDATE record (galloc 0x1a bytes, list at loop+0x30) */
typedef struct SRCand {
    /* +0x00 */ struct SRCand *next;   /* candidate list                         */
    /* +0x04 */ void         *loop;    /* owning loop                            */
    /* +0x08 */ void         *f08;     /* 0                                       */
    /* +0x0c */ void         *useCells;/* list of {next; instr@+4} using cells    */
    /* +0x10 */ void         *baseDef; /* the loop-INVARIANT defining instr (base)*/
    /* +0x14 */ int           stride;  /* the IV increment (from Instr.constK)    */
    /* +0x18 */ s16           ivReg;   /* the induction register                 */
} SRCand;

/* ---- the LOOP node (partial; from the walkers) ----------------------------
 * loop+0x08 = child loop (nested), loop+0x04 = sibling, loop+0x0c = header blk,
 * loop+0x1c = block list, loop+0x20 = per-loop def bitvector, loop+0x30 = SRCand
 * list head.                                                                    */

/* ===========================================================================
 * StrengthReduction  @ 0x572c80   — the PASS DRIVER (public entry)
 *   Called from the optimizer driver (0x500752/0x500af8, PCodeListing band).
 * ==========================================================================*/
void StrengthReduction(void *loopForest)
{
    gChanged2 = 0; gAux1 = 0; gAux2 = 0;         /* 0x5e9b20/0x5e8ff8/0x5e9ab4  */
    if (!gDoStrengthReduce)                        /* <<< THE ENABLE GATE >>>    */
        return;                                    /* opt_strength_reduction off */
    ArenaPush(0);                                              /* 0x56e0b0       */
    gTempCountSnap = gTempCount;                               /* 0x5e9b14       */
    gDefBits = galloc(4 * ((gTempCountSnap + 31) >> 5));       /* one bit/temp   */
    gUseBits = galloc(4 * ((gTempCountSnap + 31) >> 5));
    SR_WalkLoops(loopForest);                                  /* 0x572d10       */
    ArenaPop();
}

/* ===========================================================================
 * SR_WalkLoops  @ 0x572d10   — descend the loop forest (up to 6 nest levels
 *   are hand-unrolled: loop->child->child... via +0x8), innermost-first, and
 *   for each loop run the collector then the rewriter.
 * ==========================================================================*/
static void SR_WalkLoops(void *loop)
{
    for (; loop; loop = *(void**)((char*)loop + 4)) {         /* sibling chain   */
        void *inner = *(void**)((char*)loop + 8);            /* child           */
        if (inner) SR_WalkLoops(inner);                       /* recurse         */
        /* the 6-deep manual unroll in the binary is just this recursion
         * inlined; net effect = post-order over the loop tree.                  */
        SR_CollectCandidates(loop);                           /* 0x572810        */
        SR_RewriteLoop(loop);                                 /* 0x572180        */
    }
}

/* ===========================================================================
 * SR_CollectCandidates  @ 0x572810 -> SR_ScanNode 0x572990 -> SR_Register 0x572ad0
 *   Walks EVERY expression node of the loop (0x572810 is a 6-deep tree walker
 *   over child(+8)/sibling(+4)), and for each node SR_ScanNode:
 *     - iterate the block/instr list (blk+0x1c ; instr->next)
 *     - a node qualifies if  opcode(+0x20) == 0x3f  (the add-immediate/IV form)
 *       AND its useReg(+0x28) >= 0x20 (a virtual temp, not a precolored reg)
 *       AND instr.dstReg(+0x34) == useReg  (self-recurrent: t = t + K)
 *     - then across ALL defs of that reg confirm the SAME (reg, K) linear form
 *       (the +0x34/+0x3e cross-check loop); a divergent def kills the candidate.
 *   A surviving (ivReg, stride) is handed to SR_Register.
 * ==========================================================================*/
static void SR_ScanNode(void *loop)
{
    for (Instr *blk = loop->blocks; blk; blk = blk->next)          /* +0x1c     */
      for (Instr *in = blk->instrs; in; in = in->next) {
        if (in->opcode != 0x3f) continue;                          /* IV form?  */
        s16 iv = in->useReg;                                       /* +0x28     */
        if (iv < 0x20) continue;                                   /* real temp?*/
        if (in->dstReg != iv) continue;                            /* recurrent?*/
        int stride = in->constK;                                   /* +0x3e     */
        /* verify every OTHER def of iv is the identical linear update */
        int consistent = 1;
        for (Cell *d = gRegDefLists[iv]; d; d = d->next) {
            Instr *di = tableRow(gInstrTable, d->instr);
            if (!inLoop(di, loop)) continue;
            if (di->opcode != 0x3f || di->dstReg != iv || di->constK != stride)
                { consistent = 0; break; }
        }
        if (consistent) SR_Register(loop, stride, iv);             /* 0x572ad0  */
      }
}

/* ===========================================================================
 * SR_Register  @ 0x572ad0   — add (or dedup) a candidate for this loop.
 * ==========================================================================*/
static void SR_Register(void *loop, int stride, s16 ivReg)
{
    for (SRCand *c = loop->cands; c; c = c->next)                  /* +0x30     */
        if (c->ivReg == ivReg) return;                            /* dedup     */
    SRCand *c = galloc(0x1a);
    c->next = loop->cands; loop->cands = c;
    c->loop = loop; c->f08 = 0; c->useCells = 0;
    c->stride = stride; c->ivReg = ivReg;
    /* build the USE list: every in-loop instr that reads ivReg becomes a cell */
    for (Cell *u = gRegDefLists[ivReg]; u; u = u->next) {          /* +0x30 def */
        Instr *ui = tableRow(gInstrTable, u->instr);
        if (inLoop(ui, loop)) { Cell *k = galloc(8); k->next=c->useCells;
                                c->useCells=k; k->instr=ui; }
    }
    c->baseDef = SR_FindInvariantBase(ivReg, loop);               /* 0x572bb0  */
}

/* ===========================================================================
 * SR_FindInvariantBase @ 0x572bb0  — among the defs of a reg, return the one
 *   that is LOOP-INVARIANT (not in the loop's def-bitvector loop+0x20) whose
 *   opcode is 0x89 / 0x3f / 0x3c; else 0. This is the "start value" of the IV.
 * ==========================================================================*/

/* ===========================================================================
 * SR_RewriteLoop  @ 0x572180   — the REWRITE driver. Post-order over the loop
 *   tree again; for each candidate whose ivReg is defined in this loop
 *   (loop+0x20 bit set), for each USE of the reg, calls SR_AnalyzeUse; if it
 *   says the use is reducible, calls SR_EmitNewIV to replace it.
 *   There are TWO nearly identical passes (0x5721f7 and 0x5722c7) — the first
 *   over gRegUseLists[ivReg] (address USES), the second re-scan (the redundant
 *   copy is how MWCC iterates to a fixpoint within the loop).
 * ==========================================================================*/
static void SR_RewriteLoop(void *loop)
{
    /* recurse children first */
    for (Loop *sub = loop->child; sub; sub = sub->sibling) SR_RewriteLoop(sub);
    for (SRCand *c = loop->cands; c; c = c->next) {
      for (Cell *u = gRegUseLists[c->ivReg]; u; u = u->next) {
        Instr *use = tableRow(gInstrTable2, u->instr);
        if (!definedInLoop(c->ivReg, use, loop)) continue;         /* +0x20 bit */
        s16   newReg;   /* out */
        s16   stride;   /* out */
        s16   baseSel;  /* out */
        void *matchDef; /* out */
        if (SR_AnalyzeUse(c, use, &newReg, &stride, &baseSel, &matchDef)) /*0x572520*/
            SR_EmitNewIV(c, use, tableRow(gInstrTable2, use->index),
                         newReg, stride, baseSel, matchDef);       /* 0x5724b0  */
      }
    }
}

/* ===========================================================================
 * SR_AnalyzeUse  @ 0x572520   *** THE #112 DECISION FUNCTION ***
 *   out params (by the caller's stack layout): *pDisp, *pReg, *pStride(s16),
 *   *pMatch.  Returns 1 if the use is a reducible address/scaled node.
 *
 *   STEP 1 — classify use->opcode (in->opcode = *(s16*)(use+0x20)):
 *     The `sub eax,0x17 ; je …` decode chain enumerates the ELIGIBLE node kinds.
 *     Grouped by target label:
 *       * label 0x572642  (the ADDRESS/ADD-with-base group): opcodes whose
 *         (op-0x17) hits any of the cumulative sums -> these are the
 *         load/store *effective-address* nodes and integer add-with-base nodes.
 *         => go to STEP 2 (base-select + walker/disp decision).
 *       * op == 0x2d  (0x17+0x16)  -> label 0x5725c8: a MULTIPLY-BY-CONST.
 *         Capture the multiplier constant (in->constK, +0x3e) into *pDisp and
 *         fall to STEP 3 (single-use test).
 *       * op == 0x4b  (…+0x1e)     -> label 0x5725d6: a SHIFT/rlwinm scale.
 *         Reject unless:  f4a(+0x4a)==0  AND  constK(+0x3e) <= 15  AND
 *         f56(+0x56) == 31 - constK  AND  (attr & 9)==0  AND  (attr&0x20000000)==0.
 *         i.e. it must be a clean `slwi`-style power-of-2 scale with no side
 *         attributes.  Then *pDisp = (1 << constK) and fall to STEP 3.
 *       * anything else -> label 0x572790: return 0 (NOT reducible).
 *
 *   STEP 2 — BASE SELECTION + the WALKER-vs-DISPLACEMENT choice (label 0x572642):
 *     Zero *pReg,*pStride,*pMatch.  Let ivReg = cand->ivReg (use+0x18 via +0x24).
 *       if (in->baseA(+0x34) == ivReg) { *pReg=1; *pStride=2; order=(1,2); }
 *       else if (in->baseB(+0x40) == ivReg) { *pReg=2; *pStride=1; order=(2,1);}
 *     (so it identifies WHICH operand slot carries the IV and picks the OTHER as
 *      the invariant base — the order flags feed operand emission in EmitNewIV.)
 *
 *     ** THE GATE THAT PICKS THE SHAPE ** — it now counts in-loop DEFINITIONS of
 *     the *other* (base) operand across the whole loop (the `ebp` counter over
 *     gRegDefLists[baseOperand]):
 *          if (baseDefsInLoop != 0) return 0;      // 0x5726d7
 *     => the non-IV base must be LOOP-INVARIANT. If the "base" is itself
 *        recomputed in the loop (e.g. a second induction / a reloaded global),
 *        the use is NOT reduced -> the isel-default (indexed `Xx`, or add;addi)
 *        form SURVIVES. THIS is the mechanism behind the resistant #112 cases:
 *        "target deliberately recomputes the volatile address" (mmFreeTick),
 *        and "global-symbol-array base VNs through" — the base has an in-loop
 *        def/redef, so SR bails and the default indexed form stays.
 *
 *     Then it counts USES of the base operand (the 0x5726f6/0x572737/0x57275c
 *     loop building `bx`): it walks the def-chain, the operand's own use list,
 *     and the candidate's baseDef(+0x10); the final gate
 *          if (baseUseCount != 0) return 0;        // 0x57275d
 *     means: the invariant base must have NO other competing use inside the
 *     loop for the reduction to fire cleanly; if it does, keep the original.
 *     On success: *pMatch = the last invariant base instr, *pDisp = 1, return 1.
 *
 *   STEP 3 — the SINGLE-USE test for MUL/SHIFT scaled indices (label 0x5727a0):
 *     Count uses of in->useReg(+0x28) across gRegDefLists (the `ebx` counter):
 *          if (useCount != 1) return 0;            // 0x5727e9 (cmp ebx,1; jne)
 *          else return 1;
 *     => a *(base + iv*SCALE) address is reduced to a walker ONLY when the
 *        scaled index is used EXACTLY ONCE. Multiple uses of the same scaled
 *        index (the classic "slwi once, add twice" / "per-group vs per-element"
 *        shape) FAIL this test -> MWCC keeps the `slwi ; add/addi ; Xx` isel
 *        form and re-folds the constant onto the scaled index. THIS is the exact
 *        rule behind the frontier verdict "SCALE>1 K-fold is resistant for
 *        SINGLE-USE OR RECOMPUTED accesses" and "power-of-2 slwi is dead":
 *        a power-of-2 scale reaches STEP 3, and unless it is used exactly once
 *        AND its base is invariant, it is never strength-reduced to a walker.
 * ==========================================================================*/
static int SR_AnalyzeUse(SRCand *cand, Instr *use,
                         s16 *pReg, s16 *pStride, s16 *pDisp, void **pMatch)
{
    Instr *in = tableRow(gInstrTable2, use->index);
    *pReg = 0; *pStride = 0; *pMatch = 0;
    int op = in->opcode;                                          /* +0x20      */

    if (isAddressOrAddWithBase(op)) {          /* the 0x572642 group           */
        *pReg = 0; *pStride = 0;
        s16 iv = cand->ivReg;
        s16 order_a, order_b;
        if (in->baseA == iv)      { *pReg = 1; *pStride = 2; order_a=1; order_b=2; }
        else if (in->baseB == iv) { *pReg = 2; *pStride = 1; order_a=2; order_b=1; }
        s16 base = *(&in->baseA + (order_b - 1)*6/2 /*picks the non-IV operand*/);
        if (countInLoopDefs(base, cand->loop) != 0) return 0;     /* base must be invariant */
        if (countInLoopUses_of_base(base, in, cand) != 0) return 0;/* no competing use */
        *pMatch = lastInvariantBaseInstr;                         /* +0x38 out  */
        *pDisp = 1;
        return 1;
    }
    if (op == 0x2d) {                          /* MUL by const                  */
        *pDisp = in->constK;                                     /* multiplier  */
        return (countUses(in->useReg, cand->loop) == 1);         /* STEP 3      */
    }
    if (op == 0x4b) {                          /* SHIFT (slwi) scale            */
        if (in->f4a != 0) return 0;
        if (in->constK > 15) return 0;
        if (in->f56 != 31 - in->constK) return 0;                /* clean slwi  */
        if (in->attr & 9) return 0;
        if (in->attr & 0x20000000) return 0;
        *pDisp = (1 << in->constK);                              /* scale       */
        return (countUses(in->useReg, cand->loop) == 1);         /* STEP 3      */
    }
    return 0;                                   /* label 0x572790: not reducible */
}

/* ===========================================================================
 * SR_EmitNewIV  @ 0x5724b0  (and the sibling emitter @ 0x572407)
 *   galloc a fresh 0x20-byte PCode node and splice it into the use's block list
 *   (node+0x8 insert).  It records:
 *     node+0x14 = type (from the analyze out),  node+0x18 = newReg,
 *     node+0x1a = stride,  node+0x10 = base pointer (the invariant base instr),
 *     node+0x1c = (attr&6 ? 0xffff : base->useReg)   -- addressing-mode class,
 *     node+0x1e = 0xffff.
 *   This IS the "pointer walker" node: a self-incrementing IV register that
 *   absorbs the base (see frontier: `mr walker,base ; lwz K(walker) ; addi
 *   walker,4`). The +4/+K increment = the candidate stride; the displacement K
 *   that remains on the load is the analyzed *pDisp.
 * ==========================================================================*/

/* ===========================================================================
 * fn @ 0x571730  (the two assert sites)  — a MATCH helper: given (a,b) operand
 *   descriptors it asserts each reg-field(+0x18) >= 0 (0x3a2/0x3a6), then scans
 *   the loop's instr list for an existing IV/base instr whose operands equal
 *   (class 0/4, reg == a) — i.e. "does an equivalent reduced IV already exist?"
 *   so the emitter can REUSE it instead of creating a duplicate. (This is the
 *   in-pass CSE of induction variables; not the #112 decision, but explains why
 *   two accesses that share an IV collapse to ONE walker.)
 * ==========================================================================*/

/* ============================================================================
 * ===  DERIVED #112 SOURCE LEVERS (each tied to a code path above)  =========
 * ============================================================================
 * L1 (ENABLE GATE, 0x5e9714): `#pragma opt_strength_reduction off` around a fn
 *     disables the ENTIRE pass -> every address keeps its ISEL-default form.
 *     Use when TARGET itself uses the indexed `Xx` / add;addi form and MWCC's
 *     default would strength-reduce it to a walker. DIRECTIONAL (frontier-proven):
 *     SR-off matches when target is indexed; REGRESSES when target is walker/disp.
 *
 * L2 (STEP-3 single-use, 0x5727e9): a *scaled* index (mul or slwi) is reduced to
 *     a walker ONLY if used EXACTLY ONCE and its base is invariant. To FORCE the
 *     walker (target walks): give the scaled index exactly one use. To FORCE the
 *     indexed/disp form (target indexes): make the SAME scaled index feed TWO+
 *     accesses (the "slwi once, add twice" shape) -> STEP 3 fails -> no reduction.
 *     This is why sharing a multi-use element pointer (SaveGame/ObjSeq wins) or
 *     conversely re-deriving per access flips the shape.
 *
 * L3 (STEP-2 invariant-base, 0x5726d7 & 0x57275d): the non-IV base must be
 *     LOOP-INVARIANT and have no competing in-loop use. If TARGET keeps the
 *     default indexed form, INTRODUCE an in-loop (re)definition or an extra use
 *     of the base (e.g. reload the global inside the loop, or reuse the base reg
 *     for another value) -> SR bails. If TARGET uses a walker, HOIST the base to
 *     a single loop-invariant local with no other uses so both gates pass.
 *     (Explains "global-symbol-array base VNs through" resistance and the
 *      "target deliberately recomputes the volatile addr" reversals.)
 *
 * L4 (IV-CSE, fn 0x571730): two address uses that reduce to the SAME (base,iv)
 *     collapse to ONE walker. To keep TWO separate walkers/pointers (target has
 *     two), make the two uses NOT operand-identical (different base or stride);
 *     to merge them (target has one), make them identical.
 *
 * NON-LEVERS (the pass has no knob for these — do not chase):
 *   * The displacement value K left on the load after reduction is whatever the
 *     address expression carried; you cannot independently tune walker-stride vs
 *     residual-disp — they come from (stride, *pDisp) together.
 *   * Operand order flags (order_a/order_b) are set by which slot the IV lands
 *     in (baseA vs baseB), which is fixed by the isel node, not by C spelling of
 *     a+b vs b+a (add is commuted before this pass).
 * ==========================================================================*/
