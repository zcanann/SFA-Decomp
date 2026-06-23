/* ============================================================================
 * RECOVERED (entry + kill + model): mwcceppc.exe (GC/2.0)
 *   TU = IroCSE.c   band 0x46a360-0x46bef0  (17 functions)
 * Disassembly: docs/mwcc_re/disasm/IroCSE.c.objdump.txt
 *
 * The GLOBAL (cross-block, IR-level) common-subexpression pass = the hoisting
 * half of `opt_common_subs`. Unlike the per-block ValueNumbering.c (which only
 * substitutes a redundant USE to the first-occurrence web), IroCSE runs a
 * forward AVAILABLE-EXPRESSION dataflow over the flowgraph and can move/replace
 * an expression across blocks — this is what hoists a CSE temp to a dominator or
 * leaves it at first-use, the PlayControl/matcher-2 residual.
 *
 * STATUS: driver 0x46a360 + kill 0x46aaa0 decoded; the available/kill model is
 * pinned. Replacement (0x4692a0) and expr-equality (0x469dd0) live in IroUtil.c;
 * bit-vector ops are IroBitVect.c (0x52bxxx). [inf] on helper internals.
 * ==========================================================================*/

extern void *gFunc;        /* 0x5e9868  function IR (flowgraph)                 */
extern u32 **gAvailSet;    /* 0x5e9d28  current AVAILABLE-expression bit-vector  */
extern u32 **gKillSet;     /* 0x5e9d6c  killed-this-stmt bit-vector              */
extern void *gExprList;    /* 0x5e984c  list of CSE-candidate expressions        */
extern u8    gKillByOp[];  /* 0x5ea2a9  per-opcode "kills memory" flag           */

extern int  Expr_Equal(void *a, void *b);     /* 0x469dd0  (IroUtil)             */
extern void Expr_Replace(void *use, void *def);/* 0x4692a0  replace use w/ def ref*/
extern void *Stmt_KilledMem(void *stmt);      /* 0x4626f0  the clobbered location */
extern void BitVec_Copy(u32 *dst);            /* 0x52bdd0 etc.                    */

/* ===========================================================================
 * IroCSE_Run  @ 0x46a360   — available-expression global CSE driver
 *   For each block (gFunc->blocks via +0x32/+0x34) and each statement (+0xe..):
 *     1. AVAIL TEST + REPLACE: if this expression equals one already AVAILABLE
 *        (its bit set in gAvailSet AND Expr_Equal vs the live candidate in
 *        gExprList), REPLACE this occurrence with a reference to that earlier
 *        def (Expr_Replace 0x4692a0) and mark it (flags|=8). The earlier def is
 *        the one that keeps its computed value -> the CSE "temp" lives THERE.
 *     2. GEN: set this expression's bit in gAvailSet (now available downstream).
 *     3. KILL: IroCSE_KillStmt(stmt) removes expressions this statement clobbers.
 * ==========================================================================*/
void IroCSE_Run(void)
{
    void *blk, *stmt, *cand;
    for (blk = gFunc /*->blocks*/; blk; blk = *(void**)((char*)blk+0x32))
      for (stmt = *(void**)((char*)blk+0xe); stmt; stmt = *(void**)((char*)stmt+0x34)) {
        void *e = *(void**)((char*)stmt+0x12);
        if (e && /* expression node */ ( *(u16*)((char*)e+2) & 8) == 0) {
            /* walk live candidates; if one is available & equal, replace */
            for (cand = gExprList; cand; cand = *(void**)((char*)cand+0x26)) {
                int idx = *(u16*)((char*)cand+2);                  /* expr id   */
                if (idx < *gAvailSet[0] &&                         /* in range  */
                    (gAvailSet[idx>>5] & (1u<<(idx&31))) &&        /* AVAILABLE 0x46a3dc */
                    Expr_Equal(e, cand) /* and not killed */) {
                    Expr_Replace(e, cand);     /* use -> ref to earlier  0x46a3fb */
                    *(u16*)((char*)stmt+2) |= 8;
                    break;
                }
            }
            int id = *(u16*)((char*)e+2);
            gAvailSet[id>>5] |= (1u<<(id&31));                     /* GEN  0x46a43d */
        }
        IroCSE_KillStmt(stmt);                                     /*      0x46a452 */
      }
}

/* ===========================================================================
 * IroCSE_KillStmt  @ 0x46aaa0   — remove expressions clobbered by `stmt`
 *   Switches on the IR opcode (jump table 0x5aae6c, op-2). For a store/call/def
 *   node that may write memory (gKillByOp[op]/0x5ea2a9 set), it finds the
 *   clobbered location (Stmt_KilledMem 0x4626f0) and walks gExprList, clearing
 *   the avail/kill bit of every expression that reads a may-aliasing location.
 *   => A CALL or aliasing STORE between two uses of a memory-load expression
 *      KILLS it, so the second use is NOT redundant and is RECOMPUTED.
 * ==========================================================================*/
void IroCSE_KillStmt(void *stmt);  /* decoded structurally above; body in disasm */

/* ===========================================================================
 * CSE CANDIDACY — what enters gExprList (0x46b2e0 + 0x457540)  [decoded]
 *   IroCSE_BuildCandidates (0x46b232) walks blocks/statements; for each it calls
 *   IroCSE_AddCandidate (0x46b2e0), which adds the expr to gExprList (0x5e984c)
 *   ONLY IF all three hold:
 *     1. node flag bit1 set (it's an expression statement),
 *     2. IsCSEEligible(node) (0x457540) is true, AND
 *     3. NO sub-node carries flag 0x10000 (disqualifier; subtree-walk 0x4692a0
 *        with callback 0x46b3e0 — a volatile/non-reusable marker).
 *   IsCSEEligible (0x457540) is gated by a per-node-SUBTYPE table:
 *     eligible iff  gCSEEligible[node->subtype] != 0   (0x5def68[node->0x1]).
 *     (Plus special-casing for load/address subtypes 0xf/0x10.)
 *   => Whether an expression (e.g. a const SDA2 load) is a reusable CSE candidate
 *   is decided by its OPERATION SUBTYPE, set during InstrSelection — NOT by a
 *   source spelling you can toggle. So if two builds differ on candidacy for the
 *   "same" const, the difference is the node subtype the front-end assigned, which
 *   isn't a clean-C knob. Such a residual is bankable (interference/codegen-bound),
 *   unless a genuine source restructure changes the expression's subtype.
 * ==========================================================================*/

/* ===========================================================================
 * MATCHING MODEL (the PlayControl rule)
 *
 * Where does a CSE temp materialize, and is it volatile or saved?
 *  - The temp lives at the FIRST AVAILABLE occurrence of the expression (the def
 *    that the later use is replaced with). It is NOT anticipation-hoisted to a
 *    dominator where it wasn't computed — placement follows the FIRST computation
 *    in program order on the dominating path.
 *  - A MEMORY-LOAD expression (e.g. `header.mNumFrames`) is KILLED by any
 *    intervening call/aliasing store. So:
 *      * two uses with a CALL between -> killed -> recomputed each side (VOLATILE,
 *        short live range). This is what PlayControl's TARGET does.
 *      * two uses with NO clobber between -> available -> second replaced, temp at
 *        the first occurrence. If that first occurrence is in a dominator block
 *        before a call, the temp is live across the call -> SAVED register.
 *  - A REGISTER local caching the load is NOT a memory expression, so a call does
 *    NOT kill it -> it stays available across the call -> hoisted/saved. (This is
 *    why matcher-2's single-def local got pushed to a saved reg.)
 *
 * => PlayControl fix direction: keep the divisor a DIRECT memory load at each
 *    modulo (a killable memory expression, NOT a cached local), and order the
 *    operands so the FIRST divisor load occurs at the target's first-use point
 *    (after the dividend `A+B`, not at block-top). The call in the branch then
 *    kills it across the branch so it stays volatile and is recomputed where the
 *    target recomputes — matching the first-use/volatile shape.
 * ==========================================================================*/
