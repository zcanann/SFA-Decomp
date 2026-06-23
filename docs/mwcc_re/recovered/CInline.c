/* ============================================================================
 * RECOVERED (decision heuristic): mwcceppc.exe (GC/2.0)
 *   TU = CInline.c   band 0x55bcb0-0x5624a0  (55 functions)
 * Disassembly: docs/mwcc_re/disasm/CInline.c.objdump.txt
 *
 * The inliner (`-inline auto` + `#pragma dont_inline`). The full substitution
 * machinery is 55 functions; what matters for MATCHING is the DECISION: will a
 * given call be inlined? That's gated by InlineSizeOK (0x55c2e0) + the
 * eligibility checks in CanInlineCall (0x55c350). Both decoded below; the rest
 * (actual body cloning/renaming) is not line-decoded.
 * ==========================================================================*/

/* ===========================================================================
 * InlineSizeOK  @ 0x55c2e0   — the auto-inline SIZE/COST gate  [decoded]
 *   Returns true (inlineable) iff the callee body is small enough:
 *     1. statement count (excluding stmt types 1 and 2) <= 30, AND
 *     2. sum of per-node cost (node->0xe->0x2) over the body's node list
 *        (0x5e99c4) <= 1024.
 *   Either limit exceeded -> not inlineable.
 * ==========================================================================*/
static int InlineSizeOK(void *body)
{
    void *stmt; int n = 0; int cost = 0; void *node;

    for (stmt = body; stmt; stmt = *(void**)stmt) {            /*       0x55c2f0 */
        u8 t = *(u8*)((char*)stmt + 4);
        if (t != 1 && t != 2) n++;                             /* count real stmts */
        if (n > 30) return 0;                                  /* > 30 stmts  0x55c2fe */
    }
    for (node = gNodeList /*0x5e99c4*/; node; node = *(void**)node) { /*  0x55c320 */
        void *p = *(void**)((char*)node + 4);
        cost += *(u16*)((char*)*(void**)((char*)p + 0xe) + 2); /* node->0xe->0x2 */
    }
    return cost <= 0x400;                                      /* > 1024 cost 0x55c32f */
}

/* ===========================================================================
 * CanInlineCall  @ 0x55c350   — per-call eligibility  [partly decoded]
 *   For a call, decides whether to inline. Checks (in order):
 *     - callee descriptor flags (desc->0xe->0x16): bit 0x100 set + bit 0x2 clear
 *       gate the auto path (the `inline`/eligible markers).
 *     - recursion guard: walks the active-inline stack (0x5e2af0); if the callee
 *       is already being inlined up the chain, refuse (no recursive inline).
 *     - dont_inline pragma state + the size gate (InlineSizeOK).
 *   AND — implicit but decisive for matching — MWCC can only inline a call whose
 *   callee BODY is available in THIS translation unit (defined earlier in the
 *   same .c, or declared inline with a visible body). A call to a function in a
 *   DIFFERENT TU is never inlined (no body) -> it emits a `bl`.
 * ==========================================================================*/
int CanInlineCall(void *callNode);   /* flags+recursion+size; body in disasm   */

extern void *gNodeList;   /* 0x5e99c4  the body's node list (cost is summed here)*/
extern void *gInlineStack;/* 0x5e2af0  active-inline chain (recursion guard)     */

/* ===========================================================================
 * MATCHING MODEL (inlining)
 *
 * A call is auto-inlined (under `-inline auto`) iff ALL hold:
 *   (a) the callee's BODY is available in this TU (same .c, or visible inline),
 *   (b) callee size: <= 30 statements AND <= 1024 cost units (InlineSizeOK),
 *   (c) not blocked by `#pragma dont_inline on`,
 *   (d) not recursive (callee not already on the inline chain).
 *
 * Matching consequences:
 *  - **Target inlined a call your build emits as `bl` (extra RELOC to a fn_):**
 *    almost always (a) — the callee lives in a DIFFERENT .c in the decomp split
 *    but was in the SAME TU in the original. FIX = move the callee into the same
 *    .c (or the split is wrong). This is a file-organization match, not a code one.
 *  - **Target emits a `bl` where your build inlined:** the callee crossed a size
 *    threshold (just over 30 stmts / 1024 cost), or the original had
 *    `#pragma dont_inline on` around it. FIX = restore the pragma, or the callee
 *    body differs in size.
 *  - A trivial accessor (1-2 stmts) inlined in the target but called in yours is
 *    the classic "wrong TU" tell.
 * ==========================================================================*/
