/* ============================================================================
 * RECOVERED (decision): mwcceppc.exe (GC/2.0)  TU = IroPropagate.c
 *   band 0x470060-0x471680  (10 functions)
 * Disassembly: docs/mwcc_re/disasm/IroPropagate.c.objdump.txt
 *
 * Copy/constant propagation (the `#pragma opt_propagation` pass). The driver
 * (0x470060) collects propagatable assignments as candidates and substitutes
 * the RHS at downstream uses (eliminating the copy when all uses are replaced).
 * The DECISION — what is propagatable — is IsPropagatable (0x4709f0), decoded.
 * ==========================================================================*/

extern void *gFunc;           /* 0x5e9868 */
extern void *Expr_Var(void *node);     /* 0x46a330  symbol/var of an expr      */
extern int   Expr_IsLeaf(void *node);  /* 0x46a300  const / simple leaf?       */
extern int   Var_Escaped(void *var);   /* 0x4e76a0  volatile / address-taken?  */
extern int   Type_Compatible(void*,void*); /* 0x46a1c0                          */

/* ===========================================================================
 * IsPropagatable  @ 0x4709f0   — can this assignment's RHS be propagated?
 *   Returns true iff:
 *     - the statement is an ASSIGNMENT (opcode 3, subtype 0x1e), AND
 *     - the LHS is a variable whose type matches and is NOT volatile/address-
 *       taken (Var_Escaped false), AND
 *     - either the RHS is a simple/const leaf (Expr_IsLeaf -> constant
 *       propagation), OR the RHS is a variable that is not escaped and is
 *       type-compatible with the LHS (copy propagation).
 *   Any volatile/address-taken operand, non-leaf non-var RHS, or type mismatch
 *   -> NOT propagatable (the copy/assignment stays).
 * ==========================================================================*/
static int IsPropagatable(void *stmt)
{
    void *lhs, *rhs_var;
    if (*(u8*)stmt != 3) return 0;                  /* assignment       0x4709f7 */
    if (*((u8*)stmt + 1) != 0x1e) return 0;         /* simple-assign kind 0x470a00 */
    lhs = Expr_Var(*(void**)((char*)stmt + 0x20));  /* dest var         0x470a0a */
    if (!lhs) return 0;
    if (*(u16*)((char*)lhs+0xe) != *(u16*)((char*)stmt+0xe)) return 0; /* type   */
    if (Var_Escaped(lhs)) return 0;                 /* dest escaped     0x470a2d */

    if (*(u16*)((char*)*(void**)((char*)stmt+0x20)+2) & 0x80000)      /* dest flag*/
        return Expr_IsLeaf(*(void**)((char*)stmt+0x24)); /* const only  0x470a4c */

    if (Expr_IsLeaf(*(void**)((char*)stmt+0x24))) return 1;  /* const   0x470a6a */
    rhs_var = Expr_Var(*(void**)((char*)stmt+0x24));         /* copy:   0x470a84 */
    if (!rhs_var) return 0;
    if (Var_Escaped(rhs_var)) return 0;             /* src escaped      0x470a95 */
    return Type_Compatible(*(void**)((char*)stmt+0xe),
                           *(void**)((char*)lhs+0xe)); /* types         0x470aab */
}

/* ===========================================================================
 * MATCHING MODEL (propagation) — completes the copy-elimination picture
 *
 * A value `x = y` (or `x = const`) is PROPAGATED (uses of x replaced by y/const,
 * copy potentially deleted) unless x or y is **volatile or ADDRESS-TAKEN**, or
 * the types mismatch. `#pragma opt_propagation off` disables it wholesale.
 *
 * This is the EARLIEST of THREE independent copy-elimination stages — know which
 * one a stuck copy escaped:
 *   1. Propagation (here, IR-level): copy dies unless a side is escaped/volatile.
 *   2. Value-number fold (ValueNumbering 0x5090f2): copy dies if dest/src share a
 *      value number.
 *   3. Coalescer (Coloring 0x508c10): copy dies if its two webs don't interfere.
 * A surviving `mr` escaped ALL THREE. Levers:
 *   - To KILL a copy at the earliest stage: keep both sides non-address-taken,
 *     non-volatile, same type (then propagation folds it).
 *   - To KEEP a copy (match a surviving `mr`): make a side address-taken (`&x`),
 *     volatile, or a type-straddling access — that blocks propagation (and often
 *     VN), so the copy survives to coloring. This is the mechanism behind the
 *     CLAUDE.md "distrust raw derefs / typed-local" idiom: a typed local that's
 *     address-taken or union-aliased keeps values distinct, where a clean scalar
 *     would have been propagated away.
 * ==========================================================================*/
