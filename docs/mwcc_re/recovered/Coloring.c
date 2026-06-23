/* ============================================================================
 * RECOVERED: mwcceppc.exe (GC/2.0)  TU = Coloring.c   band 0x508680-0x509010
 * ----------------------------------------------------------------------------
 * Disassembly: docs/mwcc_re/disasm/Coloring.c.objdump.txt
 * Anchored by assert string "Coloring.c" @ .data 0x5bcbe8.
 *
 * THE PRIZE: the priority graph-coloring register allocator. This decides
 * "which physical register" for every value. 7 of 8 functions are decoded;
 * the actionable matching levers are in docs/mwcc_re/LEVERS.md.
 *
 * It is a textbook CHAITIN-BRIGGS allocator:
 *   driver (0x508680): per class, iterate { BuildInterference; Coalesce;
 *       order = Simplify();  ok = Select(order);  ok ? Apply : InsertSpill }
 *   Simplify (0x508a20): build a stack, removing low-degree webs first (in web-
 *       index order), optimistically spilling the min degree/cost web when stuck.
 *   Select   (0x508900): pop the stack, give each web the LOWEST free register
 *       not used by an interfering neighbor; spill if none free.
 *   Apply    (0x5087d0): rewrite each operand's web index -> assigned register.
 *   Coalesce (0x508c10): merge copy src/dst webs (value identity) so the copy
 *       collapses -- this is the `mr`-survival decision from the blog.
 *
 * CONFIDENCE: control flow + offsets are read from the binary (HIGH). Inferred
 * names marked [inf]. The FP compare direction in the spill-cost metric and the
 * upstream coalesce-eligibility flags are noted where not 100% pinned.
 * ==========================================================================*/

/* ---- the WEB (one per value to be colored); array at *(void**)0x5e9858 ----- */
typedef struct Web {
    /* +0x00 */ struct Web *link;     /* next in the simplify stack / temp lists  */
    /* +0x04 */ void       *value;    /* IR value identity (coalesce rewrites it) */
    /* +0x0c */ int         f0xc;     /* RETRACTED "spillCost": the web is bzero'd  */
                                      /* at creation (0x57b470/0x440b80) and +0xc  */
                                      /* is NEVER written -> always 0. The ratio   */
                                      /* degree/f0xc is degree/0 = +Inf for ALL    */
                                      /* webs, so there is NO cost weighting.       */
    /* +0x10 */ u16         index;    /* web index i (set = i by builder 0x57b576;  */
                                      /* NOT "regsNeeded" — earlier over-claim)     */
    /* +0x12 */ s16         degree;   /* WORKING interference degree (mutated)    */
    /* +0x14 */ u16         reg;      /* ASSIGNED physical register (0xffff=none) */
    /* +0x16 */ u16         flags;    /* 1=spilled 2=stacked 4=precolored         */
                                      /* 0x10=coalesce-dst 0x20=coalesce-src      */
                                      /* 0x40=loop-region                         */
    /* +0x18 */ s16         nadj;     /* adjacency length (static degree)         */
    /* +0x1a */ s16         adj[1];   /* neighbor web indices                     */
} Web;

extern Web **gWebArray;       /* 0x5e9858 */
extern int   webStart[5];     /* 0x5e9800  = #physical regs in class (precolored)*/
extern int   webEnd[5];       /* 0x5e9b04  = one-past-last web index of class    */
extern u8    gCurClass;       /* 0x5ea299 */
extern u16   gClassRegCount;  /* 0x5e0898 */

/* the three coalesce move/copy lists (Cell{next; moveRef value at +4}) */
extern void *gCoalesce0;      /* 0x5e9b00 */
extern void *gCoalesce1;      /* 0x5e99c4 */
extern void *gCoalesce2;      /* 0x5e98f4 */
extern void *gBlockList;      /* 0x5e9838  basic-block list (for Apply)          */

extern int   GetAllocRegCount(int cls);   /* 0x4fe520  k; 0 => class uncolorable */
extern u32   GetAllocRegMask(int cls);    /* 0x4fe4d0  bitmask of usable regs    */
extern s16   GetReservedReg(int cls);     /* 0x4fe470  fallback reg, -1 if none  */
extern void *RegInfo_Desc(void *value);   /* 0x4d0150  operand/move descriptor   */
extern int   RegInfo_CanSpill(void *value);/* 0x4d0db0                           */
extern void  RegInfo_Begin(int cls);      /* 0x4d0040 / 0x4d0070                 */
extern void  SpillCode_Begin(void);       /* 0x57cd00 [inf] before spill-select  */
extern float  kFloatMax;     /* 0x5bcbf4 = 0x7f7fffff (FLT_MAX)                  */

/* ===========================================================================
 * Color_Apply  @ 0x5087d0   — commit the coloring
 *   Walk every block/instruction; for each operand of the current class,
 *   replace its web index (operand+0x4) with the web's assigned register
 *   (web+0x14). Then fix up coalesced special instrs via 0x4dd120.
 * ==========================================================================*/
static void Color_Apply(void)
{
    void *blk, *inst; int i; void *op; Web *w;

    for (blk = gBlockList; blk; blk = *(void**)blk)            /*       0x5087d0 */
      for (inst = *(void**)((char*)blk+0x14); inst; inst = *(void**)inst) {
        op = (char*)inst + 0x24;                               /* operands       */
        for (i = (s16)*(s16*)((char*)inst+0x22) - 1; i >= 0; i--, op=(char*)op+0xc) {
            if (*(u8*)op == 0 && *((u8*)op+1) == gCurClass) {  /* reg, this class */
                w = gWebArray[*(s16*)((char*)op+4)];           /*       0x508808 */
                *(u16*)((char*)op+4) = w->reg;                 /* web idx -> reg  */
            }
        }
        if ((*(u32*)((char*)inst+0x14) & 0x10) &&              /* coalesced move  */
            *((u8*)inst+0x31) == gCurClass &&
            *(u16*)((char*)inst+0x34) == *(u16*)((char*)inst+0x28))
            fn_4dd120(inst);                                   /* drop dead move  */
      }
}

/* ===========================================================================
 * Color_Select  @ 0x508900   — assign registers (the Briggs "select")
 *   Walk the worklist `stack` (in pop order); for each web, start from the
 *   class's usable-register mask, clear every bit used by an already-colored
 *   interfering neighbor, then take the LOWEST remaining register. If none is
 *   free, try the reserved reg; else mark the web spilled and report failure.
 *   Returns nonzero iff every web colored (no spill).
 * ==========================================================================*/
static int Color_Select(Web *stack)
{
    int  ok = 1;                                               /*       0x50890b */
    u32  classMask, avail;
    Web *w; int j, r;

    RegInfo_Begin(gCurClass);                                  /*       0x508919 */
    classMask = GetAllocRegMask(gCurClass);                    /*       0x508925 */

    for (w = stack; w; w = w->link) {                          /*       0x508936 */
        avail = classMask;
        for (j = 0; j < (s16)w->nadj; j++) {                   /* clear neighbors */
            Web *nb = gWebArray[w->adj[j]];                    /*       0x508947 */
            u16  nr = nb->reg;
            if (nr == 0xffff) continue;                        /* uncolored       */
            if ((s16)nr >= webStart[gCurClass]) continue;      /* not a phys reg  */
            avail &= ~(0xfffffffe << nr);  /* clears bits <= nr; see note 0x50896f*/
        }
        if (avail != 0) {                                      /* a reg is free   */
            for (r = 0; r < webStart[gCurClass]; r++)          /* LOWEST free reg */
                if (avail & (1 << r)) { w->reg = (u16)r; break;}/*      0x50899e */
        } else {
            r = GetReservedReg(gCurClass);                     /*       0x5089b6 */
            if (r != -1) {
                w->reg = (u16)r;
                classMask |= (1 << r);
            } else {                                            /* SPILL          */
                if (!RegInfo_CanSpill(w->value))               /*       0x5089dc */
                    CError_Assert("Coloring.c", 278);
                w->flags |= 1;                                 /* mark spilled    */
                ok = 0;
            }
        }
    }
    return ok;
}

/* ===========================================================================
 * Color_Simplify  @ 0x508a20   — build the coloring stack  *** THE ORDER ***
 *   k = #allocatable regs for the class. Repeatedly:
 *     pass over webs in INDEX (creation) order; any unprocessed web with
 *     working degree < k is REMOVED (its neighbors' degrees decremented) and
 *     pushed on the stack; high-degree webs are parked. Repeat while progress.
 *   When no low-degree web remains but high-degree ones do, pick the OPTIMISTIC
 *   SPILL: the parked web minimizing  degree/spillCost  (regsNeeded>=regcount =>
 *   FLT_MAX = pinned, never chosen), remove it, and resume simplifying.
 *   Returns the stack head; Select colors webs in this order (lowest reg first).
 * ==========================================================================*/
static Web *Color_Simplify(void)
{
    int  k = GetAllocRegCount(gCurClass);                      /*       0x508a2d */
    Web *stack = 0;                                            /* ebp            */
    Web *parked = 0;                                           /* ebx            */
    int  changed, i, n;
    Web *w;

    do {                                                       /*       0x508a38 */
        changed = 0;
        for (i = webStart[gCurClass]; i < webEnd[gCurClass]; i++) {
            w = gWebArray[i];
            if (w->flags & 6) continue;                        /* stacked/precol  */
            if (w->degree >= k) {                              /* high degree     */
                w->link = parked; parked = w;                  /*       0x508aa0 */
            } else {                                           /* SIMPLIFY remove */
                for (n = 0; n < (s16)w->nadj; n++)             /*       0x508a71 */
                    gWebArray[w->adj[n]]->degree--;            /* relax neighbors */
                w->flags |= 2;                                 /* stacked         */
                w->link = stack; stack = w;                    /* push            */
                changed = 1;
            }
        }
    } while (changed);                                         /*       0x508ab5 */

    while (parked) {                                           /*       0x508bfb */
        Web *best = parked;                                    /* optimistic spill*/
        SpillCode_Begin();                                     /*       0x508ac8 */
        /* The "ratio" the code computes is degree / web->f0xc, and f0xc is ALWAYS
         * 0 (verified: web is bzero'd, +0xc never written) => ratio = +Inf for
         * every web. The min-ratio search (strict <) therefore NEVER updates, so
         * `best` stays the FIRST parked web. Parked is built by prepend over webs
         * in INDEX order [regCount,webEnd), so its head is the HIGHEST-index web.
         * => optimistic spill removes the highest-index high-degree web first.
         * The selection is STRUCTURAL (web index), not cost-weighted.  0x508ad2 */
        for (w = parked; w; w = w->link) {                     /*       0x508b10 */
            /* degree/f0xc(=0) == +Inf; never less than best's +Inf  0x508b3a    */
        }
        for (n = 0; n < (s16)best->nadj; n++)                  /* remove `best`   */
            gWebArray[best->adj[n]]->degree--;
        best->flags |= 2;
        best->link = stack; stack = best;

        do {                                                   /* resume simplify */
            changed = 0; parked = 0;                           /*       0x508b80 */
            for (i = webStart[gCurClass]; i < webEnd[gCurClass]; i++) {
                w = gWebArray[i];
                if (w->flags & 6) continue;
                if (w->degree >= k) { w->link = parked; parked = w; }
                else { for (n=0;n<(s16)w->nadj;n++) gWebArray[w->adj[n]]->degree--;
                       w->flags |= 2; w->link = stack; stack = w; changed = 1; }
            }
        } while (changed);
    }
    return stack;                                              /* ebp     0x508c03*/
}

/* ===========================================================================
 * Color_Coalesce  @ 0x508c10   — merge copies  *** THE `mr` RULE ***
 *   First precolor the physical regs: web[r].reg = r for r in [0, regcount).
 *   Then walk three move/copy lists (0x5e9b00, 0x5e99c4, 0x5e98f4). For each
 *   move whose RegInfo descriptor is a coalesceable copy of THIS class
 *   (desc+0x24 bit1, desc+0x25==class), give the source web (desc+0x26) the
 *   move's value identity (web+0x4 = move->value). If bit2 is also set, mark
 *   src web flag 0x20 and dst web (desc+0x28) flag 0x10, and share identity.
 *   Sharing identity makes Simplify/Select treat src==dst as one web => same
 *   register => the copy is dead and Apply (0x5087d0) drops it. A copy whose
 *   descriptor lacks these flags is NOT coalesced -> the `mr` survives.
 *   (The flags are set UPSTREAM during web/move building; that eligibility test
 *    -- src/dst non-interfering, compatible class -- is the next thing to read.)
 * ==========================================================================*/
static void Color_Coalesce(int cls)
{
    void *mv, *desc; Web *src, *dst; void *val; int r;

    /* precolor physical registers */
    for (r = 0; r < webStart[cls]; r++)                        /*       0x508c33 */
        gWebArray[r]->reg = (u16)r;

    for (mv = gCoalesce0; mv; mv = *(void**)mv) {              /*       0x508c53 */
        val  = *(void**)((char*)mv + 4);
        desc = RegInfo_Desc(val);                              /*       0x508c69 */
        if (!(*(u8*)((char*)desc+0x24) & 2)) continue;         /* coalesceable?   */
        if (*(u8*)((char*)desc+0x25) != cls) continue;         /* class match     */
        gWebArray[*(s16*)((char*)desc+0x26)]->value = val;     /* src identity    */
        if (!(*(u8*)((char*)desc+0x24) & 4)) continue;
        gWebArray[*(s16*)((char*)desc+0x26)]->flags |= 0x20;   /* src marked      */
        gWebArray[*(s16*)((char*)desc+0x28)]->flags |= 0x10;   /* dst marked      */
        gWebArray[*(s16*)((char*)desc+0x28)]->value = val;     /* dst identity    */
    }
    /* gCoalesce1 (0x5e99c4): identical processing                       0x508cd4 */
    /* gCoalesce2 (0x5e98f4): lighter -- only desc+0x24 bit1, src identity 0x508d57*/
}
