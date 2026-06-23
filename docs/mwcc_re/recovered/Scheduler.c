/* ============================================================================
 * RECOVERED: mwcceppc.exe (GC/2.0)  TU = Scheduler.c   band 0x00508100-0x00508680
 * ----------------------------------------------------------------------------
 * Source of truth: build/compilers/GC/2.0/mwcceppc.exe  (image base 0x400000)
 * Disassembly:     docs/mwcc_re/disasm/Scheduler.c.objdump.txt
 *   objdump -d --start-address=0x508100 --stop-address=0x508680 <mwcceppc.exe>
 * Anchored by assert string "Scheduler.c" @ .data 0x5bcbc8, ref'd at 0x508151
 * (push line 0x1d6=470; call CError @0x463760).
 *
 * This is the PowerPC basic-block LIST SCHEDULER's *dependency-graph builder*
 * (the `#pragma scheduling on/off` pass; 312 `off` sites in this game's src/).
 * It does NOT contain the ready-list emit loop itself (that caller lives in the
 * adjacent PCodeListing.c band 0x500c40-0x508100 and is still TODO) — these 5
 * functions construct the dependency DAG that the emit loop then walks.
 *
 * CONFIDENCE: control flow + struct offsets are read directly from the binary
 * and are HIGH confidence. Semantic NAMES (defSites, priority, etc.) are
 * INFERRED from usage and marked [inf]. Edge direction is pinned by the three
 * call sites (def/use/mem) all agreeing: an edge means "A depends on B" with B
 * earlier in program order — see Sched_AddDep. Anything still uncertain says so.
 * ==========================================================================*/

/* ---- PCode operand (12 bytes), array at PCode+0x24, count at PCode+0x22 ---- */
typedef struct PCodeArg {
    u8   kind;       /* +0x00  0 = register operand (only kind that makes deps);
                                1..3 = imm/label/mem -> skipped                */
    s8   regClass;   /* +0x01  register class 0..4 (index into the reg tables) */
    u16  argFlags;   /* +0x02  bit0|bit1 tested; bit1 (0x2) => operand is a DEF */
    s16  reg;        /* +0x04  physical/virtual register number (signed)       */
    /* +0x06..+0x0b: remaining 6 bytes not touched by Scheduler.c              */
} PCodeArg;

/* ---- PCode instruction (the thing a SchedNode wraps) ---------------------- */
typedef struct PCode {
    /* ... */
    u32       flags;     /* +0x14  side-effect class bits (see masks below)    */
    u16       argCount;  /* +0x22  number of PCodeArg entries                  */
    PCodeArg  args[1];   /* +0x24  operand array                              */
} PCode;

/* PCode.flags masks used by Sched_AddInstrDeps (0x508100): */
#define PCF_LOAD       0x00020002   /* reads memory  -> dep on prior stores    */
#define PCF_STORE      0x00040004   /* writes memory -> Sched_AddStoreDeps     */
#define PCF_CALL       0x00000080   /* call/branch   -> ordered via gCallNodes */
#define PCF_SIDEFX_A   0x00000008   /* + the (or-1) / 0x1000000 / 0x100 combo  */
#define PCF_VOLATILE   0x00040000   /* in store handler: also chain into loads */

/* ---- Scheduler DAG node (wraps one PCode); allocated by the emit loop ----- */
typedef struct SchedNode {
    /* +0x00 */ struct SchedNode *next; /* link in the block's node list       */
    /* +0x04 */ u32        payload;     /* [inf] back-ref / value id           */
    /* +0x08 */ struct Dep *deps;       /* head of this node's dependency list */
    /* +0x0c */ PCode      *pcode;      /* the instruction                     */
    /* +0x10 */ u16         baseLatency;/* [inf] this node's own issue latency  */
    /* +0x16 */ u16         priority;   /* [inf] critical-path height (longest  */
                                        /*       weighted dep chain to a root) */
    /* +0x18 */ u16         numUsers;   /* [inf] # of nodes that depend on this */
} SchedNode;

/* ---- dependency edge (10 bytes), allocated by Sched_AddDep ---------------- */
typedef struct Dep {
    /* +0x00 */ struct Dep *next;   /* next edge in the owner's dep list       */
    /* +0x04 */ SchedNode  *on;     /* the (earlier) node this one depends on  */
    /* +0x08 */ u16         weight; /* edge latency                            */
} Dep;

/* ---- simple cons cell (8 bytes) used for the ordering worklists ----------- */
typedef struct Cell { struct Cell *next; SchedNode *node; } Cell;

/* ============================ globals (0x5e08xx) =========================== */
/* Per-register-class tables, indexed [0..4]; sized/zeroed by Sched_Init.      */
extern int       regClassCount[5]; /* 0x5e9b04  #registers in each class       */
extern SchedNode **lastUse[5];     /* 0x5e087e  [inf] per-reg: uses since def  */
extern SchedNode **lastDef[5];     /* 0x5e086a  [inf] per-reg: defining node   */

/* Per-block ordering worklists (lists of recently-seen nodes), reset by Init. */
extern Cell *gStoreNodes;  /* 0x5e0862  stores seen so far in the block        */
extern Cell *gLoadNodes;   /* 0x5e0866  loads  seen so far                     */
extern Cell *gSideFxNodes; /* 0x5e085e  side-effecting ops (target hook said so)*/
extern Cell *gCallNodes;   /* 0x5e085a  calls / PCF_CALL ops                   */
extern SchedNode *gFirstNode; /* 0x5e0856 block anchor node (set by emit loop) */
extern u16   gMaxPriority; /* 0x5e0854  max critical-path height in the block  */

extern TargetInfo *gTarget;/* 0x5e0850  machine descriptor                     */
/* gTarget->f0x04  [inf] feature flag gating reg latency
 * gTarget->f0x08  (u16) call/result latency cycles
 * gTarget->f0x20  fn ptr: "does this PCode have side effects?" (bool)         */

extern void  *galloc(int n);   /* 0x440ce0  compiler arena allocator           */
extern int    MayAlias(void *memA, void *memB);          /* 0x511fc0           */
extern void   CError_Assert(char *file, int line);       /* 0x463760           */

/* ===========================================================================
 * Sched_AddDep  @ 0x5084f0   "A depends on B"  (the AddEdge primitive)
 *   Adds a dependency edge A->B (A must issue after B), merging duplicates and
 *   keeping the max weight; bumps B's user count and recomputes A's critical-
 *   path priority. useLatency selects whether the edge carries result latency.
 * ==========================================================================*/
static void Sched_AddDep(SchedNode *A, SchedNode *B, char useLatency)
{
    Dep *e;
    int  w;

    if (A == B)                       /* no self-dependency            0x508500 */
        return;

    w = useLatency ? A->baseLatency : 0;          /*               0x508510-22 */

    for (e = A->deps; e != 0; e = e->next) {      /* dup edge?          0x508522 */
        if (e->on == B) {
            if (e->weight < w) {                  /* keep the larger    0x508535 */
                e->weight = w;
                if (w + B->priority > A->priority)/*                    0x508545 */
                    A->priority = w + B->priority;
            }
            return;
        }
    }

    e = (Dep *)galloc(0xa);                        /* new edge          0x508566 */
    e->on   = B;
    e->next = A->deps;
    A->deps = e;
    e->weight = (u16)w;

    if (useLatency) {                              /* call-result latency 0x50857d */
        if (B->pcode->flags & 1)                   /* [inf] B produces a slow val */
            e->weight += gTarget->f0x08;
    }

    B->numUsers++;                                 /* +0x18             0x50859d */

    w = e->weight + B->priority;                   /* propagate height  0x5085a1 */
    if (w > A->priority)
        A->priority = (u16)w;
}

/* ===========================================================================
 * Sched_AddRegDeps  @ 0x508400
 *   Wire up register dependencies for ONE register operand of node `n`.
 *   defList = lastDef[c][r] (0x5e086a), useList = lastUse[c][r] (0x5e087e):
 *     isDef -> WAR (depend on prior uses) + WAW (depend on prior defs), then
 *              append n to defList.   (n is now the latest writer.)
 *     isUse -> RAW (depend on prior defs), then append n to useList.
 *   regClass gates whether RAW/WAW edges carry the result latency (load-use).
 * ==========================================================================*/
static void Sched_AddRegDeps(char regClass, SchedNode *n,
                             Cell **defList, Cell **useList, int isDef)
{
    Cell *c;
    char  lat;

    if (isDef) {                                   /*                   0x508415 */
        for (c = *useList; c; c = c->next)         /* WAR: prior uses   0x508417 */
            if (c->node != n)
                Sched_AddDep(n, c->node, 1);
        for (c = *defList; c; c = c->next) {       /* WAW: prior defs   0x508439 */
            if (c->node != n) {
                lat = 1;
                if (regClass)                      /*               0x50844c-65 */
                    lat = (gTarget->f0x04 == 0) ? 1 : 0; /* [inf] gate latency */
                Sched_AddDep(n, c->node, lat);
            }
        }
        c = (Cell *)galloc(8);                      /* append n to defs  0x508478 */
        c->node = n; c->next = *defList; *defList = c;
    } else {                                        /* isUse           0x508491 */
        for (c = *defList; c; c = c->next) {        /* RAW: current defs        */
            if (c->node != n) {
                lat = 1;
                if (regClass)
                    lat = (gTarget->f0x04 == 0) ? 1 : 0;
                Sched_AddDep(n, c->node, lat);
            }
        }
        c = (Cell *)galloc(8);                      /* append n to uses  0x5084cf */
        c->node = n; c->next = *useList; *useList = c;
    }
}

/* ===========================================================================
 * Sched_AddStoreDeps  @ 0x508350
 *   A store node `n` must follow every prior load AND store it may alias.
 *   Then n joins the store list; if it is also volatile (PCF_VOLATILE) it
 *   additionally joins the load list so later loads order against it too.
 * ==========================================================================*/
static void Sched_AddStoreDeps(SchedNode *n)
{
    Cell *c;

    for (c = gLoadNodes; c; c = c->next)            /* vs prior loads  0x508356 */
        if (MayAlias(c->node->pcode->f0x0c, n->pcode->f0x0c))
            Sched_AddDep(n, c->node, 1);

    for (c = gStoreNodes; c; c = c->next)           /* vs prior stores 0x50838b */
        if (MayAlias(c->node->pcode->f0x0c, n->pcode->f0x0c))
            Sched_AddDep(n, c->node, 1);

    c = (Cell *)galloc(8);                          /* join stores     0x5083c0 */
    c->node = n;
    c->next = gStoreNodes;
    gStoreNodes = c;

    if (n->pcode->flags & PCF_VOLATILE) {           /* also join loads 0x5083d8 */
        c = (Cell *)galloc(8);
        c->node = n;
        c->next = gLoadNodes;
        gLoadNodes = c;
    }
}

/* ===========================================================================
 * Sched_AddInstrDeps  @ 0x508100   (assert "Scheduler.c":470)
 *   Build all dependency edges for node `n` (n->pcode = the instruction):
 *     1. for each register operand: Sched_AddRegDeps (skipping the fixed EABI
 *        bases r2/r13, and r0-when-meaning-zero).
 *     2. memory ordering from pcode->flags: loads chain after aliasing stores;
 *        stores -> Sched_AddStoreDeps; calls chain through gCallNodes; ops the
 *        target marks side-effecting chain through gSideFxNodes; everything
 *        chains after the block anchor gFirstNode when it has no deps yet.
 *     3. track gMaxPriority = max node priority in the block.
 * ==========================================================================*/
void Sched_AddInstrDeps(SchedNode *priorNodes, SchedNode *n) /* args 0x1c/0x20(esp) */
{
    PCode    *p = n->pcode;                         /* ebx=n; ebp=n->pcode 0x50810b */
    int       i;
    PCodeArg *a = &p->args[0];                      /* lea 0x24(ebp)     0x508116 */
    SchedNode *m;
    Cell     *c;

    for (i = 0; i < (s16)p->argCount; i++, a++) {  /*                   0x5081c2 */
        if (a->kind != 0)                          /* only registers    0x508120 */
            continue;

        if (a->reg < 0 || a->reg > regClassCount[a->regClass]) /* range 0x508133 */
            CError_Assert("Scheduler.c", 470);     /*                   0x50814c */

        /* skip the fixed EABI base regs in the GPR class (4):          0x50815d */
        if (a->kind == 0 && a->regClass == 4) {
            if (a->reg == 2 || a->reg == 0xd)      /* r2=SDA2, r13=SDA  0x50816c */
                continue;
            if (a->reg == 0 && (a->argFlags & 3) == 0) /* r0==literal 0 0x50817a */
                continue;
        }

        Sched_AddRegDeps(a->regClass, n,           /*                   0x508183 */
                         &lastDef[a->regClass][a->reg],   /* 0x5e086a */
                         &lastUse[a->regClass][a->reg],   /* 0x5e087e */
                         a->argFlags & 2);                /* isDef    */
    }

    /* ---- memory / control ordering from the instruction's flags ---- */
    if (p->flags & PCF_LOAD) {                      /*                   0x5081d5 */
        for (c = gStoreNodes; c; c = c->next)       /* depend on aliasing stores */
            if (MayAlias(c->node->pcode->f0x0c, p->f0x0c))
                Sched_AddDep(n, c->node, 1);
        c = (Cell *)galloc(8);                      /* join loads        0x508212 */
        c->node = n; c->next = gLoadNodes; gLoadNodes = c;
    } else if (p->flags & PCF_STORE) {              /*                   0x508230 */
        Sched_AddStoreDeps(n);
    }

    if (p->flags & PCF_CALL) {                      /* call ordering     0x508241 */
        for (c = gCallNodes; c; c = c->next)
            if (c->node != n)
                Sched_AddDep(n, c->node, 0);
        c = (Cell *)galloc(8);                      /* join calls        0x50826b */
        c->node = n; c->next = gCallNodes; gCallNodes = c;
    }

    /* Hard barrier: an op flagged 0x1000000 or 0x100, or one the target's
     * side-effect hook flags, depends on EVERY prior node in the block.   0x508283
     * (The `(flags&8)|1` test at 0x50828b is always-true dead code.)              */
    if ((p->flags & 0x1000000) || (p->flags & 0x100) || gTarget->vtbl_f0x20(p)) {
        for (m = priorNodes; m; m = m->next)        /*                   0x5082b0 */
            if (m != n)
                Sched_AddDep(n, m, 0);
        c = (Cell *)galloc(8);                      /* join side-effects 0x5082ca */
        c->node = n; c->next = gSideFxNodes; gSideFxNodes = c;
    }

    for (c = gSideFxNodes; c; c = c->next)          /* order after sidefx 0x5082e2 */
        if (c->node != n)
            Sched_AddDep(n, c->node, 0);

    if (n->deps == 0 && gFirstNode)                 /* anchor a floater  0x50830e */
        Sched_AddDep(n, gFirstNode, 0);             /* single edge, not a loop    */

    if (n->priority > gMaxPriority)                 /*                   0x50832e */
        gMaxPriority = n->priority;
}

/* ===========================================================================
 * Sched_Init  @ 0x5085c0
 *   Per-block reset: (re)allocate and zero the per-register def/use tables for
 *   every register class, then clear the ordering worklists and max priority.
 * ==========================================================================*/
void Sched_Init(void)
{
    int cls, r;

    for (cls = 0; cls < 5; cls++) {                 /*                   0x5085ca */
        lastUse[cls] = (SchedNode **)galloc(regClassCount[cls] * 4);
        lastDef[cls] = (SchedNode **)galloc(regClassCount[cls] * 4);
        for (r = 0; r < regClassCount[cls]; r++) {  /* zero both         0x508612 */
            lastDef[cls][r] = 0;
            lastUse[cls][r] = lastDef[cls][r];
        }
    }
    gStoreNodes = 0;                                /*                   0x508642 */
    gLoadNodes  = gStoreNodes;
    gSideFxNodes = 0;
    gCallNodes   = 0;
    gMaxPriority = 0;
}
