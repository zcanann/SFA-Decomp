/* ============================================================================
 * RECOVERED: mwcceppc.exe (GC/2.0)  TU = PCodeListing.c   (emit-loop sub-band)
 *            list-scheduler READY-LIST EMIT LOOP  +  per-block driver
 * ----------------------------------------------------------------------------
 * Source of truth: build/compilers/GC/2.0/mwcceppc.exe  (image base 0x400000)
 * Disassembly:     objdump -d --start-address=0xADDR --stop-address=0xADDR ...
 *
 *   Sched_Driver       0x507ce0 - 0x507de1   per-block: gate + invoke scheduler
 *   Sched_EmitBlock    0x507df0 - 0x507fbd   build DAG, then cycle-by-cycle emit
 *   Sched_PickReady    0x507fc0 - 0x5080fd   ready-node SELECTION (the key+tiebreak)
 *
 * These three live in the PCodeListing.c band (0x500c40-0x508100), immediately
 * adjacent to and the CALLER of Scheduler.c (0x508100, the DAG builder). They
 * are not assert-anchored themselves (no CError site inside them); they are
 * pinned by (a) the direct calls to Sched_Init @0x5085c0 and Sched_AddInstrDeps
 * @0x508100, and (b) sharing every global (0x5e0850..0x5e0856) with the already-
 * recovered Scheduler.c. Read recovered/Scheduler.c first — struct offsets and
 * the SchedNode/Cell/Dep layouts are defined there and reused verbatim here.
 *
 * CONFIDENCE: control flow + struct offsets read directly from the binary, HIGH.
 * The scheduler is BOTTOM-UP (ready = all *dependents* emitted) — see the
 * numUsers decrement at 0x507f33; this is pinned, not inferred. Field semantics
 * named [inf] are inferred from use. The #pragma-scheduling -> block-flag-bit
 * linkage is NOT fully traced (see Sched_Driver note) and is flagged as such.
 *
 * RETRACTION / CORRECTION of README: README previously said "scheduling off =>
 * DAG still built, reorder bypassed". The disasm shows the WHOLE pass (DAG build
 * AND reorder, both inside Sched_EmitBlock) is one unit and is skipped wholesale
 * when the per-block gate fires — there is no "build DAG but don't reorder" path.
 * "Off" therefore means: Sched_EmitBlock is never called for that block, so the
 * block keeps exactly the order InstrSelection emitted. Corrected below.
 * ==========================================================================*/

/* ---- machine descriptor (gTarget @ 0x5e0850) ------------------------------
 * Not a C++ vtable: gTarget is a flat struct of scalars + function pointers.
 * One of ~7 per-CPU tables (0x5d2910, 0x5d3438, 0x5d3fc8, 0x5d4af0, 0x5d5618,
 * 0x5d6140, 0x5d0be8, 0x5d1c10) selected by CPU byte 0x5e4824 in Sched_Driver. */
typedef struct TargetInfo {
    /* +0x00 */ int  issueWidth;        /* [inf] max instrs emitted per cycle   */
    /* +0x04 */ int  f0x04;             /* [inf] reg-latency feature flag (Scheduler.c) */
    /* +0x08 */ u16  callResultLatency; /* extra weight for flags&1 producers    */
    /* +0x0c */ u16 (*baseLatency)(PCode*);  /* node's own issue latency        */
    /* +0x10 */ void (*beginBlock)(void);    /* reset per-block emit state      */
    /* +0x14 */ int  (*canIssue)(PCode*);    /* funit/slot available this cycle? */
    /* +0x18 */ void (*commit)(PCode*);      /* reserve resources for emitted op */
    /* +0x1c */ void (*endCycle)(void);      /* advance one machine cycle       */
    /* +0x20 */ int  (*hasSideEffects)(PCode*); /* used by Scheduler.c          */
} TargetInfo;

/* ---- SchedNode (26 bytes, galloc(0x1a)) — offsets confirmed against Scheduler.c
 *  +0x00 prev     link toward OLDER nodes (set 0x507e7b)
 *  +0x04 next     link toward NEWER nodes (set 0x507e78); list head = newest
 *  +0x08 deps     Dep* list (this node depends on each dep->on)
 *  +0x0c pcode    PCode*
 *  +0x10 baseLatency  own issue latency  (= +0x16 at birth, 0x507e47)
 *  +0x12 readyCycle   [inf] earliest cycle this node may be placed (init 0)
 *  +0x14 slack        [inf] = gMaxPriority - priority   (computed 0x507e90)
 *  +0x16 priority     critical-path height (starts = baseLatency, raised by DAG)
 *  +0x18 numUsers     # of not-yet-emitted dependents (READINESS COUNTER)
 * Note +0x00/+0x04 are the *doubly-linked* node list the emit loop walks; this
 * refines Scheduler.c's single "next @+0x00" guess.                            */

extern TargetInfo *gTarget;       /* 0x5e0850 */
extern SchedNode  *gFirstNode;    /* 0x5e0856 block anchor (set when pcode&1)  */
extern u16         gMaxPriority;  /* 0x5e0854 */
extern int         gHasUnitTable; /* 0x5e9728 gate for the per-opcode tiebreak */
extern u8          gUnitTable[];  /* 0x5bff51 per-opcode table, stride 18 bytes */
extern signed char gCpuType;      /* 0x5e4824 */

extern void  Sched_Init(void);                           /* 0x5085c0 */
extern void  Sched_AddInstrDeps(SchedNode *prior, SchedNode *n); /* 0x508100 */
extern void  PCode_Append(PCBlock *blk, PCode *p);       /* 0x4dd160 append to blk list, blk->instrCount++ */
extern void *galloc(int n);                              /* 0x440ce0 */

/* ---- PCode basic block (the arg threaded through; offsets from this band) --
 *  +0x00 next       next block
 *  +0x14 firstInstr head of instruction list (rebuilt by the scheduler)
 *  +0x18 lastInstr  tail; also the iteration seed for DAG build (0x507e0c)
 *  +0x28 instrCount u16 (gate: <=2 => never scheduled, 0x507db0)
 *  +0x2a flags      u16; bit0|bit1 (mask 3) = "do not schedule" gate, bit3
 *                   (0x8) = "already scheduled" sentinel                       */

/* ===========================================================================
 * Sched_PickReady  @ 0x507fc0      THE SELECTION (deliverable A + B + D)
 *   Scan the node list (newest->oldest via +0x04? no: via +0x00, see below) for
 *   the best READY node to emit at `cycle`. Returns 0 if none ready this cycle.
 *
 *   READY (deliverable B) — all three required, checked at 0x507fd5/0x507fdc/
 *   0x507fe2 (and again for each candidate at 0x508012/0x50801d/0x508027):
 *     (1) node->numUsers == 0          all dependents already emitted (BOTTOM-UP)
 *     (2) node->readyCycle <= cycle    latency gate (deliverable D)
 *     (3) gTarget->canIssue(pcode)!=0  functional-unit/slot free this cycle
 *
 *   SELECTION KEY (deliverable A) — strict lexicographic order, most significant
 *   first; `incumbent`=esi (the current best), `cand`=edi:
 *     K1 deadline window  [0x508041-0x50805d]:
 *        prefer the node whose slack (+0x14 = gMaxPriority-priority) <= cycle
 *        over one whose slack > cycle. (High-priority nodes enter the window at
 *        lower cycles -> effectively a "is this node due yet" deadline.)
 *        If both in-window or both out, fall through to K2.
 *     K2 frees-most-predecessors  [0x50805f-0x508099]:
 *        count deps whose dep->on->numUsers == 1 (emitting this node will drop
 *        that predecessor's user-count to 0, making it ready). HIGHER count wins.
 *     K3 priority  [0x50809b-0x5080ab]:
 *        node->priority (+0x16, critical-path height). HIGHER wins.
 *     K4 per-opcode unit key  [0x5080ad-0x5080e6], ONLY if gHasUnitTable != 0:
 *        key = gUnitTable[ pcode->opcode * 18 ]  (opcode = (s16)pcode[+0x20]).
 *        LOWER key wins (candidate taken only when incumbentKey > candKey).
 *     K5 tie -> keep incumbent. The list is scanned head-first and the incumbent
 *        is the earlier-seen node, so an exact tie resolves to list order.
 * ==========================================================================*/
static SchedNode *Sched_PickReady(SchedNode *list, int cycle)
{
    SchedNode *best, *c;
    int bestFrees, candFrees;
    Dep *d;

    for (best = list; best; best = best->prev)         /* +0x00 walk  0x507ff4 */
        if (best->numUsers == 0 && best->readyCycle <= cycle
            && gTarget->canIssue(best->pcode))
            break;                                      /* first ready 0x507ff2 */
    if (!best)
        return 0;                                      /*             0x507ffe */

    for (c = best->prev; c; c = c->prev) {             /*             0x5080ea */
        if (c->numUsers != 0) continue;                /*             0x508012 */
        if (c->readyCycle > cycle) continue;           /*             0x50801d */
        if (!gTarget->canIssue(c->pcode)) continue;    /*             0x508027 */

        /* K1: deadline window (slack <= cycle) ---------------------- 0x50803d */
        if (best->slack <= cycle && c->slack >  cycle) continue;       /* keep best */
        if (best->slack >  cycle && c->slack <= cycle) { best = c; continue; }

        /* K2: number of predecessors this node would free ---------- 0x50805f */
        candFrees = 0;
        for (d = c->deps;    d; d = d->next) if (d->on->numUsers == 1) candFrees++;
        bestFrees = 0;
        for (d = best->deps; d; d = d->next) if (d->on->numUsers == 1) bestFrees++;
        if (bestFrees > candFrees) continue;           /*             0x508095 */
        if (bestFrees < candFrees) { best = c; continue; } /*         0x508099 */

        /* K3: critical-path priority ------------------------------- 0x50809b */
        if (best->priority > c->priority) continue;
        if (best->priority < c->priority) { best = c; continue; }

        /* K4: per-opcode unit-table key (lower wins), gated -------- 0x5080ad */
        if (gHasUnitTable) {
            u8 candKey = gUnitTable[(s16)c->pcode->opcode    * 18];
            u8 bestKey = gUnitTable[(s16)best->pcode->opcode * 18];
            if (bestKey > candKey)                     /* strictly lower cand   */
                best = c;                              /*             0x5080e8 */
        }
        /* K5: otherwise keep incumbent (list order) */
    }
    return best;                                       /*             0x5080f4 */
}

/* ===========================================================================
 * Sched_EmitBlock  @ 0x507df0       BUILD DAG then DRAIN (deliverables B,D)
 *   Phase 1 (0x507e13-0x507e84): walk the block's instructions oldest->newest
 *     (seed blk->lastInstr @+0x18, advance via pcode->+0x04), wrap each in a
 *     fresh SchedNode, init priority=baseLatency=gTarget->baseLatency(pcode),
 *     call Sched_AddInstrDeps to wire the dependency DAG, and thread the node
 *     into the doubly-linked list (head `nl` = newest).
 *   Phase 2 (0x507e90): slack[n] = gMaxPriority - priority[n] for every node.
 *   Phase 3 (0x507ea4-...): clear blk's instruction list, gTarget->beginBlock(),
 *     then the CYCLE LOOP: for cycle = 0,1,...
 *       for issue = 0 .. gTarget->issueWidth-1:
 *         pick = Sched_PickReady(nl, cycle); if none -> break (advance cycle)
 *         COMMIT pick (0x507f15-0x507f4f): for each dep (pick depends on dep->on)
 *             dep->on->numUsers--                       <-- readiness propagation
 *             dep->on->readyCycle = max(readyCycle, cycle + dep->weight)  <-- latency
 *         append pick->pcode to the block, gTarget->commit(pcode), unlink pick.
 *       gTarget->endCycle(); cycle++
 *     until the list empties.
 *   NB: numUsers counts DEPENDENTS (Scheduler.c increments B->numUsers when A
 *   depends on B). Decrementing it on commit => a node becomes ready when all
 *   its USERS are emitted => the schedule is built BOTTOM-UP. readyCycle/weight
 *   are the only cycle/latency model: a predecessor cannot be placed until
 *   `weight` cycles after the dependent that used its result. (deliverable D)
 * ==========================================================================*/
void Sched_EmitBlock(PCBlock *blk)
{
    SchedNode *nl = 0, *n, *pick;
    PCode     *p;
    int        cycle, issue;
    Dep       *d;

    Sched_Init();                                      /*             0x507df7 */
    gFirstNode = 0;                                    /*             0x507dfc */

    for (p = blk->lastInstr; p; p = p->next) {         /* +0x18 seed  0x507e0c */
        n = (SchedNode *)galloc(0x1a);                 /*             0x507e15 */
        n->prev = n->next = n->deps = 0;
        n->pcode = p;
        n->priority = gTarget->baseLatency(p);         /* +0x16       0x507e3b */
        n->baseLatency = n->priority;                  /* +0x10       0x507e47 */
        n->readyCycle = 0;                             /* +0x12                */
        n->slack = 0;                                  /* +0x14                */
        n->numUsers = 0;                               /* +0x18                */
        Sched_AddInstrDeps(nl, n);                     /*             0x507e5f */
        if (p->flags & 1) gFirstNode = n;              /* anchor      0x507e6e */
        if (nl) nl->next = n;                          /*             0x507e78 */
        n->prev = nl; nl = n;                          /*             0x507e7b */
    }

    for (n = nl; n; n = n->prev)                       /*             0x507e90 */
        n->slack = gMaxPriority - n->priority;

    blk->lastInstr = 0;                                /*             0x507ea8 */
    blk->firstInstr = 0;                               /*             0x507eb6 */
    blk->instrCount = 0;                               /*             0x507ebd */
    gTarget->beginBlock();                             /*             0x507ec9 */

    for (cycle = 0; nl; cycle++) {                     /* cycle loop  0x507ee0 */
        for (issue = 0; issue < gTarget->issueWidth; issue++) { /*   0x507f89 */
            pick = Sched_PickReady(nl, cycle);         /*             0x507f04 */
            if (!pick) break;                          /*             0x507f0d */
            p = pick->pcode;
            for (d = pick->deps; d; d = d->next) {     /* commit      0x507f30 */
                d->on->numUsers--;                     /*             0x507f33 */
                if (d->on->readyCycle < cycle + d->weight)
                    d->on->readyCycle = cycle + d->weight;          /* 0x507f45 */
            }
            PCode_Append(blk, p);                      /*             0x507f56 */
            gTarget->commit(p);                        /*             0x507f66 */
            if (pick->next) pick->next->prev = pick->prev; /* unlink  0x507f71 */
            else            nl = pick->prev;           /*             0x507f77 */
            if (pick->prev) pick->prev->next = pick->next;          /* 0x507f7f */
        }
        gTarget->endCycle();                           /*             0x507fa2 */
    }
}

/* ===========================================================================
 * Sched_Driver  @ 0x507ce0     per-block GATE (deliverable C)
 *   Selects the per-CPU TargetInfo (switch on gCpuType 0x5e4824), then walks the
 *   function's block list (head @0x5e9838) and schedules each block UNLESS gated:
 *     - blk->instrCount <= 2            never scheduled            (0x507db0)
 *     - !force && (blk->flags & 3)      per-block "do not schedule"(0x507db7)
 *     - blk->flags & 8                  already scheduled          (0x507dc4)
 *   Otherwise: Sched_EmitBlock(blk); blk->flags |= 8.
 *
 *   `force` is the function's only argument. Two call sites:
 *     0x433dd7  Sched_Driver(0)  -- respects the per-block (flags & 3) gate
 *     0x43402e  Sched_Driver(1)  -- forced; ignores (flags & 3)
 *
 *   THE #pragma scheduling GATE: a block with (flags & 3) set is skipped in the
 *   non-forced pass => Sched_EmitBlock is never entered => no DAG, no reorder =>
 *   the block keeps InstrSelection's emission order. Bits 0/1 of flags+0x2a are
 *   set near block construction (e.g. 0x4f9830 orw $1, 0x4f9238 orw $2 in the
 *   PCodeScheduling emit code; 0x4335c0/0x433cbb in this TU). The exact pragma-
 *   variable -> bit write was NOT traced end-to-end; that bits 0/1 == the
 *   "scheduling off" marker is [inf] (strongly implied by being the only gate
 *   the scheduler honors, but unproven). Bit 3 (0x8) is proven = "scheduled".
 * ==========================================================================*/
void Sched_Driver(char force)
{
    PCBlock *blk;

    gTarget = select_target_by_cpu(gCpuType);          /* switch      0x507ce6 */
    build_block_list();                                /*             0x507d9c (0x512120) */

    for (blk = *(PCBlock **)0x5e9838; blk; blk = blk->next) {        /* 0x507da1 */
        if (blk->instrCount <= 2)            continue; /*             0x507db0 */
        if (!force && (blk->flags & 3))      continue; /*             0x507db7 */
        if (blk->flags & 8)                  continue; /*             0x507dc4 */
        Sched_EmitBlock(blk);                          /*             0x507dce */
        blk->flags |= 8;                               /*             0x507dd4 */
    }
}
