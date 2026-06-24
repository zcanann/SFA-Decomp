/* ============================================================================
 * RECOVERED: mwcceppc.exe (GC/2.0) — the WEB-NUMBERING ORDER (color order)
 * ----------------------------------------------------------------------------
 * Why this file exists: LEVERS.md 4/4a claimed "web index = IR-definition order"
 * and treated register assignment order as POSITIONAL (decl/program/creation
 * order). Three independent matcher escalations (smallbasket resolveCollision &
 * fn_801816F8, staff_setupSwipe's `swipe` param) produced saved-register orders
 * that positional order cannot explain — including a PARAM web colored LAST
 * despite being defined first. Reading the actual numbering loop shows why:
 *
 *   WEB INDEX = DESCENDING ALLOCATION PRIORITY, **not** definition order.
 *
 * Numbering order sets coloring order (Color_Simplify/Select walk web-index
 * order) which sets the saved-register fallback order (GetReservedReg hands out
 * r31,r30,r29… to webs in the order they exhaust volatiles). So the value with
 * the HIGHEST priority gets web index 0 -> colored first -> r31 (saved) or the
 * lowest-free volatile (r3 / f0).
 *
 * CONFIDENCE: the numbering loop control flow + the priority field + the loop
 * pin are READ DIRECTLY (HIGH). The SEMANTIC of desc+0x4 was then probed
 * EMPIRICALLY by compiling controlled inputs with this exact compiler+flags
 * (-O4,p -opt nopeephole,noschedule; harness: scratch probe[123].c). Results
 * below supersede the first draft's "loop-weighted reference count" guess —
 * that guess is RETRACTED: reference/use count is empirically INERT.
 *
 * EMPIRICAL RESULTS (validated, reproducible — probe[123]):
 *   - USE COUNT IS IRRELEVANT, IN EVERY USE FORM. A single-def value used 1x vs
 *     Nx produces a BYTE-IDENTICAL function whether the extra uses are load/store
 *     BASE uses (g_quse, f_pmore), ARITHMETIC-operand uses (n_opheavy: q+q+q+q),
 *     or COMPARE-operand uses (n_cmp: if(q>k)…). desc+0x4 is NOT a use weight of
 *     any kind. (n_cmp's apparent shuffle is the p++/r++ MULTI-DEF effect, not
 *     the compares.) Retraction logged; beats the over-claim.
 *   - *** THE LEVER: web creation order = LOCAL DECLARATION order. *** For a
 *     local whose decl and init are SEPARATED (`T *ax; … ax = e;`, the
 *     resolveCollision shape), the BARE DECLARATION position sets creation order;
 *     the assignment/first-use/addi-emission positions are all INERT. Proven:
 *       s_late      (decl y,z,ax; assign ax last)  -> y=r31,z=r30,ax=r29
 *       s_axassignfirst (decl y,z,ax; assign ax FIRST) -> ax STILL r29 (assign inert)
 *       s_axdeclfirst   (decl ax,y,z; assign ax last)  -> ax=r31  (DECL moved it)
 *     Holds in a faithful multi-block repro (early-return + assign-in-if +
 *     use-after-calls + computed index: t_axfirst ax=r31 vs t_axlast ax=r29) and
 *     WITH the st/obj saved-web interaction (u_ax2: declaring ax 2nd moves it
 *     r28->r30, y/z cascade down). So "decl reorder is inert" (an earlier claim
 *     here) is WRONG and RETRACTED -- it is the primary handle.
 *   - The earlier "forward vs reverse by value kind" note was an artifact of the
 *     copy-vs-address distinction in trivial fns; the governing variable is decl
 *     order. (Param-copy fns can look reversed because the copy coalesces into
 *     the param web, which is created at a usage-bound point -- see caveat.)
 *   - CAVEAT (why a naive decl swap can still miss): a PARAMETER's web (e.g.
 *     `obj`) is created at a usage-bound position interleaved with the locals,
 *     NOT in the decl list. So to land a local at a target index you must place
 *     its decl relative to where the param web falls. This is what made the
 *     matcher's single `st;axes;endY;endZ` try miss on the real fn: the lever is
 *     real, the sweep was just incomplete. Sweep decl positions accounting for
 *     the param's slot.
 *   - MULTI-DEF separately promotes a param-copy web (g_qdef2/f_pmulti: q->r31)
 *     but not an address-temp (h_xmulti). Secondary; decl order is primary.
 *   - LOOP RESIDENCE pin (desc+0x24 & 0x40, set in IroLoop.c -> desc+0x4=100000)
 *     is the CONFIRMED-from-binary top-priority override; loop-referenced values
 *     number first regardless of decl order.
 *   - USE COUNT in every form is INERT (see above).
 *
 * NET (playbook): register/saved-reg numbering order among local webs is
 * CONTROLLABLE via LOCAL DECLARATION ORDER (earlier decl -> lower index -> r31 /
 * lowest volatile), with a loop-residence override on top. It is NOT use count
 * and NOT assignment/statement/materialization order. The only complication is
 * the interleaved usage-bound slot of PARAMETER webs, which a decl sweep must
 * account for. This is a real lever, not a wall.
 *
 * BOUNDARY (honest, unresolved frontier — found on smallbasket_resolveCollision):
 *   The decl-order lever reliably moves ARRAY-ELEMENT and plain-local pointers
 *   (endY=&endPoints[1] etc. -- basket's real-fn sweep confirms they move with
 *   decl order). But the STRUCT-MEMBER address-temp `axes = hitResults.axes` was
 *   DECL-POSITION INVARIANT in the real function: pinned to the LAST saved slot
 *   (r27) in all 4 decl positions (full map in basket's escalation). Since the
 *   target needs axes NOT-last (st,obj,axes,endY,endZ), it is unreachable -> a
 *   PRINCIPLED bank at 99.845 with the mechanism mapped.
 *   IMPORTANT caveat on the caveat: I could NOT reproduce this pin in isolation.
 *   Probes that mirror the case closely -- struct-member temp, multi-member
 *   struct access (.radii/.axes/.hitInfo/.solidFlags), st-from-param + obj saved
 *   across 3 calls, axes feeding an st byte-store (probe10 v_axfirst, probe11
 *   rc_axfirst) -- ALL still moved axes with decl order. So "struct-member temps
 *   are pinned" is NOT a general rule (disproved by probe); the real pin is a
 *   context-specific residual not yet isolated. Flagged as the next frontier;
 *   do NOT over-generalize it into "struct-member access defeats the lever."
 * ==========================================================================*/

/* ---- the RegInfo descriptor (alloc 0x2a bytes, bzero'd; RegInfo_Desc 0x4d0150)
 *   +0x04  s32  priority   [inf] allocation priority / loop-weighted ref weight.
 *                          PINNED to 100000 (0x186a0) when (+0x24 & 0x40).
 *   +0x22  u8   skip?      numbering eligibility: must be 0
 *   +0x23  u8   eligible?  numbering eligibility: must be != 0
 *   +0x24  u8   flags      bit1(0x02)=numbered, bit6(0x40)=loop-resident pin,
 *                          (bit at +0x24&2 also = "is a coalesce/colorable move")
 *   +0x25  u8   class      register class (set by RegInfo classify 0x4d03a0)
 *   +0x26  u16  webIndex   THE WEB NUMBER = webEnd[class]++  (set by 0x4fe550)
 * ------------------------------------------------------------------------- */

/* ===========================================================================
 * CodeGen_NumberWebs  @ 0x435650   *** THE COLOR-ORDER DECISION ***
 *   Repeatedly: scan the value worklist (lists 0x5e9b00 then 0x5e99c4) for the
 *   single eligible, not-yet-numbered value with the MAXIMUM priority desc+0x4,
 *   and number THAT one (0x4d03a0 -> 0x4fe550, webIndex = webEnd[class]++).
 *   Loop while there remains work (global 0x5e9c90 != 0). => values are numbered
 *   in DESCENDING priority order. This is a priority worklist, NOT an in-order
 *   instruction/operand walk.
 *
 *   Eligibility per value v (desc = RegInfo_Desc(v)):
 *     desc+0x26 == 0      (not already numbered)
 *     desc+0x23 != 0  &&  desc+0x22 == 0
 *     desc+0x4  >= 2      (priority threshold)
 *     v->type (v+0xe[0]) == 4  &&  v->regclass (v+0xe field) in [4,14]
 *   And: if (desc+0x24 & 0x40)  desc+0x4 = 100000  (loop pin, applied in-loop).
 * ==========================================================================*/
static void CodeGen_NumberWebs(void)
{
    void *best; int bestPri;
    do {                                                  /* 0x4357ef while 0x5e9c90 */
        best = 0; bestPri = -1;                           /* 0x435660 */
        for (cell = gWorklist0 /*0x5e9b00*/; cell; cell = cell->next) {  /* 0x435679 */
            v = cell->value; desc = RegInfo_Desc(v);      /* 0x435687 */
            if (desc->flags & 0x40) desc->priority = 100000;          /* 0x43569a */
            if (desc->webIndex != 0) continue;            /* 0x4356a1 already numbered */
            if (desc->eligible == 0 || desc->skip != 0) continue;     /* 0x4356a8 */
            if (desc->priority < bestPri) continue;       /* 0x4356e0 keep max */
            if (desc->priority < 2) continue;             /* 0x4356e4 threshold */
            if (v->type != 4) continue;                   /* 0x4356ea */
            if (v->regclass < 4 || v->regclass > 14) continue;        /* 0x4356ef */
            best = v; bestPri = desc->priority;           /* 0x4356fd */
        }
        /* …identical scan over gWorklist1 (0x5e99c4)…  0x435730 */
        if (best) Number(best);   /* 0x4d03a0 -> webIndex = webEnd[class]++ 0x4357c5 */
    } while (gColorWork /*0x5e9c90*/);
}

/* ===========================================================================
 * GetReservedReg  @ 0x4fe470   — the saved-register fallback pool (CONFIRMED)
 *   Reserved-reg order table 0x5e3e68 (per class, r31-descending) is consumed by
 *   a PERSISTENT per-class counter 0x5e97d4 that only advances. The Nth web to
 *   reach Color_Select's "no volatile free" branch gets the Nth entry. So the
 *   saved register a web receives is purely a function of the ORDER webs are
 *   colored = web-index order. (0x5e5c78[class][reg] marks already-used regs to
 *   skip.) Confirms LEVERS lever 1a's r31-descending pool; corrects the *driver*
 *   of that order from "creation order" to "priority order".
 * ==========================================================================*/

/* ---------------------------------------------------------------------------
 * THE LOOP PIN  (CONFIRMED — corrects the model)
 *   desc->flags bit 0x40 is OR'd in by IroLoop.c (band 0x4a5cf0-0x4acba0):
 *   sites 0x4accd9, 0x4acfa4, 0x4b0a76, 0x4dd8dd — all in the loop optimizer.
 *   When set, the numbering loop forces desc+0x4 = 100000, so a LOOP-RESIDENT
 *   value is numbered FIRST regardless of where it appears in program order ->
 *   web index 0 -> r31 (saved) / f0 / r3 (volatile). This is the single
 *   highest-leverage, fully-confirmed handle: move a value's references into or
 *   out of a loop body to raise/lower its register priority.
 *
 * THE IDENTICAL-ASM PARADOX (why this is a CIR/tree-level lever)
 *   In smallbasket_resolveCollision the target and our build are byte-identical
 *   except a 3-register rotation among axes/endY/endZ — same opcodes, same
 *   addresses, same final use counts. A deterministic compiler cannot emit two
 *   register assignments from one instruction stream, so the priority desc+0x4
 *   that drives numbering is accumulated UPSTREAM of instruction selection (on
 *   the CIR/tree), where two C spellings that converge to identical asm can
 *   carry different tree-level reference weights. Consequence: the lever is the
 *   C EXPRESSION's tree-level reference count / loop nesting, not anything
 *   visible in the final asm, and not declaration/statement order.
 *
 * COROLLARY — corrected matching levers (supersede LEVERS.md 4/4a):
 *   - Register/saved-reg order among colorable webs follows DESCENDING priority
 *     (loop-weighted ref weight), ties -> creation order. NOT definition/decl
 *     order (decl order only ever breaks an exact priority tie).
 *   - To move a value to a register closer to r31/f0/r3: raise its priority
 *     (more references, or reference it inside a loop -> 100000 pin). To push it
 *     toward r28/higher index: lower its references (cache its derefs into other
 *     locals; recompute instead of holding).
 *
 * OPEN: line-pin the desc+0x4 accumulation site (per-reference weight rule);
 *   confirm the >=2 threshold's meaning; validate the whole model against a
 *   byte-match landing (matcher tests in flight on resolveCollision/fn_801816F8/
 *   staff_setupSwipe/tricky mtex).
 * ------------------------------------------------------------------------- */

/* ===========================================================================
 * THE WORKLIST BUILDER — full chain decoded (answers "what sets creation order")
 * ---------------------------------------------------------------------------
 * The numbering loop (0x435650) consumes a worklist at 0x5e9b00/0x5e99c4. That
 * worklist is BUILT by the codegen tree-walk, and its order IS web creation /
 * tie-break order. Traced end to end:
 *
 *   CTemplateNew.c driver @ 0x531040   (recursive expression codegen)
 *     - dispatches on CIR node opcode via jump table 0x5bfbc8(,op,4)
 *     - recurses into operands, visiting value nodes in EVALUATION order
 *     - for a colorable value node: push value, call 0x4efa20
 *           |
 *           v
 *   CFunc.c walk @ 0x4efa20   (the ONLY caller of the worklist push)
 *     - per node: 0x4f0a90 (resets 0x5e9b00/0x5e99c4 to 0, chains the prior
 *       instruction's list onto 0x5e9cd8) then 0x4f0b60 -> 0x4f0e90 allocates a
 *       RegisterObject node (copies value+0x4/+0xc/+0x10/+0x16) and PREPENDS it
 *       to 0x5e9b00.
 *           |
 *           v
 *   Numbering @ 0x435650: max desc+0x4 first; TIE-BREAK = worklist order =
 *     creation order = the order the codegen walk first evaluated each value.
 *
 * => WEB CREATION ORDER = CIR EXPRESSION-TREE CODEGEN EVALUATION ORDER.
 *
 * This resolves the "identical-stream / different-register" paradox: numbering
 * runs at CIR-eval time, BEFORE instruction selection places the machine addi.
 * So a value can be EVALUATED (and thus numbered) early in the CIR yet have its
 * addi EMITTED late (e.g. smallbasket axes' addi at c1c) — number and emission
 * position are decoupled. Two source spellings that produce an identical PCode
 * stream can still differ in CIR evaluation order -> different numbering -> the
 * register rotation we see, with everything else byte-identical.
 *
 * WHY smallbasket axes is PINNED (and immovable from C, verified directly):
 *   The CIR evaluation order of the three address temps is NOT the C statement
 *   order — it is the order the FRONT-END LINEARIZER canonicalized the tree to.
 *   Verified on the real object: C statement reorder, decl reorder, aggregate-
 *   decl reorder, formation-site move, scalar-decl reorder, and use-block edits
 *   ALL leave axes evaluated last (pinned r27). The linearizer canonicalizes
 *   endPoints-element temps before the hitResults-member temp regardless of
 *   source, so axes is created last. The retail target's CIR evaluated axes
 *   earlier — reachable only by a CIR-shape difference the available C does not
 *   produce.
 *
 * NEXT FRONTIER (precise): the canonical evaluation order is decided in
 *   IroLinearForm.c (disasm already dumped: disasm/IroLinearForm.c.objdump.txt).
 *   To turn this last class into a lever, decode how the linearizer orders
 *   sibling assignment / address-of-member vs address-of-array-element temps —
 *   that rule (and whether any C construct perturbs it) is the only thing left
 *   between "mechanism understood" and "axes-class reachable from C".
 *
 * ===========================================================================
 * DEEP-DIVE CONCLUSION (smallbasket_resolveCollision, exhaustive direct probing)
 * ---------------------------------------------------------------------------
 * The numbering TRIGGER was pinned empirically: the axes web numbers at the
 * source position of its FIRST DEREF relative to endZ's first deref. Put the
 * axes deref before endZ's -> axes numbers r29 (the target value!); after ->
 * r27. CONFIRMED: a config exists (axes decl 2nd + axes block hoisted ahead of
 * the endZ store) that yields the EXACT target registers axes=r29/endY=r28/
 * endZ=r27. So axes is NOT pinned; it is fully movable.
 *
 * THE CATCH (why it can't be banked-into-a-match): under the unit's flags
 * (-opt nopeephole,noschedule) NUMBERING ORDER == EMISSION ORDER. Moving the
 * axes deref early to fix the register necessarily emits the axes stores early
 * too -> the 5-instruction block lands ~5% out of place, a net LOSS vs the
 * 0.155% the register rotation costs. The retail target has axes=r29 WITH the
 * block emitted late (c18-c28) -- i.e. numbering DECOUPLED from emission. We
 * could not reproduce that decoupling from clean C under noschedule; #pragma
 * scheduling on diverges massively (69%) and is not what retail used.
 *
 * KEY OBSERVATION: target c18-c28 is BYTE-IDENTICAL to our baseline (same
 * li/addi/stb sequence, same stack offsets, stores direct via r1); ONLY the
 * addi's destination register differs (r29 vs r27). So the instruction stream
 * is already a perfect match -- this is a pure web-numbering TIE-BREAK that our
 * GC/2.0 build resolves one way and the retail toolchain resolved the other,
 * for identical input. Because the stream already matches, ANY source edit that
 * moves the register also moves an instruction => strictly worse. Verified
 * across: 24 decl perms, statement reorder, 8-position block sweep, formation
 * deferral, all-direct stores, aggregate/scalar reorder, radii-first, types,
 * scheduling on. smallbasket_resolveCollision is at its CLEAN-C CEILING (99.845);
 * the residual rotation is a toolchain-internal numbering tie-break, not a
 * recoverable-from-C divergence. (The general decl-order lever remains valid for
 * functions whose deref/numbering position is movable WITHOUT moving emission --
 * this function is the degenerate case where they are welded together.)
 * ------------------------------------------------------------------------- */
