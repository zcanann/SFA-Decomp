/* ============================================================================
 * RECOVERED: mwcceppc.exe (GC/2.0)  TU = IroUnrollLoop.c   band 0x4a1080-0x4a5cf0
 * ----------------------------------------------------------------------------
 * Disassembly: docs/mwcc_re/disasm/IroUnrollLoop.c.objdump.txt
 * Anchored fns: 0x4a1080, 0x4a1430, 0x4a1bd0, 0x4a2200, 0x4a3f80 (assert sites).
 * 25 funcs in band; this is the IR-LEVEL (Iro) loop unroller — runs on the Iro
 * expression/CFG (types ->12 nodes, 0x468c90=IroNodeGetX helpers), NOT PCode.
 * It is upstream of ISEL, so it governs the #113 "speculative unroller" family
 * (2x/8x body replication + live-counter-vs-mtctr;bdnz), which is DISTINCT from
 * the #112 backend strength-reducer (see recovered/StrengthReduction.c).
 *
 * CONFIDENCE: entry/gate/emitter control flow read from binary (HIGH); the exact
 * unroll-factor arithmetic pinned at the imul site. Node-field names [inf].
 * This is a DECISION-LEVEL skeleton (per the brief), not a full instruction map.
 * ==========================================================================*/

extern int   IroLoop_IsWellFormed(void *loop);   /* 0x46a290 [inf] returns bool */
extern int   IroLoop_HasSideEffects(void *loop); /* 0x4c3670 [inf]              */
extern void  Assertion(int line, char *file);    /* 0x463760                    */
extern void *IroNode_X(void*);                   /* 0x468c90 accessor family    */
extern void *IroCopyLoopBody(void*);             /* 0x46cd10 [inf] clone body   */
extern u16   gNewTemp;                           /* 0x5e9000 fresh temp id      */

/* loop/cfg node offsets used below (Iro node, distinct from PCode Instr):
 *   loop->hdr(+0x12) ; hdr->body(+0xe) ; body->tripInfo(+0x8) word ; +0xa loop
 *   config ; cfg+0x20 / cfg+0x24 = the two UNROLL THRESHOLDS (see gate).        */

/* ===========================================================================
 * IroUnrollLoop_Analyze  @ 0x4a1080  — ELIGIBILITY.
 *   ok = IroLoop_IsWellFormed(loop) && !... ; a loop that is not well-formed,
 *   or whose body has disqualifying side effects / unknown trip form, is marked
 *   non-unrollable (byte [esp+0x18] flag). Asserts loop->hdr and hdr->body are
 *   non-null. This is the guard the whole pass keys off.
 * ==========================================================================*/

/* ===========================================================================
 * IroUnrollLoop_Emit  @ 0x4a3f80   *** THE UNROLL DECISION + CLONE ***
 *   THE GATE (0x4a3fe6):
 *     u16 trip = *(u16*)(body + 8);            // static iteration count / bound
 *     if (trip <= cfg->minTrip(+0x20)) goto no_unroll;   // too few iterations
 *     if (trip <= cfg->maxTrip(+0x24)) goto no_unroll;   // (second threshold)
 *   i.e. the loop is only unrolled when its known trip count sits in the
 *   configured window. Small fixed-count loops (the 2x special-glyph scan in
 *   gametext textMeasureFn, #113) hit the LOW threshold and get 2x-unrolled;
 *   loops outside the window keep the rolled `mtctr ; bdnz` form.
 *
 *   THE FACTOR (0x4a40a2):
 *     newBound = origBound(+0x14 = [esp+0x14]) * unrollFactor([esp+0x34]);
 *     stored to clone->bound(+0x12). The clone (IroCopyLoopBody 0x46cd10)
 *     replicates the body `factor` times; the residual/remainder loop is emitted
 *     when trip % factor != 0 (the jge/jl at 0x4a40ac chooses body vs remainder).
 *
 *   NET SHAPE: a fully-unrolled body with `factor` copies + a fresh induction
 *   temp (gNewTemp 0x5e9000) whose increment is scaled by `factor`. When the
 *   trip count is exact the counter is dropped entirely (why some targets show
 *   a chunked-store loop with NO live counter — matches the audio unroll notes).
 * ==========================================================================*/

/* ============================================================================
 * ===  DERIVED #113 (unroller) SOURCE LEVERS  ===============================
 * ============================================================================
 * U1: unroll fires on a STATICALLY-KNOWN trip count in the config window. A
 *     `for(n=K; n!=0; n--)` / `for(i=0;i<K;i++)` with small constant K is the
 *     shape that 2x/8x-unrolls (target `li r0,K/2 ; mtctr ; addi r4,-2`). To
 *     MATCH a target that unrolls: write the loop with the SAME constant bound
 *     and countdown form so the trip count is visible here. To match a target
 *     that does NOT unroll: make the bound runtime (non-constant) so the trip
 *     count is unknown -> Analyze bails -> rolled `bdnz`.
 * U2: the unroll factor comes from the loop config, not source; you cannot pick
 *     2x vs 8x from C. Match by replicating the sibling loop that already
 *     unrolled (frontier fn_80137DF8 sibling-unroll win) rather than tuning.
 * U3: KEEP unrolled-store address expressions PARENTHESIZED as `(row+K)` — this
 *     is a #112 interaction downstream (flattening regressed 86.4->79.8); the
 *     unroller emits the clones, but the address SHAPE inside each clone is then
 *     decided by StrengthReduction.c / ISEL (see that file's L2/L3).
 * ==========================================================================*/
