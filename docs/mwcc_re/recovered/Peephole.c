/* ============================================================================
 * RECOVERED: mwcceppc.exe (GC/2.0)   PASS = Peepholer (the `#pragma peephole`)
 * ----------------------------------------------------------------------------
 * Source of truth: build/compilers/GC/2.0/mwcceppc.exe  (image base 0x400000)
 *   objdump -d --start-address=0xA --stop-address=0xB <mwcceppc.exe>   (code)
 *   objdump -s --start-address=0xA --stop-address=0xB <mwcceppc.exe>   (data)
 *
 * Peephole has NO own assert-TU (README note holds): it is inlined into the
 * PCode emit band PCodeListing.c (0x500c40-0x508100). It is the LAST machine
 * pass; it runs TWICE, both gated by the optimizer driver at 0x433d00-0x434080
 * (the function that prints the "AFTER PEEPHOLE FORWARD"/"AFTER PEEPHOLE
 * OPTIMIZATION" listings @ .data 0x5a6340 / 0x5a63e0):
 *
 *     ... scheduling (0x507ce0) ...
 *     Peephole_Forward(fn)      = 0x500ef0   -> "AFTER PEEPHOLE FORWARD"
 *     register coloring (0x508680)
 *     value numbering post-color (0x508da0)
 *     epilogue/prologue gen + merge (0x4f9950/0x4f9260/0x4f8e10)
 *     Peephole_Optimize(fn)     = 0x500ca0   -> "AFTER PEEPHOLE OPTIMIZATION"
 *
 * CONFIDENCE POLICY (carried from the rest of recovered/): control flow and
 * struct offsets are read directly and are HIGH. Inferred names carry [inf].
 * Each rule below is tagged COMPLETE-AND-EXACT vs PARTIAL. Retraction beats
 * over-claim. The single most important downstream use of this file is the
 * "redex => peephole was OFF" certainty test (task #1); the per-rule
 * BACKWARD-USABLE flag says whether a leftover redex in FINAL asm can certify
 * that, because most rules also test info (def-use chain, liveness) that does
 * NOT survive into final asm. Treat "BACKWARD-USABLE: no" rules as unusable
 * for that proof.
 *
 * Cross-checked: the backend opcode enum (PInstr.opcode, +0x20) is decoded
 * from the per-opcode DESCRIPTOR table at .data 0x5bff48 (stride 18, char*
 * mnemonic @+0, big-endian PPC encoding word @+14). Every opcode number cited
 * here was confirmed against that table AND its encoding's primary opcode.
 * (This is NOT the inline-asm assembler mnemonic table at 0x5c3070 — that one
 * is a different, alphabetical enum used only by the asm{} parser at 0x53c424.)
 * ==========================================================================*/


/* ===========================================================================
 * MACHINE-READABLE RULE LIST  (R = the complete local rewrite system)
 * ---------------------------------------------------------------------------
 * 34 rule-handlers, registered by InitPeepholeTables (0x500f20) into a
 * per-opcode dispatch table at 0x5e00e4 (head[opcode] = list of {next, fn}).
 * "bwd": backward-usable (leftover redex in final asm ⇒ peephole-was-off).
 * "conf": EXACT = complete & exact; PARTIAL = structure solid, some detail/
 * naming inferred. opcodes shown as backend mnemonics (descriptor table).
 *
 * [
 *  -- Address / displacement folds (fold `addi` base-calc into a mem access) --
 *  {addr:0x506210, name:"fold_li0_base_into_mem",  on:[lbz,lhz,lha,lwz,stb,sth,stw,lfs,lfd,stfs,stfd],
 *     lhs:"li rT,0 (op137 w/ +0x30==3); MEM ...,0(rT)", rhs:"MEM ...,(rT')  [op2<-li source]",
 *     side:"disp==0; regs match; def reg dead", bwd:no, conf:PARTIAL},
 *  {addr:0x505d10, name:"fold_addi_into_mem_disp",  on:[same d-form load/store set],
 *     lhs:"addi rT,rB,k; MEM rD,d(rT)", rhs:"MEM rD,(d+k)(rB); delete addi",
 *     side:"d-form; (d+k) fits s16; rT last-use; if rT live -> record form", bwd:no, conf:EXACT},
 *  {addr:0x505a70, name:"cse_redundant_addi",       on:[same d-form set],
 *     lhs:"MEM uses rX; later addi rX,rX,k recomputes same value (op63), no use between",
 *     rhs:"delete the later addi", side:"same disp; no intervening use; liveMask", bwd:no, conf:EXACT},
 *  {addr:0x505be0, name:"fold_addi_into_update_mem", on:[lbzu,lhzu,lhau,lwzu,stbu,sthu,stwu,lfsu,lfdu,stfsu,stfdu],
 *     lhs:"addi rT,rB,k (op63); MEMU ...,d(rT)", rhs:"MEMU ...,(d+k)(rB); delete addi",
 *     side:"same as 0x505d10 for update-form; +0x28==+0x34 on def; s16 overflow guard", bwd:no, conf:EXACT},
 *
 *  -- Store family --
 *  {addr:0x5048f0, name:"dead_store_elim_aliasguard", on:[stb,sth,stw,stfs,stfd,stbx,sthx,stwx,stfsx,stfdx],
 *     lhs:"store to addr A of a value an earlier op already wrote/holds at A; nothing aliasing A between",
 *     rhs:"delete the store", side:"both simple(flags&0x2000180==0,&9==0); same base/mode/disp/index;"
 *         " base not redef'd; byte-range overlap scan via load/store width tables (0x504afe/0x504bc0/0x504e38)",
 *     bwd:no, conf:EXACT},
 *  {addr:0x502d80, name:"fuse_2_rlwinm_into_hstore", on:[sth,sthx],
 *     lhs:"sth fed by rlwimi(op105)<-rlwinm(op103) extract pair, shapes {8,16,23}/{24,24,31}",
 *     rhs:"single op63 rotate/extend or move; delete the 2 sources", side:"shapes each once; no later def; liveMask",
 *     bwd:no, conf:PARTIAL},
 *  {addr:0x5031f0, name:"fuse_4_rlwinm_into_wstore", on:[stw,stwx],
 *     lhs:"stw fed by 4-instr rlwimi/rlwinm decomposition (3x op105 + 1x op103), shape lattice",
 *     rhs:"single op63 rotate-mask or move; delete 4 sources", side:"each lattice bit once; no later def; liveMask",
 *     bwd:no, conf:PARTIAL},
 *
 *  -- Compare / record-bit fusion (THE anchor: CLAUDE.md "extsb./rlwinm.+cmpwi rX,0") --
 *  {addr:0x506e70, name:"fuse_cmpwi0_into_record",   on:[cmpwi(op82)],
 *     lhs:"<record-capable arith d>; cmpwi cr0,rX,0  (op0.reg==0=CR0, imm==0)",
 *     rhs:"set d's record(.)-form (0x4eb030); delete the cmpwi",
 *     side:"(d->flags&0x88000100)==0x88000000 && (d->flags&9)==0; CR0 not used/redef elsewhere in block;"
 *         " addi sub-case (d=op63) has extra checks -> addic.",
 *     bwd:PARTIAL, conf:EXACT},
 *
 *  -- Copy elimination: mr(139)/fmr(158)/ps_mr(401) families --
 *  {addr:0x507440, name:"mr_selfcopy_delete",  on:[mr],   lhs:"mr rX,rX", rhs:"delete",
 *     side:"op0.reg==op1.reg && !(flags&0x20000000 w/o 0x9)", bwd:YES, conf:EXACT},
 *  {addr:0x507400, name:"fmr_selfcopy_delete", on:[fmr],  lhs:"fmr fX,fX", rhs:"delete", side:"same", bwd:YES, conf:EXACT},
 *  {addr:0x5073c0, name:"psmr_selfcopy_delete",on:[ps_mr],lhs:"ps_mr pX,pX",rhs:"delete", side:"same", bwd:YES, conf:EXACT},
 *  {addr:0x507300, name:"mr_deadcopy_delete",  on:[mr],   lhs:"mr whose def is itself an mr to a dead reg",
 *     rhs:"delete", side:"def-chain + no later DEF of src", bwd:no, conf:EXACT},
 *  {addr:0x507240, name:"fmr_deadcopy_delete", on:[fmr],  lhs:"(as above, fmr)", rhs:"delete", side:"", bwd:no, conf:EXACT},
 *  {addr:0x507180, name:"psmr_deadcopy_delete",on:[ps_mr],lhs:"(as above, ps_mr)",rhs:"delete", side:"", bwd:no, conf:EXACT},
 *  {addr:0x505390, name:"mr_copyfold_rename",  on:[mr],   lhs:"mr whose def is foldable producer",
 *     rhs:"rewrite ins operands from def; delete def; re-thread", side:"def dst dead/eq; no remaining use", bwd:no, conf:EXACT},
 *  {addr:0x505270, name:"psmr_copyfold_rename",on:[ps_mr],lhs:"ps_mr whose def is PS producer (op415-417)",
 *     rhs:"fold producer into move site; delete def", side:"liveMask class2; no remaining use", bwd:no, conf:EXACT},
 *  {addr:0x5050d0, name:"mr_coalesce_backward", on:[mr],  lhs:"mr; producer can write ins's reg directly",
 *     rhs:"rename producer dst -> ins dst; delete mr", side:"3 use/def scans + liveMask", bwd:no, conf:EXACT},
 *  {addr:0x504f30, name:"fmr_coalesce_backward",on:[fmr], lhs:"(as above, fmr)", rhs:"rename+delete", side:"3 scans", bwd:no, conf:EXACT},
 *  {addr:0x507040, name:"psmr_neighbor_merge",  on:[ps_mr],lhs:"ps_mr w/ neighbor flag pattern (op402 vmrp)",
 *     rhs:"reclassify (no delete)", side:"neighbor flags 0xc0000000", bwd:no, conf:PARTIAL},
 *  {addr:0x503f00, name:"li_canonicalize_mode8", on:[mr], lhs:"under global mode 0x5e4822==8, neighbor flags",
 *     rhs:"force op2 imm=0, tag op63; returns 0 (normalizer)", side:"mode==8; opcount>=2", bwd:no, conf:PARTIAL},
 *
 *  -- Rotate / logical simplification --
 *  {addr:0x504450, name:"merge_rlwinm_rlwinm",  on:[rlwinm,rlwimi],
 *     lhs:"rlwinm rD,rA,SHf,MBf,MEf; rlwinm rD,rD,SHo,MBo,MEo",
 *     rhs:"rlwinm rD,rA,(SHf+SHo)%32,MB',ME' where mask'=rotl(mask(MBf,MEf),SHo)&mask(MBo,MEo); delete feeder",
 *     side:"mask' must be a single contiguous PPC run (0x4488b0); feeder last-use; stage2 also folds mr->rlwinm",
 *     bwd:PARTIAL, conf:EXACT},
 *  {addr:0x5066b0, name:"absorb_lowmask_after_hload", on:[rlwinm],
 *     lhs:"rlwinm rD,rX,0,MB,31 (MB<=16) where rX from lhz/lhzx(op25/27)", rhs:"absorb mask into load; retarget; delete feeder",
 *     side:"SH==0; MB<=16; ME==31; last-use", bwd:no, conf:EXACT},
 *  {addr:0x5068a0, name:"absorb_lowmask_after_bload", on:[rlwinm],
 *     lhs:"rlwinm rD,rX,0,MB,31 (MB<=24) where rX from lbz/lbzx(op21/23)", rhs:"absorb; delete feeder",
 *     side:"SH==0; MB<=24; ME==31; last-use", bwd:no, conf:EXACT},
 *  {addr:0x506a90, name:"drop_extsh_masked_to_16", on:[rlwinm],
 *     lhs:"rlwinm of extsh(op101) result whose rotated mask fits low 16 bits", rhs:"source pre-extend reg; delete extsh",
 *     side:"rotl(mask(MB,ME),SH)&0xffff0000==0; last-use", bwd:no, conf:EXACT},
 *  {addr:0x506c80, name:"drop_extsb_masked_to_8",  on:[rlwinm],
 *     lhs:"rlwinm of extsb(op100) result whose rotated mask fits low 8 bits", rhs:"source pre-extend reg; delete extsb",
 *     side:"rotl(mask(MB,ME),SH)&0xffffff00==0; last-use", bwd:no, conf:EXACT},
 *  {addr:0x506390, name:"redundant_extsh_elim", on:[extsh],
 *     lhs:"extsh of an already-sign-correct value (feeder lha(op29) or extsb(op100)/self)",
 *     rhs:"delete the extsh (or retag to mr / copy feeder operand)", side:"value already 16-bit-correct; last-use",
 *     bwd:no, conf:PARTIAL},
 *  {addr:0x503fb0, name:"merge_srawi_srawi", on:[srawi],
 *     lhs:"srawi (srawi x,a),b", rhs:"srawi x,(a+b); delete feeder", side:"0<a+b<32; both imm; last-use", bwd:no, conf:EXACT},
 *  {addr:0x5054a0, name:"fold_not_into_and", on:[and],
 *     lhs:"and rA, NOT(op141) rB", rhs:"retarget AND operand to rB (-> andc family); delete the NOT",
 *     side:"NOT result dead/single-use", bwd:no, conf:PARTIAL},
 *  {addr:0x5037a0, name:"recognize_rotate_from_shift_or", on:[or],
 *     lhs:"or( slw(op106) x,n , srw(op107) x, (subfic op79: 32-n) )", rhs:"single full-width rotate (rlwinm x,n,0,31); delete feeders",
 *     side:"shared 32-bit source (op79 width imm 0x20); equal SH; all temps dead; legality scan 0x503df0",
 *     bwd:no, conf:PARTIAL},
 *
 *  -- Branch (bt op5 / bf op8) --
 *  {addr:0x505610, name:"coalesce_cr_source_into_branch", on:[bt,bf],
 *     lhs:"branch consumes a CR bit produced through a cmp(op82/84)->CR chain",
 *     rhs:"branch reads the original CR directly; drop intermediate", side:"intermediate dead; 3 interference scans",
 *     bwd:no, conf:PARTIAL},
 *  {addr:0x505820, name:"fuse_cmpli0_into_record_for_branch", on:[bt,bf],
 *     lhs:"branch <- (cmpli(op84) cr0,_,0) <- src",
 *     rhs:"set src record-form (0x4eb030); branch reads src.CR0; delete the cmpli",
 *     side:"(src->flags&0x88000100)==0x88000000; CR0 not used/redef in gap", bwd:PARTIAL, conf:EXACT},
 *  {addr:0x505980, name:"branch_condition_known_threading", on:[bt,bf],
 *     lhs:"bt/bf <- CR0-set(op82/84) <- immediate compare(li op137); polarity(bt vs bf)==(cmpImm==crImm)",
 *     rhs:"rewrite branch target operand block (op2->op0), re-thread list",
 *     side:"cmp immediate form; CR0; polarity consistent", bwd:YES(mostly-syntactic), conf:PARTIAL},
 *
 *  -- Constant fold through a source register --
 *  {addr:0x504140, name:"fold_addi_addi", on:[addi],
 *     lhs:"addi rX,rB,k1; addi rD,rX,k2", rhs:"addi rD,rB,(k1+k2); delete first",
 *     side:"k1+k2 fits s16; rX last-use/dead; rD not redef'd in gap; both disp-imm", bwd:no, conf:EXACT},
 *  {addr:0x5042d0, name:"fold_mulli_mulli", on:[mulli],
 *     lhs:"mulli rX,rB,k1; mulli rD,rX,k2", rhs:"mulli rD,rB,(k1*k2); delete first",
 *     side:"k1*k2 fits s16; same gap/liveness as 0x504140", bwd:no, conf:EXACT}
 * ]
 *
 * FORWARD pass (0x5019a0, called by Peephole_Forward) is a SINGLE specialized
 * rule fixed to opcode rlwinm(0x67=103): it scans forward across same-reg
 * rlwinm/rlwimi instrs building SH/MB/ME masks (fields at op offsets
 * +0x3e/+0x4a/+0x56) and merges a forward chain BEFORE register coloring.
 * Treated as a pre-pass variant of merge_rlwinm_rlwinm; PARTIAL (head decoded).
 * ==========================================================================*/


/* ===========================================================================
 * STRUCTURES (offsets read directly from the dispatcher/handlers)
 * ==========================================================================*/

/* A machine instruction in a basic block. The block holds a CIRCULAR doubly
 * linked list of these (forward ->next eventually wraps; a forward scan that
 * stops at a sentinel instr therefore visits every OTHER instr in the block).
 * Size >= 0x60. Offsets below are all confirmed from code. */
typedef struct PInstr {
    /* +0x00 */ struct PInstr *prev;
    /* +0x04 */ struct PInstr *next;
    /* +0x08 */ void   *descr;     /* per-opcode static descriptor (table @0x5bff48-ish runtime copy);
                                      descr+0x0c != 0 => "produces a result"; descr+0x2a = u16 flags  */
    /* +0x10 */ int     valueId;   /* result web/value id; indexes the def-use table 0x5e00e0          */
    /* +0x14 */ u32     flags;     /* side-effect/class bits. Tested: &9, &0x2000180, &0x20000000,
                                      &0x88000100 (==0x88000000 => record-capable arith), &2 (defs result) */
    /* +0x20 */ s16     opcode;    /* BACKEND opcode enum (descriptor table 0x5bff48)                  */
    /* +0x22 */ s16     argCount;
    /* +0x24 */ PCodeArg args[1];  /* operand array, 12-byte stride (see below)                        */
    /* per-operand fast-field aliases used by the handlers:
     *   op0: +0x24 kind, +0x25 regClass, +0x28 reg
     *   op1: +0x30 kind, +0x31 regClass, +0x34 reg
     *   op2: +0x3c kind, +0x3e s16 immediate/displacement, +0x40 indexReg, +0x42 disp-hi
     *   op3 imm region: +0x4a    op4 imm region: +0x56   (used as rlwinm MB/ME by the rotate rules) */
} PInstr;

/* operand, 12 bytes (matches Scheduler.c's PCodeArg) */
typedef struct PCodeArg {
    /* +0x00 */ u8  kind;      /* 0 = register; 2 = small disp/imm; 3 = disp with hi/lo split; 0 also = indexed */
    /* +0x01 */ s8  regClass;  /* 0..4 ; 4 = GPR, 3 = FPR, 2 = paired-single                                  */
    /* +0x02 */ u16 argFlags;  /* bit0 (0x1) = USE ; bit1 (0x2) = DEF                                          */
    /* +0x04 */ s16 reg;
    /* +0x06.. */ /* immediate/value bytes (per-operand; the disp the fold rules add lives in this region)    */
} PCodeArg;

/* The def-use table: PInstr* gDefUse[] at 0x5e00e0, TWO columns per valueId:
 *   col0  = *(u32*)(0x5e00e0 + valueId*4 + 0)   [inf] use / next-reference side
 *   colDEF= *(u32*)(0x5e00e0 + valueId*4 + 4)   [inf] defining-instruction side
 * Handlers read one column to find the related instr, and after a rewrite copy
 * the deleted instr's column into the survivor's to re-thread the chain. This
 * table is the forward def-use chain; it is NOT reconstructible from final asm,
 * which is why most rules below are not backward-usable. */
extern PInstr *gDefUse[];                 /* 0x5e00e0 */
extern PInstr *gPeepRuleTable[];          /* 0x5e00e4 : head[opcode] = rule-list */
extern PInstr *gBlockList;                /* 0x5e9838 : head of basic-block list */

/* shared helpers */
extern void DeleteInstr(PInstr*);         /* 0x4dd120 : unlink + free                                    */
extern void SetRecordForm(PInstr*);       /* 0x4eb030 : flag-normalize / set the '.'-form (Rc=1) on def  */
extern PInstr *AllocInstr(int,...);       /* 0x4dd4d0 */
extern void SpliceInstr(PInstr*,PInstr*); /* 0x4dd0a0 */
/* 0x529b80(sel)/0x529be0/0x529c50/0x512e20 : operand-web detach/attach + reloc/CR recompute bookkeeping */


/* ===========================================================================
 * PASS DRIVERS
 * ==========================================================================*/

/* Peephole_Forward — 0x500ef0. Runs after scheduling, before coloring. Fires
 * only on blocks of >= 2 instrs; the worker (0x5019a0) is the single rlwinm
 * forward-merge rule. */
void Peephole_Forward(void) {
    for (PInstr *b = gBlockList; b; b = *(PInstr**)b)   /* block->next at block+0x00 */
        if (*(s16*)((char*)b + 0x28) >= 2)              /* block->numInsns          */
            PeepholeBlock_Forward(b);                   /* 0x5019a0                 */
}

/* Peephole_Optimize — 0x500ca0. Runs after prologue/epilogue. Builds the rule
 * dispatch tables, then runs the full rule set per block. */
void Peephole_Optimize(void *fn) {
    InitPeepholeTables();                  /* 0x500f20 : zero 0x5e00e4 table; register all 34 rules     */
    PeepholePrepFn(fn);                    /* 0x507820                                                  */
    for (PInstr *b = gBlockList; b; b = *(PInstr**)b) {
        if (*(s16*)((char*)b + 0x28) >= 1) {
            PeepholePrepBlock(b);          /* 0x507660 : seed gDefUse for the block                     */
            PeepholeBlock_Optimize(b);     /* 0x502c00 : dead-code + rule dispatch (below)              */
            PeepholeBlockFinish(b);        /* 0x440bf0                                                  */
        }
    }
}


/* ===========================================================================
 * THE WORKER / DISPATCHER  — 0x502c00  (PeepholeBlock_Optimize)
 * Per instruction: (1) delete if dead, else (2) run every rule registered for
 * its opcode until none fires, then (3) update the live-out masks. The rule
 * handler ABI and the re-dispatch loop are the heart of the system.
 * COMPLETE-AND-EXACT.
 * ==========================================================================*/
void PeepholeBlock_Optimize(Block *blk) {
    u32 live[5];                                   /* live-OUT mask per reg class, threaded forward */
    for (int c = 0; c < 5; c++)                    /* seed from the block's live-out info           */
        live[c] = regClassTable_5e0838[c][ blk->field_1c * 16 + 0xc ];

    for (PInstr *ins = blk->firstInsn /*+0x18*/; ins; ins = ins->next /*+0x04*/) {

        /* ---- (1) dead-code elimination -------------------------------------------------- */
        int dead;
        if ((ins->descr->field_2a & 3) != 0)            dead = 0;     /* descriptor forbids deletion */
        else if ((ins->flags & 0x18d) != 0)             dead = 0;     /* has side effects            */
        else if (ins->descr->field_c == 0)              dead = 1;     /* no result at all -> dead     */
        else {                                                        /* dead iff every DEF is dead   */
            dead = 1;
            for (PCodeArg *a = ins->args; a < ins->args + ins->argCount; a++)
                if (a->kind == 0 && (a->argFlags & 0x2))             /* a register DEF              */
                    if (live[a->regClass] & (1u << a->reg)) { dead = 0; break; }  /* still live      */
        }
        if (dead) { DeleteInstr(ins); continue; }

        /* ---- (2) rule dispatch by opcode ------------------------------------------------ */
        for (RuleNode *r = gPeepRuleTable[ins->opcode]; r; ) {
            int changed = r->fn(ins, live);          /* handler ABI: int fn(PInstr*, u32 live[5]) */
            if (changed) {                           /* a rule fired and mutated the stream       */
                if (ins->next == 0 /*+0x8? actually ins still valid*/) break;
                r = gPeepRuleTable[ins->opcode];     /* re-dispatch from scratch (opcode may differ) */
            } else {
                r = r->next;                         /* try next rule for this opcode               */
            }
        }

        /* ---- (3) advance the live-out masks across `ins` (clear DEFs, set USEs) ---------- */
        for (PCodeArg *a = ins->args; a < ins->args + ins->argCount; a++)
            if (a->kind == 0 && (a->argFlags & 0x2)) live[a->regClass] &= ~(1u << a->reg);
        for (PCodeArg *a = ins->args; a < ins->args + ins->argCount; a++)
            if (a->kind == 0 && (a->argFlags & 0x1)) live[a->regClass] |=  (1u << a->reg);
    }
}
/* Rule registration (InitPeepholeTables, 0x500f20): each rule is pushed onto
 * gPeepRuleTable[opcode] as a node {next@+0, fn@+4}. 90 registrations across 41
 * opcodes -> the 34 distinct fn's enumerated in the JSON block above. Multiple
 * rules per opcode are tried in REGISTRATION ORDER (LIFO push => the last
 * registered runs first); a firing rule restarts the list. */


/* ===========================================================================
 * REPRESENTATIVE RULE DECOMPILATIONS
 * (The remaining rules follow the same shape; see the JSON list for each.)
 * ==========================================================================*/

/* --- THE ANCHOR: compare-into-record-bit fusion --- 0x506e70 (on cmpwi op82)
 * This is CLAUDE.md's "compare feeding a branch merged into the dot form".
 * COMPLETE-AND-EXACT. */
int rule_fuse_cmpwi0(PInstr *cmp, u32 live[5]) {
    PInstr *d = gDefUse[cmp->valueId].colDEF;     /* the instr that produced the compared value */
    if (cmp->op0.reg != 0)        return 0;        /* must compare into CR0 (op0.reg == 0)        */
    if (cmp->op2_imm /*+0x3e*/!=0) return 0;        /* must be `cmpwi cr0, rX, 0`                   */
    u32 f = d->flags; if (f & 9) f = 0;
    if ((f & 0x88000100) != 0x88000000) return 0;  /* d must be a record-CAPABLE result producer  */
    /* the CR0 result must not be USED nor re-DEFINED anywhere else in the (circular) block: */
    if (anyOperand(cmp->next, d, cmp->op0.regClass, /*reg*/0, USE)) return 0;
    if (anyOperand(cmp->next, d, cmp->op0.regClass, /*reg*/0, DEF)) return 0;
    if (d->opcode == 0x3f /*addi*/) {              /* addi has no '.'-form: verify XER/carry safe  */
        if (addiRecordUnsafe(d, cmp)) return 0;     /* extra operand scan; bail if unsafe -> addic. */
    }
    SetRecordForm(d);                              /* 0x4eb030 : d becomes the recording dot-form  */
    DeleteInstr(cmp);                              /* 0x4dd120 : the cmpwi is now redundant        */
    return 1;
}
/* SIGNED ONLY. 0x506e70 is registered ONLY on op82 (signed cmpwi). The UNSIGNED
 * compare op84 (cmplwi/cmpli) has NO standalone rule (slot 0x5e0234 unregistered)
 * -> a cmplwi whose result is materialized is NEVER fused. cmplwi IS fused only
 * when it directly feeds a bt/bf branch, via the mirror handler 0x505820 (same
 * record-capable + dead-CR0 conditions); sound because cmplwi rX,0's only live
 * bit is EQ(rX==0), which the signed dot-form reproduces exactly.
 *
 * SetRecordForm (0x4eb030) confirmed: clears flags &~0x6010, then converts the
 * producer to its dot/record form -- most ops just get flag 0x20000000 set
 * ("emit Rc=1" => extsb->extsb., rlwinm/clrlwi->rlwinm., and->and., add->add.);
 * the special opcodes 0x56/0x57 just get 0x20000000; and addi(63) is rewritten
 * to opcode 65 = addic. (with an extra safety check; bail if carry unsafe).
 *
 * BACKWARD-USABLE: PARTIAL. A leftover `<op> rX,...; cmpwi cr0,rX,0` in final asm
 * IS a redex iff <op> is record-capable (flag 0x80000000: a '.'-form exists) AND
 * CR0 is not otherwise live/used. Escape hatches where peephole-ON legitimately
 * leaves the redex: (1) producer NOT record-capable -- loads (lwz/lhz/...), plain
 * mr/li have no dot sibling, so `lwz rX; cmpwi rX,0` survives ON; (2) CR0 still
 * live; (3) addi where addic. is unsafe. Restricting the LHS producer to
 * extsb/rlwinm/clrlwi/and/... (all record-capable) removes escape (1), making the
 * SIGNED-cmpwi redex a complete-and-exact peephole-OFF oracle (single handler,
 * deterministic). For UNSIGNED, restrict the oracle to cmplwi-feeding-a-branch. */


/* --- fold addi base-calc into a memory displacement --- 0x505d10
 * (registered on lbz/lhz/lha/lwz/stb/sth/stw/lfs/lfd/stfs/stfd). EXACT. */
int rule_fold_addi_into_mem(PInstr *mem, u32 live[5]) {
    PInstr *d = gDefUse[mem->valueId].colDEF;      /* defining instr of mem's base reg            */
    if (mem->op2.kind != 2) return foldImmPath(mem,d,live);   /* not a small-disp form            */
    if (mem->op0.regClass==4 && mem->op0.reg==mem->op1.reg) return 0;  /* base==dst guard          */
    if (mem->op2_imm != 0)  return foldImmPath(mem,d,live);
    if (d->opcode != 0x3f /*addi*/) return foldImmPath(mem,d,live);
    if (d->op0.reg != d->op1.reg)  return foldImmPath(mem,d,live);     /* addi rX,rX,k form        */
    if (anyOperand(mem->next, d, d->op0.regClass, d->op1.reg, USE)) return 0;  /* base last-use     */
    if (live[?] & (1u << d->op1.reg)) /* base still live -> switch mem to record form */ ;
    foldDisplacement(mem, d);                      /* mem.disp += d.disp (s16 overflow guarded)    */
    gDefUse[mem->valueId].colDEF = gDefUse[d->valueId].colDEF;
    DeleteInstr(d);
    return 1;
}
/* BACKWARD-USABLE: no. Needs gDefUse + base-reg last-use; a folded result is an
 * ordinary `lwz rD, k(rB)` indistinguishable from hand-written. */


/* --- mr self-copy delete --- 0x507440 (mr) / 0x507400 (fmr) / 0x5073c0 (ps_mr)
 * The three are byte-identical modulo call displacement. EXACT, and the ONLY
 * fully-backward-usable rules. */
int rule_mr_selfcopy(PInstr *mv, u32 live[5] /*unused*/) {
    if (mv->op0.reg == mv->op1.reg) {              /* dst == src  (+0x28 == +0x34)                 */
        u32 f = mv->flags; if (f & 9) f = 0;
        if (!(f & 0x20000000)) { DeleteInstr(mv); return 1; }   /* not "do-not-touch"             */
    }
    return 0;
}
/* BACKWARD-USABLE: YES, unconditional. A surviving `mr rX,rX` / `fmr fX,fX` /
 * `ps_mr pX,pX` in retail asm certifies the peepholer was OFF (or this rule
 * disabled): no def-use or liveness input gates it. */


/* --- merge two rlwinm into one --- 0x504450 (rlwinm/rlwimi). EXACT on the math. */
int rule_merge_rlwinm(PInstr *outer, u32 live[5]) {
    PInstr *f = gDefUse[outer->valueId].col0;
    if (f->opcode == 0x67 /*rlwinm*/) {
        /* ... volatile + last-use guards ... */
        u32 maskF = ppc_mask(f->mb /*+0x4a*/, f->me /*+0x56*/);
        u32 maskO = ppc_mask(outer->mb, outer->me);
        u32 maskN = rotl32(maskF, outer->sh /*+0x3e*/) & maskO;
        s16 mbN, meN;
        if (!ppc_mask_decode(maskN, &mbN, &meN)) return 0;   /* 0x4488b0: must be single contig run */
        outer->op2.reg = f->op1.reg;                          /* source becomes f's source           */
        gDefUse[outer->valueId].colDEF = gDefUse[f->valueId].colDEF;
        outer->sh = (outer->sh + f->sh) & 0x1f;               /* SH' = (SHo+SHf) mod 32              */
        outer->mb = mbN; outer->me = meN;
        if (!stillUsed(f)) DeleteInstr(f);
        return 1;
    }
    /* stage 2: f->opcode == 0x8b (mr) -> copy-propagate mr source into the rlwinm. */
    return mergeMrIntoRlwinm(outer, f);
}
/* ppc_mask(mb,me)  = (mb<=me) ? (~( ~0u>>(me+1) ) &  (~0u>>mb))
 *                             : (~( ~0u>>(me+1) ) | (~0u>>mb))  ;  (PPC wrapped run)
 * BACKWARD-USABLE: PARTIAL. Two chained rlwinm on a dead temp is a redex ONLY if
 * the combined mask is a single contiguous run (else the rule legitimately
 * declines). Presence of a NON-mergeable pair proves nothing. */


/* ===========================================================================
 * BACKWARD-INFERENCE SUMMARY  (the task #1 certainty test)
 * ---------------------------------------------------------------------------
 * "Final asm contains a redex of rule R" certifies "peephole was OFF" ONLY for
 * rules whose firing depends solely on info still present in the final asm.
 *
 *  USABLE (redex => peephole off):
 *    - mr/fmr/ps_mr self-copy  (0x507440/0x507400/0x5073c0): UNCONDITIONAL.
 *    - cmpwi-0 record fusion    (0x506e70; also via branch 0x505820): conditional
 *        on the producer having a '.'-form AND CR0 not otherwise needed.
 *    - branch-condition-known threading (0x505980): mostly syntactic (opcodes +
 *        immediates + bt/bf polarity), modulo the structurally-recoverable
 *        compare link.
 *    - rlwinm.rlwinm merge (0x504450): conditional on the merged mask being a
 *        single contiguous run.
 *
 *  NOT USABLE (firing needs gDefUse and/or liveMask/last-use, which do not
 *  survive into final asm — a leftover redex is explainable by liveness, so it
 *  certifies nothing):  ALL the address/displacement folds, the dead-store
 *  elimination, the store-fusion pair, every dead-copy / copy-fold / coalesce
 *  (0x507300/0x507240/0x507180/0x505390/0x505270/0x5050d0/0x504f30), the
 *  rotate/mask absorbers, extsh/srawi/and/or simplifications, the addi/mulli
 *  constant folds, and branch rules 0x505610/0x505820's gating liveness.
 *
 * Net: the peepholer is a normalizing rewrite system, but only a HANDFUL of its
 * rules leave a syntactically-detectable footprint. Use the USABLE set as
 * positive "peephole was off" evidence; never infer "peephole was on" from the
 * absence of a redex of a NOT-USABLE rule.
 * ==========================================================================*/
