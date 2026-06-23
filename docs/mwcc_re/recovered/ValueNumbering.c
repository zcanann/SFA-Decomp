/* ============================================================================
 * RECOVERED: mwcceppc.exe (GC/2.0)  TU = ValueNumbering.c  band 0x509010-0x50a6e0
 * ----------------------------------------------------------------------------
 * Disassembly: docs/mwcc_re/disasm/ValueNumbering.c.objdump.txt
 * The local (per-basic-block) value-numbering pass = `#pragma opt_common_subs`.
 * It (a) substitutes a redundant operand's web with the canonical web that
 * already holds the value (local CSE), and (b) DELETES a copy whose dest and
 * src carry the same value number (this is the blog's `mr`-fold).
 *
 * STATUS: entry driver 0x509010 decoded (the substitution + mr-fold + kill/gen
 * core). The 14 helpers (0x509570 record-expr, 0x5097a0/0x509970 def handlers,
 * 0x50a180 record-value, etc.) are identified by call but not line-decoded.
 * Confidence HIGH on the driver + data structures; [inf] on helper internals.
 * ==========================================================================*/

/* ---- value-number tables (per register class, set up per function) -------- */
extern int  webStart[5];      /* 0x5e9800  #phys regs (web idx < this = phys)   */
/* 0x5e08ac[class] : per-web value record array, 12 bytes (3 ints) per web:
 *   +0x0 = timestamp / value-number id (vs the 0x5e9b44 counter)
 *   +0x4 = canonical web that currently holds this web's value (the "value #")
 *   +0x8 = head of dependent-web list (killed when this web is redefined)      */
extern int *valTab[5];        /* 0x5e08ac */
extern void *gAvailList;      /* 0x5e08a8  list of saved 36-byte value records  */
extern int  gValHi;           /* 0x5e08a4  current value-number high-water       */
extern int  gValCounter;      /* 0x5e9b44  monotonic value-number counter        */

extern void Instr_Delete(void *instr);            /* 0x4dd120  remove an instr   */
extern int  Alias_AddrTaken(void *mem, int);      /* 0x511a30  Alias.c           */
extern void *galloc(int);                          /* 0x440ce0                    */
/* helpers in this TU (call-identified): */
extern void VN_RecordExpr(void *instr);   /* 0x509570  flags&8 & 0x1000100      */
extern void VN_DefHandlerA(void *instr);  /* 0x5097a0  flags&2 & 0x20           */
extern void VN_DefHandlerB(void *instr);  /* 0x509970  flags&2, no 0x20         */
extern void VN_RecordValue(void *a,void *b);/* 0x50a180 record (used by mr path) */

/* ===========================================================================
 * ValueNumber_Block  @ 0x509010   — per-basic-block local value numbering
 *   arg = a basic block; walks each instruction:
 *     1. SUBSTITUTE: for each register operand, if its web's value number
 *        matches an earlier web's, rewrite the operand to that canonical web
 *        (operand+0x4 = canonicalWeb) — local common-subexpression reuse.
 *     2. mr-FOLD: if the instruction is a copy (flags&0x10) whose dest operand
 *        and src operand have the SAME value number, DELETE it (Instr_Delete).
 *        => a copy survives iff dest and src value numbers DIFFER here.
 *     3. KILL/GEN: a defining instruction (flags&0x4, etc.) invalidates the
 *        value records that depended on the redefined web, then records the
 *        new value (so later identical computations can reuse it).
 * ==========================================================================*/
void ValueNumber_Block(void *block)               /* arg @ 0x34(esp)            */
{
    void *instr, *op, *op2;
    int   i, cls, web, cls2, web2;

    for (instr = *(void**)((char*)block + 0x14); instr; instr = *(void**)instr) {

        /* ---- (1) operand value substitution (local CSE) ----  0x509041 ---- */
        op = (char*)instr + 0x24;
        for (i = 0; i < (s16)*(s16*)((char*)instr + 0x22); i++, op = (char*)op + 0xc) {
            if (*(u8*)op != 0) continue;                       /* registers only */
            if ((*(u16*)((char*)op+2) & 0xb) != 1) continue;   /* a USE, not def  */
            cls = *(s8*)((char*)op+1);
            web = *(s16*)((char*)op+4);
            if (web < webStart[cls]) continue;                 /* physical reg    */
            int *rec = valTab[cls] + web*3;                    /* this web's record */
            int canon = rec[1];                                /* its value number  */
            if (canon == 0 || canon < webStart[cls]) continue;
            /* if the canonical web's recorded value == this web's value, reuse it */
            if (valTab[cls][canon*3] == rec[0])                /*           0x509094 */
                *(u16*)((char*)op+4) = (u16)canon;             /* SUBSTITUTE 0x509098 */
        }

        u32 flags = *(u32*)((char*)instr + 0x14);

        /* ---- (2) the mr-FOLD (blog Wall): copy with equal value #s --------- */
        if (flags & 0x10) {                                    /*           0x5090b8 */
            op  = (char*)instr + 0x24;                          /* dest operand     */
            op2 = (char*)instr + 0x30;                          /* src operand      */
            cls  = *(s8*)((char*)op+1);  web  = *(s16*)((char*)op+4);
            cls2 = *(s8*)((char*)op2+1); web2 = *(s16*)((char*)op2+4);
            if (valTab[cls][web*3] == valTab[cls2][web2*3])     /*           0x5090f2 */
                Instr_Delete(instr);   /* dest==src value => copy is redundant     */
            else
                VN_RecordValue(op, op2);  /* keep the copy; record  0x509107/0x50a180 */
            continue;
        }

        /* ---- (3) dispatch other instr classes (kill/gen, record) ---------- */
        if ((flags & 8) && (flags & 0x1000100)) { VN_RecordExpr(instr); continue; } /*0x509123*/
        if (flags & 2) {                                       /*           0x509132 */
            if (flags & 0x20) VN_DefHandlerA(instr);            /*           0x50913e */
            else              VN_DefHandlerB(instr);            /*           0x509150 */
            continue;
        }
        if (flags & 4) {                                       /* def: KILL+GEN 0x509160 */
            /* invalidate value records depending on the defined web (0x5091a0
             * loop): allocate a 36-byte saved record (galloc 0x24), splice the
             * web out of its dependent chains, reset valTab[cls][web] to a fresh
             * value number (gValCounter++). Address-taken/alias gate via
             * Alias_AddrTaken (0x511a30) decides if memory values survive. */
            /* ... (kill/gen loop, not fully line-decoded) ...                  */
        }
    }
}

/* ===========================================================================
 * MATCHING NOTES (answers the PlayControl/matcher-2 probe + the blog)
 *
 * The mr-FOLD rule (lever, validates the blog):
 *   A copy `dst = src` is ELIMINATED iff dst and src carry the SAME value number
 *   at the copy point; it SURVIVES iff they differ. The blog's `e14 |= e` no-op
 *   worked by giving the second value a DISTINCT value number so the copy
 *   survived. Clean-C way to keep a copy: ensure the two values are not value-
 *   number-identical at that point (a genuine recompute / an intervening def).
 *   Clean-C way to kill a copy: make dst and src the same value (don't recompute).
 *
 * MATERIALIZATION POINT (PlayControl residual): this LOCAL pass substitutes a
 * redundant USE to the FIRST occurrence's web (first-use materialization) and
 * never HOISTS — it only reuses within the block, rewriting operand+0x4. So the
 * "block-top hoist / hoist across the call" that matcher-2 saw does NOT come
 * from here; it comes from the EARLIER global CSE in *IroCSE.c* (0x46a360) /
 * IroLinearForm, which can move a common subexpression to a dominator and across
 * calls (forcing the temp live across the call -> a saved register, per the
 * validated Coloring model). => To crack PlayControl's last 4 regions, decompile
 * IroCSE.c next and find the availability/anticipability test that decides
 * hoist-to-dominator vs leave-at-first-use. The local VN here is consistent with
 * the target (first-use); the divergence is upstream global CSE.
 * ==========================================================================*/
