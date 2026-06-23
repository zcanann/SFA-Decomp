/* ============================================================================
 * RECOVERED (data structures + skeleton): mwcceppc.exe (GC/2.0)
 *   TU = InterferenceGraph.c   band 0x57b680-0x57c290  (3 functions)
 * Disassembly: docs/mwcc_re/disasm/InterferenceGraph.c.objdump.txt
 *
 * This builds the inputs Coloring.c consumes: per-web interference (adjacency
 * web+0x1a / degree web+0x18 / working-degree web+0x12) and spill cost (web+0xc).
 * The liveness WALK in 0x57b680 (342 lines: blocks 0x5e9838 -> instrs -> operand
 * def/use, flag bits 0x10/0x100) is summarized, not line-decoded. The two
 * data structures it maintains ARE pinned and are what matters for matching:
 * ==========================================================================*/

/* 0x5e3140 : u16 liveMap[webEnd[class]]  -- allocated & init to identity
 *   (liveMap[i] = i) at the top of BuildInterference (0x57b6a2..0x57b751).
 *   [inf] union/representative map for coalesced/live webs.                   */
extern u16 *gLiveMap;        /* 0x5e3140 */

/* 0x5e3144 : packed LOWER-TRIANGULAR interference bit-matrix.
 *   size = ((n*n/2) + 31)/32 words, n = webEnd[class]  (0x57bad0).
 *   interfere(i,j):  let hi=max(i,j), lo=min(i,j);
 *                    idx = (hi*hi >> 1) + lo;  bit = gIG[idx>>5] & (1<<(idx&31))
 *   Cleared via memset 0x57cef0; set by OR'ing the bit (0x57bb43/0x57bb60).   */
extern u32 *gIG;             /* 0x5e3144 */

/* ===========================================================================
 * InterferenceGraph_Build  @ 0x57b680   [skeleton]
 *   1. liveMap = alloc(n*2); for i in [0,n): liveMap[i] = i;        0x57b69b
 *   2. for each block (gBlockList 0x5e9838):                        0x57b751
 *        for each instruction (block+0x14):
 *          track the live set; for every pair of webs simultaneously live,
 *          mark interference (calls the 0x57bad0 bit-matrix setter) and bump
 *          each web's degree (web+0x12/+0x18) and adjacency (web+0x1a);
 *          accumulate spill cost into web+0xc weighted by loop depth.
 *   (Instruction flag bits 0x10 = defines a reg of interest, 0x100 = skip.)
 * ==========================================================================*/
void InterferenceGraph_Build(void);

/* ===========================================================================
 * InterferenceGraph_Alloc  @ 0x57bad0
 *   Allocates and zeroes the triangular bit-matrix gIG (0x5e3144) for n webs,
 *   then (loop 0x57bb15..) seeds the precolored-register interferences.
 * ==========================================================================*/
void InterferenceGraph_Alloc(void);

/* ===========================================================================
 * fn_57c060  @ 0x57c060   [inf]  — called by the driver on a SPILL round
 *   (Color_AllocateAll 0x508774). Likely frees/rebuilds the graph for the next
 *   Chaitin-Briggs iteration after spill code was inserted. Confirm later.
 * ==========================================================================*/
void InterferenceGraph_AfterSpill(void);

/* ---------------------------------------------------------------------------
 * Lever grounding (feeds LEVERS.md 3-4):
 *  - "degree = simultaneous liveness" is literal: web+0x18 is the count of
 *    webs live at the same time as this one (= popcount of the triangular
 *    bit-matrix row, built per-web at 0x57b470). web+0x12 is a working copy
 *    decremented during Simplify. Change liveness -> change degree -> change
 *    color order/result. This is the only way to move a register.
 *  - RETRACTED "spill cost in web+0xc": VERIFIED there is NO spill cost. The
 *    web is bzero'd at creation (0x57b470 -> bzero 0x440b80) and web+0xc is
 *    NEVER written -> always 0. Color_Simplify's degree/web+0xc = degree/0 =
 *    +Inf for all webs, so optimistic spill is STRUCTURAL (highest web index
 *    first), not weighted. No loop-depth weighting exists. (LEVERS.md lever 4.)
 *
 * Builder call tree (BuildInterferenceGraph 0x57b180, what the driver calls):
 *    0x57ac30  alloc per-class live/def bit-vectors
 *    0x57b2e0  per-block interference into triangular bit-matrix 0x5e3144
 *    0x57bad0  (re)alloc/seed the triangular matrix
 *    0x57b680  liveness over blocks (live-map 0x5e3140)
 *    0x57b470  CREATE webs: alloc web array 0x5e9858 + each web (bzero'd),
 *              set web+0x18=nadj(popcount row), +0x12=degree, +0x14=0xffff,
 *              +0x10=index, +0x1a[]=adjacency. (NOT +0xc — stays 0.)
 *    0x57b1e0  def-walk: set web+0x8 / flag 0x40 (multi-block def span)
 * ------------------------------------------------------------------------- */
