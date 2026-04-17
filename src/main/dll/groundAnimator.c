/*
 * Manual recovery stub based on projected debug-side source order.
 *
 * This file is intentionally not wired into the build yet.
 *
 * Corridor evidence:
 * - exact debug-side neighborhood: ... -> dll_148.c -> alphaanim.c ->
 *   groundAnimator.c -> crackanim.c -> dll_14C.c -> ...
 * - projected current EN window: 0x8017CCFC-0x8017E1AC
 * - debug-side path: dll/groundAnimator.c
 * - debug-side text: 0x801F7FE0-0x801F8B64
 *
 * Why this stub exists:
 * - groundAnimator.c is a concrete missing source target in the best current
 *   interval projection for the autoTransporter -> CFguardian corridor.
 * - Materializing it keeps that corridor organized until a safe split claim
 *   is justified.
 */

/*
 * No function names were promoted here yet.
 * Start from the projected 0x8017CCFC-0x8017E1AC window and the
 * autoTransporter -> CFguardian interval projection when this file is revisited.
 */
