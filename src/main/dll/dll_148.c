/*
 * Manual recovery stub based on projected debug-side source order.
 *
 * This file is intentionally not wired into the build yet.
 *
 * Corridor evidence:
 * - exact debug-side neighborhood: ... -> texScroll.c -> dll_147.c ->
 *   dll_148.c -> alphaanim.c -> groundAnimator.c -> crackanim.c -> ...
 * - projected current EN window: 0x8017B2CC-0x8017BF24
 * - debug-side path: dll/dll_148.c
 *
 * Why this stub exists:
 * - dll_148.c is a concrete missing source target in the best current
 *   interval projection for the autoTransporter -> CFguardian corridor.
 * - Materializing it keeps that corridor organized until a safe split claim
 *   is justified.
 */

