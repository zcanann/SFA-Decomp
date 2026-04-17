/*
 * Manual recovery stub based on projected debug-side source order.
 *
 * This file is intentionally not wired into the build yet.
 *
 * Corridor evidence:
 * - exact debug-side neighborhood: ... -> screenOverlay.c -> dll_145.c ->
 *   texScroll.c -> dll_147.c -> dll_148.c -> alphaanim.c -> ...
 * - projected current EN window: 0x8017AB28-0x8017B064
 * - debug-side path: dll/texScroll.c
 *
 * Why this stub exists:
 * - texScroll.c is a concrete missing source target in the best current
 *   interval projection for the autoTransporter -> CFguardian corridor.
 * - Materializing it keeps that corridor organized until a safe split claim
 *   is justified.
 */

