/*
 * Manual recovery stub based on projected debug-side source order.
 *
 * This file is intentionally not wired into the build yet.
 *
 * Corridor evidence:
 * - exact debug-side neighborhood: ... -> tFrameAnimator.c ->
 *   screenOverlay.c -> dll_145.c -> texScroll.c -> dll_147.c -> ...
 * - projected current EN window: 0x8017A95C-0x8017AB28
 * - debug-side path: dll/dll_145.c
 *
 * Why this stub exists:
 * - dll_145.c is a concrete missing source target in the best current
 *   interval projection for the autoTransporter -> CFguardian corridor.
 * - Materializing it keeps that corridor organized until a safe split claim
 *   is justified.
 */

