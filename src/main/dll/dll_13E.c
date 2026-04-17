/*
 * Manual recovery stub based on projected debug-side source order.
 *
 * This file is intentionally not wired into the build yet.
 *
 * Corridor evidence:
 * - exact debug-side neighborhood: autoTransporter.c -> dll_13E.c ->
 *   dll_140.c -> tFrameAnimator.c -> screenOverlay.c -> ... -> CFguardian.c
 * - projected current EN window: 0x80179864-0x80179AF4
 * - debug-side path: dll/dll_13E.c
 *
 * Why this stub exists:
 * - dll_13E.c is a concrete missing source target in the best current
 *   interval projection for the autoTransporter -> CFguardian corridor.
 * - Materializing it keeps that corridor organized until a safe split claim
 *   is justified.
 */

