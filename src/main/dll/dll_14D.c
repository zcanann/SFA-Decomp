/*
 * Manual recovery stub based on projected debug-side source order.
 *
 * This file is intentionally not wired into the build yet.
 *
 * Corridor evidence:
 * - exact debug-side neighborhood: ... -> crackanim.c -> dll_14C.c ->
 *   dll_14D.c -> dll_14F.c -> dll_150.c -> exploder.c -> ...
 * - projected current EN window: 0x8017EEBC-0x8017F168
 * - debug-side path: dll/dll_14D.c
 *
 * Why this stub exists:
 * - dll_14D.c is a concrete missing source target in the best current
 *   interval projection for the autoTransporter -> CFguardian corridor.
 * - Materializing it keeps that corridor organized until a safe split claim
 *   is justified.
 */

