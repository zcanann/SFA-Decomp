/*
 * Manual recovery stub based on projected debug-side source order.
 *
 * This file is intentionally not wired into the build yet.
 *
 * Corridor evidence:
 * - exact debug-side neighborhood: ... -> groundAnimator.c -> crackanim.c ->
 *   dll_14C.c -> dll_14D.c -> dll_14F.c -> ...
 * - projected current EN window: 0x8017E6F8-0x8017EEBC
 * - debug-side path: dll/dll_14C.c
 *
 * Why this stub exists:
 * - dll_14C.c is a concrete missing source target in the best current
 *   interval projection for the autoTransporter -> CFguardian corridor.
 * - Materializing it keeps that corridor organized until a safe split claim
 *   is justified.
 */

