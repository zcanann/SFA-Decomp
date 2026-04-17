/*
 * Manual recovery stub based on projected debug-side source order.
 *
 * This file is intentionally not wired into the build yet.
 *
 * Corridor evidence:
 * - exact debug-side neighborhood: ... -> dll_14D.c -> dll_14F.c ->
 *   dll_150.c -> exploder.c -> CFguardian.c
 * - projected current EN window: 0x801819B0-0x80181C50
 * - debug-side path: dll/dll_150.c
 *
 * Why this stub exists:
 * - dll_150.c is a concrete missing source target in the best current
 *   interval projection for the autoTransporter -> CFguardian corridor.
 * - Materializing it keeps that corridor organized until a safe split claim
 *   is justified.
 */

