/*
 * Manual recovery stub based on projected debug-side source order.
 *
 * This file is intentionally not wired into the build yet.
 *
 * Corridor evidence:
 * - exact debug-side neighborhood: staffAction.c -> treasurechest.c ->
 *   dll_131.c -> dll_134.c -> campfire.c -> dll_13B.c -> dll_13C.c ->
 *   genprops.c -> gfxEmit.c -> ... -> autoTransporter.c
 * - projected current EN window: 0x801672E4-0x801678A4
 * - debug-side path: dll/dll_131.c
 *
 * Why this stub exists:
 * - dll_131.c is a concrete missing source target in the best current
 *   interval projection for the campfire -> transporter bridge corridor.
 * - Materializing it keeps that corridor organized until a safe split claim
 *   is justified.
 */

