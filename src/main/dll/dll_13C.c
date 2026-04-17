/*
 * Manual recovery stub based on projected debug-side source order.
 *
 * This file is intentionally not wired into the build yet.
 *
 * Corridor evidence:
 * - exact debug-side neighborhood: staffAction.c -> treasurechest.c ->
 *   dll_131.c -> dll_134.c -> campfire.c -> dll_13B.c -> dll_13C.c ->
 *   genprops.c -> gfxEmit.c -> ... -> autoTransporter.c
 * - projected current EN window: 0x80169CF8-0x8016B550
 * - debug-side path: dll/dll_13C.c
 *
 * Why this stub exists:
 * - dll_13C.c is a concrete missing source target in the best current
 *   interval projection for the campfire -> transporter bridge corridor.
 * - Materializing it keeps that corridor organized until a safe split claim
 *   is justified.
 */

