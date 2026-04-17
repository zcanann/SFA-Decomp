/*
 * Manual recovery stub based on projected debug-side source order.
 *
 * This file is intentionally not wired into the build yet.
 *
 * Corridor evidence:
 * - exact debug-side neighborhood: campfire.c -> dll_13B.c -> dll_13C.c ->
 *   genprops.c -> gfxEmit.c -> dll_141.c -> dll_138.c -> transporter.c ->
 *   autoTransporter.c -> dll_13E.c -> dll_140.c
 * - projected current EN window: 0x80174B14-0x801758D4
 * - debug-side path: dll/dll_138.c
 *
 * Why this stub exists:
 * - dll_138.c is a concrete missing source target in the best current
 *   interval projection for the campfire -> transporter bridge corridor.
 * - Materializing it keeps that corridor organized until a safe split claim
 *   is justified.
 */
