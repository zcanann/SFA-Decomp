/*
 * Manual recovery stub based on exact debug-side source neighborhood.
 *
 * This file is intentionally not wired into the build yet.
 *
 * Corridor evidence:
 * - exact debug-side neighborhood in the camcontrol -> DIMBoss interval:
 *   dll_1A0.c -> dll_1A1.c -> dll_1A2.c -> MMP_mmp_barrel.c
 * - debug-side path: dll/dll_1A2.c
 *
 * Why this stub exists:
 * - dll_1A2.c is a concrete anonymous bridge target in a stable debug-side
 *   neighborhood immediately before the MMP barrel packet.
 * - Materializing it keeps that local ownership clue visible until a safe
 *   split claim or better interval projection is justified.
 */
