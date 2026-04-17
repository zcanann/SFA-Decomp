/*
 * Manual recovery stub based on exact debug-side source neighborhood.
 *
 * This file is intentionally not wired into the build yet.
 *
 * Corridor evidence:
 * - exact debug-side neighborhood in the camcontrol -> DIMBoss interval:
 *   CFwalltorch.c -> dll_17F.c -> dll_180.c -> holoPoint.c -> dll_182.c
 * - debug-side path: dll/holoPoint.c
 *
 * Why this stub exists:
 * - holoPoint.c is a concrete named bridge target in a stable debug-side
 *   neighborhood immediately after the CF wall torch packet.
 * - Materializing it keeps that local ownership clue visible until a safe
 *   split claim or better interval projection is justified.
 */
