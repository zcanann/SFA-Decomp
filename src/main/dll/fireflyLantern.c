/*
 * Manual recovery stub based on exact debug-side source neighborhood.
 *
 * This file is intentionally not wired into the build yet.
 *
 * Corridor evidence:
 * - exact debug-side neighborhood in the camcontrol -> DIMBoss interval:
 *   dll_112.c -> dll_117.c -> fireflyLantern.c -> dll_115.c -> dll_EE.c
 * - debug-side path: dll/fireflyLantern.c
 *
 * Why this stub exists:
 * - fireflyLantern.c is a concrete named source target in a stable debug-side
 *   neighborhood, even though its current EN window is not isolated yet.
 * - Materializing it keeps that exact-neighborhood clue in the tree until a
 *   safe split claim or better interval projection is justified.
 */

