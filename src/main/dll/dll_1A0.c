/*
 * Manual recovery stub based on exact debug-side source neighborhood.
 *
 * This file is intentionally not wired into the build yet.
 *
 * Corridor evidence:
 * - exact debug-side neighborhood in the camcontrol -> DIMBoss interval:
 *   holoPoint.c -> mmp_moonrock.c -> dll_1A0.c -> dll_1A1.c
 * - debug-side path: dll/dll_1A0.c
 *
 * Why this stub exists:
 * - dll_1A0.c is a concrete anonymous bridge target in a stable debug-side
 *   neighborhood immediately after holoPoint.c.
 * - Materializing it keeps that local ownership clue visible until a safe
 *   split claim or better interval projection is justified.
 */
