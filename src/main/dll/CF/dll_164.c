/*
 * Manual recovery stub based on exact debug-side source neighborhood.
 *
 * This file is intentionally not wired into the build yet.
 *
 * Corridor evidence:
 * - exact debug-side neighborhood in the camcontrol -> DIMBoss interval:
 *   CFBaby.c -> laser.c -> CFPrisonGuard.c -> dll_163.c -> dll_164.c ->
 *   dll_165.c -> dll_166.c
 * - debug-side path: dll/CF/dll_164.c
 *
 * Why this stub exists:
 * - dll_164.c is a concrete missing bridge target adjacent to stable CF
 *   anchors we already claim.
 * - Materializing it keeps that local ownership clue visible until a safe
 *   split claim or interval projection is justified.
 */
