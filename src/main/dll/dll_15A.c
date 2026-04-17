/*
 * Manual recovery stub based on exact debug-side source neighborhood.
 *
 * This file is intentionally not wired into the build yet.
 *
 * Corridor evidence:
 * - exact debug-side neighborhood in the camcontrol -> DIMBoss interval:
 *   dll_15A.c -> dll_15B.c -> CFguardian.c -> windlift.c -> dll_15E.c
 * - debug-side path: dll/dll_15A.c
 *
 * Why this stub exists:
 * - dll_15A.c is a concrete anonymous bridge target in a stable debug-side
 *   neighborhood immediately before the CF guardian packet.
 * - Materializing it keeps that local ownership clue visible until a safe
 *   split claim or better interval projection is justified.
 */

