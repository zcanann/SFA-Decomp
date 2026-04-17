/*
 * Manual recovery stub based on exact debug-side source neighborhood.
 *
 * This file is intentionally not wired into the build yet.
 *
 * Corridor evidence:
 * - exact debug-side neighborhood in the camcontrol -> DIMBoss interval:
 *   trigger.c -> dll_16C.c -> dll_159.c
 * - debug-side path: dll/dll_159.c
 *
 * Why this stub exists:
 * - dll_159.c is a concrete anonymous bridge target in a stable debug-side
 *   neighborhood immediately after trigger.c.
 * - Materializing it keeps that local ownership clue visible until a safe
 *   split claim or better interval projection is justified.
 */
