/*
 * Manual recovery stub based on exact debug-side source neighborhood.
 *
 * This file is intentionally not wired into the build yet.
 *
 * Corridor evidence:
 * - exact debug-side neighborhood in the camcontrol -> DIMBoss interval:
 *   wallanimator.c -> xyzanimator.c -> dll_132.c -> fire.c -> genprops.c
 * - debug-side path: dll/dll_132.c
 *
 * Why this stub exists:
 * - dll_132.c is a concrete anonymous bridge target in a stable debug-side
 *   neighborhood around the fire/genprops handoff.
 * - Materializing it keeps that local ownership clue visible until a safe
 *   split claim or better interval projection is justified.
 */
