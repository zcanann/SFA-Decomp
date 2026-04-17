/*
 * Manual recovery stub based on exact debug-side source neighborhood.
 *
 * This file is intentionally not wired into the build yet.
 *
 * Corridor evidence:
 * - exact debug-side neighborhood in the camcontrol -> DIMBoss interval:
 *   CFTreasSharpy.c -> CFchuckobj.c -> CFwalltorch.c -> dll_17F.c ->
 *   dll_180.c
 * - debug-side path: dll/dll_180.c
 *
 * Why this stub exists:
 * - dll_180.c is a concrete anonymous bridge target in a stable debug-side
 *   neighborhood immediately after the CF treasure/walltorch packet.
 * - Materializing it keeps that local ownership clue visible until a safe
 *   split claim or better interval projection is justified.
 */
