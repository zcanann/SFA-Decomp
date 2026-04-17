/*
 * Manual recovery stub based on exact debug-side source neighborhood.
 *
 * This file is intentionally not wired into the build yet.
 *
 * Corridor evidence:
 * - exact debug-side neighborhood in the camcontrol -> DIMBoss interval:
 *   dll_152.c -> dll_153.c -> tFrameAnimator154.c -> dll_155.c -> dll_144.c
 * - debug-side path: dll/tFrameAnimator154.c
 *
 * Why this stub exists:
 * - tFrameAnimator154.c is a concrete named bridge target in a stable
 *   debug-side neighborhood immediately after the groundAnimator/crackanim
 *   packet.
 * - Materializing it keeps that local ownership clue visible until a safe
 *   split claim or better interval projection is justified.
 */
