/*
 * Manual recovery stub based on claimed split coverage and the DIM corridor.
 *
 * This file is intentionally not wired into the build yet.
 *
 * Current EN split:
 * - main/dll/DIM/DIMExplosion.c
 * - 0x801B13F0-0x801B206C
 *
 * Nearby corridor context:
 * - previous code owner before this file is the small TRK island
 *   `dolphin/TRK_MINNOW_DOLPHIN/MWCriticalSection_gc.c`
 * - next split: main/dll/DIM/DIMwooddoor.c
 */

/*
 * No function names were promoted here yet.
 * Start from the current EN split window and the surrounding corridor.
 */
