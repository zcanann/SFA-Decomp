/*
 * Manual recovery stub based on claimed split coverage and the surrounding
 * early anonymous corridor.
 *
 * This file is intentionally not wired into the build yet.
 *
 * Current EN split:
 * - main/dll/modgfx67.c
 * - 0x801007E4-0x801007E8
 *
 * Nearby corridor context:
 * - previous split: main/dll/dll_66.c
 * - next split: main/dll/dll_68.c
 */

/*
 * No function names were promoted here yet.
 * Start from the current EN split window and the surrounding corridor.
 */



extern char sProjenergise1DoNoLongerSupported[];
extern void OSReport(const char *fmt, ...);
#pragma scheduling off
#pragma peephole off
int projenergise1_doUnsupported(void) { OSReport(sProjenergise1DoNoLongerSupported); return -1; }
#pragma peephole reset
#pragma scheduling reset
