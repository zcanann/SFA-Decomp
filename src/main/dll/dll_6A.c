/*
 * Manual recovery stub based on claimed split coverage and the surrounding
 * early anonymous corridor.
 *
 * This file is intentionally not wired into the build yet.
 *
 * Current EN split:
 * - main/dll/dll_6A.c
 * - 0x8010081C-0x80100820
 *
 * Nearby corridor context:
 * - previous split: main/dll/dll_69.c
 * - next split: main/dll/dll_6B.c
 */

/*
 * No function names were promoted here yet.
 * Start from the current EN split window and the surrounding corridor.
 */



extern char sProjenergise2DoNoLongerSupported[];
extern void OSReport(const char *fmt, ...);
#pragma scheduling off
#pragma peephole off
int projenergise2_doUnsupported(void) { OSReport(sProjenergise2DoNoLongerSupported); return -1; }
#pragma peephole reset
#pragma scheduling reset
