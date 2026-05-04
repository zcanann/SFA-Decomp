/*
 * Manual recovery stub based on claimed split coverage and the surrounding
 * early anonymous corridor.
 *
 * This file is intentionally not wired into the build yet.
 *
 * Current EN split:
 * - main/dll/dll_83.c
 * - 0x80100A14-0x80100A18
 *
 * Nearby corridor context:
 * - previous split: main/dll/dll_82.c
 * - next split: main/dll/dll_84.c
 */

/*
 * No function names were promoted here yet.
 * Start from the current EN split window and the surrounding corridor.
 */



extern char sProjcore2DoNoLongerSupported[];
extern void OSReport(const char *fmt, ...);
#pragma scheduling off
#pragma peephole off
int projcore2_doUnsupported(void) { OSReport(sProjcore2DoNoLongerSupported); return -1; }
#pragma peephole reset
#pragma scheduling reset
