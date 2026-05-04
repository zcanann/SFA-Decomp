/*
 * Manual recovery stub based on claimed split coverage and the surrounding
 * early anonymous corridor.
 *
 * This file is intentionally not wired into the build yet.
 *
 * Current EN split:
 * - main/dll/dll_70.c
 * - 0x8010088C-0x80100890
 *
 * Nearby corridor context:
 * - previous split: main/dll/dll_6F.c
 * - next split: main/dll/dll_71.c
 */

/*
 * No function names were promoted here yet.
 * Start from the current EN split window and the surrounding corridor.
 */



extern char sProjsquirt1DoNoLongerSupported[];
extern void OSReport(const char *fmt, ...);
#pragma scheduling off
#pragma peephole off
int projsquirt1_doUnsupported(void) { OSReport(sProjsquirt1DoNoLongerSupported); return -1; }
#pragma peephole reset
#pragma scheduling reset
