/*
 * Manual recovery stub based on claimed split coverage and the surrounding
 * early anonymous corridor.
 *
 * This file is intentionally not wired into the build yet.
 *
 * Current EN split:
 * - main/dll/dll_64.c
 * - 0x801008FC-0x80100900
 *
 * Nearby corridor context:
 * - previous split: main/dll/dll_74.c
 * - next split: main/dll/dll_75.c
 */

/*
 * No function names were promoted here yet.
 * Start from the current EN split window and the surrounding corridor.
 */



extern char sProjwallpowerDoNoLongerSupported[];
extern void OSReport(const char *fmt, ...);
#pragma scheduling off
#pragma peephole off
int projwallpower_doUnsupported(void) { OSReport(sProjwallpowerDoNoLongerSupported); return 0; }
#pragma peephole reset
#pragma scheduling reset
