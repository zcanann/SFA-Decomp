/*
 * Manual recovery stub based on claimed split coverage and the surrounding
 * early anonymous corridor.
 *
 * This file is intentionally not wired into the build yet.
 *
 * Current EN split:
 * - main/dll/dll_80.c
 * - 0x801009DC-0x801009E0
 *
 * Nearby corridor context:
 * - previous split: main/dll/dll_7F.c
 * - next split: main/dll/dll_81.c
 */

/*
 * No function names were promoted here yet.
 * Start from the current EN split window and the surrounding corridor.
 */



extern char sProjcore1DoNoLongerSupported[];
extern void OSReport(const char *fmt, ...);

#define PROJECTILE_UNSUPPORTED_RETURN -1

#pragma scheduling off
#pragma peephole off
int projcore1_doUnsupported(void) { OSReport(sProjcore1DoNoLongerSupported); return PROJECTILE_UNSUPPORTED_RETURN; }
#pragma peephole reset
#pragma scheduling reset
