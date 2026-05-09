/*
 * Manual recovery stub based on claimed split coverage and the surrounding
 * early anonymous corridor.
 *
 * This file is intentionally not wired into the build yet.
 *
 * Current EN split:
 * - main/dll/dll_72.c
 * - 0x801008C4-0x801008C8
 *
 * Nearby corridor context:
 * - previous split: main/dll/dll_AF.c
 * - next split: main/dll/dll_73.c
 */

/*
 * No function names were promoted here yet.
 * Start from the current EN split window and the surrounding corridor.
 */



extern char sProjship1DoNoLongerSupported[];
extern void OSReport(const char *fmt, ...);

#define PROJECTILE_UNSUPPORTED_RETURN -1

#pragma scheduling off
#pragma peephole off
int projship1_doUnsupported(void) { OSReport(sProjship1DoNoLongerSupported); return PROJECTILE_UNSUPPORTED_RETURN; }
#pragma peephole reset
#pragma scheduling reset
