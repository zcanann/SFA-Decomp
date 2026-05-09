/*
 * Manual recovery stub based on claimed split coverage and the surrounding
 * early anonymous corridor.
 *
 * This file is intentionally not wired into the build yet.
 *
 * Current EN split:
 * - main/dll/dll_7A.c
 * - 0x8010096C-0x80100970
 *
 * Nearby corridor context:
 * - previous split: main/dll/dll_79.c
 * - next split: main/dll/dll_7B.c
 */

/*
 * No function names were promoted here yet.
 * Start from the current EN split window and the surrounding corridor.
 */



extern char sProjsunshockDoNoLongerSupported[];
extern void OSReport(const char *fmt, ...);

#define PROJECTILE_UNSUPPORTED_RETURN -1

#pragma scheduling off
#pragma peephole off
int projsunshock_doUnsupported(void) { OSReport(sProjsunshockDoNoLongerSupported); return PROJECTILE_UNSUPPORTED_RETURN; }
#pragma peephole reset
#pragma scheduling reset
