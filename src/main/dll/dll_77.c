/*
 * Manual recovery stub based on claimed split coverage and the surrounding
 * early anonymous corridor.
 *
 * This file is intentionally not wired into the build yet.
 *
 * Current EN split:
 * - main/dll/dll_77.c
 * - 0x80100934-0x80100938
 *
 * Nearby corridor context:
 * - previous split: main/dll/dll_76.c
 * - next split: main/dll/dll_78.c
 */

/*
 * No function names were promoted here yet.
 * Start from the current EN split window and the surrounding corridor.
 */



extern char sProjquakeshockDoNoLongerSupported[];
extern void OSReport(const char *fmt, ...);

#define PROJECTILE_UNSUPPORTED_RETURN -1

#pragma scheduling off
#pragma peephole off
int projquakeshock_doUnsupported(void) { OSReport(sProjquakeshockDoNoLongerSupported); return PROJECTILE_UNSUPPORTED_RETURN; }
#pragma peephole reset
#pragma scheduling reset
