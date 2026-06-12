#include "main/dll/dll_70.h"

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

extern void OSReport(const char* fmt, ...);

#define PROJECTILE_UNSUPPORTED_RETURN -1

int projsquirt1_doUnsupported(void)
{
    OSReport(sProjsquirt1DoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

/*
 * --INFO--
 *
 * Function: projsquirt1_release
 * EN v1.0 Address: 0x80100890
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80100890
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void projsquirt1_release(void)
{
}

/*
 * --INFO--
 *
 * Function: projsquirt1_initialise
 * EN v1.0 Address: 0x80100894
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80100894
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void projsquirt1_initialise(void)
{
}
