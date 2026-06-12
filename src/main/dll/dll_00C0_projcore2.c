#include "main/dll/dll_83.h"

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

extern void OSReport(const char* fmt, ...);

#define PROJECTILE_UNSUPPORTED_RETURN -1

int projcore2_doUnsupported(void)
{
    OSReport(sProjcore2DoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

/*
 * --INFO--
 *
 * Function: projcore2_release
 * EN v1.0 Address: 0x80100A18
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80100A18
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void projcore2_release(void)
{
}

/*
 * --INFO--
 *
 * Function: projcore2_initialise
 * EN v1.0 Address: 0x80100A1C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80100A1C
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void projcore2_initialise(void)
{
}
