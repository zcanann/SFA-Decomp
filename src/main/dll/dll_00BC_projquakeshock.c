#include "main/dll/dll_77.h"

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

extern void OSReport(const char* fmt, ...);

#define PROJECTILE_UNSUPPORTED_RETURN -1

int projquakeshock_doUnsupported(void)
{
    OSReport(sProjquakeshockDoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

/*
 * --INFO--
 *
 * Function: projquakeshock_release
 * EN v1.0 Address: 0x80100938
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80100938
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void projquakeshock_release(void)
{
}

/*
 * --INFO--
 *
 * Function: projquakeshock_initialise
 * EN v1.0 Address: 0x8010093C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8010093C
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void projquakeshock_initialise(void)
{
}
