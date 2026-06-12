#include "main/dll/dll_6A.h"

/*
 * Manual recovery stub based on claimed split coverage and the surrounding
 * early anonymous corridor.
 *
 * This file is intentionally not wired into the build yet.
 *
 * Current EN split:
 * - main/dll/dll_6A.c
 * - 0x8010081C-0x80100820
 *
 * Nearby corridor context:
 * - previous split: main/dll/dll_69.c
 * - next split: main/dll/dll_6B.c
 */

/*
 * No function names were promoted here yet.
 * Start from the current EN split window and the surrounding corridor.
 */

extern void OSReport(const char* fmt, ...);

#define PROJECTILE_UNSUPPORTED_RETURN -1

int projenergise2_doUnsupported(void)
{
    OSReport(sProjenergise2DoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

/*
 * --INFO--
 *
 * Function: projenergise2_release
 * EN v1.0 Address: 0x80100820
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80100820
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void projenergise2_release(void)
{
}

/*
 * --INFO--
 *
 * Function: projenergise2_initialise
 * EN v1.0 Address: 0x80100824
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80100824
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void projenergise2_initialise(void)
{
}
