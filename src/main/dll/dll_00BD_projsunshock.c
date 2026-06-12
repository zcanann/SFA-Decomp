#include "main/dll/dll_7A.h"

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


extern void OSReport(const char* fmt, ...);

#define PROJECTILE_UNSUPPORTED_RETURN -1

int projsunshock_doUnsupported(void)
{
    OSReport(sProjsunshockDoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

/* === merged from main/dll/dll_7B.c [80100970-80100974) (TU re-split, docs/boundary_audit.md) === */

/*
 * --INFO--
 *
 * Function: projsunshock_release
 * EN v1.0 Address: 0x80100970
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80100970
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void projsunshock_release(void)
{
}

/* === merged from main/dll/dll_7C.c [80100974-80100978) (TU re-split, docs/boundary_audit.md) === */

/*
 * --INFO--
 *
 * Function: projsunshock_initialise
 * EN v1.0 Address: 0x80100974
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80100974
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void projsunshock_initialise(void)
{
}
