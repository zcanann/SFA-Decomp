#include "main/dll/dll_89.h"

/*
 * Manual recovery stub based on claimed split coverage and the surrounding
 * second anonymous corridor.
 *
 * This file is intentionally not wired into the build yet.
 *
 * Current EN split:
 * - main/dll/dll_89.c
 * - 0x80100A84-0x80100A88
 *
 * Nearby corridor context:
 * - previous split: main/dll/dll_88.c
 * - next split: main/dll/dll_8A.c
 */

/*
 * No function names were promoted here yet.
 * Start from the current EN split window and the surrounding corridor.
 */


extern void OSReport(const char* fmt, ...);

#define PROJECTILE_UNSUPPORTED_RETURN -1

int projdfp1r_doUnsupported(void)
{
    OSReport(sProjdfp1rDoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

/* === merged from main/dll/dll_8A.c [80100A88-80100A8C) (TU re-split, docs/boundary_audit.md) === */
#include "main/dll/dll_8A.h"

/*
 * --INFO--
 *
 * Function: projdfp1r_release
 * EN v1.0 Address: 0x80100A88
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80100A88
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void projdfp1r_release(void)
{
}

/* === moved from main/dll/dll_8B.c [80100A8C-80100A90) (TU re-split, docs/boundary_audit.md) === */
#include "main/dll/dll_8B.h"
#include "main/dll/CAM/camcontrol.h"

/*
 * --INFO--
 *
 * Function: projdfp1r_initialise
 * EN v1.0 Address: 0x80100A8C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80100A8C
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void projdfp1r_initialise(void)
{
}

/*
 * --INFO--
 *
 * Function: cameraGetTargetType
 * EN v1.0 Address: 0x80100A90
 * EN v1.0 Size: 12b
 */
u8 cameraGetTargetType(void);

/*
 * --INFO--
 *
 * Function: Camera_getMinimapInfoText
 * EN v1.0 Address: 0x80100A9C
 * EN v1.0 Size: 8b
 */
s16 Camera_getMinimapInfoText(void);
