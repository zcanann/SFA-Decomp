/*
 * projlightning5 (DLL 0x00B8) - retired "lightning 5" projectile object.
 *
 * The object's behaviour was cut from the shipping game: its "do" entry
 * point now only logs a "no longer supported" message and returns the
 * unsupported sentinel (-1). release/initialise are empty stubs kept so the
 * DLL still exports the standard projectile lifecycle entry points. One of
 * a family of identical retired projectile DLLs sharing dll_66.h
 * (projdummy, projmagicstream, projroombeam, projlightning1..7).
 */
#include "dolphin/os.h"
#include "main/dll/dll_66.h"

#define PROJECTILE_UNSUPPORTED_RETURN -1

int projlightning5_doUnsupported(void)
{
    OSReport(sProjlightning5DoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

void projlightning5_release(void)
{
}

void projlightning5_initialise(void)
{
}


char sProjlightning5DoNoLongerSupported[] = "<projlightning5 Do>No Longer supported \n";

/* descriptor/ptr table auto 0x80319638-0x80319658 */
u32 lbl_80319638[8] = { 0x00000000, 0x00000000, 0x00000000, 0x00030000, (u32)projlightning7_initialise, (u32)projlightning7_release, 0x00000000, (u32)projlightning7_doUnsupported };
