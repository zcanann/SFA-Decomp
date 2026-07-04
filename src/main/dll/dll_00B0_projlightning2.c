/*
 * projlightning2 (DLL 0x00B0) - retired "lightning 2" projectile object.
 *
 * The object's behaviour was cut from the shipping game: its "do" entry
 * point now only logs a "no longer supported" message and returns the
 * unsupported sentinel (-1). release/initialise are empty stubs kept so the
 * DLL still exports the standard projectile lifecycle entry points. This is
 * one of a family of identical retired projectile DLLs sharing dll_66.h
 * (projdummy, projmagicstream, projroombeam, projlightning1..7).
 */
#include "main/dll/dll_66.h"
#include "main/engine_shared.h"

#define PROJECTILE_UNSUPPORTED_RETURN -1

int projlightning2_doUnsupported(void)
{
    OSReport(sProjlightning2DoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

void projlightning2_release(void)
{
}

void projlightning2_initialise(void)
{
}

char sProjlightning2DoNoLongerSupported[] = "<projlightning2 Do>No Longer supported \n";

/* descriptor/ptr table auto 0x80319548-0x80319568 */
u32 lbl_80319548[8] = { 0x00000000, 0x00000000, 0x00000000, 0x00030000, (u32)projlightning3_initialise, (u32)projlightning3_release, 0x00000000, (u32)projlightning3_doUnsupported };
