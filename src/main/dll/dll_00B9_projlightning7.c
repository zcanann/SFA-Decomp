/*
 * projlightning7 (DLL 0x00B9) - retired "lightning 7" projectile object.
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
#include "main/dll/dll_descriptor_table.h"
#include "main/dll/dll_00B9_projlightning7.h"
#include "main/dll/dll_00BA_projlightning6.h"

#define PROJECTILE_UNSUPPORTED_RETURN -1

int projlightning7_doUnsupported(void)
{
    OSReport(sProjlightning7DoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

void projlightning7_release(void)
{
}

void projlightning7_initialise(void)
{
}

char sProjlightning7DoNoLongerSupported[] = "<projlightning7 Do>No Longer supported \n";

DllDescriptorTable lbl_80319688 = {{(void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00030000,
                                    projlightning6_initialise, projlightning6_release, (void*)0x00000000,
                                    projlightning6_doUnsupported}};
