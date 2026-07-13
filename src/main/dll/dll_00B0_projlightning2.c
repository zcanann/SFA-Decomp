/*
 * projlightning2 (DLL 0x00B0) - retired "lightning 2" projectile object.
 *
 * The object's behaviour was cut from the shipping game: its "do" entry
 * point now only logs a "no longer supported" message and returns the
 * unsupported sentinel (-1). release/initialise are empty stubs kept so the
 * DLL still exports the standard projectile lifecycle entry points. This is
 * one of a family of identical retired projectile DLLs.
 */
#include "dolphin/os/OSReport.h"
#include "main/dll/dll_descriptor_table.h"
#include "main/dll/dll_00B0_projlightning2.h"
#include "main/dll/dll_00B1_projlightning3.h"

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

DllDescriptorTable lbl_80319548 = {{(void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00030000,
                                    projlightning3_initialise, projlightning3_release, (void*)0x00000000,
                                    projlightning3_doUnsupported}};
