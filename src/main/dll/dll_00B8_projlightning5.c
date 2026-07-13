/*
 * projlightning5 (DLL 0x00B8) - retired "lightning 5" projectile object.
 *
 * The object's behaviour was cut from the shipping game: its "do" entry
 * point now only logs a "no longer supported" message and returns the
 * unsupported sentinel (-1). release/initialise are empty stubs kept so the
 * DLL still exports the standard projectile lifecycle entry points. One of
 * a family of identical retired projectile DLLs.
 */
#include "dolphin/os.h"
#include "main/dll/dll_descriptor_table.h"
#include "main/dll/dll_00B8_projlightning5.h"
#include "main/dll/dll_00B9_projlightning7.h"

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

DllDescriptorTable lbl_80319638 = {{(void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00030000,
                                    projlightning7_initialise, projlightning7_release, (void*)0x00000000,
                                    projlightning7_doUnsupported}};
