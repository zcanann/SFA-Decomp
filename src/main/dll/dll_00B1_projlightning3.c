/*
 * projlightning3 (DLL 0x00B1) - a retired projectile object.
 *
 * The lightning-3 projectile was cut from the shipped game: its object
 * entry point (projlightning3_doUnsupported) only logs that it is "no longer supported"
 * and returns the unsupported sentinel. release/initialise are the empty
 * object lifecycle hooks that remain so the object descriptor stays valid.
 */
#include "dolphin/os.h"
#include "main/dll/dll_66.h"
#include "main/dll/dll_descriptor_table.h"
#include "main/dll/dll_00B1_projlightning3.h"
#include "main/dll/dll_00B3_projlightning4.h"

#define PROJECTILE_UNSUPPORTED_RETURN -1

char sProjlightning3DoNoLongerSupported[] = "<projlightning3 Do>No Longer supported \n";

int projlightning3_doUnsupported(void)
{
    OSReport(sProjlightning3DoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

void projlightning3_release(void)
{
}

void projlightning3_initialise(void)
{
}

DllDescriptorTable lbl_80319598 = {{(void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00030000,
                                    projlightning4_initialise, projlightning4_release, (void*)0x00000000,
                                    projlightning4_doUnsupported}};
