/*
 * projsquirt1 (DLL 0xB6) - retired "squirt" projectile object.
 *
 * The object's behaviour has been removed: its single live entry point
 * just logs that it is no longer supported and returns failure. The
 * release/initialise descriptor hooks are empty stubs.
 */
#include "dolphin/os.h"
#include "main/dll/dll_descriptor_table.h"
#include "main/dll/dll_00B6_projsquirt1.h"
#include "main/dll/dll_00B7_projship1.h"

#define PROJECTILE_UNSUPPORTED_RETURN -1

char sProjsquirt1DoNoLongerSupported[] = "<projsquirt1 Do>No Longer supported \n";

int projsquirt1_doUnsupported(void)
{
    OSReport(sProjsquirt1DoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

void projsquirt1_release(void)
{
}

void projsquirt1_initialise(void)
{
}

DllDescriptorTable lbl_803197F8 = {{(void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00030000,
                                    projship1_initialise, projship1_release, (void*)0x00000000,
                                    projship1_doUnsupported}};
