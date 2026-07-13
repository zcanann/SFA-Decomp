/*
 * projquakeshock (DLL 0xBC) - retired "quake shock" projectile object.
 *
 * The DLL's lifecycle hooks (release/initialise) are empty and its single
 * entry point logs a "no longer supported" message and returns a failure
 * code, so this projectile type has been disabled in retail.
 */
#include "dolphin/os.h"
#include "main/dll/dll_descriptor_table.h"
#include "main/dll/dll_00BC_projquakeshock.h"
#include "main/dll/dll_00BD_projsunshock.h"

#define PROJECTILE_UNSUPPORTED_RETURN -1

int projquakeshock_doUnsupported(void)
{
    OSReport(sProjquakeshockDoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

void projquakeshock_release(void)
{
}

void projquakeshock_initialise(void)
{
}

char sProjquakeshockDoNoLongerSupported[] = "<projquakeshock Do>No Longer supported \n";

DllDescriptorTable lbl_803198D8 = {{(void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00030000,
                                    projsunshock_initialise, projsunshock_release, (void*)0x00000000,
                                    projsunshock_doUnsupported}};
