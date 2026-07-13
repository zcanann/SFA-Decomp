/*
 * projdummy (DLL 0xAB) - retired projectile object.
 *
 * One of the stubbed-out projectile DLLs. The object has
 * no behaviour left: release/initialise are empty and doUnsupported just
 * logs the "no longer supported" string and returns the failure sentinel.
 * The slot is kept so the DLL id stays valid.
 */
#include "dolphin/os/OSReport.h"
#include "main/dll/dll_descriptor_table.h"
#include "main/dll/dll_00AB_projdummy.h"
#include "main/dll/dll_00AC_projmagicstream.h"

#define PROJECTILE_UNSUPPORTED_RETURN -1

char sProjdummyDoNoLongerSupported[] = "<projdummy Do>No Longer supported \n";

int projdummy_doUnsupported(void)
{
    OSReport(sProjdummyDoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

void projdummy_release(void)
{
}

void projdummy_initialise(void)
{
}

DllDescriptorTable lbl_803193C0 = {{(void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00030000,
                                    projmagicstream_initialise, projmagicstream_release, (void*)0x00000000,
                                    projmagicstream_doUnsupported}};
