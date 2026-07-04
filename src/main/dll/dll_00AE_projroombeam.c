/*
 * projroombeam (DLL 0xAE) - retired projectile object.
 *
 * One of the dll_66 family of stubbed-out projectile DLLs. The object has
 * no behaviour left: release/initialise are empty and doUnsupported just
 * logs the "no longer supported" string and returns the failure sentinel.
 * The slot is kept so the DLL id stays valid.
 */
#include "main/dll/dll_66.h"
#include "main/engine_shared.h"

#define PROJECTILE_UNSUPPORTED_RETURN -1

int projroombeam_doUnsupported(void)
{
    OSReport(sProjroombeamDoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

void projroombeam_release(void)
{
}

void projroombeam_initialise(void)
{
}

char sProjroombeamDoNoLongerSupported[] = "<projroombeam Do>No Longer supported \n";

/* descriptor/ptr table auto 0x803194a8-0x803194c8 */
u32 lbl_803194A8[8] = { 0x00000000, 0x00000000, 0x00000000, 0x00030000, (u32)projlightning1_initialise, (u32)projlightning1_release, 0x00000000, (u32)projlightning1_doUnsupported };
