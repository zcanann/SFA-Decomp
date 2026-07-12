/*
 * projcore2 (DLL 0xC0) - retired projectile-core DLL.
 *
 * The only live entry point reports that projectiles are no longer
 * supported and returns the unsupported sentinel (-1); the DLL's
 * release/initialise lifecycle hooks are empty stubs.
 */
#include "main/dll/dll_83.h"
#include "dolphin/os/OSReport.h"
#include "main/dll/dll_descriptor_table.h"
#include "main/dll/dll_00C0_projcore2.h"
#include "main/dll/dll_00C1_projcore3.h"

#define PROJECTILE_UNSUPPORTED_RETURN -1

int projcore2_doUnsupported(void)
{
    OSReport(sProjcore2DoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

void projcore2_release(void)
{
}

void projcore2_initialise(void)
{
}

char sProjcore2DoNoLongerSupported[] = "<projcore2 Do>No Longer supported \n";

/* projcore3 (DLL 0xC1) ResourceDescriptor, referenced by modelEngine.
 * Same idiom as dll_00AD_projmagicemmit1 / dll_000A_expgfx. */
DllDescriptorTable lbl_803199F8 = {{(void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00030000,
                                    projcore3_initialise, projcore3_release, (void*)0x00000000,
                                    projcore3_doUnsupported}};
