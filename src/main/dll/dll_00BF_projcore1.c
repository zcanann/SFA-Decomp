/*
 * projcore1 (DLL 0xBF) - retired projectile-core DLL.
 *
 * The only live entry point reports that projectiles are no longer
 * supported and returns the unsupported sentinel (-1); the DLL's
 * release/initialise lifecycle hooks are empty stubs.
 */
#include "main/dll/dll_80.h"
#include "dolphin/os/OSReport.h"
#include "main/dll/dll_descriptor_table.h"
#include "main/dll/dll_00BF_projcore1.h"
#include "main/dll/dll_00C0_projcore2.h"

int projcore1_doUnsupported(void)
{
    OSReport(sProjcore1DoNoLongerSupported);
    return -1;
}

void projcore1_release(void)
{
}

void projcore1_initialise(void)
{
}

char sProjcore1DoNoLongerSupported[] = "<projcore1 Do>No Longer supported \n";

/* .data table (attributed from auto object; pointer tables regenerate ADDR32 relocs).
 * Same idiom as dll_00AD_projmagicemmit1 / dll_000A_expgfx. */
DllDescriptorTable lbl_803199B0 = {{(void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00030000,
                                    projcore2_initialise, projcore2_release, (void*)0x00000000,
                                    projcore2_doUnsupported}};
