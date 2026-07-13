/*
 * projenergise2 (DLL 0x00B5) - retired "energise" projectile object.
 *
 * No descriptor survives in this TU: only the entry point (logs that this
 * projectile is no longer supported and returns the unsupported sentinel)
 * plus empty release/initialise stubs.
 */
#include "dolphin/os.h"
#include "main/dll/dll_descriptor_table.h"
#include "main/dll/dll_00B2_projrobotfire.h"
#include "main/dll/dll_00B5_projenergise2.h"

#define PROJENERGISE2_UNSUPPORTED -1

char sProjenergise2DoNoLongerSupported[] = "<projenergise2 Do>No Longer supported \n";

int projenergise2_doUnsupported(void)
{
    OSReport(sProjenergise2DoNoLongerSupported);
    return PROJENERGISE2_UNSUPPORTED;
}

void projenergise2_release(void)
{
}

void projenergise2_initialise(void)
{
}

DllDescriptorTable lbl_80319768 = {{(void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00030000,
                                    projrobotfire_initialise, projrobotfire_release, (void*)0x00000000,
                                    projrobotfire_doUnsupported}};
