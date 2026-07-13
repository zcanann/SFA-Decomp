/*
 * projtesla (DLL 0xBE) - defunct "tesla" projectile (behaviour cut).
 *
 * Its only non-trivial entry point reports the "no longer supported" string
 * via OSReport and returns 0. The release and initialise descriptor hooks are
 * empty stubs.
 */
#include "dolphin/os/OSReport.h"
#include "main/dll/dll_descriptor_table.h"
#include "main/dll/dll_00BE_projtesla.h"
#include "main/dll/dll_00BF_projcore1.h"

int projtesla_doUnsupported(void)
{
    OSReport(sProjteslaDoNoLongerSupported);
    return 0;
}

void projtesla_release(void)
{
}

void projtesla_initialise(void)
{
}

char sProjteslaDoNoLongerSupported[] = "<projtesla Do>No Longer supported \n";

DllDescriptorTable lbl_80319968 = {{(void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00030000,
                                    projcore1_initialise, projcore1_release, (void*)0x00000000,
                                    projcore1_doUnsupported}};
