/*
 * projtesla (DLL 0xBE) - defunct "tesla" projectile (behaviour cut).
 *
 * Its only non-trivial entry point reports the "no longer supported" string
 * via OSReport and returns 0. The release and initialise descriptor hooks are
 * empty stubs.
 */
#include "main/dll/dll_7D.h"
#include "main/engine_shared.h"

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

/* descriptor/ptr table auto 0x80319968-0x80319988 */
u32 lbl_80319968[8] = { 0x00000000, 0x00000000, 0x00000000, 0x00030000, (u32)projcore1_initialise, (u32)projcore1_release, 0x00000000, (u32)projcore1_doUnsupported };
