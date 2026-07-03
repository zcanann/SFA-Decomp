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
