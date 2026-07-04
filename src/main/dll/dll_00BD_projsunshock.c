/*
 * projsunshock (DLL 0xBD) - a deprecated projectile object DLL.
 *
 * Only the standard DLL lifecycle entry points survive. The object is
 * no longer functional: doUnsupported logs a "no longer supported"
 * message and returns the failure sentinel, while release/initialise are
 * empty stubs that keep the DLL loadable.
 */
#include "main/dll/dll_7A.h"
#include "main/engine_shared.h"

int projsunshock_doUnsupported(void)
{
    OSReport(sProjsunshockDoNoLongerSupported);
    return -1;
}

void projsunshock_release(void)
{
}

void projsunshock_initialise(void)
{
}

char sProjsunshockDoNoLongerSupported[] = "<projsunshock Do>No Longer supported \n";

/*__DATA_EXTERNS__*/
extern void projtesla_doUnsupported();
extern void projtesla_release();
extern void projtesla_initialise();
/* .data table (attributed from auto object; pointer tables regenerate ADDR32 relocs) */
void* lbl_80319920[8] = { (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00030000, projtesla_initialise, projtesla_release, (void*)0x00000000, projtesla_doUnsupported };
