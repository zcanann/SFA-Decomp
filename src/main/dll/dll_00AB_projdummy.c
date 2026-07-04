/*
 * projdummy (DLL 0xAB) - retired projectile object.
 *
 * One of the dll_66 family of stubbed-out projectile DLLs. The object has
 * no behaviour left: release/initialise are empty and doUnsupported just
 * logs the "no longer supported" string and returns the failure sentinel.
 * The slot is kept so the DLL id stays valid.
 */
#include "main/dll/dll_66.h"
#include "main/engine_shared.h"

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

/*__DATA_EXTERNS__*/
/* .data table (attributed from auto object; pointer tables regenerate ADDR32 relocs) */
void* lbl_803193C0[8] = { (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00030000, projmagicstream_initialise, projmagicstream_release, (void*)0x00000000, projmagicstream_doUnsupported };
