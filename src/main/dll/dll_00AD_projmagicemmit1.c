/*
 * projmagicemmit1 (DLL 0xAD) - retired projectile object.
 *
 * One of the dll_66 family of stubbed-out projectile DLLs. The object has
 * no behaviour left: release/initialise are empty and doUnsupported just
 * logs the "no longer supported" string and returns the failure sentinel.
 * The slot is kept so the DLL id stays valid.
 */
#include "main/dll/dll_66.h"
#include "main/engine_shared.h"

int projmagicemmit1_doUnsupported(void)
{
    OSReport(sProjmagicemmit1DoNoLongerSupported);
    return -1; /* failure sentinel */
}

void projmagicemmit1_release(void)
{
}

void projmagicemmit1_initialise(void)
{
}

char sProjmagicemmit1DoNoLongerSupported[] = "<projmagicemmit1 Do>No Longer supported \n";

/*__DATA_EXTERNS__*/
/* .data table (attributed from auto object; pointer tables regenerate ADDR32 relocs) */
void* lbl_80319460[8] = { (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00030000, projroombeam_initialise, projroombeam_release, (void*)0x00000000, projroombeam_doUnsupported };
