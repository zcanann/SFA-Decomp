/*
 * projenergise2 (DLL 0x00B5) - retired "energise" projectile object.
 *
 * No descriptor survives in this TU: only the entry point (logs that this
 * projectile is no longer supported and returns the unsupported sentinel)
 * plus empty release/initialise stubs.
 */
#include "main/dll/dll_6A.h"
#include "dolphin/os.h"

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

/*__DATA_EXTERNS__*/
extern void projrobotfire_doUnsupported();
extern void projrobotfire_release();
extern void projrobotfire_initialise();
/* .data table (attributed from auto object; pointer tables regenerate ADDR32 relocs) */
void* lbl_80319768[8] = { (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00030000, projrobotfire_initialise, projrobotfire_release, (void*)0x00000000, projrobotfire_doUnsupported };
