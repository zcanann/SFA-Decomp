/*
 * projenergise1 (DLL 0xB4) - retired "energise projectile" object DLL.
 *
 * The object itself is gone: its only real entry point logs a
 * "no longer supported" message and returns -1, while the standard DLL
 * lifecycle hooks (release/initialise) are empty stubs. Effectively a
 * placeholder that keeps the DLL id valid after the projectile behavior
 * was removed.
 */
#include "main/dll/modgfx67.h"
#include "main/engine_shared.h"

#define PROJECTILE_UNSUPPORTED_RETURN -1

int projenergise1_doUnsupported(void)
{
    OSReport(sProjenergise1DoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

void projenergise1_release(void)
{
}

void projenergise1_initialise(void)
{
}

char sProjenergise1DoNoLongerSupported[] = "<projenergise1 Do>No Longer supported \n";

/* descriptor/ptr table auto 0x80319720-0x80319740 */
u32 lbl_80319720[8] = { 0x00000000, 0x00000000, 0x00000000, 0x00030000, (u32)projenergise2_initialise, (u32)projenergise2_release, 0x00000000, (u32)projenergise2_doUnsupported };
