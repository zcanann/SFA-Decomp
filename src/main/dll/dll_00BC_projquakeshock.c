/*
 * projquakeshock (DLL 0xBC) - retired "quake shock" projectile object.
 *
 * The DLL's lifecycle hooks (release/initialise) are empty and its single
 * entry point logs a "no longer supported" message and returns a failure
 * code, so this projectile type has been disabled in retail.
 */
#include "dolphin/os.h"
#include "main/dll/dll_77.h"

extern void projsunshock_doUnsupported(void);

extern void projsunshock_release(void);

extern void projsunshock_initialise(void);

#define PROJECTILE_UNSUPPORTED_RETURN -1

int projquakeshock_doUnsupported(void)
{
    OSReport(sProjquakeshockDoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

void projquakeshock_release(void)
{
}

void projquakeshock_initialise(void)
{
}

char sProjquakeshockDoNoLongerSupported[] = "<projquakeshock Do>No Longer supported \n";

/* descriptor/ptr table auto 0x803198d8-0x803198f8 */
u32 lbl_803198D8[8] = { 0x00000000, 0x00000000, 0x00000000, 0x00030000, (u32)projsunshock_initialise, (u32)projsunshock_release, 0x00000000, (u32)projsunshock_doUnsupported };
