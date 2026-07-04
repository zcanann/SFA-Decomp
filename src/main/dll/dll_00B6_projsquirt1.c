/*
 * projsquirt1 (DLL 0xB6) - retired "squirt" projectile object.
 *
 * The object's behaviour has been removed: its single live entry point
 * just logs that it is no longer supported and returns failure. The
 * release/initialise descriptor hooks are empty stubs.
 */
#include "dolphin/os.h"
#include "main/dll/dll_70.h"

extern void projship1_doUnsupported(void);

extern void projship1_release(void);

extern void projship1_initialise(void);

#define PROJECTILE_UNSUPPORTED_RETURN -1

char sProjsquirt1DoNoLongerSupported[] = "<projsquirt1 Do>No Longer supported \n";

int projsquirt1_doUnsupported(void)
{
    OSReport(sProjsquirt1DoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

void projsquirt1_release(void)
{
}

void projsquirt1_initialise(void)
{
}

/* descriptor/ptr table auto 0x803197f8-0x80319818 */
u32 lbl_803197F8[8] = { 0x00000000, 0x00000000, 0x00000000, 0x00030000, (u32)projship1_initialise, (u32)projship1_release, 0x00000000, (u32)projship1_doUnsupported };
