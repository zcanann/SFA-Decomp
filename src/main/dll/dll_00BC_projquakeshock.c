/*
 * projquakeshock (DLL 0xBC) - retired "quake shock" projectile object.
 *
 * The DLL's lifecycle hooks (release/initialise) are empty and its single
 * entry point logs a "no longer supported" message and returns a failure
 * code, so this projectile type has been disabled in retail.
 */
#include "dolphin/os.h"
#include "main/dll/dll_77.h"

/* descriptor/ptr table auto 0x803198d8-0x803198f8 (8-byte aligned in retail;
 * pointer tables regenerate ADDR32 relocs). Union u64 member forces the
 * retail 8-byte alignment after the 0x29-byte string (retail pad
 * gap_07_803198D1_data). Same idiom as dll_00B1_projlightning3. */
typedef union DllDescriptorTable
{
    void* ptrs[8];
    u64 align8;
} DllDescriptorTable;

#define PROJECTILE_UNSUPPORTED_RETURN -1

extern void projsunshock_doUnsupported(void);
extern void projsunshock_release(void);
extern void projsunshock_initialise(void);

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

DllDescriptorTable lbl_803198D8 = {{(void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00030000,
                                    projsunshock_initialise, projsunshock_release, (void*)0x00000000,
                                    projsunshock_doUnsupported}};
