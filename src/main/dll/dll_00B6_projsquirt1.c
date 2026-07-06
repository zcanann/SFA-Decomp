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

/* descriptor/ptr table auto 0x803197f8-0x80319818 (8-byte aligned in retail;
 * pointer tables regenerate ADDR32 relocs). Union u64 member forces the
 * retail 8-byte alignment after the 0x26-byte string (retail pad
 * gap_07_803197F6_data). Same idiom as dll_00B1_projlightning3. */
typedef union DllDescriptorTable {
    void* ptrs[8];
    u64 align8;
} DllDescriptorTable;

DllDescriptorTable lbl_803197F8 = { { (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00030000, projship1_initialise, projship1_release, (void*)0x00000000, projship1_doUnsupported } };
