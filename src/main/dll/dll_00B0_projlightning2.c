/*
 * projlightning2 (DLL 0x00B0) - retired "lightning 2" projectile object.
 *
 * The object's behaviour was cut from the shipping game: its "do" entry
 * point now only logs a "no longer supported" message and returns the
 * unsupported sentinel (-1). release/initialise are empty stubs kept so the
 * DLL still exports the standard projectile lifecycle entry points. This is
 * one of a family of identical retired projectile DLLs sharing dll_66.h
 * (projdummy, projmagicstream, projroombeam, projlightning1..7).
 */
#include "main/dll/dll_66.h"
#include "main/engine_shared.h"

/* descriptor/ptr table auto 0x80319548-0x80319568 (pointer tables regenerate ADDR32 relocs).
 * Union u64 member forces the retail 8-byte alignment (table follows an odd-length
 * string; retail pads to an 8-aligned table start). Same idiom as dll_000A_expgfx. */
typedef union DllDescriptorTable
{
    void* ptrs[8];
    u64 align8;
} DllDescriptorTable;

#define PROJECTILE_UNSUPPORTED_RETURN -1

int projlightning2_doUnsupported(void)
{
    OSReport(sProjlightning2DoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

void projlightning2_release(void)
{
}

void projlightning2_initialise(void)
{
}

char sProjlightning2DoNoLongerSupported[] = "<projlightning2 Do>No Longer supported \n";

DllDescriptorTable lbl_80319548 = {{(void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00030000,
                                    projlightning3_initialise, projlightning3_release, (void*)0x00000000,
                                    projlightning3_doUnsupported}};
