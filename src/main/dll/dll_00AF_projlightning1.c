/*
 * projlightning1 (DLL 0x00AF) - retired "lightning 1" projectile object.
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

#define PROJECTILE_UNSUPPORTED_RETURN -1

int projlightning1_doUnsupported(void)
{
    OSReport(sProjlightning1DoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

void projlightning1_release(void)
{
}

void projlightning1_initialise(void)
{
}

char sProjlightning1DoNoLongerSupported[] = "<projlightning1 Do>No Longer supported \n";

/*__DATA_EXTERNS__*/
/* .data table (attributed from auto object; pointer tables regenerate ADDR32 relocs).
 * Union u64 member forces the retail 8-byte alignment (table follows an odd-length
 * string; retail pads to an 8-aligned table start). Same idiom as dll_000A_expgfx. */
typedef union DllDescriptorTable
{
    void* ptrs[8];
    u64 align8;
} DllDescriptorTable;

DllDescriptorTable lbl_803194F8 = {{(void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00030000,
                                    projlightning2_initialise, projlightning2_release, (void*)0x00000000,
                                    projlightning2_doUnsupported}};
