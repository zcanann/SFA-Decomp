/*
 * projmagicstream (DLL 0xAC) - retired projectile object.
 *
 * One of the stubbed-out projectile DLLs. The object has
 * no behaviour left: release/initialise are empty and doUnsupported just
 * logs the "no longer supported" string and returns the failure sentinel.
 * The slot is kept so the DLL id stays valid.
 */
#include "dolphin/os/OSReport.h"
#include "types.h"
#include "main/dll/dll_00AC_projmagicstream.h"
#include "main/dll/dll_00AD_projmagicemmit1.h"

/* descriptor/ptr table auto 0x80319410-0x80319430.
 * Union u64 member forces the retail 8-byte alignment (table follows an odd-length
 * string; retail pads to an 8-aligned table start). Same idiom as dll_000A_expgfx. */
typedef union DllDescriptorTable
{
    u32 words[8];
    u64 align8;
} DllDescriptorTable;

char sProjmagicstreamDoNoLongerSupported[] = "<projmagicstream Do>No Longer supported \n";

int projmagicstream_doUnsupported(void)
{
    OSReport(sProjmagicstreamDoNoLongerSupported);
    return -1; /* failure sentinel */
}

void projmagicstream_release(void)
{
}

void projmagicstream_initialise(void)
{
}

DllDescriptorTable lbl_80319410 = {{0x00000000, 0x00000000, 0x00000000, 0x00030000, (u32)projmagicemmit1_initialise,
                                    (u32)projmagicemmit1_release, 0x00000000, (u32)projmagicemmit1_doUnsupported}};
