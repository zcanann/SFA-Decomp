#include "ghidra_import.h"
#include "main/audio/sal_dsp.h"
#include "dolphin/os/OSCache.h"
#include "dolphin/ar.h"

#pragma exceptions on
extern u8 lbl_803D3F60[];
extern u32 aramTop;
extern u32 aramWrite;
extern void* aramChunkCallback;

/*
 * Initializes the AR-side audio data buffer: allocates a 0x500-byte
 * scratch buffer in main RAM, zeroes it (640 halfwords = 1280 bytes),
 * DMAs it to AR memory at the base address, then sets up the global
 * allocator pointers.
 */
void aramInit(u32 extraSize)
{
    u8* status;
    u8* flag;
    u16* clear;
    u8* buf;
    u32 arBase;
    int i;

    status = lbl_803D3F60;
    arBase = ARGetBaseAddress();
    buf = salMalloc(0x500);
    clear = (u16*)buf;
    for (i = 0; i < 640; i++)
    {
        clear[i] = 0;
    }
    DCFlushRange(buf, 0x500);
    *(flag = status + 0x281) = 0;
    status[0x280] = 0;
    status[0x505] = 0;
    status[0x504] = 0;
    aramUploadData((u32)buf, arBase, 0x500, 0, 0, 0);
    while (*flag != 0)
    {
    }
    salFree(buf);
    aramTop = arBase + extraSize;
    if (aramTop > ARGetSize())
    {
        aramTop = ARGetSize();
    }
    aramWrite = arBase + 0x500;
    aramChunkCallback = NULL;
    aramInitStreamBuffers();
}

/*
 * Empty stub (4 bytes: just blr).
 */
void aramGetZeroBuffer(void)
{
}

/*
 * Returns AR base address.
 */
u32 aramGetBaseAddress(void)
{
    return ARGetBaseAddress();
}
