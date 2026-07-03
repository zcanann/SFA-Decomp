#include "ghidra_import.h"
#include "main/audio/sal_dsp.h"
#include "dolphin/os/OSCache.h"
#include "dolphin/ar.h"
extern u8 lbl_803D3F60[];
extern u32 aramTop;
extern u32 aramWrite;
extern void* aramChunkCallback;

/*
 * Initializes the AR-side audio data buffer: allocates a 0x500-byte
 * scratch buffer in main RAM, zeroes it (1280 bytes = 8 unrolled
 * iterations of 80 halfwords each), DMAs it to AR memory at the base
 * address, then sets up the global allocator pointers.
 *
 * EN v1.0 Address: 0x80284224
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x80284410
 * EN v1.1 Size: 540b
 */
void aramInit(u32 extraSize)
{
    u16* clear;
    int i;
    u32 arBase;
    u8* buf;
    u8* flag;
    u8* status;

    status = lbl_803D3F60;
    flag = status + 0x281;
    arBase = ARGetBaseAddress();
    buf = salMalloc(0x500);
    clear = (u16*)buf;
    for (i = 0; i < 640; i++)
    {
        clear[i] = 0;
    }
    DCFlushRange(buf, 0x500);
    status[0x281] = 0;
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
 *
 * EN v1.1 Address: 0x80284444
 */
void aramGetZeroBuffer(void)
{
}

/*
 * Returns AR base address.
 *
 * EN v1.1 Address: 0x80284448
 */
u32 aramGetBaseAddress(void)
{
    return ARGetBaseAddress();
}
