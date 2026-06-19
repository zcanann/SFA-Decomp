#include "ghidra_import.h"

extern void* salMalloc(u32 size);
extern void salFree(void* ptr);
extern asm void DCFlushRange(register void* addr, register u32 nBytes);
extern u32 ARGetBaseAddress(void);
extern u32 ARGetSize(void);

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
    u32 arBase;
    u8* buf;
    u8* status;
    u8* flag;
    int i;
    u16* clear;

    status = lbl_803D3F60;
    arBase = ARGetBaseAddress();
    buf = salMalloc(0x500);
    clear = (u16*)buf;
    for (i = 0; i < 8; i++)
    {
        clear[0] = 0;
        clear[1] = 0;
        clear[2] = 0;
        clear[3] = 0;
        clear[4] = 0;
        clear[5] = 0;
        clear[6] = 0;
        clear[7] = 0;
        clear[8] = 0;
        clear[9] = 0;
        clear[10] = 0;
        clear[11] = 0;
        clear[12] = 0;
        clear[13] = 0;
        clear[14] = 0;
        clear[15] = 0;
        clear[16] = 0;
        clear[17] = 0;
        clear[18] = 0;
        clear[19] = 0;
        clear[20] = 0;
        clear[21] = 0;
        clear[22] = 0;
        clear[23] = 0;
        clear[24] = 0;
        clear[25] = 0;
        clear[26] = 0;
        clear[27] = 0;
        clear[28] = 0;
        clear[29] = 0;
        clear[30] = 0;
        clear[31] = 0;
        clear[32] = 0;
        clear[33] = 0;
        clear[34] = 0;
        clear[35] = 0;
        clear[36] = 0;
        clear[37] = 0;
        clear[38] = 0;
        clear[39] = 0;
        clear[40] = 0;
        clear[41] = 0;
        clear[42] = 0;
        clear[43] = 0;
        clear[44] = 0;
        clear[45] = 0;
        clear[46] = 0;
        clear[47] = 0;
        clear[48] = 0;
        clear[49] = 0;
        clear[50] = 0;
        clear[51] = 0;
        clear[52] = 0;
        clear[53] = 0;
        clear[54] = 0;
        clear[55] = 0;
        clear[56] = 0;
        clear[57] = 0;
        clear[58] = 0;
        clear[59] = 0;
        clear[60] = 0;
        clear[61] = 0;
        clear[62] = 0;
        clear[63] = 0;
        clear[64] = 0;
        clear[65] = 0;
        clear[66] = 0;
        clear[67] = 0;
        clear[68] = 0;
        clear[69] = 0;
        clear[70] = 0;
        clear[71] = 0;
        clear[72] = 0;
        clear[73] = 0;
        clear[74] = 0;
        clear[75] = 0;
        clear[76] = 0;
        clear[77] = 0;
        clear[78] = 0;
        clear[79] = 0;
        clear += 80;
    }
    DCFlushRange(buf, 0x500);
    flag = status + 0x281;
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
