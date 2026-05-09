#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80284410.h"

extern void aramUploadData(void *src, void *dst, u32 size, int mode, int callback,
                           int callbackArg);
extern void *salMalloc(u32 size);
extern void salFree(void *p);
extern void aramInitStreamBuffers(void);
extern void DCFlushRange(void *src, u32 size);
extern u32 ARGetBaseAddress(void);
extern u32 ARGetSize(void);

extern u8 lbl_803D3F60[];
extern u32 aramTop;
extern u32 aramWrite;
extern void *aramChunkCallback;

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
    u8 *buf;
    u8 *flag;
    int i;

    arBase = ARGetBaseAddress();
    buf = salMalloc(0x500);
    for (i = 0; i < 0x500; i += 2) {
        *(u16 *)(buf + i) = 0;
    }
    DCFlushRange(buf, 0x500);
    flag = lbl_803D3F60 + 0x281;
    lbl_803D3F60[0x281] = 0;
    lbl_803D3F60[0x280] = 0;
    lbl_803D3F60[0x505] = 0;
    lbl_803D3F60[0x504] = 0;
    aramUploadData(buf, (void *)arBase, 0x500, 0, 0, 0);
    while (*flag != 0) {
    }
    salFree(buf);
    aramTop = arBase + extraSize;
    if (aramTop > ARGetSize()) {
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
