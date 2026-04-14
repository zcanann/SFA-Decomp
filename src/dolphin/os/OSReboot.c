#include <dolphin.h>
#include <dolphin/os.h>

#include "dolphin/os/__os.h"
#include <dolphin/dvd/__dvd.h>

extern u32 BOOT_REGION_START AT_ADDRESS(0x812FDFF0);
extern u32 BOOT_REGION_END AT_ADDRESS(0x812FDFEC);
extern u8 g_unk_800030E2 AT_ADDRESS(0x800030E2);
extern u32 g_unk_817FFFF8 AT_ADDRESS(0x817FFFF8);
extern u32 g_unk_817FFFFC AT_ADDRESS(0x817FFFFC);

int Prepared[2];

void* SaveEnd;
void* SaveStart;

typedef struct {
    char date[16];
    u32 entry;
    u32 size;
    u32 rebootSize;
    u32 reserved2;
} AppLoaderStruct;

AppLoaderStruct FatalParam ATTRIBUTE_ALIGN(32);

asm void Run(register void* entryPoint) {
    nofralloc

    sync
    isync
    mtlr entryPoint
    blr
}

void Callback(s32, DVDCommandBlock*) {
    Prepared[0] = TRUE;
}

static inline int IsStreamEnabled(void) {
    if (DVDGetCurrentDiskID()->streaming) {
        return TRUE;
    }

    return FALSE;
}

/*
 * --INFO--
 * PAL Address: TODO
 * PAL Size: TODO
 * EN Address: TODO
 * EN Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 */
void __OSReboot(u32 resetCode, u32 bootDol) {
    OSContext exceptionContext;
    DVDCommandBlock streamCancelBlock;
    DVDCommandBlock appLoaderReadBlock;
    DVDCommandBlock rebootReadBlock;
    u32 rebootSize;
    u32 offset;
#if SDK_REVISION < 1
    OSTime start;
#endif

    (void)resetCode;
    (void)bootDol;

    OSDisableInterrupts();

    g_unk_817FFFFC = 0;
    g_unk_817FFFF8 = 0;
    g_unk_800030E2 = 1;
    BOOT_REGION_START = (u32)SaveStart;
    BOOT_REGION_END = (u32)SaveEnd;

    OSClearContext(&exceptionContext);
    OSSetCurrentContext(&exceptionContext);

    DVDInit();
    DVDSetAutoInvalidation(TRUE);
    DVDResume();

    Prepared[0] = FALSE;
    __DVDPrepareResetAsync(Callback);
    __OSMaskInterrupts(0xFFFFFFE0);
    __OSUnmaskInterrupts(0x400);
    OSEnableInterrupts();

#if SDK_REVISION < 1
    start = OSGetTime();
#endif

    while (Prepared[0] != TRUE) {
#if SDK_REVISION < 1
        if (!DVDCheckDisk() || OS_TIMER_CLOCK < (OSGetTime() - start))
#else
        if (!DVDCheckDisk())
#endif
        {
            __OSDoHotReset(g_unk_817FFFFC);
        }
    }

    if (!__OSIsGcam && IsStreamEnabled()) {
        AISetStreamVolLeft(0);
        AISetStreamVolRight(0);
        DVDCancelStreamAsync(&streamCancelBlock, NULL);

#if SDK_REVISION < 1
        start = OSGetTime();
#endif

        while (DVDGetCommandBlockStatus(&streamCancelBlock)) {
#if SDK_REVISION < 1
            if (!DVDCheckDisk() || OS_TIMER_CLOCK < (OSGetTime() - start))
#else
            if (!DVDCheckDisk())
#endif
            {
                __OSDoHotReset(g_unk_817FFFFC);
            }
        }

        AISetStreamPlayState(AI_STREAM_STOP);
    }

    DVDReadAbsAsyncPrio(&appLoaderReadBlock, &FatalParam, sizeof(AppLoaderStruct), 0x2440, NULL, 0);

#if SDK_REVISION < 1
    start = OSGetTime();
#endif

    while (DVDGetCommandBlockStatus(&appLoaderReadBlock)) {
#if SDK_REVISION < 1
        if (!DVDCheckDisk() || OS_TIMER_CLOCK < (OSGetTime() - start))
#else
        if (!DVDCheckDisk())
#endif
        {
            __OSDoHotReset(g_unk_817FFFFC);
        }
    }

    offset = FatalParam.size + 0x20;
    rebootSize = OSRoundUp32B(FatalParam.rebootSize);
    DVDReadAbsAsyncPrio(&rebootReadBlock, (void*)0x81300000, rebootSize, offset + 0x2440, NULL, 0);

#if SDK_REVISION < 1
    start = OSGetTime();
#endif

    while (DVDGetCommandBlockStatus(&rebootReadBlock)) {
#if SDK_REVISION < 1
        if (!DVDCheckDisk() || OS_TIMER_CLOCK < (OSGetTime() - start))
#else
        if (!DVDCheckDisk())
#endif
        {
            __OSDoHotReset(g_unk_817FFFFC);
        }
    }

    ICInvalidateRange((void*)0x81300000, rebootSize);

    OSDisableInterrupts();
    ICFlashInvalidate();
    Run((void*)0x81300000);
}
