#include <dolphin.h>
#include <dolphin/os.h>

#include "dolphin/os/__os.h"
#include <dolphin/dvd/__dvd.h>

extern u32 BOOT_REGION_START AT_ADDRESS(0x812FDFF0);
extern u32 BOOT_REGION_END AT_ADDRESS(0x812FDFEC);
extern u8 g_unk_800030E2 AT_ADDRESS(0x800030E2);
extern u32 g_unk_817FFFF8 AT_ADDRESS(0x817FFFF8);
extern u32 g_unk_817FFFFC AT_ADDRESS(0x817FFFFC);

static void* SaveStart;
static void* SaveEnd;
static volatile BOOL Prepared;

typedef struct {
    char date[16];
    u32 entry;
    u32 size;
    u32 rebootSize;
    u32 reserved2;
} AppLoaderStruct;

static AppLoaderStruct FatalParam ATTRIBUTE_ALIGN(32);

#pragma dont_inline on
static asm void myFunc() { }
static void Run(register void* entryPoint) {
    OSDisableInterrupts();
    ICFlashInvalidate();
    asm {
        sync
        isync
        mtlr entryPoint
        blr
    }
}
#pragma dont_inline reset

static void Callback(s32 result, DVDCommandBlock* block) {
    (void)result;
    (void)block;
    Prepared = TRUE;
}

void __OSReboot(u32 resetCode, u32 bootDol) {
    OSContext exceptionContext;
    DVDCommandBlock appLoaderReadBlock;
    DVDCommandBlock rebootReadBlock;
    u32 rebootSize;
    s32 state;
    u32 offset;

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

    __DVDPrepareResetAsync(Callback);

    if (!DVDCheckDisk()) {
        __OSDoHotReset(g_unk_817FFFFC);
    }

    __OSMaskInterrupts(0xFFFFFFE0);
    __OSUnmaskInterrupts(0x400);
    OSEnableInterrupts();

    while (!Prepared) {
    }

    DVDReadAbsAsyncForBS(&appLoaderReadBlock, &FatalParam, sizeof(AppLoaderStruct), 0x2440, NULL);
    while (TRUE) {
        state = appLoaderReadBlock.state;
        if (state == 1) {
            continue;
        }
        if (state > 1) {
            if (state < 0xC) {
                __OSDoHotReset(g_unk_817FFFFC);
            }
            continue;
        }
        if (state < 0) {
            __OSDoHotReset(g_unk_817FFFFC);
        }
        break;
    }

    offset = FatalParam.size + 0x20;
    rebootSize = OSRoundUp32B(FatalParam.rebootSize);

    while (!Prepared) {
    }

    DVDReadAbsAsyncForBS(&rebootReadBlock, (void*)0x81300000, rebootSize, offset + 0x2440, NULL);
    while (TRUE) {
        state = rebootReadBlock.state;
        if (state == 1) {
            continue;
        }
        if (state > 1) {
            if (state < 0xC) {
                __OSDoHotReset(g_unk_817FFFFC);
            }
            continue;
        }
        if (state < 0) {
            __OSDoHotReset(g_unk_817FFFFC);
        }
        break;
    }

    ICInvalidateRange((void*)0x81300000, rebootSize);
    Run((void*)0x81300000);
}

void OSSetSaveRegion(void* start, void* end) {
    SaveStart = start;
    SaveEnd = end;
}
