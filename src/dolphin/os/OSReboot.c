#include <dolphin.h>
#include <dolphin/os.h>

#include "dolphin/os/__os.h"
#include <dolphin/dvd/__dvd.h>

extern u32 BOOT_REGION_START AT_ADDRESS(0x812FDFF0);
extern u32 BOOT_REGION_END AT_ADDRESS(0x812FDFEC);
extern u8 g_unk_800030E2 AT_ADDRESS(0x800030E2);
extern u32 g_unk_817FFFF8 AT_ADDRESS(0x817FFFF8);
extern u32 g_unk_817FFFFC AT_ADDRESS(0x817FFFFC);

static void* lbl_803DDE50;
static void* lbl_803DDE54;
static volatile BOOL lbl_803DDE58[2];

typedef struct {
    char date[16];
    u32 entry;
    u32 size;
    u32 rebootSize;
    u32 reserved2;
} AppLoaderStruct;

static AppLoaderStruct lbl_803AD3C0 ATTRIBUTE_ALIGN(32);

#pragma dont_inline on
static asm void Run(register void* entryPoint) {
    nofralloc
    mflr r0
    stw r0, 4(r1)
    stwu r1, -0x18(r1)
    stw r31, 0x14(r1)
    mr r31, r3
    bl OSDisableInterrupts
    bl ICFlashInvalidate
    sync
    isync
    mtlr r31
    blr
}

#pragma force_active on
static asm void fn_80244C78(void) {
    nofralloc
    lwz r0, 0x1c(r1)
    lwz r31, 0x14(r1)
    addi r1, r1, 0x18
    mtlr r0
    blr
}
#pragma force_active reset
#pragma dont_inline reset

static void Callback(s32 result, DVDCommandBlock* block) {
    (void)result;
    (void)block;
    lbl_803DDE58[0] = TRUE;
}

static inline void ReadApploader(DVDCommandBlock* dvdCmd, void* addr, u32 offset, u32 numBytes) {
    while (lbl_803DDE58[0] == FALSE) { }
    DVDReadAbsAsyncForBS(dvdCmd, addr, numBytes, offset + 0x2440, NULL);

    while (TRUE) {
        switch (dvdCmd->state) {
        case 0:
            break;
        case 1:
        default:
            continue;
        case -1:
        case 2:
        case 3:
        case 4:
        case 5:
        case 6:
        case 7:
        case 8:
        case 9:
        case 10:
        case 11:
            __OSDoHotReset(g_unk_817FFFFC);
            continue;
        }
        break;
    }
}

void __OSReboot(u32 resetCode, u32 bootDol) {
    OSContext exceptionContext;
    DVDCommandBlock dvdCmd;
    DVDCommandBlock dvdCmd2;
    u32 numBytes;
    u32 offset;

    OSDisableInterrupts();

    g_unk_817FFFFC = 0;
    g_unk_817FFFF8 = 0;
    g_unk_800030E2 = TRUE;
    BOOT_REGION_START = (u32)lbl_803DDE50;
    BOOT_REGION_END = (u32)lbl_803DDE54;
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

    offset = 0;
    numBytes = 32;
    ReadApploader(&dvdCmd, (void*)&lbl_803AD3C0, offset, numBytes);

    offset = lbl_803AD3C0.size + 0x20;
    numBytes = OSRoundUp32B(lbl_803AD3C0.rebootSize);
    ReadApploader(&dvdCmd2, OS_BOOTROM_ADDR, offset, numBytes);

    ICInvalidateRange(OS_BOOTROM_ADDR, numBytes);
    Run(OS_BOOTROM_ADDR);
}

void OSSetSaveRegion(void* start, void* end) {
    lbl_803DDE50 = start;
    lbl_803DDE54 = end;
}
