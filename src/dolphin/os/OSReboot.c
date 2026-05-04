#include <dolphin.h>
#include <dolphin/os.h>

#include "dolphin/os/__os.h"
#include <dolphin/dvd/__dvd.h>

extern u32 BOOT_REGION_START AT_ADDRESS(0x812FDFF0);
extern u32 BOOT_REGION_END AT_ADDRESS(0x812FDFEC);
extern u8 OS_REBOOT_BOOL AT_ADDRESS(0x800030E2);
extern u32 UNK_817FFFF8 AT_ADDRESS(0x817FFFF8);
extern u32 UNK_817FFFFC AT_ADDRESS(0x817FFFFC);

static void* SaveStart;
static void* SaveEnd;
static volatile BOOL Prepared[2];

typedef struct {
    char date[16];
    u32 entry;
    u32 size;
    u32 rebootSize;
    u32 reserved2;
} ApploaderHeader;

static ApploaderHeader Header ATTRIBUTE_ALIGN(32);

#pragma dont_inline on
static asm void myFunc() {
}

static void Run(register void (*addr)()) {
    OSDisableInterrupts();
    ICFlashInvalidate();

    asm {
        sync
        isync
        mtlr addr
        blr
    }
}
#pragma dont_inline reset

static void Callback(s32 result, DVDCommandBlock* block) {
    (void)result;
    (void)block;
    Prepared[0] = TRUE;
}

static inline void ReadApploader(DVDCommandBlock* dvdCmd, void* addr, u32 offset, u32 numBytes) {
    while (Prepared[0] == FALSE) { }
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
            __OSDoHotReset(UNK_817FFFFC);
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

    UNK_817FFFFC = 0;
    UNK_817FFFF8 = 0;
    OS_REBOOT_BOOL = TRUE;
    BOOT_REGION_START = (u32)SaveStart;
    BOOT_REGION_END = (u32)SaveEnd;
    OSClearContext(&exceptionContext);
    OSSetCurrentContext(&exceptionContext);
    DVDInit();
    DVDSetAutoInvalidation(TRUE);

    __DVDPrepareResetAsync(Callback);

    if (!DVDCheckDisk()) {
        __OSDoHotReset(UNK_817FFFFC);
    }

    __OSMaskInterrupts(0xFFFFFFE0);
    __OSUnmaskInterrupts(0x400);

    OSEnableInterrupts();

    offset = 0;
    numBytes = 32;
    ReadApploader(&dvdCmd, (void*)&Header, offset, numBytes);

    offset = Header.size + 0x20;
    numBytes = OSRoundUp32B(Header.rebootSize);
    ReadApploader(&dvdCmd2, OS_BOOTROM_ADDR, offset, numBytes);

    ICInvalidateRange(OS_BOOTROM_ADDR, numBytes);
    Run(OS_BOOTROM_ADDR);
}

void OSSetSaveRegion(void* start, void* end) {
    SaveStart = start;
    SaveEnd = end;
}
