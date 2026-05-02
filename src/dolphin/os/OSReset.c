#include <dolphin.h>
#include <dolphin/os.h>

#include "dolphin/os/__os.h"

// These macros are copied from OSThread.c. Or ARE they the same
// macros? They dont seem to be in the SDK headers.
#define ENQUEUE_INFO(info, queue)                            \
    do {                                                     \
        OSResetFunctionInfo* __prev = (queue)->tail; \
        if (__prev == 0) {                                   \
            (queue)->head = (info);                          \
        } else {                                             \
            __prev->next = (info);                           \
        }                                                    \
        (info)->prev = __prev;                               \
        (info)->next = 0;                                    \
        (queue)->tail = (info);                              \
    } while(0);

#define DEQUEUE_INFO(info, queue)                           \
    do {                                                    \
        OSResetFunctionInfo* __next = (info)->next; \
        OSResetFunctionInfo* __prev = (info)->prev; \
        if (__next == 0) {                                  \
            (queue)->tail = __prev;                         \
        } else {                                            \
            __next->prev = __prev;                          \
        }                                                   \
        if (__prev == 0) {                                  \
            (queue)->head = __next;                         \
        } else {                                            \
            __prev->next = __next;                          \
        }                                                   \
    } while(0);

#define ENQUEUE_INFO_PRIO(info, queue)               \
    do {                                             \
        OSResetFunctionInfo* __prev;         \
        OSResetFunctionInfo* __next;         \
        for(__next = (queue)->head; __next           \
          && (__next->priority <= (info)->priority); \
                __next = __next->next) ;             \
                                                     \
        if (__next == 0) {                           \
            ENQUEUE_INFO(info, queue);               \
        } else {                                     \
            (info)->next = __next;                   \
            __prev = __next->prev;                   \
            __next->prev = (info);                   \
            (info)->prev = __prev;                   \
            if (__prev == 0) {                       \
                (queue)->head = (info);              \
            } else {                                 \
                __prev->next = (info);               \
            }                                        \
        }                                            \
    } while(0);

static OSResetFunctionQueue ResetFunctionQueue;
extern u32 bootThisDol_803DEAE8;
#define bootThisDol bootThisDol_803DEAE8

void OSRegisterResetFunction(OSResetFunctionInfo* info) {
    ASSERTLINE(208, info->func);

    ENQUEUE_INFO_PRIO(info, &ResetFunctionQueue);
}

static asm void Reset(u32 resetCode) {
    nofralloc
    b L_000001BC
L_000001A0:
    mfspr r8, HID0
    ori r8, r8, 0x8
    mtspr HID0, r8
    isync
    sync
    nop
    b L_000001C0
L_000001BC:
    b L_000001DC
L_000001C0:
    mftb r5, 268
L_000001C4:
    mftb r6, 268
    subf r7, r5, r6
    cmplwi r7, 0x1124
    blt L_000001C4
    nop
    b L_000001E0
L_000001DC:
    b L_000001FC
L_000001E0:
    lis r8, 0xcc00
    ori r8, r8, 0x3000
    li r4, 0x3
    stw r4, 0x24(r8)
    stw r3, 0x24(r8)
    nop
    b L_00000200
L_000001FC:
    b L_00000208
L_00000200:
    nop
    b L_00000200
L_00000208:
    b L_000001A0
}

void __OSDoHotReset(u32 resetCode) {
    OSDisableInterrupts();
    __VIRegs[1] = 0;
    ICFlashInvalidate();
    Reset(resetCode << 3);
}

void OSResetSystem(BOOL reset, u32 resetCode, BOOL forceMenu) {
    OSResetFunctionInfo* info;
    int err;
    BOOL done;
    OSSram* sram;
    OSThread* thread;
    OSThread* next;
    BOOL disableRecalibration;
    u8 stackPad[16];

    OSDisableScheduler();
    __OSStopAudioSystem();

    if (reset == OS_RESET_SHUTDOWN) {
        disableRecalibration = __PADDisableRecalibration(TRUE);
    }

    do {
        info = ResetFunctionQueue.head;
        err = 0;
        while (info != NULL) {
            err |= !info->func(FALSE);
            info = info->next;
        }
        err |= !__OSSyncSram();
        if (err != 0) {
            done = FALSE;
        } else {
            done = TRUE;
        }
    } while (done == FALSE);

    if (reset == OS_RESET_HOTRESET && forceMenu) {
        sram = __OSLockSram();
        sram->flags |= 0x40;
        __OSUnlockSram(1);
        while (!__OSSyncSram()) {}
    }

    OSDisableInterrupts();
    info = ResetFunctionQueue.head;
    err = 0;
    while (info != NULL) {
        err |= !info->func(TRUE);
        info = info->next;
    }
    __OSSyncSram();
    LCDisable();

    if (reset == OS_RESET_HOTRESET) {
        OSDisableInterrupts();
        __VIRegs[1] = 0;
        ICFlashInvalidate();
        Reset(resetCode << 3);
    } else if (reset == OS_RESET_RESTART) {
        for (thread = __OSActiveThreadQueue.head; thread != NULL; thread = next) {
            next = thread->linkActive.next;
            switch (thread->state) {
            case 1:
            case 4:
                OSCancelThread(thread);
                break;
            default:
                break;
            }
        }

        OSEnableScheduler();
        __OSReboot(resetCode, forceMenu);
    }

    for (thread = __OSActiveThreadQueue.head; thread != NULL; thread = next) {
        next = thread->linkActive.next;
        switch (thread->state) {
        case 1:
        case 4:
            OSCancelThread(thread);
            break;
        default:
            break;
        }
    }

    memset((void*)0x80000040, 0, 0x8c);
    memset((void*)0x800000d4, 0, 0x14);
    memset((void*)0x800000f4, 0, 4);
    memset((void*)0x80003000, 0, 0xc0);
    memset((void*)0x800030c8, 0, 0xc);
    memset((void*)0x800030e2, 0, 1);

    __PADDisableRecalibration(disableRecalibration);
}

u32 OSGetResetCode() {
    if (*(volatile u8*)0x800030e2 != 0) {
        return 0x80000000;
    }

    return (__PIRegs[PI_RESETCODE] & ~7) >> 3;
}

