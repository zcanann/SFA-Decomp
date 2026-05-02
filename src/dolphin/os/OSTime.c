#include <dolphin/os.h>

#include "dolphin/os/__os.h"

asm OSTime OSGetTime(void) {
jump:
    nofralloc

    mftbu r3
    mftb r4

    // Check for possible carry from TBL to TBU
    mftbu r5
    cmpw r3, r5
    bne jump

    blr
}

asm OSTick OSGetTick(void){
    nofralloc

    mftb r3
    blr
}

OSTime __OSGetSystemTime() {
    BOOL enabled;
    OSTime* timeAdjustAddr;
    OSTime result;

    timeAdjustAddr = __OSSystemTime;
    enabled = OSDisableInterrupts();

    result = OSGetTime() + *timeAdjustAddr;
    OSRestoreInterrupts(enabled);
    return result;
}
