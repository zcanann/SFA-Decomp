#include "musyx/sal_dsp.h"
#include "musyx/hw_samplemem.h"
#include "dolphin/os.h"
#include "dolphin/os/OSInterrupt.h"

void hwEnableIrq(void) {
}

void sndEnd(void) {
    u16 count = hwIrqLevel - 1;
    hwIrqLevel = count;
    if (count == 0) {
        OSRestoreInterrupts(oldState);
    }
}

void sndBegin(void) {
    u16 count = hwIrqLevel;
    hwIrqLevel = count + 1;
    if (count == 0) {
        oldState = OSDisableInterrupts();
    }
}

void hwIRQEnterCritical(void) {
    OSDisableInterrupts();
}

void hwIRQLeaveCritical(void) {
    OSEnableInterrupts();
}

void* salMalloc(u32 size) {
    return salHooks.mallocHook(size);
}
