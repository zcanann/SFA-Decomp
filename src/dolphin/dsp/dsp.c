#include <stddef.h>
#include <dolphin.h>
#include <dolphin/hw_regs.h>

#include "dolphin/dsp/__dsp.h"

typedef struct DSPStrings {
    char initMsg[0x20];
    char buildDate[0xC];
    char buildTime[0x9];
} DSPStrings;

extern const DSPStrings sDSPStrings;
#define DSP_INIT_BUILD_DATE_MSG sDSPStrings.initMsg
#define BUILD_DATE sDSPStrings.buildDate
#define BUILD_TIME sDSPStrings.buildTime

extern DSPTaskInfo* __DSP_rude_task;
extern int __DSP_rude_task_pending;

static BOOL __DSP_init_flag;

u32 DSPCheckMailToDSP(void) {
    return (__DSPRegs[0] & (1 << 15)) >> 15;
}

u32 DSPCheckMailFromDSP(void) {
    return (__DSPRegs[2] & (1 << 15)) >> 15;
}

u32 DSPReadMailFromDSP(void) {
    return (__DSPRegs[2] << 16) | __DSPRegs[3];
}

void DSPSendMailToDSP(u32 mail) {
    __DSPRegs[0] = mail >> 16;
    __DSPRegs[1] = mail & 0xFFFF;
}

void DSPInit(void) {
    BOOL old;
    u16 tmp;

    __DSP_debug_printf(DSP_INIT_BUILD_DATE_MSG, BUILD_DATE, BUILD_TIME);

    if (__DSP_init_flag == 1)
        return;

    old = OSDisableInterrupts();
    __OSSetInterruptHandler(7, __DSPHandler);
    __OSUnmaskInterrupts(OS_INTERRUPTMASK_DSP_DSP);

    tmp = __DSPRegs[5];
    tmp = (tmp & ~0xA8) | 0x800;
    __DSPRegs[5] = tmp;

    tmp = __DSPRegs[5];
    __DSPRegs[5] = tmp = tmp & ~0xAC;

    __DSP_first_task = __DSP_last_task = __DSP_curr_task = __DSP_tmp_task = NULL;
    __DSP_init_flag = 1;

    OSRestoreInterrupts(old);
}

void DSPAssertInt(void) {
    BOOL old;
    u16 tmp;

    old = OSDisableInterrupts();
    tmp = __DSPRegs[5];
    tmp = (tmp & ~0xA8) | 2;
    __DSPRegs[5] = tmp;
    OSRestoreInterrupts(old);
}

void DSPHalt(void) {
    BOOL old;
    u16 tmp;

    old = OSDisableInterrupts();
    tmp = __DSPRegs[5];
    tmp = (tmp & ~0xA8) | 4;
    __DSPRegs[5] = tmp;
    OSRestoreInterrupts(old);
}

u32 DSPGetDMAStatus(void) {
    return __DSPRegs[5] & 0x200;
}

DSPTaskInfo* DSPAddTask(DSPTaskInfo* task) {
    BOOL old;

    old = OSDisableInterrupts();
    __DSP_add_task(task);
    task->state = 0;
    task->flags = 1;
    OSRestoreInterrupts(old);

    if (task == __DSP_curr_task) {
        __DSP_boot_task(task);
    }

    return task;
}

void __DSP_debug_printf(const char* fmt, ...) {}
