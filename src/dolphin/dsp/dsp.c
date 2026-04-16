#include <stddef.h>
#include <dolphin.h>
#include <dolphin/hw_regs.h>

#include "dolphin/dsp/__dsp.h"

#if DEBUG
#define BUILD_DATE "Apr  5 2004"
#define BUILD_TIME "03:56:49"
const char* __DSPVersion = "<< Dolphin SDK - DSP\tdebug build: Apr  5 2004 03:56:49 (0x2301) >>";
#define DSP_INIT_BUILD_DATE_MSG "DSPInit(): Build Date: %s %s\n"
#else
typedef struct DSPStrings {
    char version[0x45];
    char _pad0[3];
    char initMsg[0x1E];
    char _pad1[2];
    char buildDate[0xC];
    char buildTime[0x9];
} DSPStrings;

extern const DSPStrings sDSPStrings;
const char* __DSPVersion = sDSPStrings.version;
#define BUILD_DATE sDSPStrings.buildDate
#define BUILD_TIME sDSPStrings.buildTime
#define DSP_INIT_BUILD_DATE_MSG sDSPStrings.initMsg
#endif

extern DSPTaskInfo* __DSP_rude_task;
extern int __DSP_rude_task_pending;

static BOOL __DSP_init_flag;

u32 DSPCheckMailToDSP(void) {
    return (__DSPRegs[0] & (1 << 15)) >> 15;
}

u32 DSPCheckMailFromDSP(void) {
    return (__DSPRegs[2] & (1 << 15)) >> 15;
}

u32 DSPReadCPUToDSPMbox(void) {
    return (__DSPRegs[0] << 16) | __DSPRegs[1];
}

u32 DSPReadMailFromDSP(void) {
    return (__DSPRegs[2] << 16) | __DSPRegs[3];
}

void DSPSendMailToDSP(u32 mail) {
    __DSPRegs[0] = mail >> 16;
    __DSPRegs[1] = mail & 0xFFFF;
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

void DSPInit(void) {
    BOOL old;
    u16 tmp;

    __DSP_debug_printf(DSP_INIT_BUILD_DATE_MSG, BUILD_DATE, BUILD_TIME);

    if (__DSP_init_flag == 1)
        return;

    OSRegisterVersion(__DSPVersion);

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

BOOL DSPCheckInit(void) {
    return __DSP_init_flag;
}

void DSPReset(void) {
    BOOL old;
    u16 tmp;

    old = OSDisableInterrupts();
    tmp = __DSPRegs[5];
    tmp = (tmp & ~0xA8) | 0x800 | 1;
    __DSPRegs[5] = tmp;
    __DSP_init_flag = 0;
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
