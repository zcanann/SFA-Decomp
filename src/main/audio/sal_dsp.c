#include "main/audio/sal_dsp.h"
#include "dolphin/dsp.h"

#pragma exceptions on

typedef struct {
    DSPTaskInfo task;
    u8 pad[0x10];
    u8 dram[0x2000];
} SalDspTask;

extern u16 hwIrqLevel;
extern u32 oldState;
extern void*(*gSalMallocHook)(u32 size);
extern u32 salLastTick;
extern u16 dspCmdFirstSize;
extern u32 dspCmdList;
extern u32 salDspCallbackEnabled;
extern volatile u32 salDspInitIsDone;
extern SalDspTask lbl_803D4880;
extern u16 lbl_80330840[];
extern u16 lbl_803DC628[4];
extern void dspInitCallback(void* task);
extern void dspResumeCallback(void* task);

int salInitDsp(u32 flags)
{
    lbl_803D4880.task.iram_mmem_addr = lbl_80330840;
    lbl_803D4880.task.iram_length = lbl_803DC628[0];
    lbl_803D4880.task.iram_addr = 0;
    lbl_803D4880.task.dram_mmem_addr = (u16*)((u8*)&lbl_803D4880 + 0x60);
    lbl_803D4880.task.dram_length = 0x2000;
    lbl_803D4880.task.dram_addr = 0;
    lbl_803D4880.task.dsp_init_vector = 0x10;
    lbl_803D4880.task.dsp_resume_vector = 0x30;
    lbl_803D4880.task.init_cb = dspInitCallback;
    lbl_803D4880.task.res_cb = dspResumeCallback;
    lbl_803D4880.task.done_cb = NULL;
    lbl_803D4880.task.req_cb = NULL;
    lbl_803D4880.task.priority = 0;

    DSPInit();
    DSPAddTask(&lbl_803D4880.task);
    salDspInitIsDone = 0;
    sndEnd();
    while (salDspInitIsDone == 0)
    {
    }
    sndBegin();
    return 1;
}

int salStartDsp(void)
{
    DSPHalt();
    while (DSPGetDMAStatus() != 0)
    {
    }
    DSPAssertInt();
    return 1;
}

void salCtrlDsp(u32 dest)
{
    u32 elapsed = salGetStartDelay();
    salBuildCommandList((s16*)dest, elapsed);
    {
        u32 saved = dspCmdList;
        salDspCallbackEnabled = 0;
        PPCSync();
        DSPSendMailToDSP(((u32)0xbabe << 16) | dspCmdFirstSize);
        while (DSPCheckMailToDSP() != 0)
        {
        }
        DSPSendMailToDSP(saved);
        while (DSPCheckMailToDSP() != 0)
        {
        }
    }
}

u32 salGetStartDelay(void)
{
    OSTick now = OSGetTick();
    return OS_TICKS_TO_USEC(now - salLastTick);
}

#pragma scheduling off
void hwInitIrq(void)
{
    oldState = OSDisableInterrupts();
    hwIrqLevel = 1;
}

#pragma scheduling on
void hwEnableIrq(void)
{
}

void sndEnd(void)
{
    u16 count;

    count = hwIrqLevel - 1;
    hwIrqLevel = count;
    if (count == 0)
    {
        OSRestoreInterrupts(oldState);
    }
}

void sndBegin(void)
{
    u16 count = hwIrqLevel;
    hwIrqLevel = count + 1;
    if (count == 0)
    {
        oldState = OSDisableInterrupts();
    }
}

void hwIRQEnterCritical(void)
{
    OSDisableInterrupts();
}

void hwIRQLeaveCritical(void)
{
    OSEnableInterrupts();
}

void* salMalloc(u32 size)
{
    return gSalMallocHook(size);
}

SalDspTask lbl_803D4880;
