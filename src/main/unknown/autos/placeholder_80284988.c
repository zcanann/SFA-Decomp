#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80284988.h"
#include "dolphin/os.h"
#include "dolphin/dsp.h"

extern u16 hwIrqLevel;
extern u32 oldState;
extern void *(*gSalMallocHook)(u32 size);
extern u32 salLastTick;
extern u16 lbl_803DE32C;
extern u32 lbl_803DE330;
extern u32 salDspCallbackEnabled;
extern u32 salDspInitIsDone;
extern u32 salGetStartDelay(void);
extern void fn_8027C48C(u32 param_1, u32 elapsed);
extern DSPTaskInfo lbl_803D4880;
extern u16 lbl_80330840[];
extern u16 lbl_803DC628[4];
extern void dspInitCallback(void *task);
extern void dspResumeCallback(void *task);

/*
 * --INFO--
 *
 * Function: salInitDsp
 * EN v1.0 Address: 0x802848D8
 * EN v1.0 Size: 192b
 */
int salInitDsp(u32 flags)
{
    lbl_803D4880.iram_mmem_addr = lbl_80330840;
    lbl_803D4880.iram_length = lbl_803DC628[0];
    lbl_803D4880.iram_addr = 0;
    lbl_803D4880.dram_mmem_addr = (u16 *)((u8 *)&lbl_803D4880 + 0x60);
    lbl_803D4880.dram_length = 0x2000;
    lbl_803D4880.dram_addr = 0;
    lbl_803D4880.dsp_init_vector = 0x10;
    lbl_803D4880.dsp_resume_vector = 0x30;
    lbl_803D4880.init_cb = dspInitCallback;
    lbl_803D4880.res_cb = dspResumeCallback;
    lbl_803D4880.done_cb = NULL;
    lbl_803D4880.req_cb = NULL;
    lbl_803D4880.priority = 0;

    DSPInit();
    DSPAddTask(&lbl_803D4880);
    salDspInitIsDone = 0;
    sndEnd();
    while (salDspInitIsDone == 0) {}
    sndBegin();
    return 1;
}

/*
 * --INFO--
 *
 * Function: hwEnableIrq
 * EN v1.0 Address: 0x80284AB8
 * EN v1.0 Size: 4b
 */
void hwEnableIrq(void)
{
}

/*
 * --INFO--
 *
 * Function: sndEnd
 * EN v1.0 Address: 0x80284ABC
 * EN v1.0 Size: 56b
 */
void sndEnd(void)
{
    u16 count;

    count = hwIrqLevel - 1;
    hwIrqLevel = count;
    if (count == 0) {
        OSRestoreInterrupts(oldState);
    }
}

/*
 * --INFO--
 *
 * Function: salStartDsp
 * EN v1.0 Address: 0x80284998
 * EN v1.0 Size: 52b
 */
int salStartDsp(void)
{
    DSPHalt();
    while (DSPGetDMAStatus() != 0) {}
    DSPAssertInt();
    return 1;
}

/*
 * --INFO--
 *
 * Function: salCtrlDsp
 * EN v1.0 Address: 0x802849CC
 * EN v1.0 Size: 116b
 */
void salCtrlDsp(u32 param_1)
{
    u32 elapsed = salGetStartDelay();
    fn_8027C48C(param_1, elapsed);
    {
        u32 saved = lbl_803DE330;
        salDspCallbackEnabled = 0;
        PPCSync();
        DSPSendMailToDSP(((u32)0xbabe << 16) | lbl_803DE32C);
        while (DSPCheckMailToDSP() != 0) {}
        DSPSendMailToDSP(saved);
        while (DSPCheckMailToDSP() != 0) {}
    }
}

/*
 * --INFO--
 *
 * Function: salGetStartDelay
 * EN v1.0 Address: 0x80284A40
 * EN v1.0 Size: 76b
 */
u32 salGetStartDelay(void)
{
    OSTick now = OSGetTick();
    return OS_TICKS_TO_USEC(now - salLastTick);
}

/*
 * --INFO--
 *
 * Function: hwInitIrq
 * EN v1.0 Address: 0x80284A8C
 * EN v1.0 Size: 44b
 */
#pragma scheduling off
void hwInitIrq(void)
{
    oldState = OSDisableInterrupts();
    hwIrqLevel = 1;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: sndBegin
 * EN v1.0 Address: 0x80284AF4
 * EN v1.0 Size: 56b
 */
void sndBegin(void)
{
    u16 count = hwIrqLevel;
    hwIrqLevel = count + 1;
    if (count == 0) {
        oldState = OSDisableInterrupts();
    }
}

/*
 * --INFO--
 *
 * Function: hwIRQEnterCritical
 * EN v1.0 Address: 0x80284B2C
 * EN v1.0 Size: 32b
 */
void hwIRQEnterCritical(void)
{
    OSDisableInterrupts();
}

/*
 * --INFO--
 *
 * Function: hwIRQLeaveCritical
 * EN v1.0 Address: 0x80284B4C
 * EN v1.0 Size: 32b
 */
void hwIRQLeaveCritical(void)
{
    OSEnableInterrupts();
}

/*
 * --INFO--
 *
 * Function: salMalloc
 * EN v1.0 Address: 0x80284B6C
 * EN v1.0 Size: 40b
 */
void* salMalloc(u32 size)
{
    return gSalMallocHook(size);
}
