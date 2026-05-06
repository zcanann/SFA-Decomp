#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80284988.h"
#include "dolphin/os.h"
#include "dolphin/dsp.h"

extern u16 lbl_803DE3BC;
extern u32 lbl_803DE3C0;
extern u32 lbl_803DE374;
extern u32 lbl_803DE3B4;
extern u16 lbl_803DE32C;
extern u32 lbl_803DE330;
extern u32 lbl_803DE3A8;
extern u32 lbl_803DE3B8;
extern u32 fn_80284A40(void);
extern void fn_8027C48C(u32 param_1, u32 elapsed);
extern DSPTaskInfo lbl_803D4880;
extern u16 lbl_80330840[];
extern u16 lbl_803DC628[4];
extern void fn_80284714(void *task);
extern void fn_80284724(void *task);

/*
 * --INFO--
 *
 * Function: fn_802848D8
 * EN v1.0 Address: 0x802848D8
 * EN v1.0 Size: 192b
 */
int fn_802848D8(u32 flags)
{
    lbl_803D4880.iram_mmem_addr = lbl_80330840;
    lbl_803D4880.iram_length = lbl_803DC628[0];
    lbl_803D4880.iram_addr = 0;
    lbl_803D4880.dram_mmem_addr = (u16 *)((u8 *)&lbl_803D4880 + 0x60);
    lbl_803D4880.dram_length = 0x2000;
    lbl_803D4880.dram_addr = 0;
    lbl_803D4880.dsp_init_vector = 0x10;
    lbl_803D4880.dsp_resume_vector = 0x30;
    lbl_803D4880.init_cb = fn_80284714;
    lbl_803D4880.res_cb = fn_80284724;
    lbl_803D4880.done_cb = NULL;
    lbl_803D4880.req_cb = NULL;
    lbl_803D4880.priority = 0;

    DSPInit();
    DSPAddTask(&lbl_803D4880);
    lbl_803DE3B8 = 0;
    sndEnd();
    while (lbl_803DE3B8 == 0) {}
    sndBegin();
    return 1;
}

/*
 * --INFO--
 *
 * Function: fn_80284AB8
 * EN v1.0 Address: 0x80284AB8
 * EN v1.0 Size: 4b
 */
void fn_80284AB8(void)
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

    count = lbl_803DE3BC - 1;
    lbl_803DE3BC = count;
    if (count == 0) {
        OSRestoreInterrupts(lbl_803DE3C0);
    }
}

/*
 * --INFO--
 *
 * Function: fn_80284998
 * EN v1.0 Address: 0x80284998
 * EN v1.0 Size: 52b
 */
int fn_80284998(void)
{
    DSPHalt();
    while (DSPGetDMAStatus() != 0) {}
    DSPAssertInt();
    return 1;
}

/*
 * --INFO--
 *
 * Function: fn_802849CC
 * EN v1.0 Address: 0x802849CC
 * EN v1.0 Size: 116b
 */
void fn_802849CC(u32 param_1)
{
    u32 elapsed = fn_80284A40();
    fn_8027C48C(param_1, elapsed);
    {
        u32 saved = lbl_803DE330;
        lbl_803DE3A8 = 0;
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
 * Function: fn_80284A40
 * EN v1.0 Address: 0x80284A40
 * EN v1.0 Size: 76b
 */
u32 fn_80284A40(void)
{
    OSTick now = OSGetTick();
    return OS_TICKS_TO_USEC(now - lbl_803DE3B4);
}

/*
 * --INFO--
 *
 * Function: fn_80284A8C
 * EN v1.0 Address: 0x80284A8C
 * EN v1.0 Size: 44b
 */
#pragma scheduling off
void fn_80284A8C(void)
{
    lbl_803DE3C0 = OSDisableInterrupts();
    lbl_803DE3BC = 1;
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
    u16 count = lbl_803DE3BC;
    lbl_803DE3BC = count + 1;
    if (count == 0) {
        lbl_803DE3C0 = OSDisableInterrupts();
    }
}

/*
 * --INFO--
 *
 * Function: fn_80284B2C
 * EN v1.0 Address: 0x80284B2C
 * EN v1.0 Size: 32b
 */
void fn_80284B2C(void)
{
    OSDisableInterrupts();
}

/*
 * --INFO--
 *
 * Function: fn_80284B4C
 * EN v1.0 Address: 0x80284B4C
 * EN v1.0 Size: 32b
 */
void fn_80284B4C(void)
{
    OSEnableInterrupts();
}

/*
 * --INFO--
 *
 * Function: fn_80284B6C
 * EN v1.0 Address: 0x80284B6C
 * EN v1.0 Size: 40b
 */
void* fn_80284B6C(u32 size)
{
    return ((void* (*)(u32))lbl_803DE374)(size);
}
