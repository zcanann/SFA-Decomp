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
extern u32 fn_80284A40(void);
extern void fn_8027C48C(u32 param_1, u32 elapsed);

/*
 * --INFO--
 *
 * Function: FUN_802848d8
 * EN v1.0 Address: 0x802848D8
 * EN v1.0 Size: 4b
 */
void FUN_802848d8(int param_1)
{
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
 * Function: fn_80284ABC
 * EN v1.0 Address: 0x80284ABC
 * EN v1.0 Size: 56b
 */
void fn_80284ABC(void)
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
 * Function: fn_80284AF4
 * EN v1.0 Address: 0x80284AF4
 * EN v1.0 Size: 56b
 */
void fn_80284AF4(void)
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
