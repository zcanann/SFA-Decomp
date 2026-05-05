#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80284988.h"

extern u32 OSDisableInterrupts(void);
extern u32 OSEnableInterrupts(void);
extern u32 OSRestoreInterrupts(u32 prevState);

extern u16 lbl_803DE3BC;
extern u32 lbl_803DE3C0;

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
