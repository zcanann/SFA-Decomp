#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80283DA0.h"

extern undefined4 DAT_803defc4;
extern u32 lbl_803BD150[];
extern f32 lbl_803E78E8;
extern u32 __cvt_fp2unsigned(double value);
extern void aramInit(undefined4 value);
extern void aramGetZeroBuffer(void);

/*
 * --INFO--
 *
 * Function: hwExitStream
 * EN v1.0 Address: 0x80283D5C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80283DA0
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
u32 hwExitStream(u32 value)
{
    return __cvt_fp2unsigned((double)((lbl_803E78E8 * (f32)value) / (f32)lbl_803BD150[0]));
}

/*
 * --INFO--
 *
 * Function: hwGetStreamPlayBuffer
 * EN v1.0 Address: 0x80283D60
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80283DC0
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void hwGetStreamPlayBuffer(undefined4 unused, undefined4 value)
{
    aramInit(value);
}

/*
 * --INFO--
 *
 * Function: hwTransAddr
 * EN v1.0 Address: 0x80283D68
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80283DD4
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void hwTransAddr(void)
{
    aramGetZeroBuffer();
}

/*
 * --INFO--
 *
 * Function: FUN_80283d70
 * EN v1.0 Address: 0x80283D70
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80283DE8
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined2 FUN_80283d70(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80283d78
 * EN v1.0 Address: 0x80283D78
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80283DFC
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80283d78(int param_1,undefined param_2)
{
}
