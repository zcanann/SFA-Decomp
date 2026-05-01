#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_8028026C.h"
#include "main/unknown/autos/placeholder_8028116C.h"

extern int FUN_80271b50();
extern undefined4 FUN_80272224();
extern uint FUN_80272ec4();
extern undefined4 FUN_80280c30();
extern int FUN_80280c34();

extern uint DAT_803cd570;
extern undefined4 DAT_803defd0;
extern int* DAT_803defd4;
extern undefined4 DAT_803defea;
extern undefined4 DAT_803defeb;
extern undefined4 DAT_803defec;
extern undefined4 DAT_803defed;
extern f32 FLOAT_803e8518;
extern f32 FLOAT_803e853c;
extern f32 FLOAT_803e8554;
extern f32 FLOAT_803e8558;
extern f32 FLOAT_803e855c;
extern u8 lbl_803BD150[];
extern u8 lbl_803D3CA0[];
extern u8 lbl_803DE238;

/*
 * --INFO--
 *
 * Function: FUN_80281160
 * EN v1.0 Address: 0x80281160
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8028116C
 * EN v1.1 Size: 552b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80281160(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80281164
 * EN v1.0 Address: 0x80281164
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80281394
 * EN v1.1 Size: 972b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80281164(void)
{
}

void fn_80281194(u8 valueA, u8 valueB)
{
    lbl_803BD150[0x211] = valueA;
    lbl_803BD150[0x212] = valueB;
}

u8 fn_802811A8(void)
{
    return lbl_803DE238;
}

#pragma peephole off
void fn_802811B0(f32 *matrix, f32 *vec, f32 *out)
{
    out[0] = matrix[9] + (matrix[0] * vec[0] + matrix[1] * vec[1] + matrix[2] * vec[2]);
    out[1] = matrix[10] + (matrix[3] * vec[0] + matrix[4] * vec[1] + matrix[5] * vec[2]);
    out[2] = matrix[11] + (matrix[6] * vec[0] + matrix[7] * vec[1] + matrix[8] * vec[2]);
}
#pragma peephole reset

void fn_80281310(u8 index, u8 group, u32 flags)
{
    u8 *groupBase;
    u8 *entry;
    u32 offset;

    groupBase = lbl_803D3CA0 + group * 0x40;
    entry = groupBase;
    offset = index * 4;
    entry += offset;
    *(u32 *)entry |= flags;
}
