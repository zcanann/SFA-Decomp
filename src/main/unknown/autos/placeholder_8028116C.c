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
extern u8 gSynthInitialized;
extern f32 lbl_803E78C8;
extern f64 lbl_803E78D0;
extern f64 lbl_803E78D8;

extern void hwExit(void);
extern void fn_80275344(void);
extern void fn_80281040(void);
extern void synthExit(void);
extern double __frsqrte(double x);

void fn_80281160(void)
{
    hwExit();
    fn_80275344();
    fn_80281040();
    synthExit();
    gSynthInitialized = 0;
}

void fn_80281194(u8 valueA, u8 valueB)
{
    lbl_803BD150[0x211] = valueA;
    lbl_803BD150[0x212] = valueB;
}

u8 sndIsInstalled(void)
{
    return gSynthInitialized;
}

#pragma peephole off
#pragma fp_contract off
void salApplyMatrix(f32 *matrix, f32 *vec, f32 *out)
{
    out[0] = matrix[9] + (matrix[0] * vec[0] + matrix[1] * vec[1] + matrix[2] * vec[2]);
    out[1] = matrix[10] + (matrix[3] * vec[0] + matrix[4] * vec[1] + matrix[5] * vec[2]);
    out[2] = matrix[11] + (matrix[6] * vec[0] + matrix[7] * vec[1] + matrix[8] * vec[2]);
}
#pragma fp_contract reset
#pragma peephole reset

#pragma fp_contract off
void salNormalizeVector(f32 *v)
{
    volatile f32 divisor;
    f32 lensq = v[0] * v[0] + v[1] * v[1] + v[2] * v[2];
    divisor = lensq;
    if (lensq > lbl_803E78C8) {
        f64 g = __frsqrte((f64)lensq);
        g = lbl_803E78D0 * g * (lbl_803E78D8 - g * g * (f64)lensq);
        g = lbl_803E78D0 * g * (lbl_803E78D8 - g * g * (f64)lensq);
        divisor = (f32)((f64)lensq * (lbl_803E78D0 * g) * (lbl_803E78D8 - g * g * (f64)lensq));
    }
    v[0] /= divisor;
    v[1] /= divisor;
    v[2] /= divisor;
}
#pragma fp_contract reset

void inpSetGlobalMIDIDirtyFlag(u8 index, u8 group, u32 flags)
{
    u8 *groupBase;
    u8 *entry;
    u32 offset;

    groupBase = lbl_803D3CA0 + group * 0x40;
    offset = index * 4;
    entry = groupBase + offset;
    *(u32 *)entry |= flags;
}
