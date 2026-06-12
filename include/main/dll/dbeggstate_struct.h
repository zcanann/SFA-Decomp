#ifndef MAIN_DLL_DBEGGSTATE_STRUCT_H_
#define MAIN_DLL_DBEGGSTATE_STRUCT_H_

#include "types.h"

typedef struct DbEggState
{
    f32 waterOffset; /* float-height offset above water */
    u8 curveWalker[0x10]; /* 0x004: rom-curve walker record (state+4 to gRomCurveInterface) */
    int unk14;
    u8 unk18[0x6C - 0x18];
    f32 curvePosX; /* 0x06C: walker sample position */
    f32 curvePosY;
    f32 curvePosZ;
    u8 unk78[0x118 - 0x78];
    u8 mode; /* 0x118 */
    u8 flags119; /* bits 1/2/4/8/0x10 */
    u8 unk11A[2];
    s16 msg11C; /* 0x11C: 3-word message payload sent via ObjMsg */
    s16 msg11E;
    f32 msg120;
} DbEggState;

#endif
