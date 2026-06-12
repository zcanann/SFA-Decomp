#ifndef MAIN_DLL_DBEGGSTATE_STRUCT_H_
#define MAIN_DLL_DBEGGSTATE_STRUCT_H_

#include "types.h"
#include "main/dll/curve_walker.h"

typedef struct DbEggState
{
    f32 waterOffset; /* float-height offset above water */
    RomCurveWalker curve; /* 0x004: rom-curve walker record (state+4 to gRomCurveInterface) */
    u8 unk10C[0x118 - 0x10C];
    u8 mode; /* 0x118 */
    u8 flags119; /* bits 1/2/4/8/0x10 */
    u8 unk11A[2];
    s16 msg11C; /* 0x11C: 3-word message payload sent via ObjMsg */
    s16 msg11E;
    f32 msg120;
} DbEggState;

#endif
