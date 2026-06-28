#ifndef MAIN_DLL_DBEGGSTATE_STRUCT_H_
#define MAIN_DLL_DBEGGSTATE_STRUCT_H_

#include "types.h"
#include "main/dll/curve_walker.h"

typedef struct DbEggState
{
    f32 waterOffset; /* float-height offset above water */
    RomCurveWalker curve; /* 0x004: rom-curve walker record (state+4 to gRomCurveInterface) */
    f32 launchVelX; /* 0x10C: launch velocity vec3, set by dbegg_func0B, applied
        to anim.velocity when the egg is thrown */
    f32 launchVelY; /* 0x110 */
    f32 launchVelZ; /* 0x114 */
    u8 mode; /* 0x118 */
    u8 flags119; /* bits 1/2/4/8/0x10 */
    u8 unk11A[2];
    s16 msg11C; /* 0x11C: 3-word message payload sent via ObjMsg */
    s16 msg11E;
    f32 msg120;
} DbEggState;

#endif
