#ifndef MAIN_DLL_VECROTATEZXY_H_
#define MAIN_DLL_VECROTATEZXY_H_

#include "types.h"

/*
 * vecRotateZXY interface. The input block is a ZXY-Euler rotation (dir -
 * packed s16 angles, same encoding as anim.rotX/Y/Z) applied to a 4-vector
 * (pos, where [0] carries the value and [1..3] the components); the rotated
 * result is written to out. Shared by the pushable/transporter object family
 * (pushable / iceblast / flameblast) and wmobjcreator. MtxBuildArg is the
 * named-scalar view of the same 24-byte input layout (rx/ry/rz + w/a/b/c).
 */
typedef struct VecRotateZXYArg
{
    s16 dir[3];
    s16 pad;
    f32 pos[4];
} VecRotateZXYArg;

void vecRotateZXY(void* in, f32* out);

#endif
