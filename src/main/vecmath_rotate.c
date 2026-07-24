#include "ghidra_import.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/frame_timing.h"
#include "main/vecmath.h"
#include "main/trig.h"

extern f32 gVecMathAngleScale;
extern f32 lbl_803DE7C0;
extern f32 lbl_803DE7C4;
extern f32 lbl_803DE7F0;

void vecRotateZXY(s16* rotation, f32* vector)
{
    f32 s2;
    f32 c2;
    f32 s1;
    f32 c1;
    f32 s0;
    f32 c0;
    f32 t5;
    f32 t3;
    f32 t2;

    angleToVec2(*(u16*)((u8*)rotation + 0x0), &s0, &c0);
    angleToVec2(*(u16*)((u8*)rotation + 0x2), &s1, &c1);
    angleToVec2(*(u16*)((u8*)rotation + 0x4), &s2, &c2);
    t5 = vector[0] * c2 - vector[1] * s2;
    t3 = vector[1] * c2 + vector[0] * s2;
    vector[1] = t3 * c1 - vector[2] * s1;
    t2 = vector[2] * c1 + t3 * s1;
    vector[0] = t5 * c0 + t2 * s0;
    vector[2] = t2 * c0 - t5 * s0;
}
void mtxRotateByVec3s(f32* mtx, const void* transform)
{
    f32 cx;
    f32 sx;
    f32 cy;
    f32 sy;
    f32 s;
    f32 t1, t2, u, v;
    f32 cz;
    f32 x, y;
    f32 c;
    f32 z;
    f32 t;
    f32 sz;
    const MatrixTransform* xf = (const MatrixTransform*)transform;

    c = (f32)(int)(gVecMathAngleScale * fcos16((u16)xf->rotX));
    cx = c * lbl_803DE7F0;
    c = (f32)(int)(gVecMathAngleScale * fsin16((u16)xf->rotX));
    sx = c * lbl_803DE7F0;
    c = (f32)(int)(gVecMathAngleScale * fcos16((u16)xf->rotY));
    cy = c * lbl_803DE7F0;
    c = (f32)(int)(gVecMathAngleScale * fsin16((u16)xf->rotY));
    sy = c * lbl_803DE7F0;
    cz = (f32)(int)(gVecMathAngleScale * fcos16((u16)xf->rotZ));
    cz = cz * lbl_803DE7F0;
    sz = (f32)(int)(gVecMathAngleScale * fsin16((u16)xf->rotZ));
    sz = sz * lbl_803DE7F0;

    t1 = cy * cz;
    s = t1 * cx;
    t2 = sx * sz;
    s = t2 - s;
    mtx[0] = s;
    t2 = cy * sz;
    v = t2 * cx;
    {
        f32 p = sx * cz;
        v = v + p;
    }
    mtx[1] = v;
    mtx[2] = -(cx * sy);
    mtx[3] = (u = lbl_803DE7C0);
    mtx[4] = -(sy * cz);
    mtx[5] = sy * sz;
    mtx[6] = cy;
    mtx[7] = u;
    v = t1 * sx;
    {
        f32 p = cx * sz;
        mtx[8] = v + p;
    }
    t2 = t2 * sx;
    {
        f32 p = cx * cz;
        mtx[9] = p - t2;
    }
    mtx[10] = sx * sy;
    mtx[11] = u;
    x = xf->x;
    y = xf->y;
    z = xf->z;
    s = mtx[0];
    s = s * x;
    t = mtx[4];
    t = t * y;
    t = t + s;
    s = mtx[8];
    s = s * z;
    t = t + s;
    mtx[12] = t;
    s = mtx[1];
    s = s * x;
    t = mtx[5];
    t = t * y;
    t = t + s;
    s = mtx[9];
    s = s * z;
    t = t + s;
    mtx[13] = t;
    s = mtx[2];
    s = s * x;
    t1 = mtx[6];
    t1 = t1 * y;
    t1 = t1 + s;
    s = mtx[10];
    s = s * z;
    t1 = t1 + s;
    mtx[14] = t1;
    mtx[15] = lbl_803DE7C4;
}
