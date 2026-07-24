#include "ghidra_import.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/atan2f.h"
#include "main/frame_timing.h"
#include "main/vecmath.h"
#include "stdlib.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/trig_float_helpers.h"
#include "main/trig.h"

typedef f32 Mtx[3][4];

extern double lbl_803DE7D8;
extern f32 gVecMathAngleScale;
extern f32 lbl_803DE7C0;
extern f32 lbl_803DE7C4;
extern f32 gVecMathPi;
extern f32 lbl_803DE7EC;
extern f32 gVecMathHalfPi;
extern f32 gVecMathNegHalfPi;
extern f32 gVecMathTwoPi;

f32 interpolate(f32 a, f32 t, f32 exp)
{
    if (t <= lbl_803DE7C4)
    {
        return a * (lbl_803DE7C4 - powfBitEstimate(lbl_803DE7C4 - t, exp));
    }
    return lbl_803DE7C0;
}
void basisVectorsToEulerAngles(f32* a, f32* b, s16* out0, s16* out1, s16* out2)
{
    f32 cross[3];
    f32 sinp;
    f32 c0;
    f32 c1;
    f32 c2;
    f32 b0;
    f32 scale;
    f32 b1;
    f32 a2;
    f32 roll;
    f32 yaw;

    PSVECCrossProduct(b, a, cross);
    c0 = cross[0];
    c1 = cross[1];
    c2 = cross[2];
    b0 = b[0];
    b1 = b[1];
    a2 = a[2];
    sinp = __kernel_sin(-b[2]);
    if (sinp < gVecMathHalfPi)
    {
        if (sinp > gVecMathNegHalfPi)
        {
            roll = __kernel_cos(c2, a2);
            yaw = __kernel_cos(b0, b1);
        }
        else
        {
            roll = -__kernel_cos(c1, c0) + (yaw = lbl_803DE7C0);
        }
    }
    else
    {
        roll = __kernel_cos(c1, c0) - (yaw = lbl_803DE7C0);
    }
    {
        f32 twoPi;
        f32 angleScale;
        scale = (angleScale = gVecMathAngleScale);
        *out0 = scale * yaw / (twoPi = gVecMathTwoPi);
        *out1 = angleScale * sinp / twoPi;
        *out2 = angleScale * roll / twoPi;
    }
}

void setMatrixFromObjectTransposed(void* obj, f32* out)
{
    f32 m[16];
    setMatrixFromObjectPos(m, obj);
    out[0] = m[0];
    out[1] = m[4];
    out[2] = m[8];
    out[4] = m[1];
    out[5] = m[5];
    out[6] = m[9];
    out[8] = m[2];
    out[9] = m[6];
    out[10] = m[10];
    out[3] = m[12];
    out[7] = m[13];
    out[11] = m[14];
}

void mtx44Transpose(f32* src, f32* dst)
{
    dst[0] = src[0];
    dst[1] = src[4];
    dst[2] = src[8];
    dst[4] = src[1];
    dst[5] = src[5];
    dst[6] = src[9];
    dst[8] = src[2];
    dst[9] = src[6];
    dst[10] = src[10];
    dst[3] = src[12];
    dst[7] = src[13];
    dst[11] = src[14];
}
f32 getXZDistance(f32* a, f32* b)
{
    f32 dx = a[0] - b[0];
    f32 dz = a[2] - b[2];
    return dx * dx + dz * dz;
}

f32 Vec_xzDistance(f32* a, f32* b)
{
    f32 dx = a[0] - b[0];
    f32 dz = a[2] - b[2];
    return sqrtf(dx * dx + dz * dz);
}

f32 vec3f_distanceSquared(f32* a, f32* b)
{
    f32 dx = a[0] - b[0];
    f32 dy = a[1] - b[1];
    f32 dz = a[2] - b[2];
    return dx * dx + dy * dy + dz * dz;
}

f32 Vec_distance(f32* a, f32* b)
{
    f32 dx = a[0] - b[0];
    f32 dy = a[1] - b[1];
    f32 dz = a[2] - b[2];
    return sqrtf(dx * dx + dy * dy + dz * dz);
}

int cos16(s16 angle)
{
    return (int)(gVecMathAngleScale * fcos16((u16)angle));
}

int atan2_8002178c(float y, float x)
{
    return (int)(lbl_803DE7D8 * atan2f(y, x));
}

int getAngle(float y, float x)
{
    return (int)(lbl_803DE7D8 * atan2f(y, x));
}

int atan2i(int y, int x)
{
    return (int)(lbl_803DE7D8 * atan2f((f32)y, x));
}

void initRotationMtx(f32* m, f32 a, f32 b, f32 c)
{
    f32 z = lbl_803DE7C0;
    m[0] = z;
    m[1] = z;
    m[2] = z;
    m[3] = z;
    m[4] = z;
    m[5] = z;
    m[6] = z;
    m[7] = z;
    m[8] = z;
    m[9] = z;
    m[10] = z;
    m[11] = z;
    m[12] = z;
    m[13] = z;
    m[14] = z;
    m[15] = z;
    m[0] = a;
    m[5] = b;
    m[10] = c;
}
void vecRotateYXZ(s16* a, f32* v)
{
    f32 x, y, z;
    f32 s1, s2;
    f32 c;

    x = v[0];
    y = v[1];
    z = v[2];

    c = mathSinf((gVecMathPi * a[0]) / lbl_803DE7EC);
    s1 = x * c;
    s2 = z * c;
    c = mathCosf((gVecMathPi * a[0]) / lbl_803DE7EC);
    x *= c;
    z *= c;
    x += s2;
    z -= s1;

    c = mathSinf((gVecMathPi * a[1]) / lbl_803DE7EC);
    s1 = y * c;
    s2 = z * c;
    c = mathCosf((gVecMathPi * a[1]) / lbl_803DE7EC);
    y *= c;
    z *= c;
    y -= s2;
    z += s1;

    c = mathSinf((gVecMathPi * a[2]) / lbl_803DE7EC);
    s1 = x * c;
    s2 = y * c;
    c = mathCosf((gVecMathPi * a[2]) / lbl_803DE7EC);
    x *= c;
    y *= c;
    x -= s2;
    y += s1;

    v[0] = x;
    v[1] = y;
    v[2] = z;
}
