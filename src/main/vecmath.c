#include "ghidra_import.h"
#include "main/gameplay_runtime.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/k_cos.h"
extern float powfBitEstimate(float x, float y);
extern f32 timeDelta;

extern double lbl_803DE7D8;
extern float fcos16(int angle);
extern f32 sqrtf(f32 x);
extern f32 gVecMathAngleScale;
extern f32 lbl_803DE808;
extern f32 lbl_803DE80C;
extern f32 lbl_803DE7C0;
extern f32 lbl_803DE7C4;
extern void mtxRotateByVec3s(f32* mtx, void* transform);
extern void mtx44Transpose(f32* src, f32* dst);
extern void setMatrixFromObjectPos(f32* m, u8* p);
extern f32 lbl_803DE810;
extern int rand(void);
extern f32 lbl_803DE7F8;
extern f32 fsin16(int angle);
extern f32 lbl_803DE7F0;
extern float mathSinf(float x);
extern float mathCosf(float x);
extern f32 gVecMathPi;
extern f32 lbl_803DE7EC;
extern void angleToVec2(int angle, f32* cosOut, f32* sinOut);
extern void PSVECCrossProduct(f32* a, f32* b, f32* out);

u16*
FUN_80017460(u64 unused1, u64 unused2, u64 unused3, u64 unused4,
             u64 unused5, u64 unused6, u64 unused7, u64 unused8, u32 unused9
             , int unused10, u32 unused11, u32 unused12, u32 unused13,
             u32 unused14, u32 unused15, u32 unused16)
{
    return 0;
}

u16*
FUN_80017468(u64 unused1, u64 unused2, u64 unused3, u64 unused4,
             u64 unused5, u64 unused6, u64 unused7, u64 unused8, u32 unused9
             , u32 unused10, u32 unused11, u32 unused12, u32 unused13,
             u32 unused14, u32 unused15, u32 unused16)
{
    return 0;
}

u32
FUN_80017500(u64 unused1, u64 unused2, u64 unused3, u64 unused4,
             u64 unused5, u64 unused6, u64 unused7, u64 unused8, int unused9)
{
    return 0;
}

u32
FUN_8001786c(u64 unused1, double unused2, double unused3, u64 unused4, u64 unused5,
             u64 unused6, u64 unused7, u64 unused8, u32 unused9,
             u32 unused10, u32 unused11, u32 unused12)
{
    return 0;
}

u8*
FUN_80017998(u64 unused1, u64 unused2, u64 unused3, u64 unused4,
             u64 unused5, u64 unused6, u64 unused7, u64 unused8, u32 unused9
)
{
    return 0;
}

#pragma scheduling off
#pragma peephole off
f32 getXZDistance(f32* a, f32* b)
{
    f32 dx = a[0] - b[0];
    f32 dz = a[2] - b[2];
    return dx * dx + dz * dz;
}

f32 vec3f_distanceSquared(f32* a, f32* b)
{
    f32 dx = a[0] - b[0];
    f32 dy = a[1] - b[1];
    f32 dz = a[2] - b[2];
    return dx * dx + dy * dy + dz * dz;
}

void Vec3_ScaleAdd(f32* a, f32* b, f32 s, f32* out)
{
    out[0] = s * b[0] + a[0];
    out[1] = s * b[1] + a[1];
    out[2] = s * b[2] + a[2];
}

int getAngle(float y, float x)
{
    return (int)(lbl_803DE7D8 * fn_802924B4(y, x));
}

int atan2_8002178c(float y, float x)
{
    return (int)(lbl_803DE7D8 * fn_802924B4(y, x));
}

void mtx44ScaleRow1(u8* p, f32 s)
{
    *(f32*)(p + 0x10) *= s;
    *(f32*)(p + 0x14) *= s;
    *(f32*)(p + 0x18) *= s;
}

int cos16(u16 angle)
{
    return (int)(gVecMathAngleScale * fcos16(angle));
}

f32 Vec3_Length(f32* v)
{
    return sqrtf(v[0] * v[0] + v[1] * v[1] + v[2] * v[2]);
}

f32 Vec_xzDistance(f32* a, f32* b)
{
    f32 dx = a[0] - b[0];
    f32 dz = a[2] - b[2];
    return sqrtf(dx * dx + dz * dz);
}

f32 Vec_distance(f32* a, f32* b)
{
    f32 dx = a[0] - b[0];
    f32 dy = a[1] - b[1];
    f32 dz = a[2] - b[2];
    return sqrtf(dx * dx + dy * dy + dz * dz);
}

void Vec3_Cross(f32* a, f32* b, f32* out)
{
    out[0] = a[1] * b[2] - a[2] * b[1];
    out[1] = a[2] * b[0] - a[0] * b[2];
    out[2] = a[0] * b[1] - a[1] * b[0];
}

void Vec3_ReflectAgainstNormal(f32* a, f32* n, f32* out)
{
    f32 yy = a[1] * n[1];
    f32 dot = yy + a[0] * n[0] + a[2] * n[2];
    if (dot > lbl_803DE808)
    {
        out[0] = n[0];
        out[1] = n[1];
        out[2] = n[2];
    }
    else
    {
        f32 s = dot * lbl_803DE80C;
        out[0] = a[0];
        out[1] = a[1];
        out[2] = a[2];
        out[0] *= s;
        out[1] *= s;
        out[2] *= s;
        out[0] += n[0];
        out[1] += n[1];
        out[2] += n[2];
    }
}

typedef f32 Mtx[3][4];

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

f32 interpolate(f32 a, f32 t, f32 exp)
{
    if (t <= lbl_803DE7C4)
    {
        return a * (lbl_803DE7C4 - powfBitEstimate(lbl_803DE7C4 - t, exp));
    }
    return lbl_803DE7C0;
}

int atan2i(int y, int x)
{
    return (int)(lbl_803DE7D8 * fn_802924B4((f32)y, x));
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

void Matrix_TransformPoint(f32* m, f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz)
{
    *ox = m[12] + (m[0] * x + m[4] * y + m[8] * z);
    *oy = m[13] + (m[1] * x + m[5] * y + m[9] * z);
    *oz = m[14] + (m[2] * x + m[6] * y + m[10] * z);
}

void Matrix_TransformVector(f32* m, f32* v, f32* out)
{
    f32 vx, vy, vz;
    f32 m0, m1, m2;
    f32 t;

    vx = v[0];
    m0 = m[0];
    vy = v[1];
    m1 = m[4];
    vz = v[2];
    m2 = m[8];
    m0 = vx * m0;
    m1 = vy * m1;
    m2 = vz * m2;
    m1 = m0 + m1;
    m0 = m[1];
    t = m1 + m2;
    m1 = m[5];
    m2 = m[9];
    m0 = vx * m0;
    out[0] = t;
    m1 = vy * m1;
    m2 = vz * m2;
    m1 = m0 + m1;
    m0 = m[2];
    t = m1 + m2;
    m1 = m[6];
    m2 = m[10];
    m0 = vx * m0;
    out[1] = t;
    m1 = vy * m1;
    m2 = vz * m2;
    m0 = m0 + m1;
    out[2] = m0 + m2;
}

int randomGetRange(int lo, int hi)
{
    f32 v;
    if (lo == hi)
    {
        return lo;
    }
    v = (f32)(u32)
    rand();
    v = v / lbl_803DE7F8;
    v = v * (lbl_803DE7C4 + hi - lo);
    v = v + lo;
    return v;
}

void copyMatrix44(f32* src, f32* dst)
{
    dst[0] = src[0];
    dst[1] = src[1];
    dst[2] = src[2];
    dst[3] = src[3];
    dst[4] = src[4];
    dst[5] = src[5];
    dst[6] = src[6];
    dst[7] = src[7];
    dst[8] = src[8];
    dst[9] = src[9];
    dst[10] = src[10];
    dst[11] = src[11];
    dst[12] = src[12];
    dst[13] = src[13];
    dst[14] = src[14];
    dst[15] = src[15];
}

f32 Vec3_Normalize(f32* v)
{
    f32 len;
    f32 s;

    len = sqrtf(v[0] * v[0] + v[1] * v[1] + v[2] * v[2]);
    if (lbl_803DE808 != len)
    {
        s = lbl_803DE810 / len;
        v[0] *= s;
        v[1] *= s;
        v[2] *= s;
    }
    return len;
}

#pragma fp_contract off
void mtxRotateByVec3s(f32* mtx, void* transform)
{
    f32 cx;
    f32 sx;
    f32 cy;
    f32 sy;
    f32 z;
    f32 t1, t2, u, v;
    f32 cz;
    f32 s, t;
    f32 c;
    f32 x;
    f32 y;
    f32 sz;
    f32 zero;

    c = (f32)(int)(gVecMathAngleScale * fcos16((u16) * (s16*)transform));
    cx = c * lbl_803DE7F0;
    c = (f32)(int)(gVecMathAngleScale * fsin16((u16) * (s16*)transform));
    sx = c * lbl_803DE7F0;
    c = (f32)(int)(gVecMathAngleScale * fcos16((u16) * (s16*)((u8*)transform + 2)));
    cy = c * lbl_803DE7F0;
    c = (f32)(int)(gVecMathAngleScale * fsin16((u16) * (s16*)((u8*)transform + 2)));
    sy = c * lbl_803DE7F0;
    cz = (f32)(int)(gVecMathAngleScale * fcos16((u16) * (s16*)((u8*)transform + 4)));
    cz = cz * lbl_803DE7F0;
    sz = (f32)(int)(gVecMathAngleScale * fsin16((u16) * (s16*)((u8*)transform + 4)));
    sz = sz * lbl_803DE7F0;

    t1 = cy * cz;
    u = t1 * cx;
    s = sx * sz;
    u = s - u;
    mtx[0] = u;
    t2 = cy * sz;
    v = t2 * cx;
    v = v + sx * cz;
    mtx[1] = v;
    mtx[2] = -(cx * sy);
    mtx[3] = (zero = lbl_803DE7C0);
    mtx[4] = -(sy * cz);
    mtx[5] = sy * sz;
    mtx[6] = cy;
    mtx[7] = zero;
    u = t1 * sx;
    mtx[8] = u + cx * sz;
    t2 = t2 * sx;
    mtx[9] = cx * cz - t2;
    mtx[10] = sx * sy;
    mtx[11] = zero;
    x = *(f32*)((u8*)transform + 0xc);
    y = *(f32*)((u8*)transform + 0x10);
    z = *(f32*)((u8*)transform + 0x14);
    s = mtx[0] * x;
    t = mtx[4] * y;
    t = t + s;
    s = mtx[8] * z;
    t = t + s;
    mtx[12] = t;
    s = mtx[1] * x;
    t = mtx[5] * y;
    t = t + s;
    s = mtx[9] * z;
    t = t + s;
    mtx[13] = t;
    s = mtx[2] * x;
    t = mtx[6] * y;
    t = t + s;
    s = mtx[10] * z;
    t = t + s;
    mtx[14] = t;
    mtx[15] = lbl_803DE7C4;
}

#pragma fp_contract on
void mtx44_mult(f32* a, f32* b, f32* out)
{
    f32* end = a + 12;
    f32 a1, a0, a2;
    f32 b0, b1, b2, b3;
    f32 s, t;

    do
    {
        a0 = a[0];
        a1 = a[1];
        a2 = a[2];
        b0 = b[0];
        b1 = b[4];
        b2 = b[8];
        b0 = a0 * b0;
        b1 = a1 * b1;
        b2 = a2 * b2;
        s = b0 + b1;
        b0 = b[1];
        b1 = b[5];
        s = b2 + s;
        b2 = b[9];
        out[0] = s;
        b0 = a0 * b0;
        b1 = a1 * b1;
        b2 = a2 * b2;
        s = b0 + b1;
        b0 = b[2];
        b1 = b[6];
        s = b2 + s;
        b2 = b[10];
        out[1] = s;
        b0 = a0 * b0;
        b1 = a1 * b1;
        b2 = a2 * b2;
        out[2] = b2 + (b0 + b1);
        out += 4;
        a += 4;
    }
    while (end != a);

    a0 = a[0];
    a1 = a[1];
    a2 = a[2];
    b0 = b[0];
    b1 = b[4];
    b2 = b[8];
    b3 = b[12];
    b0 = a0 * b0;
    b1 = a1 * b1;
    b2 = a2 * b2;
    b3 = b0 + b3;
    b2 = b1 + b2;
    b0 = b[1];
    b1 = b[5];
    t = b2 + b3;
    b2 = b[9];
    b3 = b[13];
    out[0] = t;
    b0 = a0 * b0;
    b1 = a1 * b1;
    b2 = a2 * b2;
    b3 = b0 + b3;
    b2 = b1 + b2;
    b0 = b[2];
    b1 = b[6];
    t = b2 + b3;
    b2 = b[10];
    b3 = b[14];
    out[1] = t;
    b0 = a0 * b0;
    b1 = a1 * b1;
    b2 = a2 * b2;
    b3 = b0 + b3;
    b2 = b1 + b2;
    t = b2 + b3;
    out[2] = t;
}

#pragma opt_strength_reduction off
void mtx44_multSafe(int a, int b, f32* out)
{
    f32 tmp[16];
    int o3, o2, o1;
    int t;
    int row;
    f32* tp;
    int i;
    int j;
    f32 zero;

    i = 0;
    row = 0;
    zero = lbl_803DE7C0;
    tp = tmp;
    for (; i < 4; i++)
    {
        j = 0;
        t = row;
        o1 = (row + 1) * 4;
        o2 = (row + 2) * 4;
        o3 = (row + 3) * 4;
        for (; j < 4; j++)
        {
            tp[t] = zero;
            tp[t] += ((f32*)a)[row] * ((f32*)b)[j];
            tp[t] += *(f32*)(a + o1) * *(f32*)(b + (j + 4) * 4);
            tp[t] += *(f32*)(a + o2) * *(f32*)(b + (j + 8) * 4);
            tp[t] += *(f32*)(a + o3) * *(f32*)(b + (j + 12) * 4);
            t++;
        }
        row += 4;
    }
    for (i = 0; i < 16; i += 4)
    {
        *(f32*)((int)out + (i << 2)) = *(f32*)((int)tmp + (i << 2));
        *(f32*)((int)out + ((i + 1) << 2)) = *(f32*)((int)tmp + ((i + 1) << 2));
        *(f32*)((int)out + ((i + 2) << 2)) = *(f32*)((int)tmp + ((i + 2) << 2));
        *(f32*)((int)out + ((i + 3) << 2)) = *(f32*)((int)tmp + ((i + 3) << 2));
    }
}

#pragma opt_strength_reduction on
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

#pragma peephole off
void setMatrixFromObjectPos(f32* m, u8* p)
{
    f32 scale;
    f32 zero;
    f32 s0;
    f32 c0;
    f32 s1;
    f32 c1;
    f32 s2;
    f32 c2;

    angleToVec2((u16) * (s16*)(p + 0x0), &s0, &c0);
    angleToVec2((u16) * (s16*)(p + 0x2), &s1, &c1);
    angleToVec2((u16) * (s16*)(p + 0x4), &s2, &c2);
    scale = *(f32*)(p + 0x8);
    m[0] = scale * (s2 * (s1 * s0) + c2 * c0);
    m[1] = scale * (s2 * c1);
    m[2] = scale * (s2 * (s1 * c0) - c2 * s0);
    zero = lbl_803DE7C0;
    m[3] = zero;
    m[4] = scale * (c2 * (s1 * s0) - s2 * c0);
    m[5] = scale * (c2 * c1);
    m[6] = scale * (c2 * (s1 * c0) + s2 * s0);
    m[7] = zero;
    m[8] = scale * (c1 * s0);
    m[9] = -s1 * scale;
    m[10] = scale * (c1 * c0);
    m[11] = zero;
    m[12] = *(f32*)(p + 0xc);
    m[13] = *(f32*)(p + 0x10);
    m[14] = *(f32*)(p + 0x14);
    m[15] = lbl_803DE7C4;
}

#pragma dont_inline on
#pragma peephole off
void fn_800213D0(f32* a, f32* b, s16* out0, s16* out1, s16* out2)
{
    extern f32 __kernel_sin(f32);
    extern f32 __kernel_cos(f32, f32);
    extern f32 gVecMathHalfPi;
    extern f32 gVecMathNegHalfPi;
    extern f32 gVecMathTwoPi;
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
        f32 d;
        f32 s;
        scale = (s = gVecMathAngleScale);
        *out0 = scale * yaw / (d = gVecMathTwoPi);
        *out1 = s * sinp / d;
        *out2 = s * roll / d;
    }
}

#pragma fp_contract off
#pragma dont_inline off
int RandomTimer_UpdateRangeTrigger(void* timerp, f32 lo, f32 hi)
{
    extern f32 oneOverTimeDelta;
    extern f32 lbl_803DE7F4;
    f32* timer = timerp;
    int trig;
    int range;
    int val;
    u32 rv;
    f32 freq;
    f32 t;

    *timer += timeDelta / (freq = lbl_803DE7F4);
    if (*timer > lo)
    {
        if (*timer > hi)
        {
            trig = 1;
        }
        else
        {
            range = (int)(oneOverTimeDelta * (freq * (hi - lo)));
            if (range == 0)
            {
                val = 0;
            }
            else
            {
                rv = rand();
                {
                    f32 acc = rv;
                    acc = acc / lbl_803DE7F8;
                    acc = acc * ((lbl_803DE7C4 + range) - (t = lbl_803DE7C0));
                    acc = acc + t;
                    val = acc;
                }
            }
            trig = !val;
        }
        if (trig != 0)
        {
            *timer = lbl_803DE7C0;
        }
        return trig;
    }
    return 0;
}

#pragma fp_contract on
#pragma peephole off
void vecRotateZXY(u8* p, f32* v)
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

    angleToVec2(*(u16*)(p + 0x0), &s0, &c0);
    angleToVec2(*(u16*)(p + 0x2), &s1, &c1);
    angleToVec2(*(u16*)(p + 0x4), &s2, &c2);
    t5 = v[0] * c2 - v[1] * s2;
    t3 = v[1] * c2 + v[0] * s2;
    v[1] = t3 * c1 - v[2] * s1;
    t2 = v[2] * c1 + t3 * s1;
    v[0] = t5 * c0 + t2 * s0;
    v[2] = t2 * c0 - t5 * s0;
}
