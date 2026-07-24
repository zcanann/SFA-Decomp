#include "ghidra_import.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/frame_timing.h"
#include "main/vecmath.h"
#include "stdlib.h"
#include "main/trig.h"

extern f32 lbl_803DE808;
extern f32 lbl_803DE80C;
extern f32 lbl_803DE7C0;
extern f32 lbl_803DE7C4;
extern f32 lbl_803DE810;
extern f32 lbl_803DE7F8;
extern f32 lbl_803DE7F4;

void mtx44ScaleRow1(f32* p, f32 s)
{
    p[4] *= s;
    p[5] *= s;
    p[6] *= s;
}

void setMatrixFromObjectPos(f32* m, const MatrixTransform* transform)
{
    f32 scale;
    f32 zero;
    f32 s0;
    f32 c0;
    f32 s1;
    f32 c1;
    f32 s2;
    f32 c2;

    angleToVec2((u16)transform->rotX, &s0, &c0);
    angleToVec2((u16)transform->rotY, &s1, &c1);
    angleToVec2((u16)transform->rotZ, &s2, &c2);
    scale = transform->scale;
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
    m[12] = transform->x;
    m[13] = transform->y;
    m[14] = transform->z;
    m[15] = lbl_803DE7C4;
}
int RandomTimer_UpdateRangeTrigger(void* timerp, f32 lo, f32 hi)
{
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

int randomGetRange(int lo, int hi)
{
    f32 v;
    if (lo == hi)
    {
        return lo;
    }
    v = (f32)(u32)rand();
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
    } while (end != a);

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

void mtx44_multSafe(f32* a, f32* b, f32* out)
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
            tp[t] += *(f32*)((int)a + o1) * *(f32*)((int)b + (j + 4) * 4);
            tp[t] += *(f32*)((int)a + o2) * *(f32*)((int)b + (j + 8) * 4);
            tp[t] += *(f32*)((int)a + o3) * *(f32*)((int)b + (j + 12) * 4);
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

void Matrix_TransformVector(const f32* matrix, const f32* vector, f32* out)
{
    f32 vx, vy, vz;
    f32 m0, m1, m2;
    f32 t;

    vx = vector[0];
    m0 = matrix[0];
    vy = vector[1];
    m1 = matrix[4];
    vz = vector[2];
    m2 = matrix[8];
    m0 = vx * m0;
    m1 = vy * m1;
    m2 = vz * m2;
    m1 = m0 + m1;
    m0 = matrix[1];
    t = m1 + m2;
    m1 = matrix[5];
    m2 = matrix[9];
    m0 = vx * m0;
    out[0] = t;
    m1 = vy * m1;
    m2 = vz * m2;
    m1 = m0 + m1;
    m0 = matrix[2];
    t = m1 + m2;
    m1 = matrix[6];
    m2 = matrix[10];
    m0 = vx * m0;
    out[1] = t;
    m1 = vy * m1;
    m2 = vz * m2;
    m0 = m0 + m1;
    out[2] = m0 + m2;
}

void Matrix_TransformPoint(const f32* matrix, f32 x, f32 y, f32 z, f32* outX, f32* outY, f32* outZ)
{
    *outX = matrix[12] + (matrix[0] * x + matrix[4] * y + matrix[8] * z);
    *outY = matrix[13] + (matrix[1] * x + matrix[5] * y + matrix[9] * z);
    *outZ = matrix[14] + (matrix[2] * x + matrix[6] * y + matrix[10] * z);
}

void Vec3_ReflectAgainstNormal(f32* normal, f32* velocity, f32* out)
{
    f32 yProduct = normal[1] * velocity[1];
    f32 dot = yProduct + normal[0] * velocity[0] + normal[2] * velocity[2];
    if (dot > lbl_803DE808)
    {
        out[0] = velocity[0];
        out[1] = velocity[1];
        out[2] = velocity[2];
    }
    else
    {
        f32 reflectionScale = dot * lbl_803DE80C;
        out[0] = normal[0];
        out[1] = normal[1];
        out[2] = normal[2];
        out[0] *= reflectionScale;
        out[1] *= reflectionScale;
        out[2] *= reflectionScale;
        out[0] += velocity[0];
        out[1] += velocity[1];
        out[2] += velocity[2];
    }
}

void Vec3_ScaleAdd(const f32* base, const f32* vector, f32 scale, f32* out)
{
    out[0] = scale * vector[0] + base[0];
    out[1] = scale * vector[1] + base[1];
    out[2] = scale * vector[2] + base[2];
}

f32 Vec3_Normalize(f32* vector)
{
    f32 length;
    f32 inverseLength;

    length = sqrtf(vector[0] * vector[0] + vector[1] * vector[1] + vector[2] * vector[2]);
    if (lbl_803DE808 != length)
    {
        inverseLength = lbl_803DE810 / length;
        vector[0] *= inverseLength;
        vector[1] *= inverseLength;
        vector[2] *= inverseLength;
    }
    return length;
}

void Vec3_Cross(f32* lhs, f32* rhs, f32* out)
{
    out[0] = lhs[1] * rhs[2] - lhs[2] * rhs[1];
    out[1] = lhs[2] * rhs[0] - lhs[0] * rhs[2];
    out[2] = lhs[0] * rhs[1] - lhs[1] * rhs[0];
}

f32 Vec3_Length(const f32* vector)
{
    return sqrtf(vector[0] * vector[0] + vector[1] * vector[1] + vector[2] * vector[2]);
}
