#include "ghidra_import.h"

extern f32 powfBitEstimate(f32 x, f32 y);

/*
 * --INFO--
 *
 * Function: gameTextSetWindow
 * EN v1.0 Address: 0x80017434
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001746C
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
/* moved below GameTextSlot/global declarations */

/*
 * --INFO--
 *
 * Function: FUN_80017460
 * EN v1.0 Address: 0x80017460
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800191FC
 * EN v1.1 Size: 640b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined2 *
FUN_80017460(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9
            ,int param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017468
 * EN v1.0 Address: 0x80017468
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8001947C
 * EN v1.1 Size: 300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined2 *
FUN_80017468(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9
            ,undefined4 param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: textRenderStr
 * EN v1.0 Address: 0x800174D0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001AE18
 * EN v1.1 Size: 1760b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

extern f32 timeDelta;

#pragma push
#pragma scheduling off

#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma pop

/*
 * --INFO--
 *
 * Function: FUN_80017500
 * EN v1.0 Address: 0x80017500
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8001BD8C
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80017500(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8001786c
 * EN v1.0 Address: 0x8001786C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80024F40
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8001786c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,
            undefined4 param_10,undefined4 param_11,undefined4 param_12)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017998
 * EN v1.0 Address: 0x80017998
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80029260
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined *
FUN_80017998(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9
            )
{
    return 0;
}

/* Pattern wrappers. */
#pragma dont_inline on
#pragma dont_inline reset

/* ObjModel/model-file accessors. */

#pragma push
#pragma scheduling off
#pragma peephole off

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset

#pragma peephole off
#pragma peephole reset

#pragma pop

/* Global game-state / text accessors. */

#pragma dont_inline on
#pragma dont_inline reset

#pragma peephole off

#pragma peephole reset

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset

#pragma peephole off

#pragma dont_inline on

#pragma dont_inline reset
#pragma peephole reset

/* Simple field/global accessors. */

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset

#pragma peephole off
#pragma scheduling off
#pragma scheduling reset
#pragma peephole reset

#pragma push
#pragma scheduling off
#pragma peephole off

#pragma pop

#pragma dont_inline on
#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop
#pragma dont_inline reset

#pragma peephole off
#pragma peephole reset

#pragma push
#pragma scheduling off
#pragma peephole off

#pragma dont_inline on
#pragma dont_inline reset

#pragma peephole on
#pragma peephole reset

#pragma dont_inline on

#pragma dont_inline reset

#pragma pop

extern int randomGetRange(int lo, int hi);

#pragma push
#pragma scheduling off
#pragma peephole off

#pragma dont_inline on
#pragma dont_inline reset

f32 getXZDistance(f32 *a, f32 *b) {
    f32 dx = a[0] - b[0];
    f32 dz = a[2] - b[2];
    return dx * dx + dz * dz;
}

f32 vec3f_distanceSquared(f32 *a, f32 *b) {
    f32 dx = a[0] - b[0];
    f32 dy = a[1] - b[1];
    f32 dz = a[2] - b[2];
    return dx * dx + dy * dy + dz * dz;
}

void Vec3_ScaleAdd(f32 *a, f32 s, f32 *b, f32 *out) {
    out[0] = s * b[0] + a[0];
    out[1] = s * b[1] + a[1];
    out[2] = s * b[2] + a[2];
}

#pragma peephole on

#pragma peephole reset
#pragma pop

extern float fn_802924B4(float y, float x);
extern double lbl_803DE7D8;

#pragma push
#pragma scheduling off
#pragma peephole off

int getAngle(float y, float x) {
    return (int)(lbl_803DE7D8 * fn_802924B4(y, x));
}

int atan2_8002178c(float y, float x) {
    return (int)(lbl_803DE7D8 * fn_802924B4(y, x));
}

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset

#pragma peephole off
#pragma peephole reset
#pragma pop

extern f32 fcos16(int angle);
extern f32 sqrtf(f32 x);
extern f32 lbl_803DE7D0;

#pragma push
#pragma scheduling off
#pragma peephole off
void mtx44ScaleRow1(u8 *p, f32 s) {
    *(f32 *)(p + 0x10) *= s;
    *(f32 *)(p + 0x14) *= s;
    *(f32 *)(p + 0x18) *= s;
}

int cos16(u16 angle) {
    return (int)(lbl_803DE7D0 * fcos16(angle));
}

#pragma dont_inline on
#pragma dont_inline reset

f32 Vec3_Length(f32 *v) {
    return sqrtf(v[0] * v[0] + v[1] * v[1] + v[2] * v[2]);
}

f32 Vec_xzDistance(f32 *a, f32 *b) {
    f32 dx = a[0] - b[0];
    f32 dz = a[2] - b[2];
    return sqrtf(dx * dx + dz * dz);
}

f32 Vec_distance(f32 *a, f32 *b) {
    f32 dx = a[0] - b[0];
    f32 dy = a[1] - b[1];
    f32 dz = a[2] - b[2];
    return sqrtf(dx * dx + dy * dy + dz * dz);
}

void Vec3_Cross(f32 *a, f32 *b, f32 *out) {
    out[0] = a[1] * b[2] - a[2] * b[1];
    out[1] = a[2] * b[0] - a[0] * b[2];
    out[2] = a[0] * b[1] - a[1] * b[0];
}

extern f32 lbl_803DE808;
extern f32 lbl_803DE80C;

void Vec3_ReflectAgainstNormal(f32 *a, f32 *n, f32 *out) {
    f32 yy = a[1] * n[1];
    f32 dot = yy + a[0] * n[0] + a[2] * n[2];
    if (dot > lbl_803DE808) {
        out[0] = n[0];
        out[1] = n[1];
        out[2] = n[2];
    } else {
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

#pragma dont_inline on

#pragma dont_inline reset

#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off

#pragma dont_inline on

#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset

#pragma pop

typedef f32 Mtx[3][4];
extern f32 lbl_803DE7C0;
extern f32 lbl_803DE7C4;

#pragma push
#pragma scheduling off
#pragma peephole off

#pragma optimize_for_size on
#pragma optimize_for_size reset

#pragma optimize_for_size on
#pragma optimize_for_size reset

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset

extern void mtxRotateByVec3s(f32 *mtx, void *transform);
extern void mtx44Transpose(f32 *src, f32 *dst);

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma peephole reset

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset

void initRotationMtx(f32 *m, f32 a, f32 b, f32 c) {
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

#pragma dont_inline on
#pragma dont_inline reset

#pragma peephole on
#pragma peephole reset

f32 interpolate(f32 a, f32 t, f32 exp) {
    if (t <= lbl_803DE7C4) {
        return a * (lbl_803DE7C4 - powfBitEstimate(lbl_803DE7C4 - t, exp));
    }
    return lbl_803DE7C0;
}

int atan2i(int y, int x) {
    return (int)(lbl_803DE7D8 * fn_802924B4((f32)y, (f32)x));
}
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void mtx44Transpose(f32 *src, f32 *dst) {
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
#pragma dont_inline reset

extern void setMatrixFromObjectPos(f32 *mtx, u8 *obj);

#pragma dont_inline on
void setMatrixFromObjectTransposed(void *obj, f32 *out) {
    f32 m[16];
    setMatrixFromObjectPos(m, (u8 *)obj);
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
#pragma dont_inline reset

void Matrix_TransformPoint(f32 *m, f32 x, f32 y, f32 z, f32 *ox, f32 *oy, f32 *oz) {
    *ox = m[12] + (m[0] * x + m[4] * y + m[8] * z);
    *oy = m[13] + (m[1] * x + m[5] * y + m[9] * z);
    *oz = m[14] + (m[2] * x + m[6] * y + m[10] * z);
}

#pragma dont_inline on
#pragma dont_inline reset

#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma optimize_for_size on
#pragma optimize_for_size reset

#pragma dont_inline on

#pragma dont_inline reset

#pragma pop

extern f32 lbl_803DE810;

#pragma push
#pragma scheduling off
#pragma peephole off
void Matrix_TransformVector(f32 *m, f32 *v, f32 *out) {
    f32 vx = v[0];
    f32 vy = v[1];
    f32 vz = v[2];
    out[0] = vx * m[0] + vy * m[4] + vz * m[8];
    out[1] = vx * m[1] + vy * m[5] + vz * m[9];
    out[2] = vx * m[2] + vy * m[6] + vz * m[10];
}

extern int rand(void);
extern f32 lbl_803DE7F8;

#pragma dont_inline on
int randomGetRange(int lo, int hi) {
    f32 v;
    if (lo == hi) {
        return lo;
    }
    v = ((f32)(u32)rand() / lbl_803DE7F8) * (lbl_803DE7C4 + (f32)hi - (f32)lo);
    return (int)(v + (f32)lo);
}
#pragma dont_inline reset

void copyMatrix44(f32 *src, f32 *dst) {
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

void Vec3_Normalize(f32 *v) {
    f32 len = sqrtf(v[0] * v[0] + v[1] * v[1] + v[2] * v[2]);
    if (len != lbl_803DE808) {
        f32 s = lbl_803DE810 / len;
        v[0] *= s;
        v[1] *= s;
        v[2] *= s;
    }
}

#pragma dont_inline on
#pragma dont_inline reset

#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off

#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off

#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma scheduling off
#pragma peephole off
#pragma scheduling reset
#pragma peephole reset

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma peephole off
#pragma peephole reset

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma peephole off
#pragma scheduling off
#pragma scheduling reset

#pragma scheduling off
#pragma scheduling reset
#pragma peephole reset

#pragma push
#pragma scheduling off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off

#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop


#pragma push
#pragma scheduling off
#pragma peephole off
#pragma optimize_for_size on
#pragma optimize_for_size reset

#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

extern f32 fsin16(int angle);
extern f32 lbl_803DE7F0;

#pragma push
#pragma scheduling off
#pragma fp_contract off
void mtxRotateByVec3s(f32 *mtx, void *transform) {
    f32 cx;
    f32 sx;
    f32 cy;
    f32 sy;
    f32 cz;
    f32 sz;
    f32 x;
    f32 y;
    f32 z;
    f32 zero;

    cx = (f32)(int)(lbl_803DE7D0 * fcos16((u16)*(s16 *)transform)) * lbl_803DE7F0;
    sx = (f32)(int)(lbl_803DE7D0 * fsin16((u16)*(s16 *)transform)) * lbl_803DE7F0;
    cy = (f32)(int)(lbl_803DE7D0 * fcos16((u16)*(s16 *)((u8 *)transform + 2))) * lbl_803DE7F0;
    sy = (f32)(int)(lbl_803DE7D0 * fsin16((u16)*(s16 *)((u8 *)transform + 2))) * lbl_803DE7F0;
    cz = (f32)(int)(lbl_803DE7D0 * fcos16((u16)*(s16 *)((u8 *)transform + 4))) * lbl_803DE7F0;
    sz = (f32)(int)(lbl_803DE7D0 * fsin16((u16)*(s16 *)((u8 *)transform + 4))) * lbl_803DE7F0;

    mtx[0] = sx * sz - (cy * cz) * cx;
    mtx[1] = (cy * sz) * cx + sx * cz;
    mtx[2] = -(cx * sy);
    zero = lbl_803DE7C0;
    mtx[3] = zero;
    mtx[4] = -(sy * cz);
    mtx[5] = sy * sz;
    mtx[6] = cy;
    mtx[7] = zero;
    mtx[8] = (cy * cz) * sx + cx * sz;
    mtx[9] = cx * cz - (cy * sz) * sx;
    mtx[10] = sx * sy;
    mtx[11] = zero;
    x = *(f32 *)((u8 *)transform + 0xc);
    y = *(f32 *)((u8 *)transform + 0x10);
    z = *(f32 *)((u8 *)transform + 0x14);
    mtx[12] = mtx[4] * y + mtx[0] * x + mtx[8] * z;
    mtx[13] = mtx[5] * y + mtx[1] * x + mtx[9] * z;
    mtx[14] = mtx[6] * y + mtx[2] * x + mtx[10] * z;
    mtx[15] = lbl_803DE7C4;
}
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on

#pragma peephole off
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma opt_loop_invariants off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

extern f32 fn_80293E80(f32);
extern f32 sin(f32);

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma opt_strength_reduction off
#pragma opt_loop_invariants off
void mtx44_multSafe(int a, int b, f32 *out)
{
    f32 tmp[16];
    int j;
    int i;
    int row;
    int aoff;
    f32 zero;
    int toff;
    int boff;
    int o3, o2, o1;
    f32 a0, a1, a2, a3;

    row = 0;
    aoff = 0;
    zero = lbl_803DE7C0;
    for (i = 0; i < 4; i++) {
        boff = 0;
        toff = row << 2;
        o1 = (row + 1) * 4;
        o2 = (row + 2) * 4;
        o3 = (row + 3) * 4;
        for (j = 0; j < 4; j++) {
            *(f32 *)((int)tmp + toff) = zero;
            a0 = *(f32 *)(a + aoff);
            *(f32 *)((int)tmp + toff) += a0 * *(f32 *)(b + boff);
            a1 = *(f32 *)(a + o1);
            *(f32 *)((int)tmp + toff) += a1 * *(f32 *)(b + (j + 4) * 4);
            a2 = *(f32 *)(a + o2);
            *(f32 *)((int)tmp + toff) += a2 * *(f32 *)(b + (j + 8) * 4);
            a3 = *(f32 *)(a + o3);
            *(f32 *)((int)tmp + toff) += a3 * *(f32 *)(b + (j + 12) * 4);
            toff += 4;
            boff += 4;
        }
        row += 4;
        aoff += 0x10;
    }
    for (i = 0; i < 16; i++) {
        *(f32 *)((int)out + i * 4) = *(f32 *)((int)tmp + i * 4);
    }
}
#pragma opt_loop_invariants reset
#pragma opt_strength_reduction reset
#pragma dont_inline reset
#pragma pop

extern f32 lbl_803DE7E8;
extern f32 lbl_803DE7EC;

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void vecRotateYXZ(s16 *a, f32 *v)
{
    f32 x, y, z;
    f32 s1, s2;
    f32 c;

    x = v[0];
    y = v[1];
    z = v[2];

    c = fn_80293E80((lbl_803DE7E8 * (f32)a[0]) / lbl_803DE7EC);
    s1 = x * c;
    s2 = z * c;
    c = sin((lbl_803DE7E8 * (f32)a[0]) / lbl_803DE7EC);
    x *= c;
    z *= c;
    x += s2;
    z -= s1;

    c = fn_80293E80((lbl_803DE7E8 * (f32)a[1]) / lbl_803DE7EC);
    s1 = y * c;
    s2 = z * c;
    c = sin((lbl_803DE7E8 * (f32)a[1]) / lbl_803DE7EC);
    y *= c;
    z *= c;
    y -= s2;
    z += s1;

    c = fn_80293E80((lbl_803DE7E8 * (f32)a[2]) / lbl_803DE7EC);
    s1 = x * c;
    s2 = y * c;
    c = sin((lbl_803DE7E8 * (f32)a[2]) / lbl_803DE7EC);
    x *= c;
    y *= c;
    x -= s2;
    y += s1;

    v[0] = x;
    v[1] = y;
    v[2] = z;
}
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline on
#pragma dont_inline reset
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma opt_common_subs off
#pragma opt_common_subs reset
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

extern void angleToVec2(int angle, f32 *cosOut, f32 *sinOut);

#pragma push
#pragma scheduling off
void setMatrixFromObjectPos(f32 *m, u8 *p)
{
    f32 scale;
    f32 zero;
    f32 s0;
    f32 c0;
    f32 s1;
    f32 c1;
    f32 s2;
    f32 c2;

    angleToVec2((u16)*(s16 *)(p + 0x0), &s0, &c0);
    angleToVec2((u16)*(s16 *)(p + 0x2), &s1, &c1);
    angleToVec2((u16)*(s16 *)(p + 0x4), &s2, &c2);
    scale = *(f32 *)(p + 0x8);
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
    m[12] = *(f32 *)(p + 0xc);
    m[13] = *(f32 *)(p + 0x10);
    m[14] = *(f32 *)(p + 0x14);
    m[15] = lbl_803DE7C4;
}
#pragma pop

extern void PSVECCrossProduct(f32 *a, f32 *b, f32 *out);

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void fn_800213D0(f32 *a, f32 *b, s16 *out0, s16 *out1, s16 *out2)
{
    extern f32 __kernel_sin(f32);
    extern f32 __kernel_cos(f32, f32);
    extern f32 lbl_803DE7C8;
    extern f32 lbl_803DE7CC;
    extern f32 lbl_803DE7D4;
    f32 cross[3];
    f32 sinp;
    f32 c0;
    f32 c1;
    f32 c2;
    f32 b0;
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
    if (sinp < lbl_803DE7C8) {
        if (sinp > lbl_803DE7CC) {
            roll = __kernel_cos(c2, a2);
            yaw = __kernel_cos(b0, b1);
        } else {
            roll = lbl_803DE7C0 - __kernel_cos(c1, c0);
            yaw = lbl_803DE7C0;
        }
    } else {
        roll = __kernel_cos(c1, c0) - lbl_803DE7C0;
        yaw = lbl_803DE7C0;
    }
    {
        f32 s = lbl_803DE7D0;
        f32 d = lbl_803DE7D4;
        *out0 = s * yaw / d;
        *out1 = s * sinp / d;
        *out2 = s * roll / d;
    }
}
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma pop

#pragma push
#pragma scheduling off
#pragma opt_strength_reduction off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma fp_contract off
int RandomTimer_UpdateRangeTrigger(f32 lo, f32 hi, void *timerp) {
    extern f32 oneOverTimeDelta;
    extern f32 lbl_803DE7F4;
    f32 *timer = (f32 *)timerp;
    int trig;
    int range;
    int val;
    u32 rv;
    f32 freq;
    f32 t;

    *timer += timeDelta / (freq = lbl_803DE7F4);
    if (*timer > lo) {
        if (*timer > hi) {
            trig = 1;
        } else {
            range = (int)(oneOverTimeDelta * (freq * (hi - lo)));
            if (range == 0) {
                val = 0;
            } else {
                rv = rand();
                {
                    f32 acc = (f32)rv;
                    acc = acc / lbl_803DE7F8;
                    acc = acc * ((lbl_803DE7C4 + (f32)range) - (t = lbl_803DE7C0));
                    acc = acc + t;
                    val = (int)acc;
                }
            }
            trig = !val;
        }
        if (trig != 0) {
            *timer = lbl_803DE7C0;
        }
        return trig;
    }
    return 0;
}
#pragma pop

#pragma push
#pragma scheduling off
#pragma pop

#pragma push
#pragma scheduling off
void vecRotateZXY(u8 *p, f32 *v) {
    f32 s2;
    f32 c2;
    f32 s1;
    f32 c1;
    f32 s0;
    f32 c0;
    f32 t5;
    f32 t3;
    f32 t2;

    angleToVec2(*(u16 *)(p + 0x0), &s0, &c0);
    angleToVec2(*(u16 *)(p + 0x2), &s1, &c1);
    angleToVec2(*(u16 *)(p + 0x4), &s2, &c2);
    t5 = v[0] * c2 - v[1] * s2;
    t3 = v[1] * c2 + v[0] * s2;
    v[1] = t3 * c1 - v[2] * s1;
    t2 = v[2] * c1 + t3 * s1;
    v[0] = t5 * c0 + t2 * s0;
    v[2] = t2 * c0 - t5 * s0;
}
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma optimization_level 1
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off

#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma dont_inline off

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop
