#include "ghidra_import.h"
#include "main/dll/MMP/MMP_gyservent.h"

#pragma peephole off
#pragma scheduling off

extern void mtxRotateByVec3s(void *out, void *vec);
extern void mtx44Transpose(void *m, void *out);
extern void Matrix_TransformPoint(void *mtx, float x, float y, float z, float *ox, float *oy, float *oz);
extern void fn_80021EE8(void *out, void *vec);
extern void OSReport(const char *fmt, ...);
extern void fn_801993B0(double dist, double d2, double d3, double d4, double d5, double d6, double d7, double d8,
                        void *param_1, int param_2, int cat, int distInt, int p5, int p6, int p7, int p8);

extern char lbl_8032253C[];
extern f64 DOUBLE_803E40D0;
extern f64 DOUBLE_803E40F0;
extern f32 lbl_803E40D8;
extern f32 lbl_803E40DC;
extern f32 lbl_803E40E0;
extern f32 lbl_803E40E4;
extern f32 lbl_803E40E8;

/*
 * --INFO--
 *
 * Function: fn_80198FA4
 * EN v1.0 Address: 0x80198FA4
 * EN v1.0 Size: 484b
 */
void fn_80198FA4(s16 *param_1, void *param_2)
{
    void *state;
    s16 vec[3];
    f32 mtx[15];
    f32 transposed[16];
    f32 out_x;
    f32 out_y;
    f32 out_z;
    f32 tmp[20];

    state = *(void **)((char *)param_1 + 0xb8);
    param_1[0] = (s16)((*(u8 *)((char *)param_2 + 0x3d) & 0x3f) << 10);
    param_1[1] = (s16)(*(u8 *)((char *)param_2 + 0x3e) << 8);
    *(f32 *)(param_1 + 4) =
        *(f32 *)(*(int *)((char *)param_1 + 0x50) + 4) *
        ((float)(s32)*(u8 *)((char *)param_2 + 0x3a)) * lbl_803E40DC;

    vec[0] = param_1[0];
    vec[1] = param_1[1];
    vec[2] = param_1[2];
    tmp[0] = lbl_803E40E0;
    tmp[1] = lbl_803E40D8;
    tmp[2] = lbl_803E40D8;
    tmp[3] = lbl_803E40D8;
    fn_80021EE8(&tmp[4], vec);
    Matrix_TransformPoint(&tmp[4], lbl_803E40D8, lbl_803E40D8, lbl_803E40E0, &out_z, &out_y, &out_x);
    *(f32 *)((char *)state + 0xc) = out_y;
    *(f32 *)((char *)state + 0x10) = out_z;
    *(f32 *)((char *)state + 0x14) = out_x;
    *(f32 *)((char *)state + 0x18) =
        -(*(f32 *)((char *)param_1 + 0x20) * out_x +
          *(f32 *)((char *)param_1 + 0x18) * out_y +
          *(f32 *)((char *)param_1 + 0x1c) * out_z);

    vec[0] = (s16)(-param_1[0]);
    vec[1] = (s16)(-param_1[1]);
    vec[2] = 0;
    tmp[0] = lbl_803E40E0;
    tmp[1] = -*(f32 *)((char *)param_1 + 0x18);
    tmp[2] = -*(f32 *)((char *)param_1 + 0x1c);
    tmp[3] = -*(f32 *)((char *)param_1 + 0x20);
    mtxRotateByVec3s(mtx, vec);
    mtx44Transpose(mtx, (char *)state + 0x38);

    *(f32 *)((char *)state + 0x34) = lbl_803E40E4 * *(f32 *)(param_1 + 4);
    *(f32 *)((char *)state + 0x4) = lbl_803E40E8 * *(f32 *)(param_1 + 4) * lbl_803E40E8 * *(f32 *)(param_1 + 4);
    if (*(int *)((char *)param_2 + 0x14) == 0x46a31) {
        OSReport(lbl_8032253C);
    }
}

/*
 * --INFO--
 *
 * Function: fn_80199188
 * EN v1.0 Address: 0x80199188
 * EN v1.0 Size: 356b
 */
void fn_80199188(void *param_1, int param_2, int p3, int p4, int p5, int p6, int p7, int p8)
{
    void *state;
    void *cfg;
    f32 dx0, dy0, dz0;
    f32 dx1, dy1, dz1;
    f32 d0, d1;
    f32 r;
    f32 thresh;
    s8 cat;
    f32 absVal;
    s32 distInt;

    state = *(void **)((char *)param_1 + 0xb8);
    cfg = *(void **)((char *)param_1 + 0x4c);
    thresh = (float)(s32)((s8)*(u8 *)((char *)cfg + 0x3b) * 2);

    dx0 = *(f32 *)((char *)state + 0x1c) - *(f32 *)((char *)param_1 + 0x18);
    dy0 = *(f32 *)((char *)state + 0x20) - *(f32 *)((char *)param_1 + 0x1c);
    dz0 = *(f32 *)((char *)state + 0x24) - *(f32 *)((char *)param_1 + 0x20);
    d0 = dx0 * dx0 + dz0 * dz0;

    dx1 = *(f32 *)((char *)state + 0x28) - *(f32 *)((char *)param_1 + 0x18);
    dy1 = *(f32 *)((char *)state + 0x2c) - *(f32 *)((char *)param_1 + 0x1c);
    dz1 = *(f32 *)((char *)state + 0x30) - *(f32 *)((char *)param_1 + 0x20);
    d1 = dx1 * dx1 + dz1 * dz1;

    r = *(f32 *)((char *)state + 0x4);
    distInt = (s32)d1;

    if (d1 < r) {
        absVal = (dy1 < lbl_803E40D8) ? -dy1 : dy1;
        if (absVal < thresh) {
            int found = 0;
            if (d0 < r) {
                absVal = (dy0 < lbl_803E40D8) ? -dy0 : dy0;
                if (absVal < thresh) found = 1;
            }
            cat = (s8)(found ? 2 : 1);
            goto end;
        }
    }
    {
        int found = 0;
        if (d0 < r) {
            absVal = (dy0 < lbl_803E40D8) ? -dy0 : dy0;
            if (absVal < thresh) found = 1;
        }
        cat = (s8)(found ? -1 : -2);
    }
end:
    fn_801993B0((double)r, (double)d1, 0.0, (double)d0, (double)dy1, (double)dy0, (double)thresh, 0.0,
                param_1, param_2, (int)cat, distInt, p5, p6, p7, p8);
}

/*
 * --INFO--
 *
 * Function: fn_801992EC
 * EN v1.0 Address: 0x801992EC
 * EN v1.0 Size: 196b
 */
void fn_801992EC(void *param_1, int param_2, int p3, int p4, int p5, int p6, int p7, int p8)
{
    void *state;
    f32 dx0, dy0, dz0, d0;
    f32 dx1, dy1, dz1, d1;
    f32 r;
    s8 cat;

    state = *(void **)((char *)param_1 + 0xb8);

    dx0 = *(f32 *)((char *)state + 0x1c) - *(f32 *)((char *)param_1 + 0x18);
    dy0 = *(f32 *)((char *)state + 0x20) - *(f32 *)((char *)param_1 + 0x1c);
    dz0 = *(f32 *)((char *)state + 0x24) - *(f32 *)((char *)param_1 + 0x20);
    d0 = dx0 * dx0 + dy0 * dy0 + dz0 * dz0;

    dx1 = *(f32 *)((char *)state + 0x28) - *(f32 *)((char *)param_1 + 0x18);
    dy1 = *(f32 *)((char *)state + 0x2c) - *(f32 *)((char *)param_1 + 0x1c);
    dz1 = *(f32 *)((char *)state + 0x30) - *(f32 *)((char *)param_1 + 0x20);
    d1 = dx1 * dx1 + dy1 * dy1 + dz1 * dz1;

    r = *(f32 *)((char *)state + 0x4);
    if (d1 < r) {
        cat = (d0 < r) ? 2 : 1;
    } else {
        cat = (d0 < r) ? -1 : -2;
    }
    fn_801993B0((double)r, (double)d1, 0.0, (double)d0, 0.0, 0.0, 0.0, 0.0,
                param_1, param_2, (int)cat, (int)d1, p5, p6, p7, p8);
}

#pragma scheduling reset
#pragma peephole reset
