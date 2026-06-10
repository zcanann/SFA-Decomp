#include "main/dll/MMP/MMP_gyservent.h"
#include "main/game_object.h"

typedef struct MmpGyserventState {
    u8 pad0[0x4 - 0x0];
    f32 unk4;
    u8 pad8[0xC - 0x8];
    f32 unkC;
    f32 unk10;
    f32 unk14;
    f32 unk18;
    f32 unk1C;
    f32 unk20;
    f32 unk24;
    f32 unk28;
    f32 unk2C;
    f32 unk30;
    f32 unk34;
} MmpGyserventState;



extern void mtxRotateByVec3s(void *out, void *vec);
extern void mtx44Transpose(void *m, void *out);
extern void Matrix_TransformPoint(void *mtx, float x, float y, float z, float *ox, float *oy, float *oz);
extern void setMatrixFromObjectPos(void *out, void *vec);
extern void OSReport(const char *fmt, ...);
extern void objInterpretSeq(void *obj, int param_2, int triggerState, int distanceSquared);

extern char lbl_8032253C[];
extern f64 lbl_803E40D0;
extern f64 DOUBLE_803E40F0;
extern f32 lbl_803E40D8;
extern f32 lbl_803E40DC;
extern f32 lbl_803E40E0;
extern f32 lbl_803E40E4;
extern f32 lbl_803E40E8;

/*
 * --INFO--
 *
 * Function: objFn_80198fa4
 * EN v1.0 Address: 0x80198FA4
 * EN v1.0 Size: 484b
 */
void objFn_80198fa4(s16 *param_1, void *param_2)
{
    void *state;
    s16 vec[3];
    f32 mtx[15];
    f32 transposed[16];
    f32 out_x;
    f32 out_y;
    f32 out_z;
    f32 tmp[20];

    state = ((GameObject *)param_1)->extra;
    param_1[0] = (s16)((*(u8 *)((char *)param_2 + 0x3d) & 0x3f) << 10);
    param_1[1] = (s16)(*(u8 *)((char *)param_2 + 0x3e) << 8);
    *(f32 *)(param_1 + 4) =
        *(f32 *)(*(int *)&((GameObject *)param_1)->anim.modelInstance + 4) *
        ((float)(u32)*(u8 *)((char *)param_2 + 0x3a)) * lbl_803E40DC;

    vec[0] = param_1[0];
    vec[1] = param_1[1];
    vec[2] = param_1[2];
    tmp[0] = lbl_803E40E0;
    tmp[1] = lbl_803E40D8;
    tmp[2] = lbl_803E40D8;
    tmp[3] = lbl_803E40D8;
    setMatrixFromObjectPos(&tmp[4], vec);
    Matrix_TransformPoint(&tmp[4], lbl_803E40D8, *(f32 *)&lbl_803E40D8, lbl_803E40E0, &out_z, &out_y, &out_x);
    ((MmpGyserventState *)state)->unkC = out_y;
    ((MmpGyserventState *)state)->unk10 = out_z;
    ((MmpGyserventState *)state)->unk14 = out_x;
    ((MmpGyserventState *)state)->unk18 =
        -(((GameObject *)param_1)->anim.worldPosZ * out_x +
          ((GameObject *)param_1)->anim.worldPosX * out_y +
          ((GameObject *)param_1)->anim.worldPosY * out_z);

    vec[0] = (s16)(-param_1[0]);
    vec[1] = (s16)(-param_1[1]);
    vec[2] = 0;
    tmp[0] = lbl_803E40E0;
    tmp[1] = -((GameObject *)param_1)->anim.worldPosX;
    tmp[2] = -((GameObject *)param_1)->anim.worldPosY;
    tmp[3] = -((GameObject *)param_1)->anim.worldPosZ;
    mtxRotateByVec3s(mtx, vec);
    mtx44Transpose(mtx, (char *)state + 0x38);

    ((MmpGyserventState *)state)->unk34 = lbl_803E40E4 * *(f32 *)(param_1 + 4);
    ((MmpGyserventState *)state)->unk4 = lbl_803E40E8 * *(f32 *)(param_1 + 4) * lbl_803E40E8 * *(f32 *)(param_1 + 4);
    if (*(int *)((char *)param_2 + 0x14) == 0x46a31) {
        OSReport(lbl_8032253C);
    }
}

/*
 * --INFO--
 *
 * Function: objSeqMoveFn_80199188
 * EN v1.0 Address: 0x80199188
 * EN v1.0 Size: 356b
 */
void objSeqMoveFn_80199188(void *param_1, int param_2)
{
    f32 fVar1;
    f32 fVar2;
    f32 fVar3;
    f32 fVar4;
    f32 fVar5;
    f32 fVar6;
    bool bVar7;
    char cVar8;
    int iVar9;

    iVar9 = *(int *)&((GameObject *)param_1)->extra;
    fVar1 = (float)(s32)(*(u8 *)(*(int *)&((GameObject *)param_1)->anim.placementData + 0x3b) * 2);
    fVar2 = *(f32 *)(iVar9 + 0x1c) - ((GameObject *)param_1)->anim.worldPosX;
    fVar4 = *(f32 *)(iVar9 + 0x20) - ((GameObject *)param_1)->anim.worldPosY;
    fVar3 = *(f32 *)(iVar9 + 0x24) - ((GameObject *)param_1)->anim.worldPosZ;
    fVar3 = fVar2 * fVar2 + fVar3 * fVar3;
    fVar2 = *(f32 *)(iVar9 + 0x28) - ((GameObject *)param_1)->anim.worldPosX;
    fVar5 = *(f32 *)(iVar9 + 0x2c) - ((GameObject *)param_1)->anim.worldPosY;
    fVar6 = *(f32 *)(iVar9 + 0x30) - ((GameObject *)param_1)->anim.worldPosZ;
    fVar6 = fVar2 * fVar2 + fVar6 * fVar6;
    fVar2 = *(f32 *)(iVar9 + 4);
    if (fVar6 < fVar2) {
        if (fVar5 < lbl_803E40D8) {
            fVar5 = -fVar5;
        }
        if (fVar5 < fVar1) {
            bVar7 = false;
            if (fVar3 < fVar2) {
                if (fVar4 < lbl_803E40D8) {
                    fVar4 = -fVar4;
                }
                if (fVar4 < fVar1) {
                    bVar7 = true;
                }
            }
            if (bVar7) {
                cVar8 = '\x02';
            }
            else {
                cVar8 = '\x01';
            }
            goto end;
        }
    }
    bVar7 = false;
    if (fVar3 < fVar2) {
        if (fVar4 < lbl_803E40D8) {
            fVar4 = -fVar4;
        }
        if (fVar4 < fVar1) {
            bVar7 = true;
        }
    }
    if (bVar7) {
        cVar8 = -1;
    }
    else {
        cVar8 = -2;
    }
end:
    objInterpretSeq(param_1, param_2, (int)cVar8, (int)fVar6);
}

/*
 * --INFO--
 *
 * Function: objSeqFn_801992ec
 * EN v1.0 Address: 0x801992EC
 * EN v1.0 Size: 196b
 */
void objSeqFn_801992ec(void *param_1, int param_2)
{
    void *state;
    f32 dx0, dy0, dz0, d0;
    f32 dx1, dy1, dz1, d1;
    f32 r;
    s8 cat;

    state = ((GameObject *)param_1)->extra;

    dx0 = ((MmpGyserventState *)state)->unk1C - ((GameObject *)param_1)->anim.worldPosX;
    dy0 = ((MmpGyserventState *)state)->unk20 - ((GameObject *)param_1)->anim.worldPosY;
    dz0 = ((MmpGyserventState *)state)->unk24 - ((GameObject *)param_1)->anim.worldPosZ;
    d0 = dx0 * dx0 + dy0 * dy0 + dz0 * dz0;

    dx1 = ((MmpGyserventState *)state)->unk28 - ((GameObject *)param_1)->anim.worldPosX;
    dy1 = ((MmpGyserventState *)state)->unk2C - ((GameObject *)param_1)->anim.worldPosY;
    dz1 = ((MmpGyserventState *)state)->unk30 - ((GameObject *)param_1)->anim.worldPosZ;
    d1 = dx1 * dx1 + dy1 * dy1 + dz1 * dz1;

    r = ((MmpGyserventState *)state)->unk4;
    if (d1 < r) {
        cat = (d0 < r) ? 2 : 1;
    } else {
        cat = (d0 < r) ? -1 : -2;
    }
    objInterpretSeq(param_1, param_2, (int)cat, (int)d1);
}

