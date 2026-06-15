#include "main/game_object.h"

typedef struct MmpGyserventState
{
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

extern void mtxRotateByVec3s(void* out, void* vec);
extern void mtx44Transpose(void* m, void* out);
extern void Matrix_TransformPoint(void* mtx, float x, float y, float z, float* ox, float* oy, float* oz);
extern void setMatrixFromObjectPos(void* out, void* vec);
extern void OSReport(const char* fmt, ...);
extern void objInterpretSeq(void* obj, int param_2, int triggerState, int distanceSquared);

extern char lbl_8032253C[];
extern f32 lbl_803E40D8;
extern f32 lbl_803E40DC;
extern f32 lbl_803E40E0;
extern f32 lbl_803E40E4;
extern f32 lbl_803E40E8;

void objFn_80198fa4(s16* obj, void* arg2)
{
    void* state;
    s16 vec[3];
    f32 mtx[15];
    f32 transposed[16];
    f32 out_x;
    f32 out_y;
    f32 out_z;
    f32 tmp[20];

    state = ((GameObject*)obj)->extra;
    obj[0] = (s16)((*(u8*)((char*)arg2 + 0x3d) & 0x3f) << 10);
    obj[1] = (s16)(*(u8*)((char*)arg2 + 0x3e) << 8);
    *(f32*)(obj + 4) =
        ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase *
        ((float)(u32) * (u8*)((char*)arg2 + 0x3a)) * lbl_803E40DC;

    vec[0] = obj[0];
    vec[1] = obj[1];
    vec[2] = obj[2];
    tmp[0] = lbl_803E40E0;
    tmp[1] = lbl_803E40D8;
    tmp[2] = lbl_803E40D8;
    tmp[3] = lbl_803E40D8;
    setMatrixFromObjectPos(&tmp[4], vec);
    Matrix_TransformPoint(&tmp[4], lbl_803E40D8, *(f32*)&lbl_803E40D8, lbl_803E40E0, &out_z, &out_y, &out_x);
    ((MmpGyserventState*)state)->unkC = out_y;
    ((MmpGyserventState*)state)->unk10 = out_z;
    ((MmpGyserventState*)state)->unk14 = out_x;
    ((MmpGyserventState*)state)->unk18 =
        -(((GameObject*)obj)->anim.worldPosZ * out_x +
            ((GameObject*)obj)->anim.worldPosX * out_y +
            ((GameObject*)obj)->anim.worldPosY * out_z);

    vec[0] = (s16)(-obj[0]);
    vec[1] = (s16)(-obj[1]);
    vec[2] = 0;
    tmp[0] = lbl_803E40E0;
    tmp[1] = -((GameObject*)obj)->anim.worldPosX;
    tmp[2] = -((GameObject*)obj)->anim.worldPosY;
    tmp[3] = -((GameObject*)obj)->anim.worldPosZ;
    mtxRotateByVec3s(mtx, vec);
    mtx44Transpose(mtx, (char*)state + 0x38);

    ((MmpGyserventState*)state)->unk34 = lbl_803E40E4 * *(f32*)(obj + 4);
    ((MmpGyserventState*)state)->unk4 = lbl_803E40E8 * *(f32*)(obj + 4) * lbl_803E40E8 * *(f32*)(obj + 4);
    if (*(int*)((char*)arg2 + 0x14) == 0x46a31)
    {
        OSReport(lbl_8032253C);
    }
}

void objSeqMoveFn_80199188(void* obj, int arg2)
{
    f32 speed;
    f32 dx;
    f32 dz;
    f32 dy;
    f32 dy2;
    f32 dz2;
    bool nearEnd;
    char leg;
    int state;

    state = *(int*)&((GameObject*)obj)->extra;
    speed = (float)(s32)(*(u8*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x3b) * 2);
    dx = *(f32*)(state + 0x1c) - ((GameObject*)obj)->anim.worldPosX;
    dy = *(f32*)(state + 0x20) - ((GameObject*)obj)->anim.worldPosY;
    dz = *(f32*)(state + 0x24) - ((GameObject*)obj)->anim.worldPosZ;
    dz = dx * dx + dz * dz;
    dx = *(f32*)(state + 0x28) - ((GameObject*)obj)->anim.worldPosX;
    dy2 = *(f32*)(state + 0x2c) - ((GameObject*)obj)->anim.worldPosY;
    dz2 = *(f32*)(state + 0x30) - ((GameObject*)obj)->anim.worldPosZ;
    dz2 = dx * dx + dz2 * dz2;
    dx = *(f32*)(state + 4);
    if (dz2 < dx)
    {
        if (dy2 < lbl_803E40D8)
        {
            dy2 = -dy2;
        }
        if (dy2 < speed)
        {
            nearEnd = false;
            if (dz < dx)
            {
                if (dy < lbl_803E40D8)
                {
                    dy = -dy;
                }
                if (dy < speed)
                {
                    nearEnd = true;
                }
            }
            if (nearEnd)
            {
                leg = '\x02';
            }
            else
            {
                leg = '\x01';
            }
            goto end;
        }
    }
    nearEnd = false;
    if (dz < dx)
    {
        if (dy < lbl_803E40D8)
        {
            dy = -dy;
        }
        if (dy < speed)
        {
            nearEnd = true;
        }
    }
    if (nearEnd)
    {
        leg = -1;
    }
    else
    {
        leg = -2;
    }
end:
    objInterpretSeq(obj, arg2, (int)leg, (int)dz2);
}

void objSeqFn_801992ec(void* obj, int arg2)
{
    void* state;
    f32 dx0, dy0, dz0, d0;
    f32 dx1, dy1, dz1, d1;
    f32 r;
    s8 cat;

    state = ((GameObject*)obj)->extra;

    dx0 = ((MmpGyserventState*)state)->unk1C - ((GameObject*)obj)->anim.worldPosX;
    dy0 = ((MmpGyserventState*)state)->unk20 - ((GameObject*)obj)->anim.worldPosY;
    dz0 = ((MmpGyserventState*)state)->unk24 - ((GameObject*)obj)->anim.worldPosZ;
    d0 = dx0 * dx0 + dy0 * dy0 + dz0 * dz0;

    dx1 = ((MmpGyserventState*)state)->unk28 - ((GameObject*)obj)->anim.worldPosX;
    dy1 = ((MmpGyserventState*)state)->unk2C - ((GameObject*)obj)->anim.worldPosY;
    dz1 = ((MmpGyserventState*)state)->unk30 - ((GameObject*)obj)->anim.worldPosZ;
    d1 = dx1 * dx1 + dy1 * dy1 + dz1 * dz1;

    if (d1 < ((MmpGyserventState*)state)->unk4)
    {
        cat = (d0 < ((MmpGyserventState*)state)->unk4) ? 2 : 1;
    }
    else
    {
        cat = (d0 < ((MmpGyserventState*)state)->unk4) ? -1 : -2;
    }
    objInterpretSeq(obj, arg2, (int)cat, (int)d1);
}
