#include "main/game_object.h"
#include "main/audio/sfx.h"
#include "main/objprint.h"
#include "main/dll/modgfx.h"
#include "main/mm.h"
#include "dolphin/os/OSCache.h"
#include "dolphin/gx/GXBump.h"
#include "dolphin/gx/GXCull.h"
#include "sfa_light_decls.h"

#define GX_CULL_NONE 0
#define GX_CULL_FRONT 1
#define GX_CULL_BACK 2

#define OBJPRINT_OBJECT(obj) ((ObjAnimComponent *)(obj))
#define OBJPRINT_MODEL_INSTANCE(obj) (OBJPRINT_OBJECT(obj)->modelInstance)
#define OBJPRINT_BANK_TABLE(obj) ((int **)OBJPRINT_OBJECT(obj)->banks)
#define OBJPRINT_ACTIVE_BANK_INDEX(obj) (OBJPRINT_OBJECT(obj)->bankIndex)
#define OBJPRINT_ACTIVE_BANK(obj) ((int *)OBJPRINT_BANK_TABLE(obj)[OBJPRINT_ACTIVE_BANK_INDEX(obj)])
#define OBJPRINT_MODEL_COUNT(model) (((ObjDef *)(model))->modelCount)
#define OBJPRINT_JOINT_COUNT(model) (((ObjDef *)(model))->jointCount)

typedef struct
{
    s16 v[9];
} ObjJointPose18;

static inline s16* objFindJointVecByKey(int obj, int key)
{
    int i;
    int k;
    ObjDef* table;
    s16* found;

    found = NULL;
    table = ((GameObject*)obj)->anim.modelInstance;
    if (table != NULL)
    {
        i = 0;
        for (k = 0; k < (s32)(u32)table->jointCount; k++)
        {
            if ((int)*(u8*)(*(int*)&table->jointData + OBJPRINT_ACTIVE_BANK_INDEX(obj) + i + 1) != 0xff &&
                (int)*(u8*)(*(int*)&table->jointData + i) == key)
            {
                found = (s16*)&((ObjJointPose18*)((GameObject*)obj)->anim.jointPoseData)[k];
            }
            i = i + table->modelCount + 1;
        }
    }
    return found;
}

extern bool FUN_800067f0();
extern u32 FUN_8000681c();
extern double FUN_80006a30();
extern int FUN_80017730();
extern u32 FUN_80017798();
extern int FUN_8001779c();
extern int FUN_80017970();
extern u32 FUN_80017a00();
extern u32 FUN_80017a04();
extern u32 objRenderFuzzFn_8003d6f8();
extern u32 FUN_800400b0();
extern u32 FUN_80040a88();
extern void gxSetPeControl_ZCompLoc_(u32 zCompLoc);
extern void gxSetZMode_(u32 compareEnable, int compareFunc, u32 updateEnable);
extern void GXSetBlendMode(GXBlendMode type, GXBlendFactor src_factor, GXBlendFactor dst_factor, GXLogicOp op);
extern u64 FUN_8028683c();
extern u32 FUN_80286888();
extern u32 FUN_80293900();
extern u32 FUN_802950c8();
extern u32 DAT_802cba60;
extern u32 DAT_803dc070;
extern u32 DAT_803dd888;
extern u32 DAT_803dd889;
extern u32 DAT_803dd88a;
extern u32 DAT_803dd88b;
extern u32 DAT_803dd88c;
extern u32 DAT_803dd88d;
extern u32 DAT_803dd890;
extern u32 DAT_803dd894;
extern u32 DAT_803dd896;
extern u32 DAT_803dd898;
extern u32 DAT_803dd8c8;
extern f32 lbl_803DC074;
extern f32 lbl_803DF61C;
extern f32 lbl_803DF624;
extern f32 lbl_803DF658;
extern f32 lbl_803DF65C;
extern f32 lbl_803DF660;
extern f32 lbl_803DF664;
extern f32 lbl_803DF668;
extern f32 lbl_803DF66C;

void objAnimFn_80038f38(int obj, char* state)
{
    extern void ObjModel_SetBlendChannelTargets(int model, int a, int b, int c, f32 ratio, int d);
    extern f32 lbl_803DE9A4;
    extern f32 lbl_803DE9C8;
    extern f32 lbl_803DE99C;
    extern f32 lbl_803DB464;
    extern u8 framesThisStep;
    s16* found;
    int t;

    t = (s32) * (f32*)(state + 0xc);
    found = objFindJointVecByKey(obj, 1);

    if (*(s8*)state != 0)
    {
        *(s8*)state = 0;
    }
    else if (Sfx_IsPlayingFromObjectChannel((u32)obj, 0x10) != 0)
    {
        if (t != -1)
        {
            t -= framesThisStep;
            if (t < 0)
            {
                Sfx_StopObjectChannel((u32)obj, 0x10);
                *(f32*)(state + 4) = lbl_803DE9A4;
                *(s16*)(state + 0x14) = 0;
            }
            *(f32*)(state + 0xc) = t;
        }
    }
    else
    {
        *(f32*)(state + 0xc) = lbl_803DE9C8;
        *(s16*)(state + 0x14) = 0;
        if (*(f32*)(state + 4) > lbl_803DE9A4)
        {
            int* pi;
            *(f32*)(state + 4) = *(f32*)&lbl_803DE9A4;
            pi = OBJPRINT_ACTIVE_BANK(obj);
            if (*(u8*)(*pi + 0xf9) != 0)
            {
                ObjModel_SetBlendChannelTargets((int)pi, 2,
                                                *(s8*)(*(int*)((char*)pi + 0x28) + 0x2d), -1,
                                                lbl_803DE99C / lbl_803DB464, 0);
            }
        }
    }

    if (found != NULL)
    {
        found[0] = (s16)((found[0] + *(s16*)(state + 0x14)) >> 1);
    }
}

void FUN_80039468(u32 param_1, u32 param_2, u16 sfxId, short pitch, u32 frame,
                  u32 force)
{
    u32 obj;
    bool playing;
    u8* state;
    u64 ctx;

    ctx = FUN_80286840();
    obj = (u32)((u64)ctx >> 0x20);
    state = (u8*)ctx;
    if (((force & 0xff) != 0) || (playing = FUN_800067f0(obj, 0x10), !playing))
    {
        FUN_8000681c(obj, 0x10, sfxId);
        *(float*)(state + 0xc) =
            (f32)(s32)(frame);
        *(short*)(state + 0x14) = -pitch;
        *state = 1;
        *(float*)(state + 4) = lbl_803DF61C;
    }
    FUN_8028688c();
    return;
}

u32* FUN_80039518(void)
{
    return &DAT_802cba60;
}

int FUN_80039520(int obj, u32 tag)
{
    u32 remaining;
    int hitDef;
    u8* entry;
    int offset;
    int found;

    found = 0;
    hitDef = (int)((GameObject*)obj)->anim.modelInstance;
    if (hitDef != 0)
    {
        entry = *(u8**)(hitDef + 0xc);
        if (entry == (u8*)0x0)
        {
            return 0;
        }
        offset = 0;
        for (remaining = (u32) * (u8*)(hitDef + 0x59); remaining != 0; remaining = remaining - 1)
        {
            if (tag == *entry)
            {
                found = *(int*)&((GameObject*)obj)->anim.textureSlots + offset;
            }
            entry = entry + 2;
            offset = offset + 0x10;
        }
    }
    return found;
}

int FUN_8003964c(int obj, u32 key)
{
    u32 remaining;
    int vecOffset;
    int entryIdx;
    int model;
    int found;

    found = 0;
    model = (int)OBJPRINT_MODEL_INSTANCE(obj);
    if (model != 0)
    {
        entryIdx = 0;
        vecOffset = 0;
        for (remaining = OBJPRINT_JOINT_COUNT(model); remaining != 0; remaining = remaining - 1)
        {
            if ((*(char*)(*(int*)(model + 0x10) + OBJPRINT_ACTIVE_BANK_INDEX(obj) + entryIdx + 1) != -1) &&
                (key == *(u8*)(*(int*)(model + 0x10) + entryIdx)))
            {
                found = *(int*)&((GameObject*)obj)->anim.jointPoseData + vecOffset;
            }
            entryIdx = OBJPRINT_MODEL_COUNT(model) + entryIdx + 1;
            vecOffset = vecOffset + 0x12;
        }
    }
    return found;
}

u32 FUN_8003988c(double a, double b, int curve, short* outAngle)
{
    u32 done;
    double clamped;
    double ratio;
    float coeff0;
    float coeff1;
    float coeff2;
    float coeff3;
    u32 local_38;
    u32 uStack_34;
    u32 local_30;
    u32 uStack_2c;
    u64 local_28;
    u32 local_20;
    u32 uStack_1c;

    coeff0 = (float)a;
    coeff1 = (float)a;
    coeff2 = (float)b;
    coeff3 = (float)-b;
    if ((int)*(short*)(curve + 0x14) == (int)*(short*)(curve + 0x16))
    {
        done = 1;
    }
    else
    {
        uStack_34 = (int)*outAngle ^ 0x80000000;
        local_38 = 0x43300000;
        uStack_2c = (int)*(short*)(curve + 0x16) ^ 0x80000000;
        local_30 = 0x43300000;
        local_20 = 0x43300000;
        ratio = (double)
        (((f32)(s32)
        uStack_34 -
            (f32)(s32)
        uStack_2c
        )
        /
        ((f32)(s32)((int)*(short*)(curve + 0x14)) -
            (f32)(s32)
        uStack_2c
        )
        )
        ;
        clamped = (double)lbl_803DF61C;
        if ((ratio <= clamped) && (clamped = ratio, ratio < (double)lbl_803DF624))
        {
            clamped = (double)lbl_803DF624;
        }
        uStack_1c = uStack_2c;
        ratio = FUN_80006a30(clamped, &coeff0, (float*)0x0);
        if (*(short*)(curve + 0x14) < *(short*)(curve + 0x16))
        {
            ratio = -ratio;
        }
        *outAngle = (short)(int)(ratio * (double)lbl_803DC074 +
            (double)(float)((double)(int)*outAngle));
        if ((((double)lbl_803DF61C == clamped) || (0x1ffe < *outAngle)) || (*outAngle < -0x1ffe))
        {
            *outAngle = *(short*)(curve + 0x14);
            done = 1;
        }
        else
        {
            done = 0;
        }
    }
    return done;
}

u32 FUN_80039a28(int curve, int state)
{
    u32 done;
    double clamped;
    double ratio;
    float coeff0;
    float coeff1;
    float coeff2;
    float coeff3;
    u32 local_38;
    u32 uStack_34;
    u32 local_30;
    u32 uStack_2c;
    u64 local_28;
    u32 local_20;
    u32 uStack_1c;

    coeff0 = lbl_803DF658;
    coeff1 = lbl_803DF658;
    coeff2 = lbl_803DF65C;
    coeff3 = lbl_803DF660;
    if ((int)*(short*)(curve + 0x14) == (int)*(short*)(curve + 0x16))
    {
        done = 1;
    }
    else
    {
        uStack_34 = (int)*(short*)(state + 2) ^ 0x80000000;
        local_38 = 0x43300000;
        uStack_2c = (int)*(short*)(curve + 0x16) ^ 0x80000000;
        local_30 = 0x43300000;
        local_20 = 0x43300000;
        ratio = (double)
        (((f32)(s32)
        uStack_34 -
            (f32)(s32)
        uStack_2c
        )
        /
        ((f32)(s32)((int)*(short*)(curve + 0x14)) -
            (f32)(s32)
        uStack_2c
        )
        )
        ;
        clamped = (double)lbl_803DF61C;
        if ((ratio <= clamped) && (clamped = ratio, ratio < (double)lbl_803DF624))
        {
            clamped = (double)lbl_803DF624;
        }
        uStack_1c = uStack_2c;
        ratio = FUN_80006a30(clamped, &coeff0, (float*)0x0);
        if (*(short*)(curve + 0x14) < *(short*)(curve + 0x16))
        {
            ratio = -ratio;
        }
        *(short*)(state + 2) =
            (short)(int)(ratio * (double)lbl_803DC074 +
                (double)(float)((double)(int)*(short*)(state + 2)));
        if ((((double)lbl_803DF61C == clamped) || (0x1ffe < *(short*)(state + 2))) ||
            (*(short*)(state + 2) < -0x1ffe))
        {
            *(u16*)(state + 2) = *(u16*)(curve + 0x14);
            done = 1;
        }
        else
        {
            done = 0;
        }
    }
    return done;
}

void FUN_80039e6c(double val, short* obj, char* curve, int state)
{
    float limit;
    u16 phase;
    float minVal;
    u32 tmp;
    int prevAngle;
    bool active;

    active = (double)lbl_803DF664 < val;
    if (((u32)(int) * (short*)(curve + 0x1a) >> 8 & 0xff) != active)
    {
        *(u16*)(curve + 0x1a) = (u16)active << 8;
    }
    phase = *(u16*)(curve + 0x1a) & 0xff;
    if (phase == 2)
    {
        if ((*curve != '\0') || (prevAngle = FUN_80039a28((int)curve, state), prevAngle != 0))
        {
            *(u16*)(curve + 0x1a) = (u16)active << 8;
        }
    }
    else if (phase < 2)
    {
        if (phase == 0)
        {
            if (*curve == '\0')
            {
                *(u16*)(curve + 0x1a) = (u16)active << 8 | 1;
                tmp = randomGetRange(100, 400);
                *(short*)(curve + 0x1c) = tmp;
                *(u16*)(curve + 0x14) = *(u16*)(state + 2);
            }
            else
            {
                *(u16*)(curve + 0x1a) = (u16)active << 8 | 3;
                *(u16*)(curve + 0x16) = *(u16*)(state + 2);
                *(float*)(curve + 0x10) = lbl_803DF61C;
            }
        }
        else
        {
            *(u16*)(curve + 0x1c) = *(short*)(curve + 0x1c) - (u16)DAT_803dc070;
            if (*(short*)(curve + 0x1c) < 0)
            {
                prevAngle = (int)*(short*)(curve + 0x14);
                tmp = randomGetRange(0, 0x1fff);
                *(short*)(curve + 0x14) = tmp;
                if (prevAngle < 1)
                {
                    if (*(short*)(curve + 0x14) - prevAngle < 0xe38)
                    {
                        *(short*)(curve + 0x14) = *(short*)(curve + 0x14) + 0xe38;
                    }
                    if (0x1fff < *(short*)(curve + 0x14))
                    {
                        curve[0x14] = '\x1f';
                        curve[0x15] = -1;
                    }
                }
                else
                {
                    if (prevAngle - *(short*)(curve + 0x14) < 0xe38)
                    {
                        *(short*)(curve + 0x14) = *(short*)(curve + 0x14) + 0xe38;
                    }
                    if (0x1fff < *(short*)(curve + 0x14))
                    {
                        curve[0x14] = '\x1f';
                        curve[0x15] = -1;
                    }
                    *(short*)(curve + 0x14) = -*(short*)(curve + 0x14);
                }
                *(u16*)(curve + 0x1a) = (u16)active << 8 | 2;
                curve[0x1c] = '\0';
                curve[0x1d] = '\0';
                *(u16*)(curve + 0x16) = *(u16*)(state + 2);
            }
        }
    }
    else if (phase < 4)
    {
        if (*curve == '\0')
        {
            *(u16*)(curve + 0x1a) = (u16)active << 8;
        }
        else
        {
            prevAngle = FUN_80017730();
            *(short*)(curve + 0x14) = prevAngle - *obj;
            if (0x8000 < *(short*)(curve + 0x14))
            {
                *(short*)(curve + 0x14) = *(short*)(curve + 0x14) + 1;
            }
            if (*(short*)(curve + 0x14) < -0x8000)
            {
                *(short*)(curve + 0x14) = *(short*)(curve + 0x14) + -1;
            }
            minVal = lbl_803DF624;
            tmp = (u32) * (short*)(curve + 0x14);
            if (((int)tmp < 0x2000) && (-0x2000 < tmp))
            {
                if (*(float*)(curve + 0x10) <= lbl_803DF624)
                {
                    *(short*)(state + 2) = *(short*)(curve + 0x14);
                }
                else
                {
                    *(short*)(state + 2) =
                        (short)(int)(*(float*)(curve + 0x10) *
                            (float)((double)(int)*(short*)(curve + 0x16) - tmp) +
                            (float)((double)(int)tmp
                            ));
                    limit = -(lbl_803DF668 * lbl_803DC074 - *(float*)(curve + 0x10));
                    *(float*)(curve + 0x10) = limit;
                    if (limit < minVal)
                    {
                        *(float*)(curve + 0x10) = minVal;
                    }
                }
            }
            else
            {
                *(u16*)(curve + 0x1a) = (u16)active << 8;
            }
        }
    }
    if (*(short*)(state + 2) < -0x1fff)
    {
        *(u16*)(state + 2) = 0xe001;
    }
    else if (0x1fff < *(short*)(state + 2))
    {
        *(u16*)(state + 2) = 0x1fff;
    }
    return;
}

void FUN_8003a1c4(int obj, int ctx)
{
    u32 scaled;
    short* found;
    int model;
    int entryIdx;
    int vecOffset;

    found = 0x0;
    model = (int)OBJPRINT_MODEL_INSTANCE(obj);
    if (model != 0)
    {
        entryIdx = 0;
        vecOffset = 0;
        for (scaled = OBJPRINT_JOINT_COUNT(model); scaled != 0; scaled = scaled - 1)
        {
            if ((*(char*)(*(int*)(model + 0x10) + OBJPRINT_ACTIVE_BANK_INDEX(obj) + entryIdx + 1) != -1) &&
                (*(char*)(*(int*)(model + 0x10) + entryIdx) == '\0'))
            {
                found = (short*)(*(int*)&((GameObject*)obj)->anim.jointPoseData + vecOffset);
            }
            entryIdx = OBJPRINT_MODEL_COUNT(model) + entryIdx + 1;
            vecOffset = vecOffset + 0x12;
        }
    }
    if (found != 0x0)
    {
        if (*found != 0)
        {
            scaled = *found * 3;
            *found = (short)((int)scaled >> 2) + (u16)((int)scaled < 0 && (scaled & 3) != 0);
        }
        if (found[1] != 0)
        {
            scaled = found[1] * 3;
            found[1] = (short)((int)scaled >> 2) + (u16)((int)scaled < 0 && (scaled & 3) != 0);
        }
        *(u16*)(ctx + 0x1a) = 0;
        return;
    }
    return;
}

void fn_8003A328(double amount, short* obj, char* ctx)
{
    u32 tmp;
    short* found;
    int model;
    int entryIdx;
    int vecOffset;

    found = 0x0;
    model = (int)OBJPRINT_MODEL_INSTANCE(obj);
    if (model != 0)
    {
        entryIdx = 0;
        vecOffset = 0;
        for (tmp = OBJPRINT_JOINT_COUNT(model); tmp != 0; tmp = tmp - 1)
        {
            if ((*(char*)(*(int*)(model + 0x10) + OBJPRINT_ACTIVE_BANK_INDEX(obj) + entryIdx + 1) != -1) &&
                (*(char*)(*(int*)(model + 0x10) + entryIdx) == '\0'))
            {
                found = (short*)(*(int*)(obj + 0x36) + vecOffset);
            }
            entryIdx = OBJPRINT_MODEL_COUNT(model) + entryIdx + 1;
            vecOffset = vecOffset + 0x12;
        }
    }
    if (found != 0x0)
    {
        if (*found != 0)
        {
            tmp = *found * 3;
            *found = (short)((int)tmp >> 2) + (u16)((int)tmp < 0 && (tmp & 3) != 0);
        }
        if (amount < (double)lbl_803DF624)
        {
            amount = -amount;
        }
        if ((double)lbl_803DF664 < amount)
        {
            FUN_80039bc4(amount, (u32)(u32)obj, ctx, (int)found);
        }
        else
        {
            FUN_80039e6c(amount, obj, ctx, (int)found);
        }
        *(u16*)(ctx + 0x1a) = *(u16*)(ctx + 0x1a) & 0xff;
        *(u16*)(ctx + 0x1a) =
            *(u16*)(ctx + 0x1a) | (u16)((double)lbl_803DF664 < amount) << 8;
    }
}

void FUN_8003a9c8(int base, u32 count, u16 a, u16 b)
{
    u32 blocks;

    if ((int)count < 1)
    {
        return;
    }
    blocks = count >> 3;
    if (blocks != 0)
    {
        do
        {
            *(u16*)(base + 0x14) = a;
            *(u16*)(base + 0x44) = b;
            *(u16*)(base + 0x74) = a;
            *(u16*)(base + 0xa4) = b;
            *(u16*)(base + 0xd4) = a;
            *(u16*)(base + 0x104) = b;
            *(u16*)(base + 0x134) = a;
            *(u16*)(base + 0x164) = b;
            *(u16*)(base + 0x194) = a;
            *(u16*)(base + 0x1c4) = b;
            *(u16*)(base + 500) = a;
            *(u16*)(base + 0x224) = b;
            *(u16*)(base + 0x254) = a;
            *(u16*)(base + 0x284) = b;
            *(u16*)(base + 0x2b4) = a;
            *(u16*)(base + 0x2e4) = b;
            base = base + 0x300;
            blocks = blocks - 1;
        }
        while (blocks != 0);
        count = count & 7;
        if (count == 0)
        {
            return;
        }
    }
    do
    {
        *(u16*)(base + 0x14) = a;
        *(u16*)(base + 0x44) = b;
        base = base + 0x60;
        count = count - 1;
    }
    while (count != 0);
    return;
}

void FUN_8003ac24(int obj, u32* keys, int count)
{
    u32 remaining;
    int idx;
    short* found;
    int hitDef;
    int entryIdx;
    int vecOffset;

    for (idx = 0; idx < count; idx = idx + 1)
    {
        found = 0x0;
        hitDef = *(int*)&((GameObject*)obj)->anim.modelInstance;
        if (hitDef != 0)
        {
            entryIdx = 0;
            vecOffset = 0;
            for (remaining = (u32) * (u8*)(hitDef + 0x5a); remaining != 0; remaining = remaining - 1)
            {
                if ((*(char*)(*(int*)(hitDef + 0x10) + ((GameObject*)obj)->anim.bankIndex + entryIdx + 1) != -1) &&
                    (*keys == (u32) * (u8*)(*(int*)(hitDef + 0x10) + entryIdx)))
                {
                    found = (short*)(*(int*)&((GameObject*)obj)->anim.jointPoseData + vecOffset);
                }
                entryIdx = *(char*)(hitDef + 0x55) + entryIdx + 1;
                vecOffset = vecOffset + 0x12;
            }
        }
        if (found != 0x0)
        {
            found[1] = (short)(found[1] * 3 >> 2);
            *found = (short)(*found * 3 >> 2);
            found[2] = (short)(found[2] * 3 >> 2);
        }
        keys = keys + 1;
    }
    return;
}

void FUN_8003ad08(int obj, u32* keys, int count, int out)
{
    u32 remaining;
    u16* found;
    int hitDef;
    int entryIdx;
    int vecOffset;
    int idx;

    for (idx = 0; idx < count; idx = idx + 1)
    {
        found = (u16*)0x0;
        hitDef = *(int*)&((GameObject*)obj)->anim.modelInstance;
        if (hitDef != 0)
        {
            entryIdx = 0;
            vecOffset = 0;
            for (remaining = (u32) * (u8*)(hitDef + 0x5a); remaining != 0; remaining = remaining - 1)
            {
                if ((*(char*)(*(int*)(hitDef + 0x10) + ((GameObject*)obj)->anim.bankIndex + entryIdx + 1) != -1) &&
                    (*keys == (u32) * (u8*)(*(int*)(hitDef + 0x10) + entryIdx)))
                {
                    found = (u16*)(*(int*)&((GameObject*)obj)->anim.jointPoseData + vecOffset);
                }
                entryIdx = *(char*)(hitDef + 0x55) + entryIdx + 1;
                vecOffset = vecOffset + 0x12;
            }
        }
        if (found != (u16*)0x0)
        {
            *(u16*)(out + 0x16) = found[1];
            *(u16*)(out + 0x46) = *found;
        }
        keys = keys + 1;
        out = out + 0x60;
    }
    return;
}

void FUN_8003add8(u32 param_1, u32 param_2, int state, u32 maxAngle, u32 flag,
                  u32 minRange)
{
    int scratch4;
    float dx;
    float deltaZ;
    u32 count;
    short clampHi;
    short stepVal;
    int scratch0;
    int scratch1;
    short* srcPtr;
    int scratch2;
    int scratch3;
    short* foundEntry;
    double in_f28;
    double in_f29;
    double in_f30;
    double in_f31;
    double in_ps28_1;
    double in_ps29_1;
    double in_ps30_1;
    double in_ps31_1;
    u64 packed;
    short local_88[4];
    u32 local_80;
    u32 uStack_7c;
    s64 local_78;
    u64 local_70;
    double local_68;
    float local_38;
    float fStack_34;
    float local_28;
    float fStack_24;
    float local_18;
    float fStack_14;
    float local_8;
    float fStack_4;

    local_8 = (float)in_f31;
    fStack_4 = (float)in_ps31_1;
    local_18 = (float)in_f30;
    fStack_14 = (float)in_ps30_1;
    local_28 = (float)in_f29;
    fStack_24 = (float)in_ps29_1;
    local_38 = (float)in_f28;
    fStack_34 = (float)in_ps28_1;
    packed = FUN_8028683c();
    srcPtr = (short*)((u64)packed >> 0x20);
    scratch0 = packed;
    foundEntry = 0x0;
    scratch1 = *(int*)(srcPtr + 0x28);
    if (scratch1 != 0)
    {
        scratch2 = 0;
        scratch3 = 0;
        for (count = (u32) * (u8*)(scratch1 + 0x5a); count != 0; count = count - 1)
        {
            if ((*(char*)(*(int*)(scratch1 + 0x10) + *(char*)((int)srcPtr + 0xad) + scratch2 + 1) != -1) &&
                (*(char*)(*(int*)(scratch1 + 0x10) + scratch2) == '\0'))
            {
                foundEntry = (short*)(*(int*)(srcPtr + 0x36) + scratch3);
            }
            scratch2 = *(char*)(scratch1 + 0x55) + scratch2 + 1;
            scratch3 = scratch3 + 0x12;
        }
    }
    if (foundEntry != 0x0)
    {
        if (scratch0 == 0)
        {
            foundEntry[1] = foundEntry[1] >> 1;
            *foundEntry = *foundEntry >> 1;
        }
        else
        {
            dx = *(float*)(srcPtr + 6) - *(float*)(scratch0 + 0xc);
            deltaZ = *(float*)(srcPtr + 10) - *(float*)(scratch0 + 0x14);
            FUN_80293900((double)(dx * dx + deltaZ * deltaZ));
            scratch0 = FUN_80017730();
            local_88[0] = scratch0 - *srcPtr;
            if (0x8000 < local_88[0])
            {
                local_88[0] = local_88[0] + 1;
            }
            if (local_88[0] < -0x8000)
            {
                local_88[0] = local_88[0] + -1;
            }
            if ((flag & 0xff) != 0)
            {
                local_88[0] = local_88[0] + -0x8000;
            }
            scratch0 = FUN_80017730();
            local_88[1] = scratch0 + -0x3fff;
            uStack_7c = maxAngle ^ 0x80000000;
            local_80 = 0x43300000;
            scratch0 = (int)(lbl_803DF66C *
                (f32)(s32)(maxAngle));
            local_78 = (s64)scratch0;
            clampHi = scratch0;
            srcPtr = local_88;
            dx = lbl_803DF66C * (f32)(s32)(minRange);
            scratch0 = dx;
            local_68 = (double)(s64)scratch0;
            scratch1 = -(int)(short)scratch0;
            scratch2 = -clampHi;
            scratch3 = 2;
            scratch0 = state;
            do
            {
                *srcPtr = *srcPtr - *(short*)(scratch0 + 0x14);
                stepVal = *srcPtr;
                if (stepVal < scratch1)
                {
                    stepVal = scratch1;
                }
                else
                {
                    scratch4 = dx;
                    local_68 = (double)(s64)scratch4;
                    if ((int)(short)scratch4 < stepVal)
                    {
                        local_70 = (double)(s64)scratch4;
                        stepVal = scratch4;
                    }
                }
                *srcPtr = stepVal;
                *(short*)(scratch0 + 0x14) = *(short*)(scratch0 + 0x14) + *srcPtr;
                if ((int)clampHi < (int)*(short*)(scratch0 + 0x14))
                {
                    *(short*)(scratch0 + 0x14) = clampHi;
                }
                if (*(short*)(scratch0 + 0x14) < scratch2)
                {
                    *(short*)(scratch0 + 0x14) = scratch2;
                }
                scratch0 = scratch0 + 0x30;
                srcPtr = srcPtr + 1;
                scratch3 = scratch3 + -1;
            }
            while (scratch3 != 0);
            foundEntry[1] = *(short*)(state + 0x14);
            *foundEntry = *(short*)(state + 0x44);
        }
    }
    FUN_80286888();
    return;
}

void FUN_8003b1a4(int obj, int ctx)
{
    u32 remaining;
    int* found5;
    char* entry;
    int* found4;
    int hitDef;
    int offset;

    found5 = 0x0;
    hitDef = (int)((GameObject*)obj)->anim.modelInstance;
    if ((hitDef != 0) && (entry = *(char**)(hitDef + 0xc), entry != 0x0))
    {
        offset = 0;
        for (remaining = (u32) * (u8*)(hitDef + 0x59); remaining != 0; remaining = remaining - 1)
        {
            if (*entry == '\x05')
            {
                found5 = (int*)(*(int*)&((GameObject*)obj)->anim.textureSlots + offset);
            }
            entry = entry + 2;
            offset = offset + 0x10;
        }
    }
    found4 = 0x0;
    if ((hitDef != 0) && (entry = *(char**)(hitDef + 0xc), entry != 0x0))
    {
        offset = 0;
        for (remaining = (u32) * (u8*)(hitDef + 0x59); remaining != 0; remaining = remaining - 1)
        {
            if (*entry == '\x04')
            {
                found4 = (int*)(*(int*)&((GameObject*)obj)->anim.textureSlots + offset);
            }
            entry = entry + 2;
            offset = offset + 0x10;
        }
    }
    if (found5 == 0x0)
    {
        return;
    }
    if (found4 == 0x0)
    {
        return;
    }
    hitDef = *found4 + DAT_803dc070 * 0x30;
    if (0x1ff < hitDef)
    {
        hitDef = 0x200;
    }
    *found5 = hitDef;
    *found4 = hitDef;
    *(u8*)(ctx + 0x1e) = 1;
    return;
}

void FUN_8003b280(int obj, int ctx)
{
    int* found5;
    u32 state;
    char* entry;
    int* found4;
    int hitDef;
    int offset;

    found5 = 0x0;
    hitDef = (int)((GameObject*)obj)->anim.modelInstance;
    if ((hitDef != 0) && (entry = *(char**)(hitDef + 0xc), entry != 0x0))
    {
        offset = 0;
        for (state = (u32) * (u8*)(hitDef + 0x59); state != 0; state = state - 1)
        {
            if (*entry == '\x05')
            {
                found5 = (int*)(*(int*)&((GameObject*)obj)->anim.textureSlots + offset);
            }
            entry = entry + 2;
            offset = offset + 0x10;
        }
    }
    found4 = 0x0;
    if ((hitDef != 0) && (entry = *(char**)(hitDef + 0xc), entry != 0x0))
    {
        offset = 0;
        for (state = (u32) * (u8*)(hitDef + 0x59); state != 0; state = state - 1)
        {
            if (*entry == '\x04')
            {
                found4 = (int*)(*(int*)&((GameObject*)obj)->anim.textureSlots + offset);
            }
            entry = entry + 2;
            offset = offset + 0x10;
        }
    }
    if ((found5 != 0x0) && (found4 != 0x0))
    {
        state = (int)*(char*)(ctx + 0x1e) & 0xf;
        if (state == 1)
        {
            if (((int)*(char*)(ctx + 0x1e) & 0x80U) == 0)
            {
                hitDef = *found4 + DAT_803dc070 * 0x60;
                if (0x200 < hitDef)
                {
                    if (hitDef + -0x200 < 0)
                    {
                        hitDef = 0;
                        *(u8*)(ctx + 0x1e) = 0;
                    }
                    else
                    {
                        hitDef = 0x2ff;
                        *(u8*)(ctx + 0x1e) = 0x81;
                    }
                    *(u8*)(ctx + 0x1f) = 0x28;
                }
            }
            else
            {
                hitDef = *found4 + DAT_803dc070 * -0x60;
                if (hitDef < 0)
                {
                    hitDef = 0;
                    *(u8*)(ctx + 0x1e) = 0;
                    *(u8*)(ctx + 0x1f) = 0;
                }
            }
            *found5 = hitDef;
            *found4 = hitDef;
        }
        else if (state == 0)
        {
            if (*(char*)(ctx + 0x1f) < '\x01')
            {
                state = randomGetRange(0, 1000);
                if (0x3de < state)
                {
                    *(u8*)(ctx + 0x1e) = 1;
                    *(u8*)(ctx + 0x1f) = 0;
                }
            }
            else
            {
                *(u8*)(ctx + 0x1f) = *(char*)(ctx + 0x1f) - DAT_803dc070;
            }
        }
        FUN_800396cc(obj, ctx);
    }
    return;
}

void FUN_8003b444(short* obj, char* ctx)
{
    u32 scaled;
    short* found;
    int model;
    int entryIdx;
    int vecOffset;

    found = 0x0;
    model = *(int*)(obj + 0x28);
    if (model != 0)
    {
        entryIdx = 0;
        vecOffset = 0;
        for (scaled = (u32) * (u8*)(model + 0x5a); scaled != 0; scaled = scaled - 1)
        {
            if ((*(char*)(*(int*)(model + 0x10) + *(char*)((int)obj + 0xad) + entryIdx + 1) != -1) &&
                (*(char*)(*(int*)(model + 0x10) + entryIdx) == '\0'))
            {
                found = (short*)(*(int*)(obj + 0x36) + vecOffset);
            }
            entryIdx = *(char*)(model + 0x55) + entryIdx + 1;
            vecOffset = vecOffset + 0x12;
        }
    }
    if (found != 0x0)
    {
        if (*found != 0)
        {
            scaled = *found * 3;
            *found = (short)((int)scaled >> 2) + (u16)((int)scaled < 0 && (scaled & 3) != 0);
        }
        FUN_80039e6c((double)lbl_803DF624, obj, ctx, (int)found);
        *(u16*)(ctx + 0x1a) = *(u16*)(ctx + 0x1a) & 0xff;
    }
    return;
}

void FUN_8003b540(u8 param_1, u8 param_2, u8 param_3, u8 param_4)
{
    DAT_803dd88d = param_1;
    DAT_803dd88c = param_2;
    DAT_803dd88b = param_3;
    DAT_803dd889 = 1;
    DAT_803dd88a = param_4;
    return;
}

void FUN_8003b56c(u16 param_1, u16 param_2, u16 param_3)
{
    DAT_803dd898 = param_1;
    DAT_803dd896 = param_2;
    DAT_803dd894 = param_3;
    DAT_803dd888 = 1;
    return;
}

void FUN_8003b818(int obj)
{
    if ((OBJPRINT_ACTIVE_BANK(obj) != 0) &&
        (FUN_80040a88(obj), *(int*)&((GameObject*)obj)->anim.hitVolumeTransforms != 0))
    {
        FUN_800400b0();
    }
    return;
}

void FUN_8003b870(u32 param_1)
{
    DAT_803dd890 = param_1;
    return;
}

void FUN_8003b878(u32 param_1, u32 param_2, u32 param_3, u32 param_4,
                  int obj, u32 renderFlag)
{
    short seqId;
    u32 ctxHi;
    int child;
    VtableFn* vfn;
    int walk;
    char flag;
    int i;
    u64 ctx;

    ctx = FUN_8028683c();
    ctxHi = (u32)((u64)ctx >> 0x20);
    if (((((*(u16*)(obj + 0xb0) & 0x40) == 0) && (*(int*)&((GameObject*)obj)->ownerObj == 0)) &&
            ((*(u16*)(obj + 6) & 0x4000) == 0)) &&
        ((*(int*)&((GameObject*)obj)->anim.parent == 0 || ((*(u16*)(*(int*)&((GameObject*)obj)->anim.parent + 6) & 0x4000) == 0))
        ))
    {
        FUN_80017a04();
        *(u16*)(obj + 0xb0) = *(u16*)(obj + 0xb0) | 0x800;
        flag = renderFlag;
        if (*(int**)(obj + 0x68) == 0x0)
        {
            if (flag != '\0')
            {
                seqId = ((GameObject*)obj)->anim.seqId;
                if ((seqId == 0x1f) || ((seqId < 0x1f && (seqId == 0))))
                {
                    FUN_802950c8(obj, ctxHi, ctx, param_3, param_4, flag);
                }
                else if ((OBJPRINT_ACTIVE_BANK(obj) != 0) &&
                    (FUN_80040a88(obj), *(int*)&((GameObject*)obj)->anim.hitVolumeTransforms != 0))
                {
                    FUN_800400b0();
                }
            }
        }
        else if ((*(u16*)(obj + 0xb0) & 0x4000) == 0)
        {
            vfn = *(VtableFn**)(**(int**)(obj + 0x68) + 0x10);
            if (vfn != (VtableFn*)0x0)
            {
                (*vfn)(obj, ctxHi, ctx, param_3, param_4, renderFlag);
            }
        }
        else if (((flag != '\0') &&
                (OBJPRINT_ACTIVE_BANK(obj) != 0)) &&
            (FUN_80040a88(obj), *(int*)&((GameObject*)obj)->anim.hitVolumeTransforms != 0))
        {
            FUN_800400b0();
        }
        FUN_80017a00();
        walk = obj;
        for (i = 0; i < (int)(u32) * (u8*)(obj + 0xeb); i = i + 1)
        {
            child = *(int*)&((GameObject*)walk)->childObjs[0];
            if (*(short*)(child + 0x44) == 0x2d)
            {
                FUN_8003b590(child, obj,OBJPRINT_ACTIVE_BANK(child));
            }
            walk = walk + 4;
        }
    }
    FUN_80286888();
    return;
}

void FUN_8003c10c(int model, int* mtxArr)
{
    u32 rem;
    int cache;
    u32 mtx;
    u32 count;
    u32 dst;

    cache = FUN_8001779c();
    if (*(char*)(model + 0xf4) != '\0')
    {
        FUN_8003be6c();
    }
    count = (u32) * (u8*)(model + 0xf3) + (u32) * (u8*)(model + 0xf4);
    if ((count < 2) || (100 < count))
    {
        DAT_803dd8c8 = 3;
    }
    else
    {
        mtx = FUN_80017970(mtxArr, 0);
        FUN_802420e0(mtx, count * 0x40);
        dst = cache + 0x2700;
        for (count = count * 2 & 0xfe; rem = count & 0xff, 0x7f < rem; count = count - 0x80)
        {
            FUN_80017798(dst, mtx, 0);
            mtx = mtx + 0x1000;
            dst = dst + 0x1000;
        }
        if (rem != 0)
        {
            FUN_80017798(dst, mtx, rem);
        }
        DAT_803dd8c8 = 1;
    }
    return;
}

extern u32 lbl_803DCC10;
extern u8 lbl_803DCC3C;
void fn_8003B950(u32 x) { lbl_803DCC10 = x; }
u8 fn_8003BB74(void) { return lbl_803DCC3C; }
void fn_8003BB7C(u8 x) { lbl_803DCC3C = x; }

extern s16 lbl_803DCC18, lbl_803DCC16, lbl_803DCC14;
extern u8 lbl_803DCC08;

void fn_8003B608(s16 a, s16 b, s16 c)
{
    lbl_803DCC18 = a;
    lbl_803DCC16 = b;
    lbl_803DCC14 = c;
    lbl_803DCC08 = 1;
}

void fn_80039264(s32* p)
{
    *p = -1;
}

extern int lbl_802CAE88[10];

void* seqFn_800394a0(void)
{
    return lbl_802CAE88;
}

extern u8 lbl_803DCC09;
extern u8 lbl_803DCC0A;
extern u8 lbl_803DCC0B;
extern u8 lbl_803DCC0C;
extern u8 lbl_803DCC0D;
extern void objRenderModel(int* obj, int** table);
extern void objRenderFn_80041018(int* obj);

void* objModelGetVecFn_800395d8(void* obj, int target)
{
    int vecOffset;
    int entries;
    int entryIdx;
    void* m;
    void* result;
    int count;
    int i;

    result = NULL;
    m = OBJPRINT_MODEL_INSTANCE(obj);
    if (m != NULL)
    {
        entryIdx = 0;
        vecOffset = 0;
        count = OBJPRINT_JOINT_COUNT(m);
        for (i = 0; i < count; i++)
        {
            entries = *(int*)&((ObjDef*)m)->jointData;
            if ((int)*(u8*)(entries + OBJPRINT_ACTIVE_BANK_INDEX(obj) + entryIdx + 1) != 0xff &&
                (s32)*(u8*)(entries + entryIdx) == target)
            {
                result = (char*)((GameObject*)obj)->anim.jointPoseData + vecOffset;
            }
            entryIdx += OBJPRINT_MODEL_COUNT(m) + 1;
            vecOffset += 0x12;
        }
    }
    return result;
}

void fn_8003A9C0(char* p, int count, s16 a, s16 b)
{
    while (count > 0)
    {
        *(s16*)(p + 0x14) = a;
        *(s16*)(p + 0x44) = b;
        p += 0x60;
        count--;
    }
}
extern f32 lbl_803DE9C8;
extern f32 lbl_803DE99C;

void objAudioFn_80039270(u32 obj, void* p, u16 sfxId)
{
    if (Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0)
    {
        Sfx_PlayFromObjectChannel(obj, 0x10, sfxId);
        *(f32*)((char*)p + 0xc) = lbl_803DE9C8;
        *(s16*)((char*)p + 0x14) = -0x500;
        *(u8*)p = 1;
        *(f32*)((char*)p + 4) = lbl_803DE99C;
    }
}

void objRenderFn_8003b8f4(int* obj)
{
    int** table = OBJPRINT_BANK_TABLE(obj);
    if (table[OBJPRINT_ACTIVE_BANK_INDEX(obj)] != NULL)
    {
        objRenderModel(obj, table);
        if (((GameObject*)obj)->anim.hitVolumeTransforms != NULL)
        {
            objRenderFn_80041018(obj);
        }
    }
}

void fn_8003B5E0(int a, int b, int c, u8 d)
{
    lbl_803DCC0D = a;
    lbl_803DCC0C = b;
    lbl_803DCC0B = c;
    lbl_803DCC09 = 1;
    lbl_803DCC0A = d;
}

ObjTextureRuntimeSlot* objFindTexture(void* obj, int target, int unusedMaterialIndex)
{
    ObjTextureRuntimeSlot* result = NULL;
    ObjDef* modelDef = ((GameObject*)obj)->anim.modelInstance;
    if (modelDef != NULL)
    {
        int count;
        ObjTextureSlotDef* entries = modelDef->textureSlotDefs;
        if (entries == NULL) return NULL;
        {
            int i;
            count = modelDef->textureSlotCount;
            for (i = 0; i < count; i++)
            {
                if (target == entries[i].tag)
                {
                    result = &((GameObject*)obj)->anim.textureSlots[i];
                }
            }
        }
    }
    return result;
}

extern void objRenderShadow(void* obj);

void objRenderShadowIfVisible(void* obj)
{
    void** arr = *(void***)&((GameObject*)obj)->anim.banks;
    s8 idx = ((GameObject*)obj)->anim.bankIndex;
    if (arr[idx] != NULL)
    {
        objRenderShadow(obj);
    }
}

#pragma dont_inline on
int fn_800399C0(s16* curve, s16* state)
{
    extern f32 Curve_EvalHermite(int, f32, int);
    extern f32 timeDelta;
    extern f32 lbl_803DE99C;
    extern f32 lbl_803DE9A4;
    extern f32 lbl_803DE9D8;
    extern f32 lbl_803DE9DC;
    extern f32 lbl_803DE9E0;
    f32 buf[4];
    f32 ratio;
    s16 lo;
    s16 hi;

    buf[0] = lbl_803DE9D8;
    buf[1] = lbl_803DE9D8;
    buf[2] = lbl_803DE9DC;
    buf[3] = lbl_803DE9E0;

    lo = curve[10];
    hi = curve[11];
    if (lo != hi)
    {
        ratio = ((f32)(s32)
        state[1] - (f32)(s32)
        hi
        )
        /
        ((f32)(s32)
        lo - (f32)(s32)
        hi
        )
        ;
    }
    else
    {
        return 1;
    }

    if (ratio > lbl_803DE99C)
    {
        ratio = lbl_803DE99C;
    }
    else if (ratio < lbl_803DE9A4)
    {
        ratio = lbl_803DE9A4;
    }

    {
        f32 rate = Curve_EvalHermite((int)buf, ratio, 0);
        if (curve[10] < curve[11])
        {
            rate = -rate;
        }
        state[1] = rate * timeDelta + (f32)(s32)
        state[1];
    }

    if (lbl_803DE99C == ratio || state[1] >= 8191 || state[1] <= -8191)
    {
        state[1] = curve[10];
        return 1;
    }
    return 0;
}
#pragma dont_inline reset

void fn_8003A168(int obj, int state)
{
    s16* found;

    found = objFindJointVecByKey(obj, 0);
    if (found == NULL) return;
    if (found[0] != 0)
    {
        found[0] = (s16)((s32)found[0] * 3 / 4);
    }
    if (found[1] != 0)
    {
        found[1] = (s16)((s32)found[1] * 3 / 4);
    }
    *(s16*)(state + 0x1a) = 0;
}

void objModelClearVecFn_8003aa40(int obj)
{
    s16* found;
    int slot;

    for (slot = 0; slot < 0x16; slot++)
    {
        found = objFindJointVecByKey(obj, slot);
        if (found != NULL)
        {
            found[0] = 0;
            found[1] = 0;
            found[2] = 0;
        }
    }
}

void fn_8003AC14(int obj, int* keys, int count)
{
    s16* found;
    int idx;

    for (idx = 0; idx < count; idx++)
    {
        found = objFindJointVecByKey(obj, *keys);
        if (found != NULL)
        {
            found[1] = (s16)(found[1] * 3 >> 2);
            found[0] = (s16)(found[0] * 3 >> 2);
            found[2] = (s16)(found[2] * 3 >> 2);
        }
        keys++;
    }
}

void objFn_8003acfc(int obj, int* keys, int count, int out)
{
    s16* found;
    int idx;

    for (idx = 0; idx < count;)
    {
        found = objFindJointVecByKey(obj, *keys);
        if (found != NULL)
        {
            *(s16*)(out + 0x16) = found[1];
            *(s16*)(out + 0x46) = found[0];
        }
        keys++;
        idx++;
        out += 0x60;
    }
}

void fn_8003AAE0(int obj, int* keys, int count, int lo, int hi)
{
    s16* found;
    int idx;
    int v;

    for (idx = 0; idx < count; idx++)
    {
        found = objFindJointVecByKey(obj, *keys);
        if (found != NULL)
        {
            v = found[0];
            if (v < lo) v = lo;
            else if (v > hi) v = hi;
            found[0] = v;
            v = found[1];
            if (v < lo) v = lo;
            else if (v > hi) v = hi;
            found[1] = v;
            v = found[2];
            if (v < lo) v = lo;
            else if (v > hi) v = hi;
            found[2] = v;
        }
        keys++;
    }
}

extern u8 framesThisStep;

static inline ObjTextureRuntimeSlot* characterFindEyeJoint(int obj, int kind)
{
    ObjTextureSlotDef* list;
    int n;
    int k;
    ObjDef* modelDef;
    ObjTextureRuntimeSlot* found;

    found = NULL;
    modelDef = ((GameObject*)obj)->anim.modelInstance;
    if (modelDef != NULL)
    {
        list = modelDef->textureSlotDefs;
        if (list == NULL)
        {
            return NULL;
        }
        n = (s32)(u32)modelDef->textureSlotCount;
        for (k = 0; k < n; k++)
        {
            if (list->tag == kind)
            {
                found = &((GameObject*)obj)->anim.textureSlots[k];
            }
            list++;
        }
    }
    return found;
}

void characterDoEyeMovements(int obj, int p4, f32 unused);

void fn_8003B228(int obj, int p2)
{
    ObjTextureRuntimeSlot* foundA;
    ObjTextureRuntimeSlot* foundB;
    int val;

    foundA = characterFindEyeJoint(obj, 5);
    foundB = characterFindEyeJoint(obj, 4);
    if (foundA == NULL || foundB == NULL)
    {
        return;
    }
    val = foundB->textureId;
    val += framesThisStep * 0x30;
    if (val >= 0x200)
    {
        val = 0x200;
    }
    foundA->textureId = val;
    foundB->textureId = val;
    *(u8*)(p2 + 0x1e) = 1;
}

extern void* ObjModel_GetJointMatrix(int* model, int joint);
extern int lbl_803DCC48;

void modelInitMtxs(int def, int model)
{
    int cache;
    int mtx;
    int count;
    u8 rem;

    cache = (int)getCache();
    if (*(u8*)(def + 0xf4) != 0)
    {
        modelCalcVtxGroupMtxs(def, model);
    }
    count = (s32)(u32) * (u8*)(def + 0xf3) + (s32)(u32) * (u8*)(def + 0xf4);
    if (count >= 2 && count <= 0x64)
    {
        mtx = (int)ObjModel_GetJointMatrix((int*)model, 0);
        DCFlushRange((void*)mtx, count << 6);
        rem = (u8)(count << 1);
        cache += 0x2700;
        while (rem >= 0x80)
        {
            copyToCache((void*)cache, (void*)mtx, 0);
            rem -= 0x80;
            mtx += 0x1000;
            cache += 0x1000;
        }
        if (rem != 0)
        {
            copyToCache((void*)cache, (void*)mtx, rem);
        }
        lbl_803DCC48 = 1;
    }
    else
    {
        lbl_803DCC48 = 3;
    }
}

extern void fn_80039DF8(int obj, s16* curve, s16* state, f32 x);
extern f32 lbl_803DE9A4;

void objAudioFn_800393f8(u32 p1, int p2, u16 p3, int p4, int p5, u8 p6)
{
    if (p6 == 0 && Sfx_IsPlayingFromObjectChannel(p1, 0x10) != 0)
    {
        return;
    }
    Sfx_PlayFromObjectChannel(p1, 0x10, p3);
    *(f32*)((char*)p2 + 0xc) = p5;
    *(s16*)((char*)p2 + 0x14) = (s16)(-p4);
    *(u8*)((char*)p2 + 0) = 1;
    *(f32*)((char*)p2 + 4) = lbl_803DE99C;
}

void fn_8003B500(int obj, s16* state)
{
    s16* found;

    found = objFindJointVecByKey(obj, 0);
    if (found != NULL)
    {
        if (found[0] != 0)
        {
            found[0] = (s16)(found[0] * 3 / 4);
        }
        fn_80039DF8(obj, state, found, lbl_803DE9A4);
        *(s16*)((char*)state + 0x1a) = (s16)(u16)(u8) * (s16*)((char*)state + 0x1a);
    }
}

extern void ObjModel_SetBlendChannelTargets(int model, int a, int b, int c, f32 ratio, int d);
extern f32 lbl_803DB464;

void objSoundFn_800392f0(int p1, int p2, int p3, u8 flag6)
{
    u16 sfx;
    s16 pitch;
    u32 count;
    int model;
    int did;

    pitch = *(s16*)((char*)p3 + 2);
    sfx = (u16) * (s16*)((char*)p3 + 0);
    if (flag6 != 0 || Sfx_IsPlayingFromObjectChannel((u32)p1, 0x10) == 0)
    {
        Sfx_PlayFromObjectChannel((u32)p1, 0x10, sfx);
        *(f32*)((char*)p2 + 0xc) = lbl_803DE9C8;
        *(s16*)((char*)p2 + 0x14) = (s16)(-pitch);
        *(u8*)((char*)p2 + 0) = 1;
        *(f32*)((char*)p2 + 4) = lbl_803DE99C;
    }
    count = *(u8*)((char*)p3 + 4);
    if (count != 0)
    {
        model = (int)OBJPRINT_ACTIVE_BANK(p1);
        if (*(u8*)((char*)*(int*)model + 0xf9) != 0)
        {
            ObjModel_SetBlendChannelTargets(model, 2,
                                            *(s8*)((char*)*(int*)((char*)model + 0x28) + 0x2d),
                                            count - 1, lbl_803DE99C / lbl_803DB464, 0);
            did = 1;
        }
        else
        {
            did = 0;
        }
        if (did != 0)
        {
            *(s16*)((char*)p3 + 2) = 0;
        }
    }
}

extern int Obj_GetActiveModel(int obj);
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;

void objPosFn_80039510(int obj, int key, int out)
{
    int* table;
    int i;
    int k;
    int n;
    int joint;
    int model;

    table = (void*)((GameObject*)obj)->anim.modelInstance;
    i = 0;
    n = (s32)(u32)((ObjDef*)table)->jointCount;
    for (k = 0; k < n; k++)
    {
        if (key == (int)(*(u8**)&((ObjDef*)table)->jointData)[i])
        {
            joint = (*(u8**)&((ObjDef*)table)->jointData + i + OBJPRINT_ACTIVE_BANK_INDEX(obj))[1];
            break;
        }
        i = i + ((ObjDef*)table)->modelCount + 1;
    }
    model = Obj_GetActiveModel(obj);
    model = (int)ObjModel_GetJointMatrix((int*)model, joint);
    *(f32*)((char*)out + 0) = *(f32*)((char*)model + 0xc);
    *(f32*)((char*)out + 4) = *(f32*)((char*)model + 0x1c);
    *(f32*)((char*)out + 8) = *(f32*)((char*)model + 0x2c);
    *(f32*)((char*)out + 0) = *(f32*)((char*)out + 0) + playerMapOffsetX;
    *(f32*)((char*)out + 8) = *(f32*)((char*)out + 8) + playerMapOffsetZ;
}

extern void PSMTXConcat(void* a, void* b, void* c);
extern f32 lbl_803DEA04;

void modelMtxFn_8003be38(int p1, int p2, int p3, int p4)
{
    int cache;
    int count;
    int i;
    int mid;
    int dstB;
    int dstA;
    f32 fill;

    cache = (int)getCache();
    count = (s32)(u32) * (u8*)((char*)p1 + 0xf3) + (s32)(u32) * (u8*)((char*)p1 + 0xf4);
    dstA = cache + 0x2700;
    mid = cache;
    dstB = cache + 0x12c0;
    cacheQueueWait(0);
    i = 0;
    fill = lbl_803DEA04;
    for (; i < count; i++)
    {
        PSMTXConcat((void*)p3, (void*)dstA, (void*)mid);
        PSMTXConcat((void*)mid, (void*)p4, (void*)dstB);
        *(f32*)((char*)dstB + 0xc) = fill;
        *(f32*)((char*)dstB + 0x1c) = fill;
        *(f32*)((char*)dstB + 0x2c) = fill;
        dstA += 0x40;
        mid += 0x30;
        dstB += 0x30;
    }
    lbl_803DCC48 = 2;
}

extern void doNothing_beforeRenderObject(int x);
extern void doNothing_afterRenderObject(void);
extern void playerRender(int obj, int a, int b, int c, int d, int flag);

void objRender(int a, int b, int c, int d, int obj, int flag)
{
    void* sub;
    int walk;
    int i;
    void (*vfn)(int, int, int, int, int, int);

    if ((((GameObject*)obj)->objectFlags & 0x40) != 0 ||
        ((GameObject*)obj)->ownerObj != NULL) return;
    if ((((GameObject*)obj)->anim.flags & OBJANIM_FLAG_HIDDEN) != 0) return;
    sub = *(void**)&((GameObject*)obj)->anim.parent;
    if (sub != NULL && (((GameObject*)sub)->anim.flags & OBJANIM_FLAG_HIDDEN) != 0) return;

    doNothing_beforeRenderObject(4);
    ((GameObject*)obj)->objectFlags |= 0x800;
    sub = *(void**)&((GameObject*)obj)->anim.dll;
    if (sub != NULL)
    {
        if ((((GameObject*)obj)->objectFlags & 0x4000) == 0)
        {
            vfn = *(void(**)(int, int, int, int, int, int))(*(int*)sub + 0x10);
            if (vfn != NULL)
            {
                vfn(obj, a, b, c, d, flag);
            }
        }
        else if ((s8)flag != 0 && OBJPRINT_ACTIVE_BANK(obj) != NULL)
        {
            (*(void(*)(int))objRenderModel)(obj);
            if (((GameObject*)obj)->anim.hitVolumeTransforms != NULL)
            {
                objRenderFn_80041018((int*)obj);
            }
        }
    }
    else if ((s8)flag != 0)
    {
        switch (((GameObject*)obj)->anim.seqId)
        {
        case 0:
        case 0x1f:
            playerRender(obj, a, b, c, d, flag);
            break;
        default:
            if (OBJPRINT_ACTIVE_BANK(obj) != NULL)
            {
                (*(void(*)(int))objRenderModel)(obj);
                if (((GameObject*)obj)->anim.hitVolumeTransforms != NULL)
                {
                    objRenderFn_80041018((int*)obj);
                }
            }
            break;
        }
    }
    doNothing_afterRenderObject();
    for (i = 0, walk = obj; i < (s32)(u32)((GameObject*)obj)->childCount; i++)
    {
        int staff = *(int*)&((GameObject*)walk)->childObjs[0];
        if (((GameObject*)staff)->anim.classId == 0x2d)
        {
            staffMtxFn_8003b620(staff, obj, (int)OBJPRINT_ACTIVE_BANK(staff), a, b, c);
        }
        walk += 4;
    }
}

extern f32 timeDelta;

void objModelAndSoundFn_80039118(int obj, int p2)
{
    int frame;
    int model;
    int kfval;
    int* kf;

    f32 t;

    if (*(s32*)((char*)p2 + 0) < 0) return;
    t = *(f32*)((char*)p2 + 8) - timeDelta;
    *(f32*)((char*)p2 + 8) = t;
    if (t < lbl_803DE9A4)
    {
    frame = *(int*)((char*)p2 + 0);
    if (frame >= *(int*)((char*)p2 + 4))
    {
        *(int*)((char*)p2 + 0) = -1;
        model = (int)OBJPRINT_ACTIVE_BANK(obj);
        if (*(u8*)((char*)*(int*)model + 0xf9) != 0)
        {
            ObjModel_SetBlendChannelTargets(model, 2,
                                            *(s8*)((char*)*(int*)((char*)model + 0x28) + 0x2d),
                                            -1, lbl_803DE99C / lbl_803DB464, 0);
        }
    }
    else
    {
        if (frame == 1)
        {
            Sfx_PlayFromObjectChannel((u32)obj, 0x10, *(u16*)((char*)p2 + 0x14));
        }
        kf = *(int**)((char*)p2 + 0x10);
        frame = *(int*)((char*)p2 + 0);
        *(int*)((char*)p2 + 0) = frame + 1;
        kfval = kf[frame];
        model = (int)OBJPRINT_ACTIVE_BANK(obj);
        if (*(u8*)((char*)*(int*)model + 0xf9) != 0)
        {
            ObjModel_SetBlendChannelTargets(model, 2,
                                            *(s8*)((char*)*(int*)((char*)model + 0x28) + 0x2d),
                                            kfval - 1, lbl_803DE99C / lbl_803DB464, 0);
        }
        *(f32*)((char*)p2 + 8) = *(f32*)((char*)p2 + 8) + *(f32*)((char*)p2 + 0xc);
    }
    }
}

extern f32 lbl_803DE9E4;

void fn_8003A230(int obj, void* state, f32 val)
{
    s16* found;
    int flag;

    found = objFindJointVecByKey(obj, 0);
    if (found != NULL)
    {
        if (found[0] != 0)
        {
            found[0] = (s16)(found[0] * 3 / 4);
        }
        if (val < lbl_803DE9A4)
        {
            val = -val;
        }
        if (val <= lbl_803DE9E4)
        {
            fn_80039DF8(obj, (s16*)state, found, val);
        }
        else
        {
            fn_80039B54(obj, (s16*)state, found, val);
        }
        *(s16*)((char*)state + 0x1a) = (s16)(u16)(u8) * (s16*)((char*)state + 0x1a);
        if (val > lbl_803DE9E4)
        {
            flag = 1;
        }
        else
        {
            flag = 0;
        }
        *(s16*)((char*)state + 0x1a) = (s16)(*(s16*)((char*)state + 0x1a) | (flag << 8));
    }
}

extern int getAngle(float y, float x);
extern f32 gObjPrintDegToAngle;

void fn_8003B0D0(int obj, int target, int state, s16 maxAngle)
{
    s16* found;

    found = objFindJointVecByKey(obj, 0);
    if (found != NULL)
    {
        *(s16*)((char*)state + 0x14) = (s16)((s16)getAngle(((GameObject*)obj)->anim.localPosX -
                                                            *(f32*)((char*)target + 0xc),
                                                        ((GameObject*)obj)->anim.localPosZ -
                                                            *(f32*)((char*)target + 0x14)) -
                                          ((GameObject*)obj)->anim.rotX);
        maxAngle = (s16)(int)(gObjPrintDegToAngle * maxAngle);
        if (*(s16*)((char*)state + 0x14) > maxAngle)
        {
            *(s16*)((char*)state + 0x14) = maxAngle;
        }
        if (*(s16*)((char*)state + 0x14) < -maxAngle)
        {
            *(s16*)((char*)state + 0x14) = -maxAngle;
        }
        found[1] = *(s16*)((char*)state + 0x14);
    }
}

int fn_80039834(s16* curve, s16* state, f32 a, f32 b);

int fn_8003A8B4(int objArg, int* keyList, int countArg, char* p4Arg)
{
    extern f32 lbl_803DE9D8;
    extern f32 lbl_803DE9DC;
    int* keys;
    int i;
    int total;
    char* p4;
    int count;
    int obj;
    s16* found;

    obj = objArg;
    count = countArg;
    p4 = p4Arg;
    total = 0;
    i = 0;
    keys = keyList;
    while (i < count)
    {
        found = objFindJointVecByKey(obj, *keys);
        total += fn_800399C0((s16*)p4, found);
        total += fn_80039834((s16*)(p4 + 0x30), found, lbl_803DE9D8, lbl_803DE9DC);
        keys++;
        i++;
        p4 += 0x60;
    }
    return (count * 2 - total) == 0;
}

#pragma dont_inline on
int fn_80039834(s16* curve, s16* state, f32 a, f32 b)
{
    extern f32 Curve_EvalHermite(int, f32, int);
    extern f32 timeDelta;
    extern f32 lbl_803DE99C;
    extern f32 lbl_803DE9A4;
    f32 buf[4];
    f32 ratio;
    s16 lo;
    s16 hi;

    buf[0] = a;
    buf[1] = a;
    buf[2] = b;
    buf[3] = -b;

    lo = curve[10];
    hi = curve[11];
    if (lo != hi)
    {
        ratio = ((f32)(s32) * state - (f32)(s32)
        hi
        )
        /
        ((f32)(s32)
        lo - (f32)(s32)
        hi
        )
        ;
    }
    else
    {
        return 1;
    }

    if (ratio > lbl_803DE99C)
    {
        ratio = lbl_803DE99C;
    }
    else if (ratio < lbl_803DE9A4)
    {
        ratio = lbl_803DE9A4;
    }

    {
        f32 rate = Curve_EvalHermite((int)buf, ratio, 0);
        if (curve[10] < curve[11])
        {
            rate = -rate;
        }
        *state = rate * timeDelta + (f32)(s32) * state;
    }

    if (lbl_803DE99C == ratio || *state >= 8191 || *state <= -8191)
    {
        *state = curve[10];
        return 1;
    }
    return 0;
}
#pragma dont_inline reset

int fn_8003BB84(f32 * m, f32 * out);

int objRotateFn_8003bce8(f32* m, s16* outA, s16* outB, s16* outC)
{


    extern f32 lbl_803DEA04;
    extern f32 gObjPrintHalfPi;
    extern f32 gObjPrintNegHalfPi;
    extern const f32 gObjPrintAngleUnitScale;
    extern const f32 gObjPrintTwoPi;
    f32 buf[12];
    f32 x;
    f32 y;
    f32 z;

    if (fn_8003BB84(m, buf) == 0)
    {
        return 0;
    }
    x = __kernel_sin(-buf[6]);
    if (x < gObjPrintHalfPi)
    {
        if (x > gObjPrintNegHalfPi)
        {
            y = __kernel_cos(buf[2], buf[10]);
            z = __kernel_cos(buf[4], buf[5]);
        }
        else
        {
            y = __kernel_cos(buf[1], buf[0]);
            z = lbl_803DEA04;
            y = z - y;
        }
    }
    else
    {
        y = __kernel_cos(buf[1], buf[0]);
        z = lbl_803DEA04;
        y = y - z;
    }
    *outC = (s16)(s32)(gObjPrintAngleUnitScale * z / gObjPrintTwoPi);
    *outB = (s16)(s32)(gObjPrintAngleUnitScale * x / gObjPrintTwoPi);
    *outA = (s16)(s32)(gObjPrintAngleUnitScale * y / gObjPrintTwoPi);
    return 1;
}

#pragma opt_common_subs off
int fn_8003BB84(f32* m, f32* out)
{
    extern void PSVECNormalize(f32 * src, f32 * dst);
    extern f32 lbl_803DEA04;
    f32 v3[3];
    f32 v1[3];
    f32 v2[3];
    f32 zero;

    v1[0] = m[0];
    v1[1] = m[1];
    v1[2] = m[2];
    v2[0] = m[4];
    v2[1] = m[5];
    v2[2] = m[6];
    v3[0] = m[8];
    v3[1] = m[9];
    v3[2] = m[10];

    if ((v1[0] == lbl_803DEA04 && v1[1] == lbl_803DEA04 && v1[2] == lbl_803DEA04)
        || (v2[0] == lbl_803DEA04 && v2[1] == lbl_803DEA04 && v2[2] == lbl_803DEA04)
        || (v3[0] == lbl_803DEA04 && v3[1] == lbl_803DEA04 && v3[2] == lbl_803DEA04))
    {
        return 0;
    }

    PSVECNormalize(v1, v1);
    PSVECNormalize(v2, v2);
    PSVECNormalize(v3, v3);

    out[0] = v1[0];
    out[1] = v1[1];
    out[2] = v1[2];
    zero = lbl_803DEA04;
    out[3] = zero;
    out[4] = v2[0];
    out[5] = v2[1];
    out[6] = v2[2];
    out[7] = zero;
    out[8] = v3[0];
    out[9] = v3[1];
    out[10] = v3[2];
    out[11] = zero;
    return 1;
}
#pragma opt_common_subs reset

void fn_80039B54(int obj, s16* curve, s16* state, f32 val)
{
    extern f32 lbl_803DE9E4;
    int masked;
    int flag;

    masked = (curve[13] >> 8) & 0xff;
    if (val > lbl_803DE9E4)
    {
        flag = 1;
    }
    else
    {
        flag = 0;
    }
    if (masked != flag)
    {
        curve[13] = (s16)(flag << 8 | 4);
        curve[11] = state[1];
        curve[10] = 0;
        curve[14] = 0;
    }

    switch ((u8)curve[13])
    {
    case 0:
        curve[13] = (s16)(flag << 8);
        curve[14] = randomGetRange(0x32, 0xc8);
        break;
    case 1:
        curve[14] -= framesThisStep;
        if (curve[14] < 0)
        {
            if ((int)randomGetRange(0, 100) > 90)
            {
                curve[13] = (s16)(flag << 8 | 5);
                if (*(s8*)curve != 0)
                {
                    if ((int)randomGetRange(0, 100) > 0)
                    {
                        curve[10] = 0x1fff;
                        if ((int)randomGetRange(0, 1) == 0)
                        {
                            curve[10] = -curve[10];
                        }
                    }
                }
                else
                {
                    curve[10] = 0x1fff;
                    if ((int)randomGetRange(0, 1) == 0)
                    {
                        curve[10] = -curve[10];
                    }
                }
            }
        }
        break;
    case 2:
        break;
    case 5:
        if (curve[14] > 0)
        {
            curve[14] -= framesThisStep;
        }
        else if (fn_800399C0(curve, state))
        {
            curve[13] = (s16)(flag << 8 | 6);
            curve[10] = -curve[10];
            curve[14] = randomGetRange(0x14, 0x64);
        }
        break;
    case 6:
        if (curve[14] > 0)
        {
            curve[14] -= framesThisStep;
        }
        else if (fn_800399C0(curve, state))
        {
            curve[13] = (s16)(flag << 8 | 4);
            curve[10] = 0;
            curve[14] = randomGetRange(0x14, 0x64);
        }
        break;
    case 4:
        if (curve[14] > 0)
        {
            curve[14] -= framesThisStep;
        }
        else if (fn_800399C0(curve, state))
        {
            curve[13] = (s16)(flag << 8);
            state[1] = 0;
        }
        break;
    }
}

void fn_80039DF8(int obj, s16* curve, s16* state, f32 val)
{
    extern f32 lbl_803DE9E4;
    extern f32 lbl_803DE9E8;
    int masked;
    int flag;

    masked = (curve[13] >> 8) & 0xff;
    if (val > lbl_803DE9E4)
    {
        flag = 1;
    }
    else
    {
        flag = 0;
    }
    if (masked != flag)
    {
        curve[13] = (s16)(flag << 8);
    }

    switch ((u8)curve[13])
    {
    case 0:
        if (*(s8*)curve != 0)
        {
            curve[13] = (s16)(flag << 8 | 3);
            curve[11] = state[1];
            *(f32*)((char*)curve + 0x10) = lbl_803DE99C;
        }
        else
        {
            curve[13] = (s16)(flag << 8 | 1);
            curve[14] = randomGetRange(100, 400);
            curve[10] = state[1];
        }
        break;
    case 1:
        curve[14] -= framesThisStep;
        if (curve[14] < 0)
        {
            int old = curve[10];
            curve[10] = randomGetRange(0, 0x1fff);
            if (old > 0)
            {
                if (old - curve[10] < 0xe38)
                {
                    curve[10] += 0xe38;
                }
                if (curve[10] > 0x1fff)
                {
                    curve[10] = 0x1fff;
                }
                curve[10] = -curve[10];
            }
            else
            {
                if (curve[10] - old < 0xe38)
                {
                    curve[10] += 0xe38;
                }
                if (curve[10] > 0x1fff)
                {
                    curve[10] = 0x1fff;
                }
            }
            curve[13] = (s16)(flag << 8 | 2);
            curve[14] = 0;
            curve[11] = state[1];
        }
        break;
    case 2:
        if (*(s8*)curve != 0 || fn_800399C0(curve, state) != 0)
        {
            curve[13] = (s16)(flag << 8);
        }
        break;
    case 3:
        if (*(s8*)curve == 0)
        {
            curve[13] = (s16)(flag << 8);
        }
        else
        {
            int angle;
            int n;
            angle = getAngle(((GameObject*)obj)->anim.localPosX - *(f32*)((char*)curve + 4),
                             ((GameObject*)obj)->anim.localPosZ - *(f32*)((char*)curve + 0xc));
            curve[10] = (s16)(angle - (u16)((GameObject*)obj)->anim.rotX);
            if (curve[10] > 0x8000)
            {
                curve[10] = (s16)(curve[10] - 0xffff);
            }
            if (curve[10] < -0x8000)
            {
                curve[10] = (s16)(curve[10] + 0xffff);
            }
            n = curve[10];
            if (n > 0x1fff || n < -0x1fff)
            {
                curve[13] = (s16)(flag << 8);
            }
            else
            {
                f32 t = *(f32*)((char*)curve + 0x10);
                f32 lo = lbl_803DE9A4;
                if (t > lo)
                {
                    f32 nv;
                    state[1] = t * (f32)(curve[11] - n) + n;
                    nv = -(lbl_803DE9E8 * timeDelta - *(f32*)((char*)curve + 0x10));
                    *(f32*)((char*)curve + 0x10) = nv;
                    if (nv < lo)
                    {
                        *(f32*)((char*)curve + 0x10) = lo;
                    }
                }
                else
                {
                    state[1] = n;
                }
            }
        }
        break;
    }

    if (state[1] < -0x1fff)
    {
        state[1] = -0x1fff;
    }
    else if (state[1] > 0x1fff)
    {
        state[1] = 0x1fff;
    }
}

#pragma opt_loop_invariants off
void fn_8003ADC4(int obj, char* tgt, char* p3, int a, u8 inv, int b)
{
    extern f32 sqrtf(f32);
    extern f32 gObjPrintDegToAngle;
    s16 ang[2];
    s16* found;
    void* m;

    found = NULL;
    m = (void*)((GameObject*)obj)->anim.modelInstance;
    if (m != NULL)
    {
        int entryIdx = (int)found, vecOffset = (int)found;
        int n = ((ObjDef*)m)->jointCount;
        int j;
        for (j = 0; j < n; j++)
        {
            int entries = *(int*)&((ObjDef*)m)->jointData;
            if ((int)*(u8*)(entries + OBJPRINT_ACTIVE_BANK_INDEX(obj) + entryIdx + 1) != 0xff &&
                (int)*(u8*)(entries + entryIdx) == 0)
            {
                found = (s16*)((char*)((GameObject*)obj)->anim.jointPoseData + vecOffset);
            }
            entryIdx += ((ObjDef*)m)->modelCount + 1;
            vecOffset += 0x12;
        }
    }
    if (found != NULL)
    {
        if (tgt == NULL)
        {
            found[1] = found[1] >> 1;
            found[0] = found[0] >> 1;
        }
        else
        {
            f32 dx = ((GameObject*)obj)->anim.localPosX - *(f32*)(tgt + 0xc);
            f32 dy = ((GameObject*)obj)->anim.localPosZ - *(f32*)(tgt + 0x14);
            f32 dz = ((GameObject*)obj)->anim.localPosY - *(f32*)(tgt + 0x10);
            f32 dist = sqrtf(dx * dx + dy * dy);
            int minB;
            int negA;
            char* p;
            s16* ap;
            int i;
            f32 prodB;

            ang[0] = (s16)getAngle(dx, dy) - (u16)((GameObject*)obj)->anim.rotX;
            if (ang[0] > 0x8000)
            {
                ang[0] = (s16)(ang[0] - 0xffff);
            }
            if (ang[0] < -0x8000)
            {
                ang[0] = (s16)(ang[0] + 0xffff);
            }
            if (inv != 0)
            {
                ang[0] = (s16)(ang[0] + 0x8000);
            }
            ang[1] = (s16)((s16)getAngle(dist, dz) - 0x3fff);

            a = (s16)(s32)(gObjPrintDegToAngle * a);
            p = p3;
            ap = ang;
            prodB = gObjPrintDegToAngle * b;
            minB = -(s16)(s32)prodB;
            negA = -a;
            for (i = 0; i < 2; i++)
            {
                int v;
                int w;
                *ap -= *(s16*)(p + 0x14);
                v = *ap;
                if (v < minB)
                {
                    w = minB;
                }
                else
                {
                    if (v > (s16)(int)(f64)prodB)
                    {
                        v = (int)(f64)prodB;
                    }
                    w = (s16)v;
                }
                *ap = (s16)w;
                *(s16*)(p + 0x14) += *ap;
                if (*(s16*)(p + 0x14) > a)
                {
                    *(s16*)(p + 0x14) = a;
                }
                if (*(s16*)(p + 0x14) < negA)
                {
                    *(s16*)(p + 0x14) = negA;
                }
                p += 0x30;
                ap++;
            }
            found[1] = *(s16*)(p3 + 0x14);
            found[0] = *(s16*)(p3 + 0x44);
        }
    }
}

#pragma opt_loop_invariants reset
#pragma opt_propagation off
#pragma opt_common_subs off
void staffMtxFn_8003b620(int staffArg, int objArg, int modelArg, int a, int b, int c)
{
    extern f32 playerMapOffsetX;
    extern f32 playerMapOffsetZ;
    extern f32 sqrtf(f32);
    f32 va[3];
    f32 vb[3];
    int k;
    char* q;
    f32* vp;
    int i;
    char* base;
    int model;
    int obj;
    int staff;

    staff = staffArg;
    obj = objArg;
    model = modelArg;
    if (*(u8*)(*(char**)(staff + 0x50) + 0x58) >= 2 && ((GameObject*)staff)->anim.classId == 0x2d)
    {
        int off;
        base = (char*)((GameObject*)staff)->extra;
        i = 0;
        k = 1;
        off = 0x18;
        q = base;
        vp = va;

        while (i < *(s16*)(base + 0xb0))
        {
            if (k < *(u8*)(*(char**)(staff + 0x50) + 0x58))
            {
                void* jm;
                char* t;
                int joint;
                joint = (*(s8**)(*(char**)(staff + 0x50) + 0x2c))[off +
                            OBJPRINT_ACTIVE_BANK_INDEX(staff) + 0x2a];
                jm = ObjModel_GetJointMatrix((int*)model, joint);
                t = *(char**)(*(char**)(staff + 0x50) + 0x2c);
                vp[0] = *(f32*)(t + off + 0x18);
                va[1] = *(f32*)(t + off + 0x1c);
                va[2] = *(f32*)(t + off + 0x20);
                PSMTXMultVec(jm, vp, vp);
                vp[0] = vp[0] + playerMapOffsetX;
                va[2] = va[2] + playerMapOffsetZ;
                *(f32*)(q + 0x6c) = vp[0];
                *(f32*)(q + 0x74) = va[1];
                *(f32*)(q + 0x7c) = va[2];
            }
            if (k < *(u8*)(*(char**)(staff + 0x50) + 0x58))
            {
                char* t = *(char**)(*(char**)(staff + 0x50) + 0x2c);
                char* row = t + off;
                int idx2 = *(s8*)(row + OBJPRINT_ACTIVE_BANK_INDEX(staff) + 0x12);
                char* mtx2 = *(char**)(model + ((*(u16*)(model + 0x18) & 1) * 4) + 0xc) + idx2 * 0x40;
                vb[0] = *(f32*)row;
                vb[1] = *(f32*)(t + off + 4);
                vb[2] = *(f32*)(t + off + 8);
                PSMTXMultVec(mtx2, vb, vb);
                vb[0] = vb[0] + playerMapOffsetX;
                vb[2] = vb[2] + playerMapOffsetZ;
                *(f32*)(q + 0x54) = vb[0];
                *(f32*)(q + 0x5c) = vb[1];
                *(f32*)(q + 0x64) = vb[2];
            }
            k += 2;
            off += 0x30;
            q += 4;
            i++;
        }

        if (*(s16*)(base + 0xb0) != 0)
        {
            char* r = base + *(s16*)(base + 0xb2) * 4;
            va[0] = *(f32*)(r + 0x6c);
            va[1] = *(f32*)(r + 0x74);
            va[2] = *(f32*)(r + 0x7c);
            (*(void (**)(int, int, f32*))(*(int*)((GameObject*)staff)->anim.dll + 0x28))(staff, obj, vb);
            va[0] = va[0] - vb[0];
            va[1] = va[1] - vb[1];
            va[2] = va[2] - vb[2];
            ((GameObject*)staff)->anim.rotX = getAngle(va[0], va[2]);
            {
                f32 dx = va[0] * va[0];
                f32 dz = va[2] * va[2];
                ((GameObject*)staff)->anim.rotY = (s16)(-getAngle(va[1], sqrtf(dx + dz)) + 0x4000);
            }
            ((GameObject*)staff)->anim.rotZ = 0;
        }
    }
}
#pragma opt_common_subs reset
#pragma opt_propagation reset

void characterDoEyeAnims(int obj, int state)
{
    extern f32 lbl_803DE9A4;
    ObjTextureRuntimeSlot* a;
    ObjTextureRuntimeSlot* b;

    a = characterFindEyeJoint(obj, 5);
    b = characterFindEyeJoint(obj, 4);

    if (a == NULL || b == NULL)
    {
        return;
    }
    {
        int st;
        int v;

        v = b->textureId;
        st = *(s8*)(state + 0x1e);

        switch (st & 0xf)
        {
        case 0:
            {
                s8 t = *(s8*)(state + 0x1f);
                if (t > 0)
                {
                    *(s8*)(state + 0x1f) = t - framesThisStep;
                }
                else if ((int)randomGetRange(0, 1000) > 0x3de)
                {
                    *(u8*)(state + 0x1e) = 1;
                    *(u8*)(state + 0x1f) = 0;
                }
            }
            break;
        case 1:
            if ((st & 0x80) != 0)
            {
                v = v - framesThisStep * 0x60;
                if (v < 0)
                {
                    v = 0;
                    *(u8*)(state + 0x1e) = 0;
                    *(u8*)(state + 0x1f) = 0;
                }
            }
            else
            {
                v = v + framesThisStep * 0x60;
                if (v > 0x200)
                {
                    if (v - 0x200 < 0)
                    {
                        v = 0;
                        *(u8*)(state + 0x1e) = 0;
                    }
                    else
                    {
                        v = 0x2ff;
                        *(s8*)(state + 0x1e) = -127;
                    }
                    *(u8*)(state + 0x1f) = 0x28;
                }
            }
            a->textureId = v;
            b->textureId = v;
            break;
        }
        characterDoEyeMovements(obj, state, lbl_803DE9A4);
    }
}

void characterDoEyeMovements(int obj, int p4, f32 unused)
{
    ObjTextureRuntimeSlot* foundA;
    ObjTextureRuntimeSlot* foundB;
    s16 t;
    int flag;
    s8 timer;

    foundA = characterFindEyeJoint(obj, 1);
    foundB = characterFindEyeJoint(obj, 0);
    if (foundA == NULL || foundB == NULL)
    {
        return;
    }

    flag = 0;
    t = *(s16*)(p4 + 0x22);
    if (t == 0)
    {
        flag = 1;
    }
    if (t > 0)
    {
        if (foundA->offsetS >= *(int*)(p4 + 0x24))
        {
            flag = 1;
        }
    }
    if (t < 0)
    {
        if (foundA->offsetS <= *(int*)(p4 + 0x24))
        {
            flag = 1;
        }
    }
    if (flag != 0)
    {
        *(int*)(p4 + 0x24) = randomGetRange(-0x3e8, 0x3e8);
        *(s16*)(p4 + 0x22) = (*(int*)(p4 + 0x24) < foundA->offsetS) ? -0x96 : 0x96;
        *(s8*)(p4 + 0x20) = randomGetRange(0x1e, 0x64);
    }
    timer = *(s8*)(p4 + 0x20);
    if (timer > 0)
    {
        *(s8*)(p4 + 0x20) = timer - framesThisStep;
    }
    else
    {
        foundA->offsetS = (s16)(foundA->offsetS + *(s16*)(p4 + 0x22) * framesThisStep);
        foundA->offsetT = 0;
        foundB->offsetS = foundA->offsetS;
        foundB->offsetT = 0;
    }
}

void modelCalcVtxGroupMtxs(int def, int model)
{
    extern void PSMTXTrans(f32* m, f32 x, f32 y, f32 z);
    f32 ma[12];
    f32 mb[12];
    f32 trans[12];
    int off;
    int i;

    for (i = 0, off = 0; i < *(u8*)(def + 0xf4); i++)
    {
        u8* grp;
        f32* out;
        f32* m2;
        f32* m1;
        f32 w;
        f32 wi;
        char* jd;

        grp = (u8*)(*(int*)(def + 0x54) + off);
        out = ObjModel_GetJointMatrix((int*)model, i + *(u8*)(def + 0xf3));
        m1 = ObjModel_GetJointMatrix((int*)model, grp[0]);
        m2 = ObjModel_GetJointMatrix((int*)model, grp[1]);

        w = grp[2];
        w *= 0.25f;
        wi = 1.0f - w;

        jd = (char*)(*(int*)(def + 0x3c) + grp[0] * 0x1c);
        PSMTXTrans(trans, -*(f32*)(jd + 0x10), -*(f32*)(jd + 0x14), -*(f32*)(jd + 0x18));
        PSMTXConcat(m1, trans, ma);
        jd = (char*)(*(int*)(def + 0x3c) + grp[1] * 0x1c);
        PSMTXTrans(trans, -*(f32*)(jd + 0x10), -*(f32*)(jd + 0x14), -*(f32*)(jd + 0x18));
        PSMTXConcat(m2, trans, mb);

        out[0] = ma[0] * w + mb[0] * wi;
        out[1] = ma[1] * w + mb[1] * wi;
        out[2] = ma[2] * w + mb[2] * wi;
        out[3] = ma[3] * w + mb[3] * wi;
        out[4] = ma[4] * w + mb[4] * wi;
        out[5] = ma[5] * w + mb[5] * wi;
        out[6] = ma[6] * w + mb[6] * wi;
        out[7] = ma[7] * w + mb[7] * wi;
        out[8] = ma[8] * w + mb[8] * wi;
        out[9] = ma[9] * w + mb[9] * wi;
        out[10] = ma[10] * w + mb[10] * wi;
        out[11] = ma[11] * w + mb[11] * wi;
        off += 4;
    }
}

typedef struct ObjPrintFlipFlag
{
    u8 flip : 1;
    u8 rest : 7;
} ObjPrintFlipFlag;

#pragma opt_loop_invariants off
int objMathFn_8003a380(int obj, char* tgt, f32* pos, char* p4, s16* spd, int unk6, int p7, f32 yOff)
{
    extern f32 sqrtf(f32);
    extern f32 gObjPrintDegToAngle;
    extern f32 lbl_803DE9D8;
    extern f32 lbl_803DE9DC;
    extern int lbl_803DB460;
    extern ObjPrintFlipFlag lbl_803DCC00;
    s16 src[2];
    s16 dst[2];
    int i;
    s16 ret;
    GameObject* go = (GameObject*)obj;
    s16* found[1];
    s16* sp2;
    f32 dx, dy, dz, dist;

    sp2 = spd + 0xf;
    dx = pos[0] - *(f32*)(tgt + 0xc);
    dz = pos[2] - *(f32*)(tgt + 0x14);
    dy = (pos[1] + yOff) - *(f32*)(tgt + 0x10);
    dist = sqrtf(dx * dx + dz * dz);

    src[0] = (s16)getAngle(dx, dz) - (u16)go->anim.rotX;
    if (src[0] > 0x8000)
    {
        src[0] = (s16)(src[0] - 0xffff);
    }
    if (src[0] < -0x8000)
    {
        src[0] = (s16)(src[0] + 0xffff);
    }
    src[1] = p7 - (u16) - getAngle(dist, dy);
    if (src[1] > 0x8000)
    {
        src[1] = (s16)(src[1] - 0xffff);
    }
    if (src[1] < -0x8000)
    {
        src[1] = (s16)(src[1] + 0xffff);
    }

    ret = src[0];
    if (lbl_803DCC00.flip)
    {
        src[0] -= 0x8000;
        src[1] = -src[1];
        lbl_803DCC00.flip = 0;
    }

    i = 0;
    while (i < 10)
    {
        int key;
        void* m;

        key = lbl_802CAE88[i];
        found[0] = NULL;
        m = (void*)go->anim.modelInstance;
        if (m != NULL)
        {
            int iv[2];
            int n;
            int j;
            iv[0] = (int)found[0];
            iv[1] = (int)found[0];
            n = ((ObjDef*)m)->jointCount;
            for (j = 0; j < n; j++)
            {
                int entries = *(int*)&((ObjDef*)m)->jointData;
                if ((int)*(u8*)(entries + OBJPRINT_ACTIVE_BANK_INDEX(go) + iv[0] + 1) != 0xff &&
                    key == (int)*(u8*)(entries + iv[0]))
                {
                    found[0] = (s16*)((int)go->anim.jointPoseData + iv[1]);
                }
                iv[0] += ((ObjDef*)m)->modelCount + 1;
                iv[1] += 0x12;
            }
        }
        if (found[0] == NULL)
        {
            int t = (s16)ret;
            t = (t >= 0) ? t : -t;
            return (s16)(t < 0x100);
        }

        {
            int n2;
            for (n2 = 0; n2 < 2; n2++)
            {
                int lim;
                s16 v;
                if (n2 % 2 != 0)
                {
                    lim = (s32)(gObjPrintDegToAngle * (f32)sp2[i]);
                }
                else
                {
                    lim = (s32)(gObjPrintDegToAngle * (f32)spd[i]);
                }
                v = src[n2];
                dst[n2] = v;
                if (v > (s16)lim)
                {
                    dst[n2] = lim;
                    src[n2] -= lim;
                }
                else if (v < -(s16)lim)
                {
                    dst[n2] = -(s16)lim;
                    src[n2] += lim;
                }
                else
                {
                    src[n2] = 0;
                }
            }
        }

        if (p4 != NULL)
        {
            *(s16*)(p4 + 0x14) = dst[0];
            fn_800399C0((s16*)p4, found[0]);
            *(s16*)(p4 + 0x44) = dst[1];
            fn_80039834((s16*)(p4 + 0x30), found[0], lbl_803DE9D8, lbl_803DE9DC);
            p4 += 0x60;
        }
        else
        {
            s16* fv = found[0];
            int d1 = (s16)((s16)((fv[1] + dst[0]) >> 1) - fv[1]);
            s16 lim;
            int d2;
            int t2;
            int lim3;

            lim = (d1 < framesThisStep * ((s16)(s32)(gObjPrintDegToAngle * (f32)-spd[i]) / lbl_803DB460))
                      ? framesThisStep * ((s16)(s32)(gObjPrintDegToAngle * (f32)-spd[i]) / lbl_803DB460)
                      : ((d1 > framesThisStep * ((s16)(s32)(gObjPrintDegToAngle * (f32)spd[i]) / lbl_803DB460))
                             ? framesThisStep * ((s16)(s32)(gObjPrintDegToAngle * (f32)spd[i]) / lbl_803DB460)
                             : d1);
            d2 = (s16)((s16)((fv[0] + dst[1]) >> 1) - fv[0]);
            t2 = (s16)(s32)(*(f32*)&gObjPrintDegToAngle * (f32)sp2[i]);
            lim3 = (d2 < framesThisStep * (-t2 / (lbl_803DB460 << 1)))
                       ? framesThisStep * (-t2 / (lbl_803DB460 << 1))
                       : ((d2 > framesThisStep * (t2 / (lbl_803DB460 << 1))) ? framesThisStep * (t2 / (lbl_803DB460 << 1)) : d2);
            fv[0] += (s16)lim3;
            fv[1] += lim;
        }

        if (i == 0)
        {
            ret -= found[0][1];
        }
        i++;
    }
    return src[0];
}
#pragma opt_loop_invariants reset

typedef struct ObjPrintGXColor
{
    u8 r, g, b, a;
} ObjPrintGXColor;

typedef struct IndTexMtx23
{
    f32 m[6];
} IndTexMtx23;

int modelRenderCb_8003c268(int obj, int* model, int ropIdx)
{
    extern u8*ObjModel_GetRenderOp(int m, int p);
    extern void textureFn_8006c4e0(int* tbl, int* cnt);
    extern u32*Shader_getLayer(u8* shader, int idx);
    extern void selectTexture(u8* tex, int mapId);
    extern void GXSetTexCoordGen2(GXTexCoordID dst_coord, GXTexGenType func, GXTexGenSrc src_param, u32 mtx, GXBool normalize, u32 pt_texmtx);

    extern void GXSetTevOrder(GXTevStageID stage, GXTexCoordID coord, GXTexMapID map, GXChannelID color);
    extern void GXSetTevColorIn(GXTevStageID stage, GXTevColorArg a, GXTevColorArg b, GXTevColorArg c, GXTevColorArg d);
    extern void GXSetTevAlphaIn(GXTevStageID stage, GXTevAlphaArg a, GXTevAlphaArg b, GXTevAlphaArg c, GXTevAlphaArg d);
    extern void GXSetTevSwapMode(GXTevStageID stage, GXTevSwapSel ras_sel, GXTevSwapSel tex_sel);
    extern void GXSetTevColorOp(GXTevStageID stage, GXTevOp op, GXTevBias bias, GXTevScale scale, GXBool clamp, GXTevRegID out_reg);
    extern void GXSetTevAlphaOp(GXTevStageID stage, GXTevOp op, GXTevBias bias, GXTevScale scale, GXBool clamp, GXTevRegID out_reg);
    extern void GXSetTevKColor(int id, ObjPrintGXColor c);
    extern void GXSetTevKAlphaSel(GXTevStageID stage, GXTevKAlphaSel sel);
    extern void GXSetTevKColorSel(GXTevStageID stage, GXTevKColorSel sel);
    extern void PSMTXScale(f32* m, f32 x, f32 y, f32 z);
    extern void PSMTXTrans(f32* m, f32 x, f32 y, f32 z);
    extern void GXLoadTexMtxImm(f32* m, int id, int type);
    extern void**ObjModel_GetRenderOpTextureRefs(int* model, int ropIdx);
    extern void getTextureFn_8006c5e4(int* out);
    extern void newshadows_getReflectionScrollOffsets(f32 * x, f32 * y);


    extern void GXSetIndTexMtx(int id, IndTexMtx23* m, int scale);

    extern void GXSetNumTevStages(u8 nStages);
    extern void GXSetNumTexGens(u8 nTexGens);
    extern void* objCreateLight(int arg, u8 addToList);
    extern void modelLightStruct_setLightKind(int* lt, int v);
    extern void modelLightStruct_setDirection(int* lt, f32 x, f32 y, f32 z);
    extern void modelLightStruct_setDiffuseColor(int* lt, int r, int g, int b, int a);
    extern void GXSetChanAmbColor(int chan, ObjPrintGXColor c);
    extern void GXSetChanMatColor(int chan, ObjPrintGXColor c);
    extern void modelLightStruct_loadChannelLight(int chan, int* lt, int obj);
    extern void ModelLightStruct_free(int* lt);
    extern void fn_8006C4C0(int* a, int* b, int* c);

    extern void GXSetFog(int type, f32 a, f32 b, f32 c, f32 d, ObjPrintGXColor color);
    extern void GXSetBlendMode(GXBlendMode type, GXBlendFactor src_factor, GXBlendFactor dst_factor, GXLogicOp op);
    extern IndTexMtx23 lbl_802C1B40;
    extern IndTexMtx23 lbl_802C1B58;
    extern int lbl_803DCC44;
    extern u8 lbl_803DCC3E;
    extern u8 lbl_803DCC3D;
    extern u32 lbl_803DE9FC;
    extern u32 lbl_803DEA00;
    extern u32 lbl_803DB470;
    extern u32 lbl_803DB468;
    extern int lbl_803DB498;
    extern int lbl_803DB49C;
    extern f32 lbl_803DEA28;
    extern f32 lbl_803DEA2C;
    extern f32 lbl_803DEA30;
    extern f32 lbl_803DEA34;
    extern f32 lbl_803DEA38;
    extern f32 lbl_803DEA04;
    extern f32 lbl_803DEA1C;
    f32 mtx4[12];
    f32 mtx3[12];
    f32 mtx2[12];
    f32 mtxR[12];
    f32 mtx5[12];
    IndTexMtx23 mtxA;
    IndTexMtx23 mtxB;
    ObjPrintGXColor kc;
    int texTbl;
    int texCnt;
    int t164;
    f32 sx;
    f32 sy;
    ObjPrintGXColor kc2;
    int a174;
    int b178;
    int stk380;
    u8* rop;
    f32 fz;
    u8 v;

    kc = *(ObjPrintGXColor*)&lbl_803DE9FC;
    mtxA = lbl_802C1B40;
    mtxB = lbl_802C1B58;
    rop = ObjModel_GetRenderOp(*model, ropIdx);
    if ((*(u32*)(rop + 0x3c) & 0x200) == 0)
    {
        if ((lbl_803DCC44 & 3) != 0)
        {
            lbl_803DCC3E = 0;
            return 0;
        }
        lbl_803DCC3E = 1;
        objRenderFuzzFn_8003d6f8(obj);
        return 1;
    }
    lbl_803DCC3E = 1;
    textureFn_8006c4e0(&texTbl, &texCnt);
    fz = (f32)(s32)lbl_803DCC44 / (f32)(s32)texCnt;
    fz = fz * fz;
    fz = fz * lbl_803DEA28;
    selectTexture(textureIdxToPtr(*Shader_getLayer(rop, 0)), 0);
    GXSetTexCoordGen2(GX_TEXCOORD2, GX_TG_MTX2x4, GX_TG_TEX0, 0x3c, GX_FALSE, 0x7d);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD2, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_TEXC);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_FALSE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    v = *(u8*)(obj + 0xf1);
    kc.b = v;
    kc.g = v;
    kc.r = v;
    GXSetTevKColor(GX_KCOLOR0, kc);
    GXSetTevKAlphaSel(GX_TEVSTAGE1, GX_TEV_KASEL_K0_A);
    GXSetTevKColorSel(GX_TEVSTAGE1, GX_TEV_KCSEL_K0);
    PSMTXScale(mtx3, lbl_803DEA2C, *(f32*)&lbl_803DEA2C, lbl_803DEA04);
    PSMTXTrans(mtx2, lbl_803DEA28, *(f32*)&lbl_803DEA28, lbl_803DEA1C);
    PSMTXConcat(mtx2, mtx3, mtx3);
    GXLoadTexMtxImm(mtx3, 0x43, 0);
    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX2x4, GX_TG_NRM, 0x1e, GX_FALSE, 0x43);
    selectTexture(*ObjModel_GetRenderOpTextureRefs(model, ropIdx), 1);
    GXSetTevDirect(GX_TEVSTAGE1);
    GXSetTevOrder(GX_TEVSTAGE1, GX_TEXCOORD0, GX_TEXMAP1, GX_COLOR0A0);
    GXSetTevSwapMode(GX_TEVSTAGE1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorIn(GX_TEVSTAGE1, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_RASC);
    GXSetTevAlphaIn(GX_TEVSTAGE1, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevColorOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
    GXSetTevAlphaOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    getTextureFn_8006c5e4(&t164);
    selectTexture((void*)t164, 4);
    newshadows_getReflectionScrollOffsets(&sx, &sy);
    PSMTXTrans(mtxR, lbl_803DEA28 * sx, *(f32*)&lbl_803DEA28 * sy, lbl_803DEA04);
    mtxR[0] = lbl_803DEA1C;
    mtxR[5] = lbl_803DEA1C;
    GXLoadTexMtxImm(mtxR, 0x46, 0);
    GXSetTexCoordGen2(GX_TEXCOORD1, GX_TG_MTX2x4, GX_TG_TEX0, 0x3c, GX_FALSE, 0x46);
    GXSetIndTexOrder(GX_INDTEXSTAGE0, GX_TEXCOORD1, GX_TEXMAP4);
    GXSetIndTexCoordScale(0, 0, 0);
    mtxA.m[0] = fz;
    mtxA.m[4] = fz;
    GXSetIndTexMtx(GX_ITM_0, &mtxA, (s8)lbl_803DB498);
    GXSetTevIndirect(2, 0, 0, 7, 1, 6, 6, 0, 0, 0);
    GXSetTevOrder(GX_TEVSTAGE2, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    GXSetTevSwapMode(GX_TEVSTAGE2, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorIn(GX_TEVSTAGE2, GX_CC_ZERO, GX_CC_CPREV, GX_CC_C1, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE2, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevColorOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    selectTexture(textureIdxToPtr(*(int*)(rop + 0x38)), 2);
    GXSetTexCoordGen2(GX_TEXCOORD3, GX_TG_MTX2x4, GX_TG_TEX0, 0x3c, GX_FALSE, 0x7d);
    GXSetIndTexOrder(GX_INDTEXSTAGE1, GX_TEXCOORD3, GX_TEXMAP2);
    GXSetIndTexCoordScale(1, 0, 0);
    mtxB.m[1] = fz;
    mtxB.m[5] = fz;
    GXSetIndTexMtx(GX_ITM_1, &mtxB, (s8)lbl_803DB49C);
    GXSetTevIndirect(3, 1, 0, 7, 2, 0, 0, 1, 0, 1);
    selectTexture(*(void**)(texTbl + lbl_803DCC44 * 4), 3);
    PSMTXScale(mtx4, lbl_803DEA30, *(f32*)&lbl_803DEA30, lbl_803DEA1C);
    GXLoadTexMtxImm(mtx4, 0x40, 0);
    GXSetTexCoordGen2(GX_TEXCOORD4, GX_TG_MTX2x4, GX_TG_TEX0, 0x3c, GX_TRUE, 0x40);
    GXSetTevKColorSel(GX_TEVSTAGE3, GX_TEV_KCSEL_1_2);
    GXSetTevOrder(GX_TEVSTAGE3, GX_TEXCOORD4, GX_TEXMAP3, GX_ALPHA_BUMPN);
    GXSetTevColorIn(GX_TEVSTAGE3, GX_CC_TEXC, GX_CC_KONST, GX_CC_CPREV, GX_CC_CPREV);
    GXSetTevAlphaIn(GX_TEVSTAGE3, GX_CA_ZERO, GX_CA_TEXA, GX_CA_RASA, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE3, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE3, GX_TEV_SUB, GX_TB_ADDHALF, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE3, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    if (lbl_803DCC44 < 0xc)
    {
        GXSetNumTevStages(4);
        GXSetNumIndStages(2);
        GXSetNumTexGens(5);
    }
    else
    {
        int* lt;
        kc2 = *(ObjPrintGXColor*)&lbl_803DEA00;
        lt = objCreateLight(obj, 0);
        if (lt != NULL)
        {
            modelLightStruct_setLightKind(lt, 4);
            modelLightStruct_setDirection(lt, lbl_803DEA04, lbl_803DEA34, *(f32*)&lbl_803DEA04);
            modelLightStruct_setDiffuseColor(lt, 0xff, 0xff, 0xff, 0xff);
            modelLightChannels_reset(0);
            modelLightChannel_configure(2, 0, 0);
            GXSetChanAmbColor(GX_ALPHA0, *(ObjPrintGXColor*)&lbl_803DB470);
            GXSetChanMatColor(2, *(ObjPrintGXColor*)&lbl_803DB468);
            modelLightStruct_loadChannelLight(2, lt, obj);
            modelLightChannels_applyGXControls();
            ModelLightStruct_free(lt);
        }
        GXSetTevKColor(GX_KCOLOR0, kc2);
        GXSetTevKAlphaSel(GX_TEVSTAGE5, GX_TEV_KASEL_K0_A);
        GXSetTevKColorSel(GX_TEVSTAGE5, GX_TEV_KCSEL_K0);
        fn_8006C4C0(&a174, &b178, &stk380);
        selectTexture(*(void**)(a174 + ((lbl_803DCC44 - 0xc) + lbl_803DCC3D * b178) * 4), 5);
        PSMTXScale(mtx5, lbl_803DEA38, *(f32*)&lbl_803DEA38, lbl_803DEA1C);
        GXLoadTexMtxImm(mtx5, 0x49, 0);
        GXSetTexCoordGen2(GX_TEXCOORD5, GX_TG_MTX2x4, GX_TG_TEX0, 0x3c, GX_TRUE, 0x49);
        GXSetTevDirect(GX_TEVSTAGE4);
        GXSetTevOrder(GX_TEVSTAGE4, GX_TEXCOORD5, GX_TEXMAP5, GX_COLOR0A0);
        GXSetTevColorIn(GX_TEVSTAGE4, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_CPREV);
        GXSetTevAlphaIn(GX_TEVSTAGE4, GX_CA_ZERO, GX_CA_TEXA, GX_CA_RASA, GX_CA_ZERO);
        GXSetTevSwapMode(GX_TEVSTAGE4, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(GX_TEVSTAGE4, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevAlphaOp(GX_TEVSTAGE4, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
        GXSetTevDirect(GX_TEVSTAGE5);
        GXSetTevOrder(GX_TEVSTAGE5, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
        GXSetTevColorIn(GX_TEVSTAGE5, GX_CC_CPREV, GX_CC_KONST, GX_CC_A1, GX_CC_ZERO);
        GXSetTevAlphaIn(GX_TEVSTAGE5, GX_CA_APREV, GX_CA_A1, GX_CA_A1, GX_CA_ZERO);
        GXSetTevSwapMode(GX_TEVSTAGE5, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(GX_TEVSTAGE5, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevAlphaOp(GX_TEVSTAGE5, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetNumTevStages(6);
        GXSetNumIndStages(2);
        GXSetNumTexGens(6);
    }
    GXSetCullMode(GX_CULL_BACK);
    {
        GXSetFog(GX_FOG_NONE, lbl_803DEA04, lbl_803DEA04, lbl_803DEA04, lbl_803DEA04, *(ObjPrintGXColor*)&lbl_803DB468);
    }
    gxSetZMode_(1, 3, 0);
    gxSetPeControl_ZCompLoc_(1);
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    return 1;
}

typedef struct ObjPrintS10Color
{
    s16 r, g, b, a;
} ObjPrintS10Color;

int shaderFuzzFn_8003cc1c(int obj, int* model, int ropIdx)
{
    extern u8*ObjModel_GetRenderOp(int m, int p);
    extern void textureFn_8006c4e0(int* tbl, int* cnt);
    extern u32*Shader_getLayer(u8* shader, int idx);
    extern void selectTexture(u8* tex, int mapId);
    extern void GXSetTexCoordGen2(GXTexCoordID dst_coord, GXTexGenType func, GXTexGenSrc src_param, u32 mtx, GXBool normalize, u32 pt_texmtx);

    extern void GXSetTevOrder(GXTevStageID stage, GXTexCoordID coord, GXTexMapID map, GXChannelID color);
    extern void GXSetTevColorIn(GXTevStageID stage, GXTevColorArg a, GXTevColorArg b, GXTevColorArg c, GXTevColorArg d);
    extern void GXSetTevAlphaIn(GXTevStageID stage, GXTevAlphaArg a, GXTevAlphaArg b, GXTevAlphaArg c, GXTevAlphaArg d);
    extern void GXSetTevSwapMode(GXTevStageID stage, GXTevSwapSel ras_sel, GXTevSwapSel tex_sel);
    extern void GXSetTevColorOp(GXTevStageID stage, GXTevOp op, GXTevBias bias, GXTevScale scale, GXBool clamp, GXTevRegID out_reg);
    extern void GXSetTevAlphaOp(GXTevStageID stage, GXTevOp op, GXTevBias bias, GXTevScale scale, GXBool clamp, GXTevRegID out_reg);
    extern void GXSetTevKColor(int id, ObjPrintGXColor c);
    extern void GXSetTevKAlphaSel(GXTevStageID stage, GXTevKAlphaSel sel);
    extern void GXSetTevKColorSel(GXTevStageID stage, GXTevKColorSel sel);
    extern void GXSetTevColorS10(int id, ObjPrintS10Color c);
    extern void PSMTXScale(f32* m, f32 x, f32 y, f32 z);
    extern void PSMTXTrans(f32* m, f32 x, f32 y, f32 z);
    extern void GXLoadTexMtxImm(f32* m, int id, int type);
    extern void**ObjModel_GetRenderOpTextureRefs(int* model, int ropIdx);
    extern void getTextureFn_8006c5e4(int* out);
    extern void newshadows_getReflectionScrollOffsets(f32 * x, f32 * y);


    extern void GXSetIndTexMtx(int id, IndTexMtx23* m, int scale);

    extern void GXSetNumTevStages(u8 nStages);
    extern void GXSetNumTexGens(u8 nTexGens);

    extern void GXSetFog(int type, f32 a, f32 b, f32 c, f32 d, ObjPrintGXColor color);
    extern void GXSetBlendMode(GXBlendMode type, GXBlendFactor src_factor, GXBlendFactor dst_factor, GXLogicOp op);
    extern void modelLightStruct_getProjectionTevModes(int p, int* a, int* b);
    extern f32*modelLightStruct_getProjectionTexMtx(int p);
    extern void*modelLightStruct_getProjectionTexture(int p);

    extern IndTexMtx23 lbl_802C1B10;
    extern IndTexMtx23 lbl_802C1B28;
    extern ObjPrintS10Color lbl_803DE9F4;
    extern ObjPrintGXColor lbl_803DB494;
    extern int lbl_803DCC44;
    extern u8 lbl_803DCC3E;
    extern u8 lbl_803DCC35;
    extern u8 lbl_803DCC36;
    extern int lbl_803DCC5C;
    extern u8 lbl_803DCC60;
    extern int lbl_803DCC64;
    extern u32 lbl_803DB468;
    extern int lbl_803DB48C;
    extern int lbl_803DB490;
    extern f32 lbl_803DEA28;
    extern f32 lbl_803DEA2C;
    extern f32 lbl_803DEA30;
    extern f32 lbl_803DEA04;
    extern f32 lbl_803DEA1C;
    f32 mtx4[12];
    f32 mtx3[12];
    f32 mtx2[12];
    f32 mtxR[12];
    IndTexMtx23 mtxA;
    IndTexMtx23 mtxB;
    ObjPrintS10Color s10;
    int coord;
    int texTbl;
    int texCnt;
    int t150;
    f32 sx;
    f32 sy;
    int stk348;
    u8* rop;
    f32 fz;
    int stage;
    int t160;
    u8 fancy;

    s10 = lbl_803DE9F4;
    mtxA = lbl_802C1B10;
    mtxB = lbl_802C1B28;
    rop = ObjModel_GetRenderOp(*model, ropIdx);
    if ((*(u32*)(rop + 0x3c) & 0x200) == 0)
    {
        lbl_803DCC3E = 0;
        return 0;
    }
    lbl_803DCC3E = 1;
    textureFn_8006c4e0(&texTbl, &texCnt);
    if (lbl_803DCC35 != 0)
    {
        fz = lbl_803DEA04;
    }
    else
    {
        fz = (f32)(s32)lbl_803DCC44 / (f32)(s32)texCnt;
        fz = fz * lbl_803DEA28;
    }
    selectTexture(textureIdxToPtr(*Shader_getLayer(rop, 0)), 0);
    GXSetTexCoordGen2(GX_TEXCOORD2, GX_TG_MTX2x4, GX_TG_TEX0, 0x3c, GX_FALSE, 0x7d);
    if (lbl_803DCC36 == 0)
    {
        GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_TEXC);
    }
    else
    {
        if (lbl_803DCC36 == 1)
        {
            u8 v = lbl_803DCC44 << 4;
            lbl_803DB494.b = v;
            lbl_803DB494.g = v;
            lbl_803DB494.r = v;
            GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_TEXC, GX_CC_ONE, GX_CC_KONST, GX_CC_ZERO);
        }
        else
        {
            if (lbl_803DCC44 < 8)
            {
                lbl_803DB494.b = lbl_803DCC44 << 5;
            }
            else
            {
                lbl_803DB494.b = 0xff;
            }
            lbl_803DB494.g = lbl_803DB494.b;
            lbl_803DB494.r = lbl_803DB494.b;
            GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_TEXC, GX_CC_ZERO, GX_CC_KONST, GX_CC_ZERO);
        }
        GXSetTevKColor(GX_KCOLOR1, lbl_803DB494);
        GXSetTevKAlphaSel(GX_TEVSTAGE0, GX_TEV_KASEL_K1_A);
        GXSetTevKColorSel(GX_TEVSTAGE0, GX_TEV_KCSEL_K1);
    }
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD2, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_FALSE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    {
        u8 v = *(u8*)(obj + 0xf1);
        s10.b = v;
        s10.g = v;
        s10.r = v;
        s10.a = *(u8*)(obj + 0x37) - 0xff;
    }
    GXSetTevColorS10(3, s10);
    PSMTXScale(mtx3, lbl_803DEA2C, *(f32*)&lbl_803DEA2C, lbl_803DEA04);
    PSMTXTrans(mtx2, lbl_803DEA28, *(f32*)&lbl_803DEA28, lbl_803DEA1C);
    PSMTXConcat(mtx2, mtx3, mtx3);
    GXLoadTexMtxImm(mtx3, 0x43, 0);
    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX2x4, GX_TG_NRM, 0x1e, GX_FALSE, 0x43);
    selectTexture(*ObjModel_GetRenderOpTextureRefs(model, ropIdx), 1);
    GXSetTevDirect(GX_TEVSTAGE1);
    GXSetTevOrder(GX_TEVSTAGE1, GX_TEXCOORD0, GX_TEXMAP1, GX_COLOR0A0);
    GXSetTevSwapMode(GX_TEVSTAGE1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorIn(GX_TEVSTAGE1, GX_CC_ZERO, GX_CC_TEXC, GX_CC_C2, GX_CC_RASC);
    GXSetTevAlphaIn(GX_TEVSTAGE1, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_A2);
    GXSetTevColorOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
    GXSetTevAlphaOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_FALSE, GX_TEVPREV);
    if (lbl_803DCC5C != 0)
    {
        int stk364;
        int t170;
        modelLightStruct_getProjectionTevModes(lbl_803DCC64, &t170, &stk364);
        if (t170 != 0)
        {
            goto notfancy;
        }
        fancy = 1;
    }
    else
    {
    notfancy:
        fancy = 0;
    }
    if (fancy)
    {
        GXSetTevDirect(GX_TEVSTAGE2);
        GXLoadTexMtxImm(modelLightStruct_getProjectionTexMtx(lbl_803DCC64), 0x49, 0);
        GXSetTexCoordGen2(GX_TEXCOORD1, GX_TG_MTX3x4, GX_TG_POS, 0, GX_FALSE, 0x49);
        if (lbl_803DCC60 == 0 || lbl_803DCC60 == 2)
        {
            GXSetTevOrder(GX_TEVSTAGE2, GX_TEXCOORD1, GX_TEXMAP5, GX_COLOR0A0);
        }
        else
        {
            GXSetTevOrder(GX_TEVSTAGE2, GX_TEXCOORD1, GX_TEXMAP5, GX_COLOR1A1);
        }
        selectTexture(modelLightStruct_getProjectionTexture(lbl_803DCC64), 5);
        modelLightStruct_getProjectionTevModes(lbl_803DCC64, &stk348, &t160);
        if (t160 == 2)
        {
            GXSetTevColorIn(GX_TEVSTAGE2, GX_CC_ZERO, GX_CC_C1, GX_CC_TEXC, GX_CC_ZERO);
        }
        else if (t160 == 3)
        {
            GXSetTevColorIn(GX_TEVSTAGE2, GX_CC_C1, GX_CC_ZERO, GX_CC_TEXC, GX_CC_ZERO);
        }
        else if (t160 == 1)
        {
            GXSetTevColorIn(GX_TEVSTAGE2, GX_CC_ZERO, GX_CC_ZERO, GX_CC_TEXC, GX_CC_C1);
        }
        else if (lbl_803DCC60 == 0 || lbl_803DCC60 == 1)
        {
            GXSetTevColorIn(GX_TEVSTAGE2, GX_CC_ZERO, GX_CC_RASC, GX_CC_TEXC, GX_CC_C1);
        }
        else
        {
            GXSetTevColorIn(GX_TEVSTAGE2, GX_CC_ZERO, GX_CC_RASA, GX_CC_TEXC, GX_CC_C1);
        }
        GXSetTevSwapMode(GX_TEVSTAGE2, GX_TEV_SWAP0, GX_TEV_SWAP0);
        if (t160 == 1)
        {
            GXSetTevColorOp(GX_TEVSTAGE2, GX_TEV_SUB, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
        }
        else
        {
            GXSetTevColorOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
        }
        GXSetTevAlphaIn(GX_TEVSTAGE2, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
        GXSetTevAlphaOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        stage = 3;
        coord = 5;
    }
    else
    {
        stage = 2;
        coord = 1;
    }
    getTextureFn_8006c5e4(&t150);
    selectTexture((void*)t150, 4);
    newshadows_getReflectionScrollOffsets(&sx, &sy);
    PSMTXTrans(mtxR, lbl_803DEA28 * sx, *(f32*)&lbl_803DEA28 * sy, lbl_803DEA04);
    mtxR[0] = lbl_803DEA1C;
    mtxR[5] = lbl_803DEA1C;
    GXLoadTexMtxImm(mtxR, 0x46, 0);
    GXSetTexCoordGen2(coord, 1, 4, 0x3c, 0, 0x46);
    GXSetIndTexOrder(GX_INDTEXSTAGE0, coord, GX_TEXMAP4);
    GXSetIndTexCoordScale(0, 0, 0);
    mtxA.m[0] = fz;
    mtxA.m[4] = fz;
    GXSetIndTexMtx(GX_ITM_0, &mtxA, (s8)lbl_803DB48C);
    GXSetTevIndirect(stage, 0, 0, 7, 1, 6, 6, 0, 0, 0);
    GXSetTevOrder(stage, 0xff, 0xff, 0xff);
    GXSetTevSwapMode(stage, 0, 0);
    GXSetTevColorIn(stage, 0xf, 0, 4, 0xf);
    GXSetTevAlphaIn(stage, 7, 7, 7, 0);
    GXSetTevColorOp(stage, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(stage, 0, 0, 0, 0, 0);
    if (*(void**)(rop + 0x38) != NULL)
    {
        selectTexture(textureIdxToPtr(*(int*)(rop + 0x38)), 2);
        GXSetTexCoordGen2(GX_TEXCOORD3, GX_TG_MTX2x4, GX_TG_TEX0, 0x3c, GX_FALSE, 0x7d);
        GXSetIndTexOrder(GX_INDTEXSTAGE1, GX_TEXCOORD3, GX_TEXMAP2);
        GXSetIndTexCoordScale(1, 0, 0);
        mtxB.m[1] = fz;
        mtxB.m[5] = fz;
        GXSetIndTexMtx(GX_ITM_1, &mtxB, (s8)lbl_803DB490);
        GXSetTevIndirect(stage + 1, 1, 0, 7, 2, 0, 0, 1, 0, 1);
    }
    else
    {
        GXSetIndTexOrder(GX_INDTEXSTAGE1, GX_TEXCOORD3, GX_TEXMAP2);
        GXSetIndTexCoordScale(1, 0, 0);
        mtxB.m[1] = lbl_803DEA04;
        mtxB.m[5] = lbl_803DEA04;
        GXSetIndTexMtx(GX_ITM_1, &mtxB, -0xf);
        GXSetTevIndirect(stage + 1, 1, 0, 7, 2, 0, 0, 1, 0, 0);
    }
    selectTexture(*(void**)(texTbl + lbl_803DCC44 * 4), 3);
    PSMTXScale(mtx4, lbl_803DEA30, *(f32*)&lbl_803DEA30, lbl_803DEA1C);
    GXLoadTexMtxImm(mtx4, 0x40, 0);
    GXSetTexCoordGen2(GX_TEXCOORD4, GX_TG_MTX2x4, GX_TG_TEX0, 0x3c, GX_TRUE, 0x40);
    GXSetTevKColorSel(stage + 1, 4);
    if (*(void**)(rop + 0x38) != NULL)
    {
        GXSetTevOrder(stage + 1, 4, 3, 8);
        GXSetTevAlphaIn(stage + 1, 7, 4, 5, 0);
    }
    else
    {
        GXSetTevOrder(stage + 1, 4, 3, 0xff);
        GXSetTevAlphaIn(stage + 1, 4, 7, 7, 0);
    }
    GXSetTevColorIn(stage + 1, 8, 0xe, 0, 0);
    GXSetTevSwapMode(stage + 1, 0, 0);
    GXSetTevColorOp(stage + 1, 1, 1, 0, 1, 0);
    GXSetTevAlphaOp(stage + 1, 0, 0, 0, 1, 0);
    if (fancy)
    {
        GXSetNumTevStages(5);
        GXSetNumTexGens(6);
    }
    else
    {
        GXSetNumTevStages(4);
        GXSetNumTexGens(5);
    }
    GXSetNumIndStages(2);
    GXSetCullMode(GX_CULL_BACK);
    if ((*(u16*)(*model + 2) & 0x100) != 0)
    {
        GXSetFog(GX_FOG_NONE, lbl_803DEA04, lbl_803DEA04, lbl_803DEA04, lbl_803DEA04, *(ObjPrintGXColor*)&lbl_803DB468);
    }
    else
    {
        _gxSetFogParams();
    }
    gxSetZMode_(1, 3, 0);
    gxSetPeControl_ZCompLoc_(1);
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    return 1;
}
