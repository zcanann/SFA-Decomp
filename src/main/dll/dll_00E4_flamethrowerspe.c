/* DLL 0x00E4 (flamethrowerspe) - Flame thrower special effect [0x80170004-0x801702D4). */
#include "main/dll/xyzanimator.h"
#include "main/dll/genpropswgpipe_struct.h"

extern u32 ObjHitbox_SetSphereRadius();
extern u32 ObjHits_SetHitVolumeSlot();
extern u32 FUN_8003b818();

void mikabomb_hitDetect(void);

void mikabomb_free(int obj, int mode);

int mikabomb_getExtraSize(void);
int mikabomb_getObjectTypeId(void);

extern int kaldachompspit_getObjectTypeId(void);
extern int kaldachompspit_getExtraSize(void);

ObjectDescriptor gKaldaChompSpitObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)kaldachompspit_initialise,
    (ObjectDescriptorCallback)kaldachompspit_release,
    0,
    (ObjectDescriptorCallback)kaldachompspit_init,
    (ObjectDescriptorCallback)kaldachompspit_update,
    (ObjectDescriptorCallback)kaldachompspit_hitDetect,
    (ObjectDescriptorCallback)kaldachompspit_render,
    (ObjectDescriptorCallback)kaldachompspit_free,
    (ObjectDescriptorCallback)kaldachompspit_getObjectTypeId,
    kaldachompspit_getExtraSize,
};

ObjectDescriptor gPinPonSpikeObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)pinponspike_initialise,
    (ObjectDescriptorCallback)pinponspike_release,
    0,
    (ObjectDescriptorCallback)pinponspike_init,
    (ObjectDescriptorCallback)pinponspike_update,
    (ObjectDescriptorCallback)pinponspike_hitDetect,
    (ObjectDescriptorCallback)pinponspike_render,
    (ObjectDescriptorCallback)pinponspike_free,
    (ObjectDescriptorCallback)pinponspike_getObjectTypeId,
    pinponspike_getExtraSize,
};

ObjectDescriptor gPollenObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)pollen_initialise,
    (ObjectDescriptorCallback)pollen_release,
    0,
    (ObjectDescriptorCallback)pollen_init,
    (ObjectDescriptorCallback)pollen_update,
    (ObjectDescriptorCallback)pollen_hitDetect,
    (ObjectDescriptorCallback)pollen_render,
    (ObjectDescriptorCallback)pollen_free,
    (ObjectDescriptorCallback)pollen_getObjectTypeId,
    pollen_getExtraSize,
};

PollenFragmentConfig lbl_80320538 = {
    0x0000,
    0x049F,
    0x00B9,
    0x04BA,
    0x04BA,
    -1,
    0.2f,
    0x0000,
    0xC000,
};

PollenFragmentConfig lbl_8032054C = {
    0x02FA,
    0x02FB,
    0x0496,
    0x068F,
    0x068F,
    0x068F,
    0.4f,
    0x0026,
    0x7000,
};

PollenFragmentConfig lbl_80320560 = {
    0x02FA,
    0x02FB,
    0x0496,
    0x068F,
    0x068F,
    0x068F,
    0.4f,
    0x0026,
    0x2000,
};

PollenFragmentConfig lbl_80320574 = {
    0x02FA,
    0x02FB,
    0x0496,
    0x068F,
    0x068F,
    -1,
    0.2f,
    0x0000,
    0x2000,
};

PollenFragmentConfig lbl_80320588 = {
    0x02FA,
    0x02FB,
    0x0496,
    0x068F,
    0x068F,
    0x068F,
    0.4f,
    0x0026,
    0x3000,
};

PollenFragmentConfig* lbl_8032059C[] = {
    &lbl_80320538,
    &lbl_8032054C,
    &lbl_80320560,
    &lbl_80320574,
    &lbl_80320588,
};

ObjectDescriptor gPollenFragmentObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)pollenfragment_initialise,
    (ObjectDescriptorCallback)pollenfragment_release,
    0,
    (ObjectDescriptorCallback)pollenfragment_init,
    (ObjectDescriptorCallback)pollenfragment_update,
    (ObjectDescriptorCallback)pollenfragment_hitDetect,
    (ObjectDescriptorCallback)pollenfragment_render,
    (ObjectDescriptorCallback)pollenfragment_free,
    (ObjectDescriptorCallback)pollenfragment_getObjectTypeId,
    pollenfragment_getExtraSize,
};

#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/genprops.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/dll_00C8_depthoffieldpoint.h"
#include "main/dll/dll_00E3_fireball.h"
#include "main/dll/dll_00E4_flamethrowerspe.h"
#include "main/engine_shared.h"

typedef struct FlamethrowerspeState
{
    u8 pad0[0x4 - 0x0];
    f32 lifeTimer;
    f32 sizeScale;
    f32 sphereRadius;
    s32 phase;
    u8 pad14[0x18 - 0x14];
    u8 unk18;
    u8 pad19[0x24 - 0x19];
    f32 unk24;
    s32 unk28;
    f32 unk2C;
    u8 pad30[0x50 - 0x30];
    f32 unk50;
    u8 pad54[0x6A - 0x54];
    s16 unk6A;
    u8 pad6C[0x6E - 0x6C];
    s16 unk6E;
    u8 unk70;
    u8 pad71[0x94 - 0x71];
    s32 unk94;
    s32 unk98;
    u8 pad9C[0xAA - 0x9C];
    u8 unkAA;
    u8 padAB[0xB0 - 0xAB];
    s16 unkB0;
    u8 padB2[0xE8 - 0xB2];
    s32 unkE8;
    u8 padEC[0x114 - 0xEC];
    s16 unk114;
    s16 unk116;
} FlamethrowerspeState;

/* FlamethrowerspeState.phase values */
#define FLAMETHROWERSPE_PHASE_LAUNCH 1 /* compute launch velocity, then -> ACTIVE */
#define FLAMETHROWERSPE_PHASE_ACTIVE 2 /* fly + shrink until the lifetime timer expires */

extern u32 FUN_80006810();
extern u64 FUN_80006824();
extern u32 FUN_8001753c();
extern u32 FUN_80017588();
extern u32 FUN_8001759c();
extern u32 FUN_800175b0();
extern u32 FUN_800175bc();
extern u32 FUN_800175cc();
extern u32 FUN_800175d0();
extern u32 FUN_800175d8();
extern u32 FUN_800175ec();
extern void* FUN_80017624();
extern u32 FUN_80017688();
extern u32 FUN_80017690();
extern u64 FUN_80017698();
extern int FUN_80017a54();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern u32 FUN_80017ac8();
extern u64 FUN_8002fc3c();
extern void ObjGroup_RemoveObject(u32 obj, int group);
extern void ObjGroup_AddObject(u32 obj, int group);
extern u32 FUN_800810f8();
extern u32 FUN_80081118();
extern u64 FUN_800e842c();
extern int FUN_80286838();
extern u32 FUN_80286884();
extern u32 fcos16Precise();
extern u32 FUN_80294c48();
extern u32 FUN_80294c60();
extern int FUN_80294cf8();
extern int FUN_80294d10();
extern u32 FUN_80294d60();
extern u32 FUN_80294d6c();
extern u32 DAT_80321678;
extern int DAT_80321688;
extern u32 DAT_80321698;
extern int DAT_803216a8;
extern u32 DAT_803ad324;
extern u32 DAT_803ad328;
extern u32 DAT_803ad32c;
extern u32 DAT_803ad330;
extern u32 DAT_803ad334;
extern u32 DAT_803ad338;
extern f64 DOUBLE_803e4068;
extern f32 lbl_803DC074;
extern f32 lbl_803E3F20;
extern f32 lbl_803E3F24;
extern f32 lbl_803E3F28;
extern f32 lbl_803E3F2C;
extern f32 lbl_803E3F30;
extern f32 lbl_803E3F34;
extern f32 lbl_803E3F38;
extern f32 lbl_803E3F3C;
extern f32 lbl_803E3F40;
extern f32 lbl_803E3F44;
extern f32 lbl_803E3F48;
extern f32 lbl_803E3F4C;
extern f32 lbl_803E3F50;
extern f32 lbl_803E3F54;
extern f32 lbl_803E3F58;
extern f32 lbl_803E3F5C;
extern f32 lbl_803E3F60;
extern f32 lbl_803E3F64;
extern f32 lbl_803E3F68;
extern f32 lbl_803E3F6C;
extern f32 lbl_803E3F70;
extern f32 lbl_803E3F74;
extern f32 lbl_803E3F78;
extern f32 lbl_803E3F7C;
extern f32 lbl_803E3F80;
extern f32 lbl_803E3F84;
extern f32 lbl_803E3F88;
extern f32 lbl_803E3F8C;
extern f32 lbl_803E3FA4;
extern f32 lbl_803E3FA8;
extern f32 lbl_803E3FC4;
extern f32 lbl_803E4040;
extern f32 lbl_803E4044;
extern f32 lbl_803E4048;
extern f32 lbl_803E404C;
extern f32 lbl_803E4050;
extern f32 lbl_803E4054;
extern f32 lbl_803E4058;
extern f32 lbl_803E405C;
extern f32 lbl_803E4060;
extern f32 lbl_803E4064;
extern f32 lbl_803E40E8;
extern f32 lbl_803E40EC;
extern f32 lbl_803E3420;
extern void gcbaddieshield_update(int* obj);








extern void shield_update(int* obj);
extern void dll_F7_update(int* obj);
extern void dll_F7_init(int* obj, int* params);
extern f32 lbl_803E3388;
extern f32 lbl_803E33A0;
extern f32 lbl_803DBD60;
extern f32 lbl_803E338C;
extern void vecRotateZXY(int* obj, f32* p);
extern void firepipe_releaseEffectObject(int* obj);
extern f32 lbl_803E3390;
extern f32 lbl_803E3394;
extern f32 lbl_803DBD68;
extern f32 lbl_803DBD6C;
extern int lbl_803DBD64;

void staticCamera_free(int obj)
{
    ObjGroup_RemoveObject(obj, 7);
    return;
}

void staticCamera_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        FUN_8003b818(obj);
    }
    return;
}

void staticCamera_init(short* obj, int params, int flag)
{
    u8* dst;

    *obj = -*(short*)(params + 0x1c);
    obj[1] = -*(short*)(params + 0x1e);
    obj[2] = -*(short*)(params + 0x20);
    dst = *(u8**)(obj + 0x5c);
    *dst = *(u8*)(params + 0x19);
    *(float*)(dst + 4) =
        (float)((double)(u32) * (u8*)(params + 0x1a));
    dst[1] = 0;
    if (flag == 0)
    {
        ObjGroup_AddObject((int)obj, 7);
    }
    return;
}

void FUN_8016d188(int obj, int owner)
{
    float factor;
    int mode;
    u32 cfgFlag;
    int stateExtra;
    double colorD;
    int ownerData;
    float intensity;
    int spawnType;
    u16 fxArgs[3];
    short fxArgsCount;
    float fxArgsScale;
    u16 fxId;
    u16 fxIdB;
    u16 fxIdC;
    short fxCount;
    float fxScale;
    float fxParam28;
    float fxParam24;
    u32 ownerZ;
    s64 tmpLL;

    stateExtra = *(int*)&((GameObject*)obj)->extra;
    if ((obj != 0) && (owner != 0))
    {
        if (*(char*)(stateExtra + 0xba) != '\0')
        {
            mode = FUN_80294d10(owner);
            if (mode == 0)
            {
                intensity = lbl_803E3F24;
                factor = lbl_803E3F28;
            }
            else
            {
                intensity = lbl_803E3F20;
                factor = lbl_803E3F20;
            }
            if (*(u8*)(stateExtra + 0xbb) == 7)
            {
                colorD = (double)lbl_803E3F2C;
                tmpLL = (s64)(int)(lbl_803E3F30 * factor);
                FUN_800810f8(colorD, colorD, colorD, (double)(lbl_803E3F34 * intensity), obj, 7,
                             (u32) * (u8*)(stateExtra + 0xba), 1, (int)(lbl_803E3F30 * factor), 0, 0);
            }
            else
            {
                colorD = (double)lbl_803E3F20;
                tmpLL = (s64)(int)(lbl_803E3F30 * factor);
                FUN_800810f8(colorD, colorD, colorD, (double)(lbl_803E3F34 * intensity), obj,
                             (u32) * (u8*)(stateExtra + 0xbb), (u32) * (u8*)(stateExtra + 0xba), 1,
                             (int)(lbl_803E3F30 * factor), 0, 0);
            }
        }
        FUN_80294c60(owner, &spawnType, &intensity);
        fxId = 0;
        fxIdB = 0;
        fxIdC = 0;
        fxScale = lbl_803E3F20;
        if (spawnType == 0x87)
        {
            stateExtra = (int)(lbl_803E3F38 * (intensity / lbl_803E3F30));
            tmpLL = (s64)stateExtra;
            fxCount = 0x15 - stateExtra;
            fxParam28 = lbl_803E3F3C * (intensity / lbl_803E3F40 - lbl_803E3F2C);
            fxId = 0xc94;
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &fxId, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &fxId, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &fxId, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &fxId, 2, -1, NULL);
            fxCount = 9;
            fxScale = lbl_803E3F48 * (intensity / lbl_803E3F40) + lbl_803E3F44;
            fxParam24 = lbl_803E3F4C;
            fxId = 0xc0e;
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b3, &fxId, 2, -1, NULL);
        }
        else if (spawnType < 0x87)
        {
            if (spawnType == 0x7f)
            {
                fxScale = lbl_803E3F58;
                fxCount = 10;
                fxParam24 = lbl_803E3F54;
                fxParam28 = lbl_803E3F50;
                fxId = 0xc0e;
                (*gPartfxInterface)->spawnObject((void*)obj, 0x7b3, &fxId, 2, -1, NULL);
            }
            else if (spawnType < 0x7f)
            {
                if ((spawnType == 0x43) && (lbl_803E3F4C < intensity))
                {
                    stateExtra = (int)(lbl_803E3F38 * (intensity / lbl_803E3F30));
                    tmpLL = (s64)stateExtra;
                    fxCount = stateExtra + 6;
                    fxParam28 = lbl_803E3F3C * (intensity / lbl_803E3F40 - lbl_803E3F2C);
                    fxId = 0xc94;
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x7b4, &fxId, 2, -1, NULL);
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x7b4, &fxId, 2, -1, NULL);
                    fxCount = 9;
                    fxScale = lbl_803E3F48 * (intensity / lbl_803E3F40) + lbl_803E3F44;
                    fxParam24 = lbl_803E3F4C;
                    fxId = 0xc0e;
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x7b3, &fxId, 2, -1, NULL);
                }
            }
            else if (spawnType == 0x85)
            {
                if (lbl_803E3F4C < intensity)
                {
                    cfgFlag = FUN_80017690(0xc55);
                    if (cfgFlag == 0)
                    {
                        factor = intensity / lbl_803E3F40;
                        stateExtra = (int)(lbl_803E3F38 * factor);
                        fxCount = stateExtra;
                        fxId = 0xc94;
                    }
                    else
                    {
                        factor = intensity / lbl_803E3F50;
                        stateExtra = (int)(lbl_803E3F38 * factor);
                        fxCount = stateExtra;
                        fxId = 0xc75;
                    }
                    tmpLL = (s64)stateExtra;
                    fxParam28 = lbl_803E3F5C * (lbl_803E3F28 - factor);
                    fxCount = 0x15 - fxCount;
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &fxId, 2, -1, NULL);
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &fxId, 2, -1, NULL);
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &fxId, 2, -1, NULL);
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &fxId, 2, -1, NULL);
                    fxCount = 9;
                    cfgFlag = FUN_80017690(0xc55);
                    if (cfgFlag == 0)
                    {
                        fxId = 0xc0e;
                        factor = lbl_803E3F40;
                    }
                    else
                    {
                        fxId = 0xc75;
                        factor = lbl_803E3F50;
                    }
                    fxScale = lbl_803E3F48 * (intensity / factor) + lbl_803E3F44;
                    fxParam24 = lbl_803E3F4C;
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x7b3, &fxId, 2, -1, NULL);
                }
            }
            else if (0x84 < spawnType)
            {
                cfgFlag = FUN_80017690(0xc55);
                if (cfgFlag == 0)
                {
                    fxId = 0xc0e;
                }
                else
                {
                    fxId = 0xc75;
                }
                factor = *(float*)(owner + 0x98);
                if (lbl_803E3F68 <= factor)
                {
                    if (factor < lbl_803E3F70)
                    {
                        fxParam28 = lbl_803E3F5C * (lbl_803E3F74 * (factor - lbl_803E3F68) - lbl_803E3F2C);
                        fxCount = 9;
                        fxScale = lbl_803E3F20;
                        fxParam24 = lbl_803E3F4C;
                        (*gPartfxInterface)->spawnObject((void*)obj, 0x7b3, &fxId, 2, -1, NULL);
                    }
                }
                else
                {
                    fxParam28 = lbl_803E3F6C;
                    fxCount = 9;
                    fxScale = lbl_803E3F20;
                    fxParam24 = lbl_803E3F4C;
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x7b3, &fxId, 2, -1, NULL);
                }
            }
        }
        else if (spawnType == 0x468)
        {
            if (lbl_803E3F4C < intensity)
            {
                stateExtra = (int)(lbl_803E3F38 * (intensity / lbl_803E3F60));
                tmpLL = (s64)stateExtra;
                fxArgsCount = 0x15 - stateExtra;
                fxArgs[0] = 0xc95;
                FUN_80294c48(*(int*)&((GameObject*)obj)->ownerObj, &ownerData);
                fxParam28 = *(float*)(ownerData + 0xc);
                fxParam24 = *(float*)(ownerData + 0x10);
                ownerZ = *(u32*)(ownerData + 0x14);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)obj)->ownerObj, 0x7b9, &fxId,
                                                 0x200001, -1, fxArgs);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)obj)->ownerObj, 0x7b9, &fxId,
                                                 0x200001, -1, fxArgs);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)obj)->ownerObj, 0x7b9, &fxId,
                                                 0x200001, -1, fxArgs);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)obj)->ownerObj, 0x7b9, &fxId,
                                                 0x200001, -1, fxArgs);
                fxArgsCount = 9;
                fxArgs[0] = 0xc95;
                fxArgsScale = lbl_803E3F64 * (intensity / lbl_803E3F60) + lbl_803E3F44;
                fxParam28 = *(float*)(ownerData + 0xc);
                fxParam24 = *(float*)(ownerData + 0x10);
                ownerZ = *(u32*)(ownerData + 0x14);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)obj)->ownerObj, 0x7ba, &fxId,
                                                 0x200001, -1, fxArgs);
            }
        }
        else if (spawnType < 0x468)
        {
            if (spawnType < 0x89)
            {
                fxCount = 0x23;
                fxParam24 = lbl_803E3F4C;
                fxParam28 = lbl_803E3F50;
                fxId = 0xc0e;
                (*gPartfxInterface)->spawnObject((void*)obj, 0x7b3, &fxId, 2, -1, NULL);
                fxCount = 0x12;
                fxParam24 = lbl_803E3F54;
                (*gPartfxInterface)->spawnObject((void*)obj, 0x7b3, &fxId, 2, -1, NULL);
            }
        }
        else if ((spawnType == 0x46f) && (lbl_803E3F4C < intensity))
        {
            stateExtra = (int)(lbl_803E3F38 * (intensity / lbl_803E3F60));
            tmpLL = (s64)stateExtra;
            fxCount = 0x15 - stateExtra;
            fxParam28 = lbl_803E3F5C * (lbl_803E3F28 - intensity / lbl_803E3F60);
            fxId = 0xc94;
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &fxId, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &fxId, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &fxId, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &fxId, 2, -1, NULL);
            fxCount = 9;
            fxScale = lbl_803E3F48 * (intensity / lbl_803E3F60) + lbl_803E3F44;
            fxParam24 = lbl_803E3F4C;
            fxId = 0xc0e;
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b3, &fxId, 2, -1, NULL);
        }
    }
    return;
}

void FUN_8016d994(int obj, u8 flagBB, u8 flagBA)
{
    int stateExtra;

    stateExtra = *(int*)&((GameObject*)obj)->extra;
    *(u8*)(stateExtra + 0xbb) = flagBB;
    *(u8*)(stateExtra + 0xba) = flagBA;
    return;
}

void FUN_8016e8cc(u64 arg1, u64 arg2, double arg3, u64 arg4,
                  u64 arg5, u64 arg6, u64 arg7, u64 arg8,
                  int obj)
{
    short clamped;
    int hits;
    int* group;
    u32 idx;
    int particle;
    int* state;
    double colorD;
    double clampedColor;

    state = ((GameObject*)obj)->extra;
    hits = FUN_80017a54(obj);
    *(u16*)(hits + 0x18) = *(u16*)(hits + 0x18) & ~0x8;
    FUN_8002fc3c((double)(float)state[0x14], (double)lbl_803DC074);
    hits = 3;
    group = state;
    do
    {
        if ((*(u8*)(group + 5) & 2) != 0)
        {
            idx = (u32) * (u16*)(group + 3);
            particle = *group + idx * 0x14;
            for (; idx < (int)(u32) * (u16*)((int)group + 0xe); idx = idx + 2)
            {
                if (group == (int*)state[0x12])
                {
                    arg3 = (double)lbl_803E3F8C;
                    colorD = (double)(float)(arg3 *
                        (double)((lbl_803E3FA4 * (float)state[0x26] -
                            *(float*)(particle + 0xc)) * lbl_803E3FA8));
                    clampedColor = (double)lbl_803E3F4C;
                    if ((clampedColor <= colorD) && (clampedColor = colorD, arg3 < colorD))
                    {
                        clampedColor = arg3;
                    }
                    *(short*)(particle + 0x10) = (short)(int)(arg3 - clampedColor);
                    *(u16*)(particle + 0x24) = *(u16*)(particle + 0x10);
                }
                else
                {
                    arg3 = (double)lbl_803E3FC4;
                    *(short*)(particle + 0x10) =
                        (short)(int)-(float)(arg3 * (double)lbl_803DC074 -
                            (double)(f32)(s32)((int)*(short*)(particle + 0x10)));
                    *(u16*)(particle + 0x24) = *(u16*)(particle + 0x10);
                }
                clamped = *(short*)(particle + 0x10);
                if (clamped < 0)
                {
                    clamped = 0;
                }
                else if (0xff < clamped)
                {
                    clamped = 0xff;
                }
                *(short*)(particle + 0x10) = clamped;
                clamped = *(short*)(particle + 0x24);
                if (clamped < 0)
                {
                    clamped = 0;
                }
                else if (0xff < clamped)
                {
                    clamped = 0xff;
                }
                *(short*)(particle + 0x24) = clamped;
                if ((*(short*)(particle + 0x10) < 1) && (*(short*)(particle + 0x24) < 1))
                {
                    *(short*)((int)group + 0x12) = *(short*)((int)group + 0x12) + -2;
                    *(short*)(group + 3) = *(short*)(group + 3) + 2;
                }
                particle = particle + 0x28;
            }
            if ((group != (int*)state[0x12]) && (*(short*)((int)group + 0x12) == 0))
            {
                *(u8*)(group + 5) = *(u8*)(group + 5) & 0xfd;
            }
        }
        group = group + 6;
        hits = hits + -1;
    }
    while (hits != 0);
    FUN_8016d188(obj, *(int*)&((GameObject*)obj)->ownerObj);
    FUN_80294d6c(*(int*)&((GameObject*)obj)->ownerObj);
    *(u8*)((int)state + 0xb9) = 0;
    if (DAT_803ad338 != '\0')
    {
        DAT_803ad324 = DAT_803ad324 + lbl_803E3F78;
        ObjHitbox_SetSphereRadius(DAT_803ad334, (short)(int)DAT_803ad324);
        ObjHits_SetHitVolumeSlot(DAT_803ad334, 0x11, 5, 0);
        DAT_803ad330 = DAT_803ad330 + lbl_803E3F7C;
        clampedColor = (double)DAT_803ad330;
        DAT_803ad328 = DAT_803ad328 * lbl_803E3F80;
        DAT_803ad32c = DAT_803ad32c * lbl_803E3F84;
        ((GameObject*)DAT_803ad334)->anim.alpha = (char)(int)DAT_803ad330;
        ((GameObject*)DAT_803ad334)->anim.rootMotionScale = ((GameObject*)DAT_803ad334)->anim.rootMotionScale +
            lbl_803E3F88;
        if ((double)DAT_803ad330 < (double)lbl_803E3F20)
        {
            DAT_803ad338 = '\0';
            FUN_80017ac8((double)DAT_803ad330, clampedColor, arg3, arg4, arg5, arg6, arg7, arg8,
                         DAT_803ad334);
            DAT_803ad334 = 0;
        }
    }
    return;
}

void FUN_80170048(void)
{
    float defaultVal;
    u32 objHi;
    int seqObj;
    int* writer;
    u32 rand;
    int glowObj;
    int* state;
    int* colorTbl;
    float* scaleTbl;
    double cosVal;
    double scaleC;
    double phase;
    double biasC;
    double offsetC;
    u64 packed;
    u64 randOffset;
    u64 randOffset2;

    packed = FUN_80286838();
    objHi = (u32)((u64)packed >> 0x20);
    scaleTbl = (float*)&DAT_80321678;
    state = *(int**)(objHi + 0xb8);
    seqObj = FUN_80017a98();
    glowObj = 0;
    if (seqObj != 0)
    {
        glowObj = FUN_80294cf8(seqObj);
    }
    defaultVal = lbl_803E4064;
    switch ((u32)packed & 0xff)
    {
    case 0:
        if (*state != 0)
        {
            FUN_800175cc((double)lbl_803E4040, *state, '\0');
        }
        defaultVal = lbl_803E4048;
        if (lbl_803E4044 != (float)state[2])
        {
            state[4] = lbl_803E4048;
            state[1] = defaultVal;
            if (glowObj != 0)
            {
                FUN_8016d994(glowObj, 7, 0);
            }
        }
        state[2] = lbl_803E4044;
        state[3] = lbl_803E404C;
        FUN_80006810(objHi, 0x42c);
        FUN_80006810(objHi, 0x42d);
        break;
    case 1:
        if (lbl_803E4044 == (float)state[2])
        {
            if (glowObj != 0)
            {
                FUN_8016d994(glowObj, 7, 8);
            }
            if (*state == 0)
            {
                writer = FUN_80017624(0, '\x01');
                *state = (int)writer;
            }
            if (*state != 0)
            {
                FUN_800175b0(*state, 2);
                FUN_800175ec((double)*(float*)(objHi + 0xc),
                             (double)(*(float*)(objHi + 0x10) - lbl_803E4050),
                             (double)*(float*)(objHi + 0x14), (int*)*state);
                FUN_8001759c(*state, 0, 0xff, 0xff, 0xff);
                FUN_80017588(*state, 0, 0xff, 0xff, 0xff);
                FUN_800175d0((double)lbl_803E4054, (double)lbl_803E4058, *state);
                FUN_800175bc(*state, 1);
                FUN_800175cc((double)lbl_803E4044, *state, '\x01');
                FUN_8001753c(*state, 0, 0);
                FUN_800175d8(*state, 1);
            }
            defaultVal = lbl_803E4044;
            if (lbl_803E4044 == (float)state[2])
            {
                state[4] = lbl_803E4048;
                state[1] = defaultVal;
            }
            state[2] = lbl_803E4048;
            scaleC = (double)lbl_803E405C;
            state[3] = lbl_803E405C;
            seqObj = 0;
            colorTbl = &DAT_80321688;
            phase = (double)lbl_803E4040;
            biasC = (double)lbl_803E4060;
            writer = state;
            offsetC = DOUBLE_803e4068;
            do
            {
                *(u16*)(writer + 0xd) = 0xc000;
                cosVal = (double)fcos16Precise();
                state[9] = (int)(*scaleTbl * (float)((double)(float)(scaleC + cosVal) * phase));
                state[5] = *colorTbl;
                rand = randomGetRange(0x78, 0x7f);
                randOffset = (double)(int)(seqObj * rand);
                *(short*)(writer + 0xf) = (short)(int)(biasC + (double)(float)(randOffset));
                writer = (int*)((int)writer + 2);
                scaleTbl = scaleTbl + 1;
                state = state + 1;
                colorTbl = colorTbl + 1;
                seqObj = seqObj + 1;
            }
            while (seqObj < 4);
            FUN_80006824(objHi, 0x42c);
            FUN_80006824(objHi, 0x42d);
        }
        break;
    case 2:
        if (glowObj != 0)
        {
            FUN_8016d994(glowObj, 7, 0);
        }
        if (lbl_803E4044 != (float)state[2])
        {
            state[4] = lbl_803E4064;
        }
        state[2] = lbl_803E4044;
        state[3] = lbl_803E404C;
        if (*state != 0)
        {
            FUN_800175cc((double)lbl_803E4040, *state, '\0');
        }
        FUN_80006810(objHi, 0x42c);
        FUN_80006810(objHi, 0x42d);
        break;
    case 3:
        if (glowObj != 0)
        {
            FUN_8016d994(glowObj, 7, 8);
        }
        if (*state == 0)
        {
            writer = FUN_80017624(0, '\x01');
            *state = (int)writer;
        }
        if (*state != 0)
        {
            FUN_800175b0(*state, 2);
            FUN_800175ec((double)*(float*)(objHi + 0xc),
                         (double)(*(float*)(objHi + 0x10) - lbl_803E4050),
                         (double)*(float*)(objHi + 0x14), (int*)*state);
            FUN_8001759c(*state, 0, 0xff, 0xff, 0xff);
            FUN_80017588(*state, 0, 0xff, 0xff, 0xff);
            FUN_800175d0((double)lbl_803E4054, (double)lbl_803E4058, *state);
            FUN_800175bc(*state, 1);
            FUN_800175cc((double)lbl_803E4044, *state, '\x01');
            FUN_8001753c(*state, 0, 0);
            FUN_800175d8(*state, 1);
        }
        if (lbl_803E4044 == (float)state[2])
        {
            state[4] = lbl_803E4064;
        }
        state[2] = lbl_803E4064;
        biasC = (double)lbl_803E405C;
        state[3] = lbl_803E405C;
        seqObj = 0;
        colorTbl = &DAT_80321688;
        offsetC = (double)lbl_803E4040;
        writer = state;
        do
        {
            *(u16*)(state + 0xd) = 0;
            scaleC = (double)fcos16Precise();
            writer[9] = (int)(*scaleTbl * (float)((double)(float)(biasC + scaleC) * offsetC));
            writer[5] = *colorTbl;
            state = (int*)((int)state + 2);
            scaleTbl = scaleTbl + 1;
            writer = writer + 1;
            colorTbl = colorTbl + 1;
            seqObj = seqObj + 1;
        }
        while (seqObj < 4);
        FUN_80006824(objHi, 0x42d);
        FUN_80006824(objHi, 0x42c);
        break;
    case 4:
        state[2] = lbl_803E4064;
        biasC = (double)lbl_803E405C;
        state[3] = lbl_803E405C;
        state[4] = defaultVal;
        seqObj = 0;
        scaleTbl = (float*)&DAT_80321698;
        colorTbl = &DAT_803216a8;
        phase = (double)lbl_803E4040;
        scaleC = (double)lbl_803E4060;
        writer = state;
        offsetC = DOUBLE_803e4068;
        do
        {
            *(u16*)(state + 0xd) = 0xc000;
            cosVal = (double)fcos16Precise();
            writer[9] = (int)(*scaleTbl * (float)((double)(float)(biasC + cosVal) * phase));
            writer[5] = *colorTbl;
            rand = randomGetRange(0x78, 0x7f);
            randOffset2 = (double)(int)(seqObj * rand);
            *(short*)(state + 0xf) = (short)(int)(scaleC + (double)(float)(randOffset2));
            state = (int*)((int)state + 2);
            scaleTbl = scaleTbl + 1;
            writer = writer + 1;
            colorTbl = colorTbl + 1;
            seqObj = seqObj + 1;
        }
        while (seqObj < 4);
        FUN_80006824(objHi, 0x42d);
        FUN_80006824(objHi, 0x42c);
        break;
    case 5:
        state[2] = lbl_803E4044;
        state[3] = lbl_803E404C;
        state[4] = lbl_803E4064;
        FUN_80006810(objHi, 0x42c);
        FUN_80006810(objHi, 0x42d);
        break;
    case 6:
        seqObj = 0;
        scaleTbl = (float*)&DAT_80321698;
        colorTbl = &DAT_803216a8;
        biasC = (double)lbl_803E405C;
        phase = (double)lbl_803E4040;
        writer = state;
        do
        {
            *(u16*)(state + 0xd) = 0x4000;
            scaleC = (double)fcos16Precise();
            writer[9] = (int)(*scaleTbl * (float)((double)(float)(biasC + scaleC) * phase));
            writer[5] = *colorTbl;
            state = (int*)((int)state + 2);
            scaleTbl = scaleTbl + 1;
            writer = writer + 1;
            colorTbl = colorTbl + 1;
            seqObj = seqObj + 1;
        }
        while (seqObj < 4);
        break;
    case 7:
        if (glowObj != 0)
        {
            FUN_8016d994(glowObj, 7, 0);
        }
        if (*state != 0)
        {
            FUN_800175cc((double)lbl_803E4040, *state, '\0');
        }
        defaultVal = lbl_803E4044;
        state[2] = lbl_803E4044;
        state[3] = defaultVal;
        state[4] = defaultVal;
        state[1] = defaultVal;
        *(u8*)(state + 0x17) = *(u8*)(state + 0x17) | 1;
        *(u8*)((int)state + 0x5d) = *(u8*)((int)state + 0x5d) | 1;
        *(u8*)((int)state + 0x5e) = *(u8*)((int)state + 0x5e) | 1;
        *(u8*)((int)state + 0x5f) = *(u8*)((int)state + 0x5f) | 1;
    }
    FUN_80286884();
    return;
}

void mikabombshadow_update(int* obj);

void FUN_801713ac(u64 arg1, double arg2, double arg3, u64 arg4,
                  u64 arg5, u64 arg6, u64 arg7, u64 arg8,
                  u32 obj)
{
    extern u64 ObjHits_DisableObject(); /* #57 */
    short seqId;
    char counter;
    u32 tmp;
    int setupData;
    int placementData;
    int stateExtra;
    u64 callResult;

    stateExtra = *(int*)&((GameObject*)obj)->extra;
    placementData = *(int*)&((GameObject*)obj)->anim.placementData;
    setupData = (int)((GameObject*)obj)->anim.modelInstance->extraSetupData;
    FUN_80017a98();
    FUN_80017a90();
    FUN_80017a98();
    FUN_80017a90();
    callResult = ObjHits_DisableObject(obj);
    if ((*(u16*)&((GameObject*)obj)->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA) != 0)
    {
        *(float*)(stateExtra + 8) = lbl_803E40E8;
        if (((GameObject*)obj)->anim.modelState != NULL)
        {
            ((GameObject*)obj)->anim.modelState->flags = OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        }
    }
    if ((int)*(short*)(stateExtra + 0x10) != 0xffffffff)
    {
        FUN_80017698((int)*(short*)(stateExtra + 0x10), 1);
        callResult = FUN_800e842c(obj);
    }
    tmp = (u32) * (short*)(placementData + 0x1e);
    if (tmp != 0xffffffff)
    {
        callResult = FUN_80017698(tmp, 1);
    }
    tmp = (u32) * (short*)(placementData + 0x2c);
    if (0 < tmp)
    {
        FUN_80017688(tmp);
    }
    seqId = *(short*)(setupData + 2);
    if (seqId == 4)
    {
        seqId = ((GameObject*)obj)->anim.seqId;
        if (seqId == 0x3cd)
        {
            setupData = FUN_80017a98();
            FUN_80294d60(callResult, arg2, arg3, arg4, arg5, arg6, arg7, arg8, setupData, 2);
            tmp = FUN_80017a98();
            FUN_80006824(tmp, SFXen_treadlpc);
            FUN_80081118((double)lbl_803E40EC, obj, 1, 0x28);
        }
        else if ((seqId < 0x3cd) && (seqId == 0xb))
        {
            tmp = FUN_80017a98();
            callResult = FUN_80006824(tmp, SFXen_treadlpc);
            setupData = FUN_80017a98();
            FUN_80294d60(callResult, arg2, arg3, arg4, arg5, arg6, arg7, arg8, setupData, 4);
            FUN_80081118((double)lbl_803E40EC, obj, 3, 0x28);
        }
        else
        {
            tmp = FUN_80017a98();
            FUN_80006824(tmp, SFXen_waterblock_stop);
            FUN_80081118((double)lbl_803E40EC, obj, 0xff, 0x28);
        }
    }
    else if ((seqId < 4) && (seqId == 1))
    {
        seqId = ((GameObject*)obj)->anim.seqId;
        if (seqId == 0x319)
        {
            FUN_80006824(obj, SFXwp_gprop2_c);
            FUN_80017698(0x3e9, 1);
            *(u16*)(stateExtra + 0x3c) = 0x4b0;
            FUN_80081118((double)lbl_803E40EC, obj, 0xff, 0x28);
        }
        else
        {
            if (seqId < 0x319)
            {
                if (seqId == 0x5a)
                {
                    FUN_80006824(obj, SFXen_treadlpc);
                    FUN_80081118((double)lbl_803E40EC, obj, 2, 0x28);
                    goto LAB_801725bc;
                }
                if ((seqId < 0x5a) && (seqId == 0x22))
                {
                    FUN_80006824(obj, SFXen_treadlpc);
                    FUN_80081118((double)lbl_803E40EC, obj, 0xff, 0x28);
                    goto LAB_801725bc;
                }
            }
            else if (seqId == 0x6a6)
            {
                tmp = FUN_80017690(0x86a);
                counter = tmp;
                if (counter < '\a')
                {
                    counter = counter + '\x01';
                }
                FUN_80017698(0x86a, counter);
                FUN_80081118((double)lbl_803E40EC, obj, 6, 0x28);
                FUN_80006824(obj, SFXen_treadlpc);
                goto LAB_801725bc;
            }
            FUN_80006824(obj, SFXen_waterblock_stop);
            FUN_80081118((double)lbl_803E40EC, obj, 0xff, 0x28);
        }
    }
    else
    {
        FUN_80006824(obj, SFXen_waterblock_stop);
        FUN_80081118((double)lbl_803E40EC, obj, 0xff, 0x28);
    }
LAB_801725bc:
    *(u32*)&((GameObject*)obj)->anim.rootMotionScale = *(u32*)(*(int*)&((GameObject*)obj)->anim.
        modelInstance + 4);
    ((GameObject*)obj)->unkF4 = 1;
    return;
}

void staff_func0F(void);

void staff_func0B(void);

void staff_setScale(void);

void staff_render(void);

void staff_hitDetect(void);

void fireball_release(void);

void fireball_initialise(void);

void flamethrowerspe_modelMtxFn(void)
{
}

void flamethrowerspe_free(void)
{
}

void flamethrowerspe_hitDetect(void)
{
}

void flamethrowerspe_release(void)
{
}

void flamethrowerspe_initialise(void)
{
}

void shield_hitDetect(void);

void shield_release(void);

void shield_initialise(void);

int animatedobj_getExtraSize(void);
int dim2roofrub_getExtraSize(void);
int depthoffieldpoint_getExtraSize(void);
int staff_getExtraSize(void);
int staff_getObjectTypeId(void);
int fireball_getExtraSize(void);
int fireball_getObjectTypeId(void);
int flamethrowerspe_getExtraSize(void) { return 0x14; }
int flamethrowerspe_getObjectTypeId(void) { return 0x0; }
int shield_getExtraSize(void);
int shield_getObjectTypeId(void);

void dim2roofrub_free(int* obj);

void staff_func10(int* obj, s32 v);
void staff_setHitReactValue(int* obj, s32 v);
void staff_addHitReactValue(int* obj, s32 delta);
void staff_getHitGeometryPoints(int* obj, f32* outA, f32* outB);
void staff_func15(int* obj, s16 idx, f32 f1, f32 f2);

void restartmarker_init(int* obj, int* state);

void staffFn_80170380(int* obj, int cmd);

void shield_init(int* obj, void* initData);

ObjectDescriptor gMikaBombObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)mikabomb_initialise,
    (ObjectDescriptorCallback)mikabomb_release,
    0,
    (ObjectDescriptorCallback)mikabomb_init,
    (ObjectDescriptorCallback)mikabomb_update,
    (ObjectDescriptorCallback)mikabomb_hitDetect,
    (ObjectDescriptorCallback)mikabomb_render,
    (ObjectDescriptorCallback)mikabomb_free,
    (ObjectDescriptorCallback)mikabomb_getObjectTypeId,
    mikabomb_getExtraSize,
};

ObjectDescriptor gMikaBombShadowObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)mikabombshadow_initialise,
    (ObjectDescriptorCallback)mikabombshadow_release,
    0,
    (ObjectDescriptorCallback)mikabombshadow_init,
    (ObjectDescriptorCallback)mikabombshadow_update,
    (ObjectDescriptorCallback)mikabombshadow_hitDetect,
    (ObjectDescriptorCallback)mikabombshadow_render,
    (ObjectDescriptorCallback)mikabombshadow_free,
    (ObjectDescriptorCallback)mikabombshadow_getObjectTypeId,
    mikabombshadow_getExtraSize,
};

ObjectDescriptor gStaticCameraObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)StaticCamera_initialise,
    (ObjectDescriptorCallback)StaticCamera_release,
    0,
    (ObjectDescriptorCallback)StaticCamera_init,
    (ObjectDescriptorCallback)StaticCamera_update,
    (ObjectDescriptorCallback)StaticCamera_hitDetect,
    (ObjectDescriptorCallback)StaticCamera_render,
    (ObjectDescriptorCallback)StaticCamera_free,
    (ObjectDescriptorCallback)StaticCamera_getObjectTypeId,
    StaticCamera_getExtraSize,
};

ObjectDescriptor gGCbaddieShieldObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)gcbaddieshield_initialise,
    (ObjectDescriptorCallback)gcbaddieshield_release,
    0,
    (ObjectDescriptorCallback)gcbaddieshield_init,
    (ObjectDescriptorCallback)gcbaddieshield_update,
    (ObjectDescriptorCallback)gcbaddieshield_hitDetect,
    (ObjectDescriptorCallback)gcbaddieshield_render,
    (ObjectDescriptorCallback)gcbaddieshield_free,
    (ObjectDescriptorCallback)gcbaddieshield_getObjectTypeId,
    gcbaddieshield_getExtraSize,
};

ObjectDescriptor gBaddieInterestPObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)baddieinterestp_initialise,
    (ObjectDescriptorCallback)baddieinterestp_release,
    0,
    (ObjectDescriptorCallback)baddieinterestp_init,
    (ObjectDescriptorCallback)baddieinterestp_update,
    (ObjectDescriptorCallback)baddieinterestp_hitDetect,
    (ObjectDescriptorCallback)baddieinterestp_render,
    (ObjectDescriptorCallback)baddieinterestp_free,
    (ObjectDescriptorCallback)baddieinterestp_getObjectTypeId,
    baddieinterestp_getExtraSize,
};

u32 lbl_80320700[] = {
    0xFFFFFFFF,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
};

ObjectDescriptor gAnimatedObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)animatedobj_init,
    (ObjectDescriptorCallback)animatedobj_update,
    0,
    (ObjectDescriptorCallback)animatedobj_render,
    (ObjectDescriptorCallback)animatedobj_free,
    0,
    animatedobj_getExtraSize,
};

u32 lbl_80320768[] = {
    0x00000000,
    0x3FD5A1CB,
    0xC0253F7D,
    0x3C23D70A,
    0x06100000,
    0x402F3B64,
    0x3F4B020C,
    0xBFFA1CAC,
    0x3C23D70A,
    0x09200000,
    0x402EB852,
    0x3F476C8B,
    0xBF73B646,
    0x3C23D70A,
    0x07200000,
    0x4032E148,
    0xBF795810,
    0xBFF8F5C3,
    0x3C23D70A,
    0x09200000,
    0x4033F7CF,
    0xBF810625,
    0xBF747AE1,
    0x3C23D70A,
    0x07200000,
    0xC02F3B64,
    0x3F4B020C,
    0xBFFC28F6,
    0x3C23D70A,
    0x09200000,
    0xC02EB852,
    0x3F476C8B,
    0xBF73B646,
    0x3C23D70A,
    0x07200000,
    0xC032E148,
    0xBF795810,
    0xBFFC49BA,
    0x3C23D70A,
    0x09200000,
    0xC033F7CF,
    0xBF810625,
    0xBF747AE1,
    0x3C23D70A,
    0x07200000,
    0x00000000,
    0x3ECF5C29,
    0x403CED91,
    0x3C23D70A,
    0x08400000,
};

ObjectDescriptor gDIM2RoofRubObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)dim2roofrub_init,
    (ObjectDescriptorCallback)dim2roofrub_update,
    0,
    (ObjectDescriptorCallback)dim2roofrub_render,
    (ObjectDescriptorCallback)dim2roofrub_free,
    0,
    dim2roofrub_getExtraSize,
};

ObjectDescriptor gDepthOfFieldPointObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)depthoffieldpoint_init,
    (ObjectDescriptorCallback)depthoffieldpoint_update,
    0,
    0,
    0,
    0,
    depthoffieldpoint_getExtraSize,
};

u16 lbl_803208A0[] = {
    0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3,
    0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3,
    0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3,
    0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3,
    0x00C2, 0x006F, 0x00C3, 0x00C3, 0x00C3, 0x00C3,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
};

u32 lbl_803208E8[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0x01020000,
    0,
    0,
};

ObjectDescriptor23 gStaffObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_23_SLOTS,
    (ObjectDescriptorCallback)staff_initialise,
    (ObjectDescriptorCallback)staff_release,
    0,
    (ObjectDescriptorCallback)staff_init,
    (ObjectDescriptorCallback)staff_update,
    (ObjectDescriptorCallback)staff_hitDetect,
    (ObjectDescriptorCallback)staff_render,
    (ObjectDescriptorCallback)staff_free,
    (ObjectDescriptorCallback)staff_getObjectTypeId,
    staff_getExtraSize,
    (ObjectDescriptorCallback)staff_setScale,
    (ObjectDescriptorCallback)staff_func0B,
    (ObjectDescriptorCallback)staff_modelMtxFn,
    (ObjectDescriptorCallback)staff_hitDetectGeometry,
    (ObjectDescriptorCallback)staff_func0E,
    (ObjectDescriptorCallback)staff_func0F,
    (ObjectDescriptorCallback)staff_func10,
    (ObjectDescriptorCallback)staff_setHitReactValue,
    (ObjectDescriptorCallback)staff_addHitReactValue,
    (ObjectDescriptorCallback)staff_getHitReactValue,
    (ObjectDescriptorCallback)staff_getHitGeometryPoints,
    (ObjectDescriptorCallback)staff_func15,
    (ObjectDescriptorCallback)staff_func16,
};

u32 lbl_80320978[] = {
    0xFF202020,
    0xFF202020,
    0xFF000000,
};

ObjectDescriptor10WithPadding gFireballObjDescriptor = {
    {
        0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
        (ObjectDescriptorCallback)fireball_initialise,
        (ObjectDescriptorCallback)fireball_release,
        0,
        (ObjectDescriptorCallback)fireball_init,
        (ObjectDescriptorCallback)fireball_update,
        (ObjectDescriptorCallback)fireball_hitDetect,
        (ObjectDescriptorCallback)fireball_render,
        (ObjectDescriptorCallback)fireball_free,
        (ObjectDescriptorCallback)fireball_getObjectTypeId,
        fireball_getExtraSize,
    },
    0,
};

u32 lbl_803209C0[] = {
    0x0000004F,
    0xFFC40000,
    0x0000001F,
    0x0000004F,
    0x00C4FF00,
    0x00000005,
    0x0000004F,
    0x00C4FF00,
    0x0000001E,
};

ObjectDescriptor13 gFlameThrowerSpeObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_13_SLOTS,
    (ObjectDescriptorCallback)flamethrowerspe_initialise,
    (ObjectDescriptorCallback)flamethrowerspe_release,
    0,
    (ObjectDescriptorCallback)flamethrowerspe_init,
    (ObjectDescriptorCallback)flamethrowerspe_update,
    (ObjectDescriptorCallback)flamethrowerspe_hitDetect,
    (ObjectDescriptorCallback)flamethrowerspe_render,
    (ObjectDescriptorCallback)flamethrowerspe_free,
    (ObjectDescriptorCallback)flamethrowerspe_getObjectTypeId,
    flamethrowerspe_getExtraSize,
    (ObjectDescriptorCallback)flamethrowerspe_setScale,
    (ObjectDescriptorCallback)flamethrowerspe_func0B,
    (ObjectDescriptorCallback)flamethrowerspe_modelMtxFn,
};

f32 lbl_80320A28[] = {
    0.5f,
    0.55f,
    0.65f,
    0.7f,
    0.5f,
    0.5f,
    0.5f,
    0.5f,
    0.5f,
    0.5f,
    0.5f,
    0.5f,
    0.3f,
    0.3f,
    0.3f,
    0.3f,
};

ObjectDescriptor gShieldObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)shield_initialise,
    (ObjectDescriptorCallback)shield_release,
    0,
    (ObjectDescriptorCallback)shield_init,
    (ObjectDescriptorCallback)shield_update,
    (ObjectDescriptorCallback)shield_hitDetect,
    (ObjectDescriptorCallback)shield_render,
    (ObjectDescriptorCallback)shield_free,
    (ObjectDescriptorCallback)shield_getObjectTypeId,
    shield_getExtraSize,
};

u32 jumptable_80320AA0[] = {
    (u32)((char*)staffFn_80170380 + 0x10C),
    (u32)((char*)staffFn_80170380 + 0x184),
    (u32)((char*)staffFn_80170380 + 0x35C),
    (u32)((char*)staffFn_80170380 + 0x3D0),
    (u32)((char*)staffFn_80170380 + 0x584),
    (u32)((char*)staffFn_80170380 + 0x550),
    (u32)((char*)staffFn_80170380 + 0x65C),
    (u32)((char*)staffFn_80170380 + 0x84),
};

ObjectDescriptor12 gCurveObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_12_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)curve_init,
    0,
    0,
    (ObjectDescriptorCallback)curve_render,
    (ObjectDescriptorCallback)curve_free,
    (ObjectDescriptorCallback)curve_getObjectTypeId,
    curve_getExtraSize,
    (ObjectDescriptorCallback)curve_setScale,
    (ObjectDescriptorCallback)curve_func11,
};

ObjectDescriptor gReStartMarkerObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)restartmarker_init,
    0,
    0,
    0,
    0,
    0,
    0,
};

ObjectDescriptor dll_F7 = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll_F7_initialise,
    (ObjectDescriptorCallback)dll_F7_release,
    0,
    (ObjectDescriptorCallback)dll_F7_init,
    (ObjectDescriptorCallback)dll_F7_update,
    (ObjectDescriptorCallback)dll_F7_hitDetect,
    (ObjectDescriptorCallback)dll_F7_render,
    (ObjectDescriptorCallback)dll_F7_free,
    (ObjectDescriptorCallback)dll_F7_getObjectTypeId,
    dll_F7_getExtraSize,
};

ObjectDescriptor11WithPadding gCheckpoint4ObjDescriptor = {
    {
        0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
        (ObjectDescriptorCallback)checkpoint4_initialise,
        (ObjectDescriptorCallback)checkpoint4_release,
        0,
        (ObjectDescriptorCallback)checkpoint4_init,
        (ObjectDescriptorCallback)checkpoint4_update,
        (ObjectDescriptorCallback)checkpoint4_hitDetect,
        (ObjectDescriptorCallback)checkpoint4_render,
        (ObjectDescriptorCallback)checkpoint4_free,
        (ObjectDescriptorCallback)checkpoint4_getObjectTypeId,
        checkpoint4_getExtraSize,
        (ObjectDescriptorCallback)checkpoint4_setScale,
    },
    0,
};

void flamethrowerspe_render(void) { objRenderFn_8003b8f4(lbl_803E3388); }
void fn_801719F8(void) { objRenderFn_8003b8f4(lbl_803E3420); }

void flamethrowerspe_func0B(int* obj)
{
    s32 v = 0x1;
    *(s32*)((char*)(int*)((GameObject*)obj)->extra + 0x10) = v;
}

void flamethrowerspe_setScale(int* obj, s16 a, s16 b, f32 f1, f32 f2, f32 f3)
{
    ((GameObject*)obj)->anim.localPosX = f1;
    ((GameObject*)obj)->anim.localPosY = f2;
    ((GameObject*)obj)->anim.localPosZ = f3;
    ((GameObject*)obj)->anim.rotY = a;
    ((GameObject*)obj)->anim.rotX = b;
}

void gcbaddieshield_update(int* obj);




void mikabombshadow_init(int* obj);

void StaticCamera_init(int* obj, int* params, int flag);

void flamethrowerspe_init(int* obj, int* params)
{
    extern void storeZeroToFloatParam(f32* p); /* #57 */
    extern u64 ObjHits_DisableObject(); /* #57 */
    int* state = ((GameObject*)obj)->extra;
    storeZeroToFloatParam(&((FlamethrowerspeState*)state)->lifeTimer);
    {
        f32 r = (f32) * (s16*)((char*)params + 0x1a) / lbl_803E33A0;
        ((FlamethrowerspeState*)state)->sizeScale = r * lbl_803DBD60;
    }
    ((GameObject*)obj)->anim.velocityY = lbl_803E338C;
    ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
    ((FlamethrowerspeState*)state)->phase = FLAMETHROWERSPE_PHASE_LAUNCH;
    ObjHits_DisableObject(obj);
}

void dll_F7_init(int* obj, int* params);


#pragma opt_common_subs off
void flamethrowerspe_update(int* obj)
{
    extern int timerCountDown(f32* p); /* #57 */
    extern void s16toFloat(f32* p, s16 val); /* #57 */
    extern void objMove(int* obj, f32 x, f32 y, f32 z); /* #57 */
    extern u32 ObjHits_EnableObject(); /* #57 */
    extern u64 ObjHits_DisableObject(); /* #57 */
    int* state = ((GameObject*)obj)->extra;
    int* src = *(int**)&((GameObject*)obj)->anim.placementData;
    switch (((FlamethrowerspeState*)state)->phase)
    {
    case FLAMETHROWERSPE_PHASE_LAUNCH:
        ((GameObject*)obj)->anim.velocityX = lbl_803E338C;
        ((GameObject*)obj)->anim.velocityZ =
            lbl_803DBD68 * (lbl_803E3390 * (((FlamethrowerspeState*)state)->sizeScale *
                (lbl_803E3394 * (f32)(s32)
        randomGetRange(0x64, 0x96)
        )
        )
        )
        ;
        vecRotateZXY(obj, &((GameObject*)obj)->anim.velocityX);
        ((FlamethrowerspeState*)state)->sphereRadius = lbl_803DBD6C * ((FlamethrowerspeState*)state)->sizeScale;
        s16toFloat(&((FlamethrowerspeState*)state)->lifeTimer, lbl_803DBD64);
        ((FlamethrowerspeState*)state)->phase = FLAMETHROWERSPE_PHASE_ACTIVE;
        break;
    case FLAMETHROWERSPE_PHASE_ACTIVE:
        if (timerCountDown(&((FlamethrowerspeState*)state)->lifeTimer) != 0)
        {
            ObjHits_DisableObject(obj);
            firepipe_releaseEffectObject(obj);
            return;
        }
        ObjHits_EnableObject(obj);
        ObjHits_SetHitVolumeSlot(obj, lbl_803209C0[(s8) * (u8*)((char*)src + 0x19) * 3 + 2], 1, 0);
        {
            f32 dt = (f32)(f64)timeDelta;
            objMove(obj, ((GameObject*)obj)->anim.velocityX * dt, ((GameObject*)obj)->anim.velocityY * dt,
                    ((GameObject*)obj)->anim.velocityZ * dt);
        }
        ObjHitbox_SetSphereRadius(obj, (int)(((FlamethrowerspeState*)state)->sphereRadius *
                                      (((f32)lbl_803DBD64 - ((FlamethrowerspeState*)state)->lifeTimer) / lbl_803DBD64)));
        break;
    }
}
#pragma opt_common_subs reset

void mikabomb_init(int* obj);



void shield_update(int* obj);

void dll_F7_update(int* obj);

#pragma opt_common_subs reset

GenPropsWGPipe GXWGFifo : (0xCC008000);

static inline void swipePos3f32(const f32 x, const f32 y, const f32 z)
{
    GXWGFifo.f32 = x;
    GXWGFifo.f32 = y;
    GXWGFifo.f32 = z;
}

static inline void swipeColor4u8(const u8 r, const u8 g, const u8 b, const u8 a)
{
    GXWGFifo.u8 = r;
    GXWGFifo.u8 = g;
    GXWGFifo.u8 = b;
    GXWGFifo.u8 = a;
}

static inline void swipeTexCoord2f32(const f32 s, const f32 t)
{
    GXWGFifo.f32 = s;
    GXWGFifo.f32 = t;
}

#pragma opt_common_subs off
