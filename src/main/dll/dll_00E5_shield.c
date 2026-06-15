/* DLL 0x00E5 — shield / kaldachompspit / pollenfragment group. TU: 0x8016B230–0x8016B2E0. */
#include "main/dll/xyzanimator.h"
#include "main/dll/genpropswgpipe_struct.h"
#include "main/dll/player_objects.h"

extern u32 randomGetRange(int min, int max);
extern undefined4 ObjHitbox_SetSphereRadius();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 FUN_8003b818();


extern void modelLightStruct_setLightKind(int light, int value);
extern void modelLightStruct_setPosition(int light, f32 x, f32 y, f32 z);
extern void modelLightStruct_setSpecularColor(int light, int r, int g, int b, int a);
extern void modelLightStruct_setDistanceAttenuation(int light, f32 near, f32 far);
extern void lightSetField4D(int light, int v);
extern void modelLightStruct_setEnabled(int light, int enabled, f32 scale);
extern void modelLightStruct_startColorFade(int light, int a, int b);

void mikabomb_hitDetect(void);

void mikabomb_free(int obj, int mode);

int mikabomb_getExtraSize(void);
int mikabomb_getObjectTypeId(void);

extern void objRenderFn_8003b8f4(f32);


extern void kaldachompspit_free(void);
extern void kaldachompspit_update(void);
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

extern f32 timeDelta;
extern void* Obj_GetPlayerObject(void);

#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/genprops.h"
#include "main/dll_000A_expgfx.h"

typedef struct ShieldState
{
    u8 pad0[0x4 - 0x0];
    f32 unk4;
    f32 unk8;
    f32 unkC;
    s32 unk10;
    u8 pad14[0x18 - 0x14];
    u8 unk18;
    u8 pad19[0x24 - 0x19];
    f32 unk24;
    s32 unk28;
    f32 unk2C;
    u8 pad30[0x50 - 0x30];
    f32 unk50;
    u8 pad54[0x5C - 0x54];
    u8 unk5C;
    u8 unk5D;
    u8 unk5E;
    u8 unk5F;
    u8 pad60[0x6A - 0x60];
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
} ShieldState;

extern undefined4 FUN_80006810();
extern undefined8 FUN_80006824();
extern undefined4 FUN_8001753c();
extern undefined4 FUN_80017588();
extern undefined4 FUN_8001759c();
extern undefined4 FUN_800175b0();
extern undefined4 FUN_800175bc();
extern undefined4 FUN_800175cc();
extern undefined4 FUN_800175d0();
extern undefined4 FUN_800175d8();
extern undefined4 FUN_800175ec();
extern void* FUN_80017624();
extern undefined4 FUN_80017688();
extern uint FUN_80017690();
extern undefined8 FUN_80017698();
extern int FUN_80017a54();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern int* Obj_SetupObject(void* setup, int mode, int mapLayer, int objIndex, void* parent);
extern undefined8 FUN_8002fc3c();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined4 FUN_800810f8();
extern undefined4 FUN_80081118();
extern undefined8 FUN_800e842c();
extern int FUN_80286838();
extern undefined4 FUN_80286884();
extern undefined4 fcos16Precise();
extern undefined4 FUN_80294c48();
extern undefined4 FUN_80294c60();
extern int FUN_80294cf8();
extern int FUN_80294d10();
extern undefined4 FUN_80294d60();
extern undefined4 FUN_80294d6c();

extern undefined4 DAT_80321678;
extern int DAT_80321688;
extern undefined4 DAT_80321698;
extern int DAT_803216a8;
extern undefined4 DAT_803ad324;
extern undefined4 DAT_803ad328;
extern undefined4 DAT_803ad32c;
extern undefined4 DAT_803ad330;
extern undefined4 DAT_803ad334;
extern undefined4 DAT_803ad338;
extern f64 DOUBLE_803e3e88;
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
extern u8 Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int size, int type);
extern int* Obj_SetupObject(void* setup, int a, int b, int c, void* d);
extern void ModelLightStruct_free(void* p);
extern int Sfx_StopFromObject(int obj, int sfxId);
extern void gcbaddieshield_update(int* obj);
extern void animatedobj_free();
extern void animatedobj_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);
extern void animatedobj_update(int* obj);
extern void animatedobj_init();
extern void dim2roofrub_render(int* obj, int p2, int p3, int p4, int p5);
extern void dim2roofrub_update(int* obj);
extern void dim2roofrub_init();
extern void depthoffieldpoint_update();
extern void depthoffieldpoint_init();
extern void staff_free(int* obj);
extern void staff_update();
extern void staff_init();
extern void staff_release();
extern void staff_initialise();
extern void staff_modelMtxFn(int* obj, int p4, int p5);
extern void staff_hitDetectGeometry();
extern s16 staff_getHitReactValue(int* obj);
extern s32 staff_func16(int* obj);
extern void fireball_free();
extern void fireball_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);
extern void fireball_hitDetect();
extern void fireball_update();
extern void fireball_init();
extern void flamethrowerspe_func0B(int* obj);
extern void flamethrowerspe_render(void);
extern void flamethrowerspe_update();
extern void flamethrowerspe_init();
extern void shield_free();
extern void shield_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);
extern void shield_update();
extern void dll_F7_free();
extern void dll_F7_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);
extern void dll_F7_update();
extern void dll_F7_init();
extern int* Obj_GetActiveModel(int obj);
extern void postRenderSetAlphaBlendState(void);
extern void ObjModel_SetPostRenderCallback(int* model, void* callback);
extern int getHudHiddenFrameCount(void);
extern void modelLightStruct_setEnabled(int handle, int flag, f32 v);
extern void vecRotateZXY(int* obj, f32* p);
extern void modelLightStruct_setPosition(int light, f32 a, f32 b, f32 c);
extern void modelLightStruct_setDistanceAttenuation(int light, f32 a, f32 b);
extern void modelLightStruct_setLightKind(int light, int v);
extern f32 fcos16(u16 angle);
extern void Sfx_SetObjectSfxVolume(f32 ratio, s16* obj, int sfx, int vol);
extern f32 lbl_803E33A8;
extern f32 lbl_803E33AC;
extern f32 lbl_803E33C4;
extern f32 lbl_803E33E8;
extern f32 lbl_803E33EC;
extern s16 lbl_803DBD70[4];
extern s16 lbl_803DBD78[4];
extern s16 lbl_803DBD80[4];
extern s16 lbl_803DBD88[4];
extern f32 lbl_803E33D8;
extern f32 lbl_803E33DC;
extern void modelLightStruct_setAffectsAabbLightSelection(int light, int v);
extern f32 lbl_803E33B0;
extern f32 lbl_803E33B4;
extern f32 lbl_803E33B8;
extern f32 lbl_803E33BC;
extern f32 lbl_803E33C0;
extern f32 lbl_803E33C8;
extern f32 lbl_803E33CC;

void staticCamera_free(int param_1)
{
    ObjGroup_RemoveObject(param_1, 7);
    return;
}

void staticCamera_render(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
    if (visible != 0)
    {
        FUN_8003b818(param_1);
    }
    return;
}

void staticCamera_init(short* param_1, int param_2, int param_3)
{
    undefined* dst;

    *param_1 = -*(short*)(param_2 + 0x1c);
    param_1[1] = -*(short*)(param_2 + 0x1e);
    param_1[2] = -*(short*)(param_2 + 0x20);
    dst = *(undefined**)(param_1 + 0x5c);
    *dst = *(undefined*)(param_2 + 0x19);
    *(float*)(dst + 4) =
        (float)((double)CONCAT44(0x43300000, (uint) * (byte*)(param_2 + 0x1a)) - DOUBLE_803e3e88);
    dst[1] = 0;
    if (param_3 == 0)
    {
        ObjGroup_AddObject((int)param_1, 7);
    }
    return;
}

void FUN_8016d188(int param_1, int param_2)
{
    float factor;
    int mode;
    uint cfgFlag;
    int stateExtra;
    double colorD;
    int ownerData;
    float intensity;
    int spawnType;
    undefined2 fxArgs[3];
    short fxArgsCount;
    float fxArgsScale;
    undefined2 fxId;
    undefined2 local_32;
    undefined2 local_30;
    short fxCount;
    float fxScale;
    float fxParam28;
    float fxParam24;
    undefined4 local_20;
    longlong tmpLL;

    stateExtra = *(int*)&((GameObject*)param_1)->extra;
    if ((param_1 != 0) && (param_2 != 0))
    {
        if (*(char*)(stateExtra + 0xba) != '\0')
        {
            mode = FUN_80294d10(param_2);
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
            if (*(byte*)(stateExtra + 0xbb) == 7)
            {
                colorD = (double)lbl_803E3F2C;
                tmpLL = (longlong)(int)(lbl_803E3F30 * factor);
                FUN_800810f8(colorD, colorD, colorD, (double)(lbl_803E3F34 * intensity), param_1, 7,
                             (uint) * (byte*)(stateExtra + 0xba), 1, (int)(lbl_803E3F30 * factor), 0, 0);
            }
            else
            {
                colorD = (double)lbl_803E3F20;
                tmpLL = (longlong)(int)(lbl_803E3F30 * factor);
                FUN_800810f8(colorD, colorD, colorD, (double)(lbl_803E3F34 * intensity), param_1,
                             (uint) * (byte*)(stateExtra + 0xbb), (uint) * (byte*)(stateExtra + 0xba), 1,
                             (int)(lbl_803E3F30 * factor), 0, 0);
            }
        }
        FUN_80294c60(param_2, &spawnType, &intensity);
        fxId = 0;
        local_32 = 0;
        local_30 = 0;
        fxScale = lbl_803E3F20;
        if (spawnType == 0x87)
        {
            stateExtra = (int)(lbl_803E3F38 * (intensity / lbl_803E3F30));
            tmpLL = (longlong)stateExtra;
            fxCount = 0x15 - (short)stateExtra;
            fxParam28 = lbl_803E3F3C * (intensity / lbl_803E3F40 - lbl_803E3F2C);
            fxId = 0xc94;
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &fxId, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &fxId, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &fxId, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &fxId, 2, -1, NULL);
            fxCount = 9;
            fxScale = lbl_803E3F48 * (intensity / lbl_803E3F40) + lbl_803E3F44;
            fxParam24 = lbl_803E3F4C;
            fxId = 0xc0e;
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b3, &fxId, 2, -1, NULL);
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
                (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b3, &fxId, 2, -1, NULL);
            }
            else if (spawnType < 0x7f)
            {
                if ((spawnType == 0x43) && (lbl_803E3F4C < intensity))
                {
                    stateExtra = (int)(lbl_803E3F38 * (intensity / lbl_803E3F30));
                    tmpLL = (longlong)stateExtra;
                    fxCount = (short)stateExtra + 6;
                    fxParam28 = lbl_803E3F3C * (intensity / lbl_803E3F40 - lbl_803E3F2C);
                    fxId = 0xc94;
                    (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b4, &fxId, 2, -1, NULL);
                    (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b4, &fxId, 2, -1, NULL);
                    fxCount = 9;
                    fxScale = lbl_803E3F48 * (intensity / lbl_803E3F40) + lbl_803E3F44;
                    fxParam24 = lbl_803E3F4C;
                    fxId = 0xc0e;
                    (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b3, &fxId, 2, -1, NULL);
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
                        fxCount = (short)stateExtra;
                        fxId = 0xc94;
                    }
                    else
                    {
                        factor = intensity / lbl_803E3F50;
                        stateExtra = (int)(lbl_803E3F38 * factor);
                        fxCount = (short)stateExtra;
                        fxId = 0xc75;
                    }
                    tmpLL = (longlong)stateExtra;
                    fxParam28 = lbl_803E3F5C * (lbl_803E3F28 - factor);
                    fxCount = 0x15 - fxCount;
                    (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &fxId, 2, -1, NULL);
                    (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &fxId, 2, -1, NULL);
                    (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &fxId, 2, -1, NULL);
                    (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &fxId, 2, -1, NULL);
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
                    (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b3, &fxId, 2, -1, NULL);
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
                factor = *(float*)(param_2 + 0x98);
                if (lbl_803E3F68 <= factor)
                {
                    if (factor < lbl_803E3F70)
                    {
                        fxParam28 = lbl_803E3F5C * (lbl_803E3F74 * (factor - lbl_803E3F68) - lbl_803E3F2C);
                        fxCount = 9;
                        fxScale = lbl_803E3F20;
                        fxParam24 = lbl_803E3F4C;
                        (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b3, &fxId, 2, -1, NULL);
                    }
                }
                else
                {
                    fxParam28 = lbl_803E3F6C;
                    fxCount = 9;
                    fxScale = lbl_803E3F20;
                    fxParam24 = lbl_803E3F4C;
                    (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b3, &fxId, 2, -1, NULL);
                }
            }
        }
        else if (spawnType == 0x468)
        {
            if (lbl_803E3F4C < intensity)
            {
                stateExtra = (int)(lbl_803E3F38 * (intensity / lbl_803E3F60));
                tmpLL = (longlong)stateExtra;
                fxArgsCount = 0x15 - (short)stateExtra;
                fxArgs[0] = 0xc95;
                FUN_80294c48(*(int*)&((GameObject*)param_1)->ownerObj, &ownerData);
                fxParam28 = *(float*)(ownerData + 0xc);
                fxParam24 = *(float*)(ownerData + 0x10);
                local_20 = *(undefined4*)(ownerData + 0x14);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)param_1)->ownerObj, 0x7b9, &fxId,
                                                 0x200001, -1, fxArgs);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)param_1)->ownerObj, 0x7b9, &fxId,
                                                 0x200001, -1, fxArgs);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)param_1)->ownerObj, 0x7b9, &fxId,
                                                 0x200001, -1, fxArgs);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)param_1)->ownerObj, 0x7b9, &fxId,
                                                 0x200001, -1, fxArgs);
                fxArgsCount = 9;
                fxArgs[0] = 0xc95;
                fxArgsScale = lbl_803E3F64 * (intensity / lbl_803E3F60) + lbl_803E3F44;
                fxParam28 = *(float*)(ownerData + 0xc);
                fxParam24 = *(float*)(ownerData + 0x10);
                local_20 = *(undefined4*)(ownerData + 0x14);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)param_1)->ownerObj, 0x7ba, &fxId,
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
                (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b3, &fxId, 2, -1, NULL);
                fxCount = 0x12;
                fxParam24 = lbl_803E3F54;
                (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b3, &fxId, 2, -1, NULL);
            }
        }
        else if ((spawnType == 0x46f) && (lbl_803E3F4C < intensity))
        {
            stateExtra = (int)(lbl_803E3F38 * (intensity / lbl_803E3F60));
            tmpLL = (longlong)stateExtra;
            fxCount = 0x15 - (short)stateExtra;
            fxParam28 = lbl_803E3F5C * (lbl_803E3F28 - intensity / lbl_803E3F60);
            fxId = 0xc94;
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &fxId, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &fxId, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &fxId, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &fxId, 2, -1, NULL);
            fxCount = 9;
            fxScale = lbl_803E3F48 * (intensity / lbl_803E3F60) + lbl_803E3F44;
            fxParam24 = lbl_803E3F4C;
            fxId = 0xc0e;
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b3, &fxId, 2, -1, NULL);
        }
    }
    return;
}

void FUN_8016d994(int param_1, undefined param_2, undefined param_3)
{
    int stateExtra;

    stateExtra = *(int*)&((GameObject*)param_1)->extra;
    *(undefined*)(stateExtra + 0xbb) = param_2;
    *(undefined*)(stateExtra + 0xba) = param_3;
    return;
}

void FUN_8016e8cc(undefined8 param_1, undefined8 param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  int param_9)
{
    short clamped;
    int hits;
    int* group;
    uint idx;
    int particle;
    int* state;
    double colorD;
    double clampedColor;
    undefined8 local_18;

    state = ((GameObject*)param_9)->extra;
    hits = FUN_80017a54(param_9);
    *(ushort*)(hits + 0x18) = *(ushort*)(hits + 0x18) & ~0x8;
    FUN_8002fc3c((double)(float)state[0x14], (double)lbl_803DC074);
    hits = 3;
    group = state;
    do
    {
        if ((*(byte*)(group + 5) & 2) != 0)
        {
            idx = (uint) * (ushort*)(group + 3);
            particle = *group + idx * 0x14;
            for (; (int)idx < (int)(uint) * (ushort*)((int)group + 0xe); idx = idx + 2)
            {
                if (group == (int*)state[0x12])
                {
                    param_3 = (double)lbl_803E3F8C;
                    colorD = (double)(float)(param_3 *
                        (double)((lbl_803E3FA4 * (float)state[0x26] -
                            *(float*)(particle + 0xc)) * lbl_803E3FA8));
                    clampedColor = (double)lbl_803E3F4C;
                    if ((clampedColor <= colorD) && (clampedColor = colorD, param_3 < colorD))
                    {
                        clampedColor = param_3;
                    }
                    *(short*)(particle + 0x10) = (short)(int)(param_3 - clampedColor);
                    *(undefined2*)(particle + 0x24) = *(undefined2*)(particle + 0x10);
                }
                else
                {
                    param_3 = (double)lbl_803E3FC4;
                    *(short*)(particle + 0x10) =
                        (short)(int)-(float)(param_3 * (double)lbl_803DC074 -
                            (double)(f32)(s32)((int)*(short*)(particle + 0x10)));
                    *(undefined2*)(particle + 0x24) = *(undefined2*)(particle + 0x10);
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
                *(byte*)(group + 5) = *(byte*)(group + 5) & 0xfd;
            }
        }
        group = group + 6;
        hits = hits + -1;
    }
    while (hits != 0);
    FUN_8016d188(param_9, *(int*)&((GameObject*)param_9)->ownerObj);
    FUN_80294d6c(*(int*)&((GameObject*)param_9)->ownerObj);
    *(undefined*)((int)state + 0xb9) = 0;
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
            FUN_80017ac8((double)DAT_803ad330, clampedColor, param_3, param_4, param_5, param_6, param_7, param_8,
                         DAT_803ad334);
            DAT_803ad334 = 0;
        }
    }
    return;
}

void FUN_80170048(void)
{
    float defaultVal;
    uint objHi;
    int seqObj;
    int* writer;
    uint rand;
    int glowObj;
    int* state;
    int* colorTbl;
    float* scaleTbl;
    double cosVal;
    double scaleC;
    double phase;
    double biasC;
    double offsetC;
    undefined8 packed;
    undefined8 local_78;
    undefined8 local_70;

    packed = FUN_80286838();
    objHi = (uint)((ulonglong)packed >> 0x20);
    scaleTbl = (float*)&DAT_80321678;
    state = *(int**)(objHi + 0xb8);
    seqObj = FUN_80017a98();
    glowObj = 0;
    if (seqObj != 0)
    {
        glowObj = FUN_80294cf8(seqObj);
    }
    defaultVal = lbl_803E4064;
    switch ((uint)packed & 0xff)
    {
    case 0:
        if (*state != 0)
        {
            FUN_800175cc((double)lbl_803E4040, *state, '\0');
        }
        defaultVal = lbl_803E4048;
        if (lbl_803E4044 != (float)state[2])
        {
            state[4] = (int)lbl_803E4048;
            state[1] = (int)defaultVal;
            if (glowObj != 0)
            {
                FUN_8016d994(glowObj, 7, 0);
            }
        }
        state[2] = (int)lbl_803E4044;
        state[3] = (int)lbl_803E404C;
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
                state[4] = (int)lbl_803E4048;
                state[1] = (int)defaultVal;
            }
            state[2] = (int)lbl_803E4048;
            scaleC = (double)lbl_803E405C;
            state[3] = (int)lbl_803E405C;
            seqObj = 0;
            colorTbl = &DAT_80321688;
            phase = (double)lbl_803E4040;
            biasC = (double)lbl_803E4060;
            writer = state;
            offsetC = DOUBLE_803e4068;
            do
            {
                *(undefined2*)(writer + 0xd) = 0xc000;
                cosVal = (double)fcos16Precise();
                state[9] = (int)(*scaleTbl * (float)((double)(float)(scaleC + cosVal) * phase));
                state[5] = *colorTbl;
                rand = randomGetRange(0x78, 0x7f);
                local_78 = (double)CONCAT44(0x43300000, seqObj * rand ^ 0x80000000);
                *(short*)(writer + 0xf) = (short)(int)(biasC + (double)(float)(local_78 - offsetC));
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
            state[4] = (int)lbl_803E4064;
        }
        state[2] = (int)lbl_803E4044;
        state[3] = (int)lbl_803E404C;
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
            state[4] = (int)lbl_803E4064;
        }
        state[2] = (int)lbl_803E4064;
        biasC = (double)lbl_803E405C;
        state[3] = (int)lbl_803E405C;
        seqObj = 0;
        colorTbl = &DAT_80321688;
        offsetC = (double)lbl_803E4040;
        writer = state;
        do
        {
            *(undefined2*)(state + 0xd) = 0;
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
        state[2] = (int)lbl_803E4064;
        biasC = (double)lbl_803E405C;
        state[3] = (int)lbl_803E405C;
        state[4] = (int)defaultVal;
        seqObj = 0;
        scaleTbl = (float*)&DAT_80321698;
        colorTbl = &DAT_803216a8;
        phase = (double)lbl_803E4040;
        scaleC = (double)lbl_803E4060;
        writer = state;
        offsetC = DOUBLE_803e4068;
        do
        {
            *(undefined2*)(state + 0xd) = 0xc000;
            cosVal = (double)fcos16Precise();
            writer[9] = (int)(*scaleTbl * (float)((double)(float)(biasC + cosVal) * phase));
            writer[5] = *colorTbl;
            rand = randomGetRange(0x78, 0x7f);
            local_70 = (double)CONCAT44(0x43300000, seqObj * rand ^ 0x80000000);
            *(short*)(state + 0xf) = (short)(int)(scaleC + (double)(float)(local_70 - offsetC));
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
        state[2] = (int)lbl_803E4044;
        state[3] = (int)lbl_803E404C;
        state[4] = (int)lbl_803E4064;
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
            *(undefined2*)(state + 0xd) = 0x4000;
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
        state[2] = (int)lbl_803E4044;
        state[3] = (int)defaultVal;
        state[4] = (int)defaultVal;
        state[1] = (int)defaultVal;
        *(byte*)(state + 0x17) = *(byte*)(state + 0x17) | 1;
        *(byte*)((int)state + 0x5d) = *(byte*)((int)state + 0x5d) | 1;
        *(byte*)((int)state + 0x5e) = *(byte*)((int)state + 0x5e) | 1;
        *(byte*)((int)state + 0x5f) = *(byte*)((int)state + 0x5f) | 1;
    }
    FUN_80286884();
    return;
}



void mikabombshadow_update(int* obj);


void FUN_801713ac(undefined8 param_1, double param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  uint param_9)
{
    extern undefined8 ObjHits_DisableObject(); /* #57 */
    short seqId;
    char counter;
    uint tmp;
    int setupData;
    int placementData;
    int stateExtra;
    undefined8 callResult;

    stateExtra = *(int*)&((GameObject*)param_9)->extra;
    placementData = *(int*)&((GameObject*)param_9)->anim.placementData;
    setupData = (int)((GameObject*)param_9)->anim.modelInstance->extraSetupData;
    FUN_80017a98();
    FUN_80017a90();
    FUN_80017a98();
    FUN_80017a90();
    callResult = ObjHits_DisableObject(param_9);
    if ((*(ushort*)&((GameObject*)param_9)->anim.flags & 0x2000) != 0)
    {
        *(float*)(stateExtra + 8) = lbl_803E40E8;
        if (((GameObject*)param_9)->anim.modelState != NULL)
        {
            ((GameObject*)param_9)->anim.modelState->flags = OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        }
    }
    if ((int)*(short*)(stateExtra + 0x10) != 0xffffffff)
    {
        FUN_80017698((int)*(short*)(stateExtra + 0x10), 1);
        callResult = FUN_800e842c(param_9);
    }
    tmp = (uint) * (short*)(placementData + 0x1e);
    if (tmp != 0xffffffff)
    {
        callResult = FUN_80017698(tmp, 1);
    }
    tmp = (uint) * (short*)(placementData + 0x2c);
    if (0 < (int)tmp)
    {
        FUN_80017688(tmp);
    }
    seqId = *(short*)(setupData + 2);
    if (seqId == 4)
    {
        seqId = ((GameObject*)param_9)->anim.seqId;
        if (seqId == 0x3cd)
        {
            setupData = FUN_80017a98();
            FUN_80294d60(callResult, param_2, param_3, param_4, param_5, param_6, param_7, param_8, setupData, 2);
            tmp = FUN_80017a98();
            FUN_80006824(tmp, SFXen_treadlpc);
            FUN_80081118((double)lbl_803E40EC, param_9, 1, 0x28);
        }
        else if ((seqId < 0x3cd) && (seqId == 0xb))
        {
            tmp = FUN_80017a98();
            callResult = FUN_80006824(tmp, SFXen_treadlpc);
            setupData = FUN_80017a98();
            FUN_80294d60(callResult, param_2, param_3, param_4, param_5, param_6, param_7, param_8, setupData, 4);
            FUN_80081118((double)lbl_803E40EC, param_9, 3, 0x28);
        }
        else
        {
            tmp = FUN_80017a98();
            FUN_80006824(tmp, SFXen_waterblock_stop);
            FUN_80081118((double)lbl_803E40EC, param_9, 0xff, 0x28);
        }
    }
    else if ((seqId < 4) && (seqId == 1))
    {
        seqId = ((GameObject*)param_9)->anim.seqId;
        if (seqId == 0x319)
        {
            FUN_80006824(param_9, SFXwp_gprop2_c);
            FUN_80017698(0x3e9, 1);
            *(undefined2*)(stateExtra + 0x3c) = 0x4b0;
            FUN_80081118((double)lbl_803E40EC, param_9, 0xff, 0x28);
        }
        else
        {
            if (seqId < 0x319)
            {
                if (seqId == 0x5a)
                {
                    FUN_80006824(param_9, SFXen_treadlpc);
                    FUN_80081118((double)lbl_803E40EC, param_9, 2, 0x28);
                    goto LAB_801725bc;
                }
                if ((seqId < 0x5a) && (seqId == 0x22))
                {
                    FUN_80006824(param_9, SFXen_treadlpc);
                    FUN_80081118((double)lbl_803E40EC, param_9, 0xff, 0x28);
                    goto LAB_801725bc;
                }
            }
            else if (seqId == 0x6a6)
            {
                tmp = FUN_80017690(0x86a);
                counter = (char)tmp;
                if (counter < '\a')
                {
                    counter = counter + '\x01';
                }
                FUN_80017698(0x86a, (int)counter);
                FUN_80081118((double)lbl_803E40EC, param_9, 6, 0x28);
                FUN_80006824(param_9, SFXen_treadlpc);
                goto LAB_801725bc;
            }
            FUN_80006824(param_9, SFXen_waterblock_stop);
            FUN_80081118((double)lbl_803E40EC, param_9, 0xff, 0x28);
        }
    }
    else
    {
        FUN_80006824(param_9, SFXen_waterblock_stop);
        FUN_80081118((double)lbl_803E40EC, param_9, 0xff, 0x28);
    }
LAB_801725bc:
    *(undefined4*)&((GameObject*)param_9)->anim.rootMotionScale = *(undefined4*)(*(int*)&((GameObject*)param_9)->anim.
        modelInstance + 4);
    ((GameObject*)param_9)->unkF4 = 1;
    return;
}




















void staff_func0F(void);


void staff_func0B(void);

void staff_setScale(void);

void staff_render(void);

void staff_hitDetect(void);

void fireball_release(void);

void fireball_initialise(void);

void flamethrowerspe_modelMtxFn(void);

void flamethrowerspe_free(void);

void flamethrowerspe_hitDetect(void);

void flamethrowerspe_release(void);

void flamethrowerspe_initialise(void);

void shield_hitDetect(void)
{
}

void shield_release(void)
{
}

void shield_initialise(void)
{
}

void shield_free(int obj)
{
    void** state = ((GameObject*)obj)->extra;
    if (state[0] != NULL)
    {
        ModelLightStruct_free(state[0]);
        state[0] = NULL;
    }
    Sfx_StopFromObject(obj, 0x42C);
    Sfx_StopFromObject(obj, 0x42D);
}












int animatedobj_getExtraSize(void);
int dim2roofrub_getExtraSize(void);
int depthoffieldpoint_getExtraSize(void);
int staff_getExtraSize(void);
int staff_getObjectTypeId(void);
int fireball_getExtraSize(void);
int fireball_getObjectTypeId(void);
int flamethrowerspe_getExtraSize(void);
int flamethrowerspe_getObjectTypeId(void);
int shield_getExtraSize(void) { return 0x60; }
int shield_getObjectTypeId(void) { return 0x0; }

void dll_F7_free(int obj);

void dim2roofrub_free(int* obj);


void staff_func10(int* obj, s32 v);
void staff_setHitReactValue(int* obj, s32 v);
void staff_addHitReactValue(int* obj, s32 delta);
void staff_getHitGeometryPoints(int* obj, f32* outA, f32* outB);
void staff_func15(int* obj, s16 idx, f32 f1, f32 f2);
void flamethrowerspe_setScale(int* obj, s16 a, s16 b, f32 f1, f32 f2, f32 f3);

void restartmarker_init(int* obj, int* state);

void staffFn_80170380(int* obj, int cmd);

void shield_init(int* obj, void* initData)
{
    int* model = Obj_GetActiveModel((int)obj);
    ObjModel_SetPostRenderCallback(model, postRenderSetAlphaBlendState);
    if (((GameObject*)obj)->anim.seqId == 0x836)
    {
        staffFn_80170380(obj, 5);
    }
    else
    {
        staffFn_80170380(obj, 7);
    }
}

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

s16 staff_getHitReactValue(int* obj);

s32 staff_func16(int* obj);





void flamethrowerspe_render(void);
void fn_801719F8(void) { objRenderFn_8003b8f4(lbl_803E3420); }


void flamethrowerspe_func0B(int* obj);

void staffSetGlow(int* obj, u8 a, u8 b);



void staff_modelMtxFn(int* obj, int p4, int p5);







int* fn_801702D4(int* obj, f32 fv)
{
    void* alloc;
    int* new_obj;
    if ((u8)Obj_IsLoadingLocked() == 0) return NULL;
    alloc = Obj_AllocObjectSetup(36, 2102);
    *(f32*)((char*)alloc + 8) = ((GameObject*)obj)->anim.worldPosX;
    *(f32*)((char*)alloc + 12) = ((GameObject*)obj)->anim.worldPosY;
    *(f32*)&((ObjDef*)alloc)->jointData = ((GameObject*)obj)->anim.worldPosZ;
    *(u8*)((char*)alloc + 4) = 1;
    *(u8*)((char*)alloc + 5) = 1;
    *(u8*)((char*)alloc + 7) = 255;
    new_obj = Obj_SetupObject(alloc, 5, -1, -1, (void*)0);
    if (new_obj != NULL)
    {
        ((GameObject*)new_obj)->anim.rootMotionScale = fv;
    }
    return new_obj;
}

void gcbaddieshield_update(int* obj);

void staff_free(int* obj);

void fireball_free(int* obj);

void depthoffieldpoint_init(int* obj);

void depthoffieldpoint_update(int* obj);

void staff_release(void);

void mikabombshadow_init(int* obj);

void StaticCamera_init(int* obj, int* params, int flag);

void flamethrowerspe_init(int* obj, int* params);

void animatedobj_free(int* obj, int seqFlag);

void staff_init(int* obj);

void dll_F7_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);

void dll_F7_init(int* obj, int* params);

void fireball_hitDetect(int* obj);

void dim2roofrub_init(int* obj, int* params);

void animatedobj_init(int* obj, int* params);

void flamethrowerspe_update(int* obj);


void mikabomb_init(int* obj);

void baddieinterestp_update(int* obj);

void animatedobj_update(int* obj);

void animatedobj_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);

void dim2roofrub_render(int* obj, int p2, int p3, int p4, int p5);

void dim2roofrub_update(int* obj);

void fireball_init(int* obj);

void fireball_update(int* obj);

void fireball_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);

void shield_update(int* obj)
{
    f32* tbl = lbl_80320A28;
    f32* state = ((GameObject*)obj)->extra;
    int i;

    if (state[1] != state[2])
    {
        state[1] = state[3] * timeDelta + state[1];
        if (state[3] > lbl_803E33AC)
        {
            if (state[1] >= state[2])
            {
                state[1] = state[2];
            }
            ((ShieldState*)state)->unk5C &= ~1;
            ((ShieldState*)state)->unk5D &= ~1;
            ((ShieldState*)state)->unk5E &= ~1;
            ((ShieldState*)state)->unk5F &= ~1;
        }
        else
        {
            if (state[1] <= state[2])
            {
                state[1] = state[2];
                ((ShieldState*)state)->unk5C |= 1;
                ((ShieldState*)state)->unk5D |= 1;
                ((ShieldState*)state)->unk5E |= 1;
                ((ShieldState*)state)->unk5F |= 1;
            }
        }
    }
    if (((GameObject*)obj)->anim.seqId == 2102)
    {
        ((GameObject*)obj)->anim.alpha = state[1] / state[4] * (f32)(s32)randomGetRange(96, 127);
    }
    else
    {
        ((GameObject*)obj)->anim.alpha = state[1] / state[4] * (f32)(s32)randomGetRange(192, 255);
    }
    Sfx_SetObjectSfxVolume(lbl_803E33A8, (s16*)obj, 1069, (s32)(lbl_803E33E8 * (state[1] / state[4])));
    if (((GameObject*)obj)->anim.alpha != 0)
    {
        ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
    }
    else
    {
        ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
    }
    {
        s16* ps = (s16*)state;
        f32* t8 = tbl + 8;
        f32* pf = state;
        f32* t12 = tbl + 12;
        f32* t4 = tbl + 4;
        for (i = 0; i < 4; i++)
        {
            ps[26] = (s32)((f32)ps[30] * timeDelta + (f32)ps[26]);
            if (((GameObject*)obj)->anim.seqId == 2102)
            {
                pf[9] = *t8 * (fcos16(ps[26]) * lbl_803E33EC + lbl_803E33C4);
                pf[5] = *t12;
            }
            else
            {
                pf[9] = *tbl * ((lbl_803E33C4 + fcos16(ps[26])) * lbl_803E33A8);
                pf[5] = *t4;
            }
            ps++;
            t8++;
            pf++;
            t12++;
            tbl++;
            t4++;
        }
    }
}

void dll_F7_update(int* obj);

void staff_initialise(void);

typedef struct ShieldFxVec
{
    u8 pad[8];
    f32 a;
    f32 v[3];
} ShieldFxVec;

void shield_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    u8* state = ((GameObject*)obj)->extra;
    s32 v = visible;
    if (v != 0)
    {
        ShieldFxVec s;
        int* model;
        f32 savedF8;
        u8 savedB36;
        s16 saved0;
        s16 saved2;
        s16 saved4;
        u8 hud;
        f32 dt;
        u8 i;
        model = Obj_GetActiveModel((int)obj);
        savedF8 = ((GameObject*)obj)->anim.rootMotionScale;
        savedB36 = ((GameObject*)obj)->anim.alpha;
        saved0 = *(s16*)obj;
        saved2 = ((GameObject*)obj)->anim.rotY;
        saved4 = ((GameObject*)obj)->anim.rotZ;
        hud = getHudHiddenFrameCount();
        if (hud != 0)
        {
            dt = lbl_803E33AC;
        }
        else
        {
            dt = timeDelta;
        }
        if (((GameObject*)obj)->anim.seqId == 2102)
        {
            for (i = 0; i < 4; i++)
            {
                if ((*(u8*)(state + i + 0x5c) & 1) == 0)
                {
                    u8* q = state + i * 2;
                    *(s16*)obj = *(s16*)(q + 0x44);
                    ((GameObject*)obj)->anim.rotY = *(s16*)(q + 0x4c);
                    ((GameObject*)obj)->anim.rotZ = *(s16*)(q + 0x54);
                    *(s16*)(q + 0x44) = dt * (f32)lbl_803DBD78[i] + (f32) * (s16*)(q + 0x44);
                    *(s16*)(q + 0x4c) = dt * (f32)lbl_803DBD80[i] + (f32) * (s16*)(q + 0x4c);
                    *(s16*)(q + 0x54) = dt * (f32)lbl_803DBD88[i] + (f32) * (s16*)(q + 0x54);
                    {
                        u8* r = state + i * 4;
                        ((GameObject*)obj)->anim.rootMotionScale = *(f32*)(r + 0x24) * savedF8 *
                            (((ShieldState*)state)->unk4 / *(f32*)&((ShieldState*)state)->unk10);
                        *(u8*)((char*)obj + 0x37) = *(f32*)(r + 0x14) * (f32)savedB36;
                    }
                    *(u16*)((char*)model + 0x18) &= ~0x8;
                    ((void (*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E33C4);
                }
            }
        }
        else
        {
            f32* pv = s.v;
            for (i = 0; i < 4; i++)
            {
                if ((*(u8*)(state + i + 0x5c) & 1) == 0)
                {
                    u32 off = i * 2 + 0x44;
                    *(s16*)obj = *(s16*)(state + off);
                    *(s16*)(state + off) = dt * (f32)lbl_803DBD70[i] + (f32) * (s16*)(state + off);
                    {
                        u8* r = state + i * 4;
                        ((GameObject*)obj)->anim.rootMotionScale = *(f32*)(r + 0x24) * savedF8;
                        *(u8*)((char*)obj + 0x37) = *(f32*)(r + 0x14) * (f32)savedB36;
                    }
                    *(u16*)((char*)model + 0x18) &= ~0x8;
                    ((void (*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E33C4);
                    if (hud == 0)
                    {
                        u8 j;
                        f32 cA = lbl_803E33D8;
                        f32 cB = lbl_803E33DC;
                        f32 cC = lbl_803E33AC;
                        f32 cD = lbl_803E33C4;
                        for (j = 0; j < 2; j++)
                        {
                            f32 f8v = ((GameObject*)obj)->anim.rootMotionScale;
                            pv[0] = cA * f8v;
                            pv[1] = cB * f8v;
                            pv[2] = cC;
                            *(s16*)obj += 32767;
                            vecRotateZXY(obj, pv);
                            pv[0] += ((GameObject*)obj)->anim.localPosX;
                            pv[1] += ((GameObject*)obj)->anim.localPosY;
                            pv[2] += ((GameObject*)obj)->anim.localPosZ;
                            s.a = cD;
                            (*gPartfxInterface)->spawnObject(obj, 2028, &s, 0x200001, -1,
                                                             NULL);
                        }
                    }
                }
            }
        }
        ((GameObject*)obj)->anim.rootMotionScale = savedF8;
        ((GameObject*)obj)->anim.alpha = savedB36;
        *(s16*)obj = saved0;
        ((GameObject*)obj)->anim.rotY = saved2;
        ((GameObject*)obj)->anim.rotZ = saved4;
    }
}

void staff_hitDetectGeometry(int* obj);
#pragma opt_common_subs reset

volatile GenPropsWGPipe GXWGFifo : (0xCC008000);

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

void staff_update(int* obj);

void staffFn_80170380(int* obj, int cmd)
{
    extern int objCreateLight(int* obj, int arg); /* #57 */
    extern void modelLightStruct_setDiffuseColor(int* light, int r, int g, int b, int a); /* #57 */
    extern void Sfx_PlayFromObject(int* obj, int sfx); /* #57 */
    f32* tbl = lbl_80320A28;
    u8* state = ((GameObject*)obj)->extra;
    int* glow = NULL;
    int* player = (int*)Obj_GetPlayerObject();
    if (player != NULL)
    {
        glow = (int*)Player_GetStaffObject((int)player);
    }
    switch ((u8)cmd)
    {
    case 7:
        if (glow != NULL)
        {
            staffSetGlow(glow, 7, 0);
        }
        if (*(int**)state != NULL)
        {
            modelLightStruct_setEnabled(*(int*)state, 0, lbl_803E33A8);
        }
        {
            f32 v = lbl_803E33AC;
            *(f32*)(state + 8) = v;
            *(f32*)(state + 0xc) = v;
            *(f32*)(state + 0x10) = v;
            *(f32*)(state + 4) = v;
        }
        state[0x5c] |= 1;
        state[0x5d] |= 1;
        state[0x5e] |= 1;
        state[0x5f] |= 1;
        break;
    case 0:
        if (*(int**)state != NULL)
        {
            modelLightStruct_setEnabled(*(int*)state, 0, lbl_803E33A8);
        }
        if (lbl_803E33AC != *(f32*)(state + 8))
        {
            f32 v = lbl_803E33B0;
            *(f32*)(state + 0x10) = v;
            *(f32*)(state + 4) = v;
            if (glow != NULL)
            {
                staffSetGlow(glow, 7, 0);
            }
        }
        *(f32*)(state + 8) = lbl_803E33AC;
        *(f32*)(state + 0xc) = lbl_803E33B4;
        Sfx_StopFromObject((int)obj, 0x42c);
        Sfx_StopFromObject((int)obj, 0x42d);
        break;
    case 1:
        if (lbl_803E33AC == *(f32*)(state + 8))
        {
            if (glow != NULL)
            {
                staffSetGlow(glow, 7, 8);
            }
            if (*(int**)state == NULL)
            {
                *(int*)state = objCreateLight(0, 1);
            }
            if (*(int**)state != NULL)
            {
                modelLightStruct_setLightKind(*(int*)state, 2);
                modelLightStruct_setPosition(*(int*)state, ((GameObject*)obj)->anim.localPosX,
                                             ((GameObject*)obj)->anim.localPosY - lbl_803E33B8,
                                             ((GameObject*)obj)->anim.localPosZ);
                modelLightStruct_setDiffuseColor(*(int**)state, 0, 255, 255, 255);
                modelLightStruct_setSpecularColor(*(int*)state, 0, 255, 255, 255);
                modelLightStruct_setDistanceAttenuation(*(int*)state, lbl_803E33BC, lbl_803E33C0);
                lightSetField4D(*(int*)state, 1);
                modelLightStruct_setEnabled(*(int*)state, 1, lbl_803E33AC);
                modelLightStruct_startColorFade(*(int*)state, 0, 0);
                modelLightStruct_setAffectsAabbLightSelection(*(int*)state, 1);
            }
            {
                f32 v1 = lbl_803E33AC;
                if (v1 == *(f32*)(state + 8))
                {
                    *(f32*)(state + 0x10) = lbl_803E33B0;
                    *(f32*)(state + 4) = v1;
                }
            }
            *(f32*)(state + 8) = lbl_803E33B0;
            {
                f32 amp = lbl_803E33C4;
                int i;
                u8* hw;
                u8* w;
                f32* t0;
                f32* t1;
                f32 k;
                f32 kc;
                *(f32*)(state + 0xc) = amp;
                i = 0;
                hw = state;
                w = state;
                t0 = tbl;
                t1 = (f32*)((char*)tbl + 0x10);
                k = lbl_803E33A8;
                kc = lbl_803E33C8;
                for (; i < 4; i++)
                {
                    f32 c;
                    f32 sum;
                    *(s16*)(hw + 0x34) = -0x4000;
                    c = fcos16((u16) * (s16*)(hw + 0x34));
                    sum = amp + c;
                    c = sum * k;
                    *(f32*)(w + 0x24) = *t0 * c;
                    *(f32*)(w + 0x14) = *t1;
                    *(s16*)(hw + 0x3c) = kc + (f32)(int)(i * randomGetRange(0x78, 0x7f));
                    hw += 2;
                    t0 += 1;
                    w += 4;
                    t1 += 1;
                }
            }
            Sfx_PlayFromObject(obj, 0x42c);
            Sfx_PlayFromObject(obj, 0x42d);
        }
        break;
    case 2:
        if (glow != NULL)
        {
            staffSetGlow(glow, 7, 0);
        }
        if (lbl_803E33AC != *(f32*)(state + 8))
        {
            *(f32*)(state + 0x10) = lbl_803E33CC;
        }
        *(f32*)(state + 8) = lbl_803E33AC;
        *(f32*)(state + 0xc) = lbl_803E33B4;
        if (*(int**)state != NULL)
        {
            modelLightStruct_setEnabled(*(int*)state, 0, lbl_803E33A8);
        }
        Sfx_StopFromObject((int)obj, 0x42c);
        Sfx_StopFromObject((int)obj, 0x42d);
        break;
    case 3:
        if (glow != NULL)
        {
            staffSetGlow(glow, 7, 8);
        }
        if (*(int**)state == NULL)
        {
            *(int*)state = objCreateLight(0, 1);
        }
        if (*(int**)state != NULL)
        {
            modelLightStruct_setLightKind(*(int*)state, 2);
            modelLightStruct_setPosition(*(int*)state, ((GameObject*)obj)->anim.localPosX,
                                         ((GameObject*)obj)->anim.localPosY - lbl_803E33B8,
                                         ((GameObject*)obj)->anim.localPosZ);
            modelLightStruct_setDiffuseColor(*(int**)state, 0, 255, 255, 255);
            modelLightStruct_setSpecularColor(*(int*)state, 0, 255, 255, 255);
            modelLightStruct_setDistanceAttenuation(*(int*)state, lbl_803E33BC, lbl_803E33C0);
            lightSetField4D(*(int*)state, 1);
            modelLightStruct_setEnabled(*(int*)state, 1, lbl_803E33AC);
            modelLightStruct_startColorFade(*(int*)state, 0, 0);
            modelLightStruct_setAffectsAabbLightSelection(*(int*)state, 1);
        }
        if (lbl_803E33AC == *(f32*)(state + 8))
        {
            *(f32*)(state + 0x10) = lbl_803E33CC;
        }
        *(f32*)(state + 8) = lbl_803E33CC;
        {
            f32 amp = lbl_803E33C4;
            int i;
            u8* hw;
            u8* w;
            f32* t0;
            f32* t1;
            f32 k;
            *(f32*)(state + 0xc) = amp;
            i = 0;
            hw = state;
            w = state;
            t0 = tbl;
            t1 = (f32*)((char*)tbl + 0x10);
            k = lbl_803E33A8;
            for (; i < 4; i++)
            {
                f32 c;
                f32 sum;
                *(s16*)(hw + 0x34) = 0;
                c = fcos16((u16) * (s16*)(hw + 0x34));
                sum = amp + c;
                c = sum * k;
                *(f32*)(w + 0x24) = *t0 * c;
                *(f32*)(w + 0x14) = *t1;
                hw += 2;
                t0 += 1;
                w += 4;
                t1 += 1;
            }
        }
        Sfx_PlayFromObject(obj, 0x42d);
        Sfx_PlayFromObject(obj, 0x42c);
        break;
    case 5:
        *(f32*)(state + 8) = lbl_803E33AC;
        *(f32*)(state + 0xc) = lbl_803E33B4;
        *(f32*)(state + 0x10) = lbl_803E33CC;
        Sfx_StopFromObject((int)obj, 0x42c);
        Sfx_StopFromObject((int)obj, 0x42d);
        break;
    case 4:
        {
            f32 v = lbl_803E33CC;
            f32 amp;
            *(f32*)(state + 8) = v;
            amp = lbl_803E33C4;
            *(f32*)(state + 0xc) = amp;
            *(f32*)(state + 0x10) = v;
            {
                int i;
                u8* hw;
                u8* w;
                f32* t0;
                f32* t1;
                f32 k;
                f32 kc;
                i = 0;
                hw = state;
                t0 = (f32*)((char*)tbl + 0x20);
                w = state;
                t1 = (f32*)((char*)tbl + 0x30);
                k = lbl_803E33A8;
                kc = lbl_803E33C8;
                for (; i < 4; i++)
                {
                    f32 c;
                    f32 sum;
                    *(s16*)(hw + 0x34) = -0x4000;
                    c = fcos16((u16) * (s16*)(hw + 0x34));
                    sum = amp + c;
                    c = sum * k;
                    *(f32*)(w + 0x24) = *t0 * c;
                    *(f32*)(w + 0x14) = *t1;
                    *(s16*)(hw + 0x3c) = kc + (f32)(int)(i * randomGetRange(0x78, 0x7f));
                    hw += 2;
                    t0 += 1;
                    w += 4;
                    t1 += 1;
                }
            }
            Sfx_PlayFromObject(obj, 0x42d);
            Sfx_PlayFromObject(obj, 0x42c);
            break;
        }
    case 6:
        {
            int i;
            u8* hw;
            u8* w;
            f32* t0;
            f32* t1;
            f32 amp;
            f32 k;
            i = 0;
            hw = state;
            t0 = (f32*)((char*)tbl + 0x20);
            w = state;
            t1 = (f32*)((char*)tbl + 0x30);
            amp = lbl_803E33C4;
            k = lbl_803E33A8;
            for (; i < 4; i++)
            {
                f32 c;
                f32 sum;
                *(s16*)(hw + 0x34) = 0x4000;
                c = fcos16((u16) * (s16*)(hw + 0x34));
                sum = amp + c;
                c = sum * k;
                *(f32*)(w + 0x24) = *t0 * c;
                *(f32*)(w + 0x14) = *t1;
                hw += 2;
                t0 += 1;
                w += 4;
                t1 += 1;
            }
            break;
        }
    }
}
