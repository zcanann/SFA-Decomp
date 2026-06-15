/* DLL 0x00EA — side-load / XYZ-animator objects [8016B230-8016B2E0) */
#include "main/dll/xyzanimator.h"
#include "main/dll/genpropswgpipe_struct.h"

extern u32 randomGetRange(int min, int max);
extern undefined4 ObjHitbox_SetSphereRadius();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 FUN_8003b818();


void mikabomb_hitDetect(void);

void mikabomb_free(int obj, int mode);

int mikabomb_getExtraSize(void);
int mikabomb_getObjectTypeId(void);

extern void objRenderFn_8003b8f4(f32);

void mikabomb_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

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

extern void* Obj_GetPlayerObject(void);
extern void* getTrickyObject(void);

#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/genprops.h"
#include "main/dll_000A_expgfx.h"

typedef struct SideloadPlacement
{
    u8 pad0[0x4 - 0x0];
    f32 unk4;
    f32 unk8;
    f32 unkC;
    f32 unk10;
    u8 pad14[0x18 - 0x14];
    u8 unk18;
    u8 pad19[0x1A - 0x19];
    u8 unk1A;
    u8 pad1B[0x3C - 0x1B];
    s16 unk3C;
    u8 pad3E[0x48 - 0x3E];
    void* unk48;
    u8 pad4C[0x50 - 0x4C];
    f32 unk50;
    u8 pad54[0x70 - 0x54];
    u8 unk70;
    u8 pad71[0x98 - 0x71];
    f32 unk98;
    u8 pad9C[0xAA - 0x9C];
    u8 unkAA;
    u8 padAB[0xB0 - 0xAB];
    s16 unkB0;
    u8 padB2[0xB8 - 0xB2];
    f32 unkB8;
    f32 unkBC;
    f32 unkC0;
    u8 padC4[0x2B1 - 0xC4];
    s8 unk2B1;
    u8 pad2B2[0x2B8 - 0x2B2];
} SideloadPlacement;

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
extern u32 GameBit_Get(int eventId);
extern void* Obj_AllocObjectSetup(int size, int type);
extern int* Obj_SetupObject(void* setup, int a, int b, int c, void* d);
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
    undefined* colorState;

    *param_1 = -*(short*)(param_2 + 0x1c);
    param_1[1] = -*(short*)(param_2 + 0x1e);
    param_1[2] = -*(short*)(param_2 + 0x20);
    colorState = *(undefined**)(param_1 + 0x5c);
    *colorState = *(undefined*)(param_2 + 0x19);
    *(float*)(colorState + 4) =
        (float)((double)CONCAT44(0x43300000, (uint) * (byte*)(param_2 + 0x1a)) - DOUBLE_803e3e88);
    colorState[1] = 0;
    if (param_3 == 0)
    {
        ObjGroup_AddObject((int)param_1, 7);
    }
    return;
}

void FUN_8016d188(int param_1, int param_2)
{
    float intensity;
    int scratch2;
    uint useAltTex;
    int amount;
    double spawnScale;
    int ownerXform;
    float progress;
    int seqId;
    undefined2 spawnParam[3];
    short frameCount;
    float spawnAlpha;
    undefined2 local_34;
    undefined2 local_32;
    undefined2 local_30;
    short frames;
    float alpha;
    float yOffset;
    float scale;
    undefined4 local_20;
    longlong amountLL;

    amount = *(int*)&((GameObject*)param_1)->extra;
    if ((param_1 != 0) && (param_2 != 0))
    {
        if (*(char*)(amount + 0xba) != '\0')
        {
            scratch2 = FUN_80294d10(param_2);
            if (scratch2 == 0)
            {
                progress = lbl_803E3F24;
                intensity = lbl_803E3F28;
            }
            else
            {
                progress = lbl_803E3F20;
                intensity = lbl_803E3F20;
            }
            if (*(byte*)(amount + 0xbb) == 7)
            {
                spawnScale = (double)lbl_803E3F2C;
                amountLL = (longlong)(int)(lbl_803E3F30 * intensity);
                FUN_800810f8(spawnScale, spawnScale, spawnScale, (double)(lbl_803E3F34 * progress), param_1, 7,
                             (uint) * (byte*)(amount + 0xba), 1, (int)(lbl_803E3F30 * intensity), 0, 0);
            }
            else
            {
                spawnScale = (double)lbl_803E3F20;
                amountLL = (longlong)(int)(lbl_803E3F30 * intensity);
                FUN_800810f8(spawnScale, spawnScale, spawnScale, (double)(lbl_803E3F34 * progress), param_1,
                             (uint) * (byte*)(amount + 0xbb), (uint) * (byte*)(amount + 0xba), 1,
                             (int)(lbl_803E3F30 * intensity), 0, 0);
            }
        }
        FUN_80294c60(param_2, &seqId, &progress);
        local_34 = 0;
        local_32 = 0;
        local_30 = 0;
        alpha = lbl_803E3F20;
        if (seqId == 0x87)
        {
            amount = (int)(lbl_803E3F38 * (progress / lbl_803E3F30));
            amountLL = (longlong)amount;
            frames = 0x15 - (short)amount;
            yOffset = lbl_803E3F3C * (progress / lbl_803E3F40 - lbl_803E3F2C);
            local_34 = 0xc94;
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &local_34, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &local_34, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &local_34, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &local_34, 2, -1, NULL);
            frames = 9;
            alpha = lbl_803E3F48 * (progress / lbl_803E3F40) + lbl_803E3F44;
            scale = lbl_803E3F4C;
            local_34 = 0xc0e;
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b3, &local_34, 2, -1, NULL);
        }
        else if (seqId < 0x87)
        {
            if (seqId == 0x7f)
            {
                alpha = lbl_803E3F58;
                frames = 10;
                scale = lbl_803E3F54;
                yOffset = lbl_803E3F50;
                local_34 = 0xc0e;
                (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b3, &local_34, 2, -1, NULL);
            }
            else if (seqId < 0x7f)
            {
                if ((seqId == 0x43) && (lbl_803E3F4C < progress))
                {
                    amount = (int)(lbl_803E3F38 * (progress / lbl_803E3F30));
                    amountLL = (longlong)amount;
                    frames = (short)amount + 6;
                    yOffset = lbl_803E3F3C * (progress / lbl_803E3F40 - lbl_803E3F2C);
                    local_34 = 0xc94;
                    (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b4, &local_34, 2, -1, NULL);
                    (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b4, &local_34, 2, -1, NULL);
                    frames = 9;
                    alpha = lbl_803E3F48 * (progress / lbl_803E3F40) + lbl_803E3F44;
                    scale = lbl_803E3F4C;
                    local_34 = 0xc0e;
                    (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b3, &local_34, 2, -1, NULL);
                }
            }
            else if (seqId == 0x85)
            {
                if (lbl_803E3F4C < progress)
                {
                    useAltTex = FUN_80017690(0xc55);
                    if (useAltTex == 0)
                    {
                        intensity = progress / lbl_803E3F40;
                        amount = (int)(lbl_803E3F38 * intensity);
                        frames = (short)amount;
                        local_34 = 0xc94;
                    }
                    else
                    {
                        intensity = progress / lbl_803E3F50;
                        amount = (int)(lbl_803E3F38 * intensity);
                        frames = (short)amount;
                        local_34 = 0xc75;
                    }
                    amountLL = (longlong)amount;
                    yOffset = lbl_803E3F5C * (lbl_803E3F28 - intensity);
                    frames = 0x15 - frames;
                    (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &local_34, 2, -1, NULL);
                    (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &local_34, 2, -1, NULL);
                    (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &local_34, 2, -1, NULL);
                    (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &local_34, 2, -1, NULL);
                    frames = 9;
                    useAltTex = FUN_80017690(0xc55);
                    if (useAltTex == 0)
                    {
                        local_34 = 0xc0e;
                        intensity = lbl_803E3F40;
                    }
                    else
                    {
                        local_34 = 0xc75;
                        intensity = lbl_803E3F50;
                    }
                    alpha = lbl_803E3F48 * (progress / intensity) + lbl_803E3F44;
                    scale = lbl_803E3F4C;
                    (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b3, &local_34, 2, -1, NULL);
                }
            }
            else if (0x84 < seqId)
            {
                useAltTex = FUN_80017690(0xc55);
                if (useAltTex == 0)
                {
                    local_34 = 0xc0e;
                }
                else
                {
                    local_34 = 0xc75;
                }
                intensity = *(float*)(param_2 + 0x98);
                if (lbl_803E3F68 <= intensity)
                {
                    if (intensity < lbl_803E3F70)
                    {
                        yOffset = lbl_803E3F5C * (lbl_803E3F74 * (intensity - lbl_803E3F68) - lbl_803E3F2C);
                        frames = 9;
                        alpha = lbl_803E3F20;
                        scale = lbl_803E3F4C;
                        (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b3, &local_34, 2, -1, NULL);
                    }
                }
                else
                {
                    yOffset = lbl_803E3F6C;
                    frames = 9;
                    alpha = lbl_803E3F20;
                    scale = lbl_803E3F4C;
                    (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b3, &local_34, 2, -1, NULL);
                }
            }
        }
        else if (seqId == 0x468)
        {
            if (lbl_803E3F4C < progress)
            {
                amount = (int)(lbl_803E3F38 * (progress / lbl_803E3F60));
                amountLL = (longlong)amount;
                frameCount = 0x15 - (short)amount;
                spawnParam[0] = 0xc95;
                FUN_80294c48(*(int*)&((GameObject*)param_1)->ownerObj, &ownerXform);
                yOffset = *(float*)(ownerXform + 0xc);
                scale = *(float*)(ownerXform + 0x10);
                local_20 = *(undefined4*)(ownerXform + 0x14);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)param_1)->ownerObj, 0x7b9, &local_34,
                                                 0x200001, -1, spawnParam);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)param_1)->ownerObj, 0x7b9, &local_34,
                                                 0x200001, -1, spawnParam);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)param_1)->ownerObj, 0x7b9, &local_34,
                                                 0x200001, -1, spawnParam);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)param_1)->ownerObj, 0x7b9, &local_34,
                                                 0x200001, -1, spawnParam);
                frameCount = 9;
                spawnParam[0] = 0xc95;
                spawnAlpha = lbl_803E3F64 * (progress / lbl_803E3F60) + lbl_803E3F44;
                yOffset = *(float*)(ownerXform + 0xc);
                scale = *(float*)(ownerXform + 0x10);
                local_20 = *(undefined4*)(ownerXform + 0x14);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)param_1)->ownerObj, 0x7ba, &local_34,
                                                 0x200001, -1, spawnParam);
            }
        }
        else if (seqId < 0x468)
        {
            if (seqId < 0x89)
            {
                frames = 0x23;
                scale = lbl_803E3F4C;
                yOffset = lbl_803E3F50;
                local_34 = 0xc0e;
                (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b3, &local_34, 2, -1, NULL);
                frames = 0x12;
                scale = lbl_803E3F54;
                (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b3, &local_34, 2, -1, NULL);
            }
        }
        else if ((seqId == 0x46f) && (lbl_803E3F4C < progress))
        {
            amount = (int)(lbl_803E3F38 * (progress / lbl_803E3F60));
            amountLL = (longlong)amount;
            frames = 0x15 - (short)amount;
            yOffset = lbl_803E3F5C * (lbl_803E3F28 - progress / lbl_803E3F60);
            local_34 = 0xc94;
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &local_34, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &local_34, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &local_34, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &local_34, 2, -1, NULL);
            frames = 9;
            alpha = lbl_803E3F48 * (progress / lbl_803E3F60) + lbl_803E3F44;
            scale = lbl_803E3F4C;
            local_34 = 0xc0e;
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b3, &local_34, 2, -1, NULL);
        }
    }
    return;
}

void FUN_8016d994(int param_1, undefined param_2, undefined param_3)
{
    int extra;

    extra = *(int*)&((GameObject*)param_1)->extra;
    *(undefined*)(extra + 0xbb) = param_2;
    *(undefined*)(extra + 0xba) = param_3;
    return;
}

void FUN_8016e8cc(undefined8 param_1, undefined8 param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  int param_9)
{
    short level;
    int scratch;
    int* emitter;
    uint partIdx;
    int partPtr;
    int* extra;
    double computed;
    double clamped;
    undefined8 local_18;

    extra = ((GameObject*)param_9)->extra;
    scratch = FUN_80017a54(param_9);
    *(ushort*)(scratch + 0x18) = *(ushort*)(scratch + 0x18) & ~0x8;
    FUN_8002fc3c((double)(float)extra[0x14], (double)lbl_803DC074);
    scratch = 3;
    emitter = extra;
    do
    {
        if ((*(byte*)(emitter + 5) & 2) != 0)
        {
            partIdx = (uint) * (ushort*)(emitter + 3);
            partPtr = *emitter + partIdx * 0x14;
            for (; (int)partIdx < (int)(uint) * (ushort*)((int)emitter + 0xe); partIdx = partIdx + 2)
            {
                if (emitter == (int*)extra[0x12])
                {
                    param_3 = (double)lbl_803E3F8C;
                    computed = (double)(float)(param_3 *
                        (double)((lbl_803E3FA4 * (float)extra[0x26] -
                            *(float*)(partPtr + 0xc)) * lbl_803E3FA8));
                    clamped = (double)lbl_803E3F4C;
                    if ((clamped <= computed) && (clamped = computed, param_3 < computed))
                    {
                        clamped = param_3;
                    }
                    *(short*)(partPtr + 0x10) = (short)(int)(param_3 - clamped);
                    *(undefined2*)(partPtr + 0x24) = *(undefined2*)(partPtr + 0x10);
                }
                else
                {
                    param_3 = (double)lbl_803E3FC4;
                    *(short*)(partPtr + 0x10) =
                        (short)(int)-(float)(param_3 * (double)lbl_803DC074 -
                            (double)(f32)(s32)((int)*(short*)(partPtr + 0x10)));
                    *(undefined2*)(partPtr + 0x24) = *(undefined2*)(partPtr + 0x10);
                }
                level = *(short*)(partPtr + 0x10);
                if (level < 0)
                {
                    level = 0;
                }
                else if (0xff < level)
                {
                    level = 0xff;
                }
                *(short*)(partPtr + 0x10) = level;
                level = *(short*)(partPtr + 0x24);
                if (level < 0)
                {
                    level = 0;
                }
                else if (0xff < level)
                {
                    level = 0xff;
                }
                *(short*)(partPtr + 0x24) = level;
                if ((*(short*)(partPtr + 0x10) < 1) && (*(short*)(partPtr + 0x24) < 1))
                {
                    *(short*)((int)emitter + 0x12) = *(short*)((int)emitter + 0x12) + -2;
                    *(short*)(emitter + 3) = *(short*)(emitter + 3) + 2;
                }
                partPtr = partPtr + 0x28;
            }
            if ((emitter != (int*)extra[0x12]) && (*(short*)((int)emitter + 0x12) == 0))
            {
                *(byte*)(emitter + 5) = *(byte*)(emitter + 5) & 0xfd;
            }
        }
        emitter = emitter + 6;
        scratch = scratch + -1;
    }
    while (scratch != 0);
    FUN_8016d188(param_9, *(int*)&((GameObject*)param_9)->ownerObj);
    FUN_80294d6c(*(int*)&((GameObject*)param_9)->ownerObj);
    *(undefined*)((int)extra + 0xb9) = 0;
    if (DAT_803ad338 != '\0')
    {
        DAT_803ad324 = DAT_803ad324 + lbl_803E3F78;
        ObjHitbox_SetSphereRadius(DAT_803ad334, (short)(int)DAT_803ad324);
        ObjHits_SetHitVolumeSlot(DAT_803ad334, 0x11, 5, 0);
        DAT_803ad330 = DAT_803ad330 + lbl_803E3F7C;
        clamped = (double)DAT_803ad330;
        DAT_803ad328 = DAT_803ad328 * lbl_803E3F80;
        DAT_803ad32c = DAT_803ad32c * lbl_803E3F84;
        ((GameObject*)DAT_803ad334)->anim.alpha = (char)(int)DAT_803ad330;
        ((GameObject*)DAT_803ad334)->anim.rootMotionScale = ((GameObject*)DAT_803ad334)->anim.rootMotionScale +
            lbl_803E3F88;
        if ((double)DAT_803ad330 < (double)lbl_803E3F20)
        {
            DAT_803ad338 = '\0';
            FUN_80017ac8((double)DAT_803ad330, clamped, param_3, param_4, param_5, param_6, param_7, param_8,
                         DAT_803ad334);
            DAT_803ad334 = 0;
        }
    }
    return;
}

void FUN_80170048(void)
{
    float value;
    uint world;
    int scratch;
    int* elem;
    uint randVal;
    int effectObj;
    int* state;
    int* src;
    float* scaleTbl;
    double cosVal;
    double base;
    double phase;
    double bias;
    double offset;
    undefined8 ret;
    undefined8 local_78;
    undefined8 local_70;

    ret = FUN_80286838();
    world = (uint)((ulonglong)ret >> 0x20);
    scaleTbl = (float*)&DAT_80321678;
    state = *(int**)(world + 0xb8);
    scratch = FUN_80017a98();
    effectObj = 0;
    if (scratch != 0)
    {
        effectObj = FUN_80294cf8(scratch);
    }
    value = lbl_803E4064;
    switch ((uint)ret & 0xff)
    {
    case 0:
        if (*state != 0)
        {
            FUN_800175cc((double)lbl_803E4040, *state, '\0');
        }
        value = lbl_803E4048;
        if (lbl_803E4044 != (float)state[2])
        {
            state[4] = (int)lbl_803E4048;
            state[1] = (int)value;
            if (effectObj != 0)
            {
                FUN_8016d994(effectObj, 7, 0);
            }
        }
        state[2] = (int)lbl_803E4044;
        state[3] = (int)lbl_803E404C;
        FUN_80006810(world, 0x42c);
        FUN_80006810(world, 0x42d);
        break;
    case 1:
        if (lbl_803E4044 == (float)state[2])
        {
            if (effectObj != 0)
            {
                FUN_8016d994(effectObj, 7, 8);
            }
            if (*state == 0)
            {
                elem = FUN_80017624(0, '\x01');
                *state = (int)elem;
            }
            if (*state != 0)
            {
                FUN_800175b0(*state, 2);
                FUN_800175ec((double)*(float*)(world + 0xc),
                             (double)(*(float*)(world + 0x10) - lbl_803E4050),
                             (double)*(float*)(world + 0x14), (int*)*state);
                FUN_8001759c(*state, 0, 0xff, 0xff, 0xff);
                FUN_80017588(*state, 0, 0xff, 0xff, 0xff);
                FUN_800175d0((double)lbl_803E4054, (double)lbl_803E4058, *state);
                FUN_800175bc(*state, 1);
                FUN_800175cc((double)lbl_803E4044, *state, '\x01');
                FUN_8001753c(*state, 0, 0);
                FUN_800175d8(*state, 1);
            }
            value = lbl_803E4044;
            if (lbl_803E4044 == (float)state[2])
            {
                state[4] = (int)lbl_803E4048;
                state[1] = (int)value;
            }
            state[2] = (int)lbl_803E4048;
            phase = (double)lbl_803E405C;
            state[3] = (int)lbl_803E405C;
            scratch = 0;
            src = &DAT_80321688;
            base = (double)lbl_803E4040;
            offset = (double)lbl_803E4060;
            elem = state;
            bias = DOUBLE_803e4068;
            do
            {
                *(undefined2*)(elem + 0xd) = 0xc000;
                cosVal = (double)fcos16Precise();
                state[9] = (int)(*scaleTbl * (float)((double)(float)(phase + cosVal) * base));
                state[5] = *src;
                randVal = randomGetRange(0x78, 0x7f);
                local_78 = (double)CONCAT44(0x43300000, scratch * randVal ^ 0x80000000);
                *(short*)(elem + 0xf) = (short)(int)(offset + (double)(float)(local_78 - bias));
                elem = (int*)((int)elem + 2);
                scaleTbl = scaleTbl + 1;
                state = state + 1;
                src = src + 1;
                scratch = scratch + 1;
            }
            while (scratch < 4);
            FUN_80006824(world, 0x42c);
            FUN_80006824(world, 0x42d);
        }
        break;
    case 2:
        if (effectObj != 0)
        {
            FUN_8016d994(effectObj, 7, 0);
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
        FUN_80006810(world, 0x42c);
        FUN_80006810(world, 0x42d);
        break;
    case 3:
        if (effectObj != 0)
        {
            FUN_8016d994(effectObj, 7, 8);
        }
        if (*state == 0)
        {
            elem = FUN_80017624(0, '\x01');
            *state = (int)elem;
        }
        if (*state != 0)
        {
            FUN_800175b0(*state, 2);
            FUN_800175ec((double)*(float*)(world + 0xc),
                         (double)(*(float*)(world + 0x10) - lbl_803E4050),
                         (double)*(float*)(world + 0x14), (int*)*state);
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
        offset = (double)lbl_803E405C;
        state[3] = (int)lbl_803E405C;
        scratch = 0;
        src = &DAT_80321688;
        bias = (double)lbl_803E4040;
        elem = state;
        do
        {
            *(undefined2*)(state + 0xd) = 0;
            base = (double)fcos16Precise();
            elem[9] = (int)(*scaleTbl * (float)((double)(float)(offset + base) * bias));
            elem[5] = *src;
            state = (int*)((int)state + 2);
            scaleTbl = scaleTbl + 1;
            elem = elem + 1;
            src = src + 1;
            scratch = scratch + 1;
        }
        while (scratch < 4);
        FUN_80006824(world, 0x42d);
        FUN_80006824(world, 0x42c);
        break;
    case 4:
        state[2] = (int)lbl_803E4064;
        offset = (double)lbl_803E405C;
        state[3] = (int)lbl_803E405C;
        state[4] = (int)value;
        scratch = 0;
        scaleTbl = (float*)&DAT_80321698;
        src = &DAT_803216a8;
        base = (double)lbl_803E4040;
        phase = (double)lbl_803E4060;
        elem = state;
        bias = DOUBLE_803e4068;
        do
        {
            *(undefined2*)(state + 0xd) = 0xc000;
            cosVal = (double)fcos16Precise();
            elem[9] = (int)(*scaleTbl * (float)((double)(float)(offset + cosVal) * base));
            elem[5] = *src;
            randVal = randomGetRange(0x78, 0x7f);
            local_70 = (double)CONCAT44(0x43300000, scratch * randVal ^ 0x80000000);
            *(short*)(state + 0xf) = (short)(int)(phase + (double)(float)(local_70 - bias));
            state = (int*)((int)state + 2);
            scaleTbl = scaleTbl + 1;
            elem = elem + 1;
            src = src + 1;
            scratch = scratch + 1;
        }
        while (scratch < 4);
        FUN_80006824(world, 0x42d);
        FUN_80006824(world, 0x42c);
        break;
    case 5:
        state[2] = (int)lbl_803E4044;
        state[3] = (int)lbl_803E404C;
        state[4] = (int)lbl_803E4064;
        FUN_80006810(world, 0x42c);
        FUN_80006810(world, 0x42d);
        break;
    case 6:
        scratch = 0;
        scaleTbl = (float*)&DAT_80321698;
        src = &DAT_803216a8;
        bias = (double)lbl_803E405C;
        offset = (double)lbl_803E4040;
        elem = state;
        do
        {
            *(undefined2*)(state + 0xd) = 0x4000;
            base = (double)fcos16Precise();
            elem[9] = (int)(*scaleTbl * (float)((double)(float)(bias + base) * offset));
            elem[5] = *src;
            state = (int*)((int)state + 2);
            scaleTbl = scaleTbl + 1;
            elem = elem + 1;
            src = src + 1;
            scratch = scratch + 1;
        }
        while (scratch < 4);
        break;
    case 7:
        if (effectObj != 0)
        {
            FUN_8016d994(effectObj, 7, 0);
        }
        if (*state != 0)
        {
            FUN_800175cc((double)lbl_803E4040, *state, '\0');
        }
        value = lbl_803E4044;
        state[2] = (int)lbl_803E4044;
        state[3] = (int)value;
        state[4] = (int)value;
        state[1] = (int)value;
        *(byte*)(state + 0x17) = *(byte*)(state + 0x17) | 1;
        *(byte*)((int)state + 0x5d) = *(byte*)((int)state + 0x5d) | 1;
        *(byte*)((int)state + 0x5e) = *(byte*)((int)state + 0x5e) | 1;
        *(byte*)((int)state + 0x5f) = *(byte*)((int)state + 0x5f) | 1;
    }
    FUN_80286884();
    return;
}

void checkpoint4_render(int param_1);

void checkpoint4_init(Checkpoint4Object* checkpoint, Checkpoint4Placement* placement);

void sideload_update(int self)
{
    int state;
    void* obj;
    short* p;

    state = *(int*)&((GameObject*)self)->anim.placementData;
    if ((Obj_IsLoadingLocked() != 0) && (Obj_GetPlayerObject() != 0) &&
        (getTrickyObject() == 0) && (GameBit_Get((int)*(short*)(state + 0x18)) != 0))
    {
        obj = Obj_AllocObjectSetup(0x18, 0x24);
        *(u8*)((char*)obj + 4) = 2;
        *(u8*)((char*)obj + 5) = 4;
        *(u8*)((char*)obj + 7) = 0xff;
        ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)self)->anim.localPosX;
        ((GameObject*)obj)->anim.localPosX = ((GameObject*)self)->anim.localPosY;
        ((GameObject*)obj)->anim.localPosY = ((GameObject*)self)->anim.localPosZ;
        p = (short*)Obj_SetupObject(obj, 5, -1, -1, (void*)0);
        *p = (short)((u8)((SideloadPlacement*)state)->unk1A << 8);
    }
}

void mikabombshadow_update(int* obj);

void curve_init(ObjAnimComponent* obj, CurvePlacementParams* params);

void FUN_801713ac(undefined8 param_1, double param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  uint param_9)
{
    extern undefined8 ObjHits_DisableObject(); /* #57 */
    short seqOrType;
    char counter;
    uint scratchU;
    int audioObj;
    int placement;
    int extra;
    undefined8 result;

    extra = *(int*)&((GameObject*)param_9)->extra;
    placement = *(int*)&((GameObject*)param_9)->anim.placementData;
    audioObj = (int)((GameObject*)param_9)->anim.modelInstance->extraSetupData;
    FUN_80017a98();
    FUN_80017a90();
    FUN_80017a98();
    FUN_80017a90();
    result = ObjHits_DisableObject(param_9);
    if ((*(ushort*)&((GameObject*)param_9)->anim.flags & 0x2000) != 0)
    {
        *(float*)(extra + 8) = lbl_803E40E8;
        if (((GameObject*)param_9)->anim.modelState != NULL)
        {
            ((GameObject*)param_9)->anim.modelState->flags = OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        }
    }
    if ((int)*(short*)(extra + 0x10) != 0xffffffff)
    {
        FUN_80017698((int)*(short*)(extra + 0x10), 1);
        result = FUN_800e842c(param_9);
    }
    scratchU = (uint) * (short*)(placement + 0x1e);
    if (scratchU != 0xffffffff)
    {
        result = FUN_80017698(scratchU, 1);
    }
    scratchU = (uint) * (short*)(placement + 0x2c);
    if (0 < (int)scratchU)
    {
        FUN_80017688(scratchU);
    }
    seqOrType = *(short*)(audioObj + 2);
    if (seqOrType == 4)
    {
        seqOrType = ((GameObject*)param_9)->anim.seqId;
        if (seqOrType == 0x3cd)
        {
            audioObj = FUN_80017a98();
            FUN_80294d60(result, param_2, param_3, param_4, param_5, param_6, param_7, param_8, audioObj, 2);
            scratchU = FUN_80017a98();
            FUN_80006824(scratchU, SFXen_treadlpc);
            FUN_80081118((double)lbl_803E40EC, param_9, 1, 0x28);
        }
        else if ((seqOrType < 0x3cd) && (seqOrType == 0xb))
        {
            scratchU = FUN_80017a98();
            result = FUN_80006824(scratchU, SFXen_treadlpc);
            audioObj = FUN_80017a98();
            FUN_80294d60(result, param_2, param_3, param_4, param_5, param_6, param_7, param_8, audioObj, 4);
            FUN_80081118((double)lbl_803E40EC, param_9, 3, 0x28);
        }
        else
        {
            scratchU = FUN_80017a98();
            FUN_80006824(scratchU, SFXen_waterblock_stop);
            FUN_80081118((double)lbl_803E40EC, param_9, 0xff, 0x28);
        }
    }
    else if ((seqOrType < 4) && (seqOrType == 1))
    {
        seqOrType = ((GameObject*)param_9)->anim.seqId;
        if (seqOrType == 0x319)
        {
            FUN_80006824(param_9, SFXwp_gprop2_c);
            FUN_80017698(0x3e9, 1);
            *(undefined2*)(extra + 0x3c) = 0x4b0;
            FUN_80081118((double)lbl_803E40EC, param_9, 0xff, 0x28);
        }
        else
        {
            if (seqOrType < 0x319)
            {
                if (seqOrType == 0x5a)
                {
                    FUN_80006824(param_9, SFXen_treadlpc);
                    FUN_80081118((double)lbl_803E40EC, param_9, 2, 0x28);
                    goto LAB_801725bc;
                }
                if ((seqOrType < 0x5a) && (seqOrType == 0x22))
                {
                    FUN_80006824(param_9, SFXen_treadlpc);
                    FUN_80081118((double)lbl_803E40EC, param_9, 0xff, 0x28);
                    goto LAB_801725bc;
                }
            }
            else if (seqOrType == 0x6a6)
            {
                scratchU = FUN_80017690(0x86a);
                counter = (char)scratchU;
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

void mikabomb_release(void);

void mikabomb_initialise(void);

void mikabombshadow_free(void);

void mikabombshadow_hitDetect(void);

void mikabombshadow_release(void);

void mikabombshadow_initialise(void);

void StaticCamera_hitDetect(void);

void StaticCamera_update(void);

void StaticCamera_release(void);

void StaticCamera_initialise(void);

void gcbaddieshield_free(void);

void gcbaddieshield_hitDetect(void);

void gcbaddieshield_release(void);

void gcbaddieshield_initialise(void);

void baddieinterestp_free(void);

void baddieinterestp_hitDetect(void);

void baddieinterestp_init(void);

void baddieinterestp_release(void);

void baddieinterestp_initialise(void);

void staff_func0F(void);

void staff_func0E(void);

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

void shield_hitDetect(void);

void shield_release(void);

void shield_initialise(void);

void shield_free(int obj);

void curve_setScale(void);

void curve_free(void);

void dll_F7_hitDetect(void);

void dll_F7_release(void);

void dll_F7_initialise(void);

void checkpoint4_setScale(void);

void checkpoint4_free(void);

void checkpoint4_hitDetect(void);

void checkpoint4_update(void);

void checkpoint4_release(void);

void checkpoint4_initialise(void);

int mikabombshadow_getExtraSize(void);
int mikabombshadow_getObjectTypeId(void);
int StaticCamera_getExtraSize(void);
int StaticCamera_getObjectTypeId(void);
int gcbaddieshield_getExtraSize(void);
int gcbaddieshield_getObjectTypeId(void);
int baddieinterestp_getExtraSize(void);
int baddieinterestp_getObjectTypeId(void);
int animatedobj_getExtraSize(void);
int dim2roofrub_getExtraSize(void);
int depthoffieldpoint_getExtraSize(void);
int staff_getExtraSize(void);
int staff_getObjectTypeId(void);
int fireball_getExtraSize(void);
int fireball_getObjectTypeId(void);
int flamethrowerspe_getExtraSize(void);
int flamethrowerspe_getObjectTypeId(void);
int shield_getExtraSize(void);
int shield_getObjectTypeId(void);
int curve_func11(void);
int curve_getExtraSize(void);
int curve_getObjectTypeId(void);
int dll_F7_getExtraSize(void);
int dll_F7_getObjectTypeId(void);

void dll_F7_free(int obj);

void dim2roofrub_free(int* obj);

int checkpoint4_getExtraSize(void);
int checkpoint4_getObjectTypeId(void);

void staff_func10(int* obj, s32 v);
void staff_setHitReactValue(int* obj, s32 v);
void staff_addHitReactValue(int* obj, s32 delta);
void staff_getHitGeometryPoints(int* obj, f32* outA, f32* outB);
void staff_func15(int* obj, s16 idx, f32 f1, f32 f2);
void flamethrowerspe_setScale(int* obj, s16 a, s16 b, f32 f1, f32 f2, f32 f3);

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

s16 staff_getHitReactValue(int* obj);

s32 staff_func16(int* obj);

void StaticCamera_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void baddieinterestp_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void curve_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void gcbaddieshield_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);

void flamethrowerspe_render(void);
void fn_801719F8(void) { objRenderFn_8003b8f4(lbl_803E3420); }

void StaticCamera_free(int x);

void flamethrowerspe_func0B(int* obj);

void staff_func10(int* obj, s32 v);

void staff_setHitReactValue(int* obj, s32 v);

void staff_modelMtxFn(int* obj, int p4, int p5);

void flamethrowerspe_setScale(int* obj, s16 a, s16 b, f32 f1, f32 f2, f32 f3);

void staff_addHitReactValue(int* obj, s32 delta);

void staff_getHitGeometryPoints(int* obj, f32* outA, f32* outB);

void gcbaddieshield_init(int* obj, void* initData);

void mikabombshadow_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);

void staff_func15(int* obj, s16 idx, f32 f1, f32 f2);

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

void mikabomb_update(int* obj);

void mikabomb_init(int* obj);

void animatedobj_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);

void dim2roofrub_render(int* obj, int p2, int p3, int p4, int p5);

void dim2roofrub_update(int* obj);

void fireball_init(int* obj);

void fireball_update(int* obj);

void fireball_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);

void shield_update(int* obj);

void dll_F7_update(int* obj);

void staff_initialise(void);

void shield_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);

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

void staffFn_80170380(int* obj, int cmd);
