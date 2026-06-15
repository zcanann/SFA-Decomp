#include "main/dll/xyzanimator.h"
#include "main/dll/genpropswgpipe_struct.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"

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

extern f32 timeDelta;
extern void* Obj_GetPlayerObject(void);

#include "ghidra_import.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/genprops.h"
#include "main/effect_interfaces.h"
#include "main/dll_000A_expgfx.h"
#include "main/camera_interface.h"
#include "main/mapEvent.h"
#include "main/objhits_types.h"
#include "main/objseq.h"
#include "main/resource.h"

typedef struct StaffDoGrowShrinkAnimState
{
    u8 pad0[0x4 - 0x0];
    f32 unk4;
    u8 unk8;
    s8 unk9;
    u8 unkA;
    u8 unkB;
    u8 unkC;
    u8 padD[0x18 - 0xD];
    u8 unk18;
    u8 pad19[0x24 - 0x19];
    f32 unk24;
    f32 unk28;
    f32 unk2C;
    u8 pad30[0x50 - 0x30];
    f32 unk50;
    u8 pad54[0x70 - 0x54];
    u8 unk70;
    u8 pad71[0xAA - 0x71];
    u8 unkAA;
    u8 padAB[0xB0 - 0xAB];
    s16 unkB0;
    u8 padB2[0xB8 - 0xB2];
} StaffDoGrowShrinkAnimState;

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
extern void gxSetPeControl_ZCompLoc_();
extern void gxSetZMode_();
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
    undefined* cameraData;

    *param_1 = -*(short*)(param_2 + 0x1c);
    param_1[1] = -*(short*)(param_2 + 0x1e);
    param_1[2] = -*(short*)(param_2 + 0x20);
    cameraData = *(undefined**)(param_1 + 0x5c);
    *cameraData = *(undefined*)(param_2 + 0x19);
    *(float*)(cameraData + 4) =
        (float)((double)CONCAT44(0x43300000, (uint) * (byte*)(param_2 + 0x1a)) - DOUBLE_803e3e88);
    cameraData[1] = 0;
    if (param_3 == 0)
    {
        ObjGroup_AddObject((int)param_1, 7);
    }
    return;
}

void FUN_8016d188(int param_1, int param_2)
{
    float power;
    int isLockedOn;
    uint gameBit;
    int state;
    double colorDouble;
    int posSrc;
    float strength;
    int fxCategory;
    undefined2 fxConfig[3];
    short fxBCount;
    float fxBF0;
    undefined2 fxId;
    undefined2 fxA;
    undefined2 fxB;
    short fxCount;
    float fxF0;
    float fxF1;
    float fxF2;
    undefined4 fxF3;
    longlong scratch64;

    state = *(int*)&((GameObject*)param_1)->extra;
    if ((param_1 != 0) && (param_2 != 0))
    {
        if (*(char*)(state + 0xba) != '\0')
        {
            isLockedOn = FUN_80294d10(param_2);
            if (isLockedOn == 0)
            {
                strength = lbl_803E3F24;
                power = lbl_803E3F28;
            }
            else
            {
                strength = lbl_803E3F20;
                power = lbl_803E3F20;
            }
            if (*(byte*)(state + 0xbb) == 7)
            {
                colorDouble = (double)lbl_803E3F2C;
                scratch64 = (longlong)(int)(lbl_803E3F30 * power);
                FUN_800810f8(colorDouble, colorDouble, colorDouble, (double)(lbl_803E3F34 * strength), param_1, 7,
                             (uint) * (byte*)(state + 0xba), 1, (int)(lbl_803E3F30 * power), 0, 0);
            }
            else
            {
                colorDouble = (double)lbl_803E3F20;
                scratch64 = (longlong)(int)(lbl_803E3F30 * power);
                FUN_800810f8(colorDouble, colorDouble, colorDouble, (double)(lbl_803E3F34 * strength), param_1,
                             (uint) * (byte*)(state + 0xbb), (uint) * (byte*)(state + 0xba), 1,
                             (int)(lbl_803E3F30 * power), 0, 0);
            }
        }
        FUN_80294c60(param_2, &fxCategory, &strength);
        fxA = 0;
        fxB = 0;
        fxId = 0;
        fxF0 = lbl_803E3F20;
        if (fxCategory == 0x87)
        {
            state = (int)(lbl_803E3F38 * (strength / lbl_803E3F30));
            scratch64 = (longlong)state;
            fxCount = 0x15 - (short)state;
            fxF1 = lbl_803E3F3C * (strength / lbl_803E3F40 - lbl_803E3F2C);
            fxA = 0xc94;
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &fxA, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &fxA, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &fxA, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &fxA, 2, -1, NULL);
            fxCount = 9;
            fxF0 = lbl_803E3F48 * (strength / lbl_803E3F40) + lbl_803E3F44;
            fxF2 = lbl_803E3F4C;
            fxA = 0xc0e;
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b3, &fxA, 2, -1, NULL);
        }
        else if (fxCategory < 0x87)
        {
            if (fxCategory == 0x7f)
            {
                fxF0 = lbl_803E3F58;
                fxCount = 10;
                fxF2 = lbl_803E3F54;
                fxF1 = lbl_803E3F50;
                fxA = 0xc0e;
                (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b3, &fxA, 2, -1, NULL);
            }
            else if (fxCategory < 0x7f)
            {
                if ((fxCategory == 0x43) && (lbl_803E3F4C < strength))
                {
                    state = (int)(lbl_803E3F38 * (strength / lbl_803E3F30));
                    scratch64 = (longlong)state;
                    fxCount = (short)state + 6;
                    fxF1 = lbl_803E3F3C * (strength / lbl_803E3F40 - lbl_803E3F2C);
                    fxA = 0xc94;
                    (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b4, &fxA, 2, -1, NULL);
                    (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b4, &fxA, 2, -1, NULL);
                    fxCount = 9;
                    fxF0 = lbl_803E3F48 * (strength / lbl_803E3F40) + lbl_803E3F44;
                    fxF2 = lbl_803E3F4C;
                    fxA = 0xc0e;
                    (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b3, &fxA, 2, -1, NULL);
                }
            }
            else if (fxCategory == 0x85)
            {
                if (lbl_803E3F4C < strength)
                {
                    gameBit = FUN_80017690(0xc55);
                    if (gameBit == 0)
                    {
                        power = strength / lbl_803E3F40;
                        state = (int)(lbl_803E3F38 * power);
                        fxCount = (short)state;
                        fxA = 0xc94;
                    }
                    else
                    {
                        power = strength / lbl_803E3F50;
                        state = (int)(lbl_803E3F38 * power);
                        fxCount = (short)state;
                        fxA = 0xc75;
                    }
                    scratch64 = (longlong)state;
                    fxF1 = lbl_803E3F5C * (lbl_803E3F28 - power);
                    fxCount = 0x15 - fxCount;
                    (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &fxA, 2, -1, NULL);
                    (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &fxA, 2, -1, NULL);
                    (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &fxA, 2, -1, NULL);
                    (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &fxA, 2, -1, NULL);
                    fxCount = 9;
                    gameBit = FUN_80017690(0xc55);
                    if (gameBit == 0)
                    {
                        fxA = 0xc0e;
                        power = lbl_803E3F40;
                    }
                    else
                    {
                        fxA = 0xc75;
                        power = lbl_803E3F50;
                    }
                    fxF0 = lbl_803E3F48 * (strength / power) + lbl_803E3F44;
                    fxF2 = lbl_803E3F4C;
                    (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b3, &fxA, 2, -1, NULL);
                }
            }
            else if (0x84 < fxCategory)
            {
                gameBit = FUN_80017690(0xc55);
                if (gameBit == 0)
                {
                    fxA = 0xc0e;
                }
                else
                {
                    fxA = 0xc75;
                }
                power = *(float*)(param_2 + 0x98);
                if (lbl_803E3F68 <= power)
                {
                    if (power < lbl_803E3F70)
                    {
                        fxF1 = lbl_803E3F5C * (lbl_803E3F74 * (power - lbl_803E3F68) - lbl_803E3F2C);
                        fxCount = 9;
                        fxF0 = lbl_803E3F20;
                        fxF2 = lbl_803E3F4C;
                        (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b3, &fxA, 2, -1, NULL);
                    }
                }
                else
                {
                    fxF1 = lbl_803E3F6C;
                    fxCount = 9;
                    fxF0 = lbl_803E3F20;
                    fxF2 = lbl_803E3F4C;
                    (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b3, &fxA, 2, -1, NULL);
                }
            }
        }
        else if (fxCategory == 0x468)
        {
            if (lbl_803E3F4C < strength)
            {
                state = (int)(lbl_803E3F38 * (strength / lbl_803E3F60));
                scratch64 = (longlong)state;
                fxBCount = 0x15 - (short)state;
                fxConfig[0] = 0xc95;
                FUN_80294c48(*(int*)&((GameObject*)param_1)->ownerObj, &posSrc);
                fxF1 = *(float*)(posSrc + 0xc);
                fxF2 = *(float*)(posSrc + 0x10);
                fxF3 = *(undefined4*)(posSrc + 0x14);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)param_1)->ownerObj, 0x7b9, &fxA,
                                                 0x200001, -1, fxConfig);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)param_1)->ownerObj, 0x7b9, &fxA,
                                                 0x200001, -1, fxConfig);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)param_1)->ownerObj, 0x7b9, &fxA,
                                                 0x200001, -1, fxConfig);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)param_1)->ownerObj, 0x7b9, &fxA,
                                                 0x200001, -1, fxConfig);
                fxBCount = 9;
                fxConfig[0] = 0xc95;
                fxBF0 = lbl_803E3F64 * (strength / lbl_803E3F60) + lbl_803E3F44;
                fxF1 = *(float*)(posSrc + 0xc);
                fxF2 = *(float*)(posSrc + 0x10);
                fxF3 = *(undefined4*)(posSrc + 0x14);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)param_1)->ownerObj, 0x7ba, &fxA,
                                                 0x200001, -1, fxConfig);
            }
        }
        else if (fxCategory < 0x468)
        {
            if (fxCategory < 0x89)
            {
                fxCount = 0x23;
                fxF2 = lbl_803E3F4C;
                fxF1 = lbl_803E3F50;
                fxA = 0xc0e;
                (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b3, &fxA, 2, -1, NULL);
                fxCount = 0x12;
                fxF2 = lbl_803E3F54;
                (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b3, &fxA, 2, -1, NULL);
            }
        }
        else if ((fxCategory == 0x46f) && (lbl_803E3F4C < strength))
        {
            state = (int)(lbl_803E3F38 * (strength / lbl_803E3F60));
            scratch64 = (longlong)state;
            fxCount = 0x15 - (short)state;
            fxF1 = lbl_803E3F5C * (lbl_803E3F28 - strength / lbl_803E3F60);
            fxA = 0xc94;
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &fxA, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &fxA, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &fxA, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &fxA, 2, -1, NULL);
            fxCount = 9;
            fxF0 = lbl_803E3F48 * (strength / lbl_803E3F60) + lbl_803E3F44;
            fxF2 = lbl_803E3F4C;
            fxA = 0xc0e;
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b3, &fxA, 2, -1, NULL);
        }
    }
    return;
}

void FUN_8016d994(int param_1, undefined param_2, undefined param_3)
{
    int state;

    state = *(int*)&((GameObject*)param_1)->extra;
    *(undefined*)(state + 0xbb) = param_2;
    *(undefined*)(state + 0xba) = param_3;
    return;
}

void FUN_8016e8cc(undefined8 param_1, undefined8 param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  int param_9)
{
    short alpha;
    int model;
    int* swipe;
    uint vtxIndex;
    int vp;
    int* state;
    double computed;
    double clamped;
    undefined8 local_18;

    state = ((GameObject*)param_9)->extra;
    model = FUN_80017a54(param_9);
    *(ushort*)(model + 0x18) = *(ushort*)(model + 0x18) & ~0x8;
    FUN_8002fc3c((double)(float)state[0x14], (double)lbl_803DC074);
    model = 3;
    swipe = state;
    do
    {
        if ((*(byte*)(swipe + 5) & 2) != 0)
        {
            vtxIndex = (uint) * (ushort*)(swipe + 3);
            vp = *swipe + vtxIndex * 0x14;
            for (; (int)vtxIndex < (int)(uint) * (ushort*)((int)swipe + 0xe); vtxIndex = vtxIndex + 2)
            {
                if (swipe == (int*)state[0x12])
                {
                    param_3 = (double)lbl_803E3F8C;
                    computed = (double)(float)(param_3 *
                        (double)((lbl_803E3FA4 * (float)state[0x26] -
                            *(float*)(vp + 0xc)) * lbl_803E3FA8));
                    clamped = (double)lbl_803E3F4C;
                    if ((clamped <= computed) && (clamped = computed, param_3 < computed))
                    {
                        clamped = param_3;
                    }
                    *(short*)(vp + 0x10) = (short)(int)(param_3 - clamped);
                    *(undefined2*)(vp + 0x24) = *(undefined2*)(vp + 0x10);
                }
                else
                {
                    param_3 = (double)lbl_803E3FC4;
                    *(short*)(vp + 0x10) =
                        (short)(int)-(float)(param_3 * (double)lbl_803DC074 -
                            (double)(f32)(s32)((int)*(short*)(vp + 0x10)));
                    *(undefined2*)(vp + 0x24) = *(undefined2*)(vp + 0x10);
                }
                alpha = *(short*)(vp + 0x10);
                if (alpha < 0)
                {
                    alpha = 0;
                }
                else if (0xff < alpha)
                {
                    alpha = 0xff;
                }
                *(short*)(vp + 0x10) = alpha;
                alpha = *(short*)(vp + 0x24);
                if (alpha < 0)
                {
                    alpha = 0;
                }
                else if (0xff < alpha)
                {
                    alpha = 0xff;
                }
                *(short*)(vp + 0x24) = alpha;
                if ((*(short*)(vp + 0x10) < 1) && (*(short*)(vp + 0x24) < 1))
                {
                    *(short*)((int)swipe + 0x12) = *(short*)((int)swipe + 0x12) + -2;
                    *(short*)(swipe + 3) = *(short*)(swipe + 3) + 2;
                }
                vp = vp + 0x28;
            }
            if ((swipe != (int*)state[0x12]) && (*(short*)((int)swipe + 0x12) == 0))
            {
                *(byte*)(swipe + 5) = *(byte*)(swipe + 5) & 0xfd;
            }
        }
        swipe = swipe + 6;
        model = model + -1;
    }
    while (model != 0);
    FUN_8016d188(param_9, *(int*)&((GameObject*)param_9)->ownerObj);
    FUN_80294d6c(*(int*)&((GameObject*)param_9)->ownerObj);
    *(undefined*)((int)state + 0xb9) = 0;
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
    float endScale;
    uint obj;
    int idx;
    int* walker;
    uint randVal;
    int spellObj;
    int* spellData;
    int* angleTbl;
    float* scaleTbl;
    double cosResult;
    double baseAngle;
    double angleSeed;
    double biasD;
    double scaleD;
    undefined8 packed;
    undefined8 convScratch1;
    undefined8 convScratch0;

    packed = FUN_80286838();
    obj = (uint)((ulonglong)packed >> 0x20);
    scaleTbl = (float*)&DAT_80321678;
    spellData = *(int**)(obj + 0xb8);
    idx = FUN_80017a98();
    spellObj = 0;
    if (idx != 0)
    {
        spellObj = FUN_80294cf8(idx);
    }
    endScale = lbl_803E4064;
    switch ((uint)packed & 0xff)
    {
    case 0:
        if (*spellData != 0)
        {
            FUN_800175cc((double)lbl_803E4040, *spellData, '\0');
        }
        endScale = lbl_803E4048;
        if (lbl_803E4044 != (float)spellData[2])
        {
            spellData[4] = (int)lbl_803E4048;
            spellData[1] = (int)endScale;
            if (spellObj != 0)
            {
                FUN_8016d994(spellObj, 7, 0);
            }
        }
        spellData[2] = (int)lbl_803E4044;
        spellData[3] = (int)lbl_803E404C;
        FUN_80006810(obj, 0x42c);
        FUN_80006810(obj, 0x42d);
        break;
    case 1:
        if (lbl_803E4044 == (float)spellData[2])
        {
            if (spellObj != 0)
            {
                FUN_8016d994(spellObj, 7, 8);
            }
            if (*spellData == 0)
            {
                walker = FUN_80017624(0, '\x01');
                *spellData = (int)walker;
            }
            if (*spellData != 0)
            {
                FUN_800175b0(*spellData, 2);
                FUN_800175ec((double)*(float*)(obj + 0xc),
                             (double)(*(float*)(obj + 0x10) - lbl_803E4050),
                             (double)*(float*)(obj + 0x14), (int*)*spellData);
                FUN_8001759c(*spellData, 0, 0xff, 0xff, 0xff);
                FUN_80017588(*spellData, 0, 0xff, 0xff, 0xff);
                FUN_800175d0((double)lbl_803E4054, (double)lbl_803E4058, *spellData);
                FUN_800175bc(*spellData, 1);
                FUN_800175cc((double)lbl_803E4044, *spellData, '\x01');
                FUN_8001753c(*spellData, 0, 0);
                FUN_800175d8(*spellData, 1);
            }
            endScale = lbl_803E4044;
            if (lbl_803E4044 == (float)spellData[2])
            {
                spellData[4] = (int)lbl_803E4048;
                spellData[1] = (int)endScale;
            }
            spellData[2] = (int)lbl_803E4048;
            angleSeed = (double)lbl_803E405C;
            spellData[3] = (int)lbl_803E405C;
            idx = 0;
            angleTbl = &DAT_80321688;
            baseAngle = (double)lbl_803E4040;
            scaleD = (double)lbl_803E4060;
            walker = spellData;
            biasD = DOUBLE_803e4068;
            do
            {
                *(undefined2*)(walker + 0xd) = 0xc000;
                cosResult = (double)fcos16Precise();
                spellData[9] = (int)(*scaleTbl * (float)((double)(float)(angleSeed + cosResult) * baseAngle));
                spellData[5] = *angleTbl;
                randVal = randomGetRange(0x78, 0x7f);
                convScratch1 = (double)CONCAT44(0x43300000, idx * randVal ^ 0x80000000);
                *(short*)(walker + 0xf) = (short)(int)(scaleD + (double)(float)(convScratch1 - biasD));
                walker = (int*)((int)walker + 2);
                scaleTbl = scaleTbl + 1;
                spellData = spellData + 1;
                angleTbl = angleTbl + 1;
                idx = idx + 1;
            }
            while (idx < 4);
            FUN_80006824(obj, 0x42c);
            FUN_80006824(obj, 0x42d);
        }
        break;
    case 2:
        if (spellObj != 0)
        {
            FUN_8016d994(spellObj, 7, 0);
        }
        if (lbl_803E4044 != (float)spellData[2])
        {
            spellData[4] = (int)lbl_803E4064;
        }
        spellData[2] = (int)lbl_803E4044;
        spellData[3] = (int)lbl_803E404C;
        if (*spellData != 0)
        {
            FUN_800175cc((double)lbl_803E4040, *spellData, '\0');
        }
        FUN_80006810(obj, 0x42c);
        FUN_80006810(obj, 0x42d);
        break;
    case 3:
        if (spellObj != 0)
        {
            FUN_8016d994(spellObj, 7, 8);
        }
        if (*spellData == 0)
        {
            walker = FUN_80017624(0, '\x01');
            *spellData = (int)walker;
        }
        if (*spellData != 0)
        {
            FUN_800175b0(*spellData, 2);
            FUN_800175ec((double)*(float*)(obj + 0xc),
                         (double)(*(float*)(obj + 0x10) - lbl_803E4050),
                         (double)*(float*)(obj + 0x14), (int*)*spellData);
            FUN_8001759c(*spellData, 0, 0xff, 0xff, 0xff);
            FUN_80017588(*spellData, 0, 0xff, 0xff, 0xff);
            FUN_800175d0((double)lbl_803E4054, (double)lbl_803E4058, *spellData);
            FUN_800175bc(*spellData, 1);
            FUN_800175cc((double)lbl_803E4044, *spellData, '\x01');
            FUN_8001753c(*spellData, 0, 0);
            FUN_800175d8(*spellData, 1);
        }
        if (lbl_803E4044 == (float)spellData[2])
        {
            spellData[4] = (int)lbl_803E4064;
        }
        spellData[2] = (int)lbl_803E4064;
        scaleD = (double)lbl_803E405C;
        spellData[3] = (int)lbl_803E405C;
        idx = 0;
        angleTbl = &DAT_80321688;
        biasD = (double)lbl_803E4040;
        walker = spellData;
        do
        {
            *(undefined2*)(spellData + 0xd) = 0;
            baseAngle = (double)fcos16Precise();
            walker[9] = (int)(*scaleTbl * (float)((double)(float)(scaleD + baseAngle) * biasD));
            walker[5] = *angleTbl;
            spellData = (int*)((int)spellData + 2);
            scaleTbl = scaleTbl + 1;
            walker = walker + 1;
            angleTbl = angleTbl + 1;
            idx = idx + 1;
        }
        while (idx < 4);
        FUN_80006824(obj, 0x42d);
        FUN_80006824(obj, 0x42c);
        break;
    case 4:
        spellData[2] = (int)lbl_803E4064;
        scaleD = (double)lbl_803E405C;
        spellData[3] = (int)lbl_803E405C;
        spellData[4] = (int)endScale;
        idx = 0;
        scaleTbl = (float*)&DAT_80321698;
        angleTbl = &DAT_803216a8;
        baseAngle = (double)lbl_803E4040;
        angleSeed = (double)lbl_803E4060;
        walker = spellData;
        biasD = DOUBLE_803e4068;
        do
        {
            *(undefined2*)(spellData + 0xd) = 0xc000;
            cosResult = (double)fcos16Precise();
            walker[9] = (int)(*scaleTbl * (float)((double)(float)(scaleD + cosResult) * baseAngle));
            walker[5] = *angleTbl;
            randVal = randomGetRange(0x78, 0x7f);
            convScratch0 = (double)CONCAT44(0x43300000, idx * randVal ^ 0x80000000);
            *(short*)(spellData + 0xf) = (short)(int)(angleSeed + (double)(float)(convScratch0 - biasD));
            spellData = (int*)((int)spellData + 2);
            scaleTbl = scaleTbl + 1;
            walker = walker + 1;
            angleTbl = angleTbl + 1;
            idx = idx + 1;
        }
        while (idx < 4);
        FUN_80006824(obj, 0x42d);
        FUN_80006824(obj, 0x42c);
        break;
    case 5:
        spellData[2] = (int)lbl_803E4044;
        spellData[3] = (int)lbl_803E404C;
        spellData[4] = (int)lbl_803E4064;
        FUN_80006810(obj, 0x42c);
        FUN_80006810(obj, 0x42d);
        break;
    case 6:
        idx = 0;
        scaleTbl = (float*)&DAT_80321698;
        angleTbl = &DAT_803216a8;
        biasD = (double)lbl_803E405C;
        scaleD = (double)lbl_803E4040;
        walker = spellData;
        do
        {
            *(undefined2*)(spellData + 0xd) = 0x4000;
            baseAngle = (double)fcos16Precise();
            walker[9] = (int)(*scaleTbl * (float)((double)(float)(biasD + baseAngle) * scaleD));
            walker[5] = *angleTbl;
            spellData = (int*)((int)spellData + 2);
            scaleTbl = scaleTbl + 1;
            walker = walker + 1;
            angleTbl = angleTbl + 1;
            idx = idx + 1;
        }
        while (idx < 4);
        break;
    case 7:
        if (spellObj != 0)
        {
            FUN_8016d994(spellObj, 7, 0);
        }
        if (*spellData != 0)
        {
            FUN_800175cc((double)lbl_803E4040, *spellData, '\0');
        }
        endScale = lbl_803E4044;
        spellData[2] = (int)lbl_803E4044;
        spellData[3] = (int)endScale;
        spellData[4] = (int)endScale;
        spellData[1] = (int)endScale;
        *(byte*)(spellData + 0x17) = *(byte*)(spellData + 0x17) | 1;
        *(byte*)((int)spellData + 0x5d) = *(byte*)((int)spellData + 0x5d) | 1;
        *(byte*)((int)spellData + 0x5e) = *(byte*)((int)spellData + 0x5e) | 1;
        *(byte*)((int)spellData + 0x5f) = *(byte*)((int)spellData + 0x5f) | 1;
    }
    FUN_80286884();
    return;
}

extern f32 lbl_803E3420;

void checkpoint4_render(int param_1);

void checkpoint4_init(Checkpoint4Object* checkpoint, Checkpoint4Placement* placement);

extern u8 Obj_IsLoadingLocked(void);
extern u32 GameBit_Get(int eventId);
extern void* Obj_AllocObjectSetup(int size, int type);
extern int* Obj_SetupObject(void* setup, int a, int b, int c, void* d);

void mikabombshadow_update(int* obj);

void curve_init(ObjAnimComponent* obj, CurvePlacementParams* params);

void FUN_801713ac(undefined8 param_1, double param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  uint param_9)
{
    extern undefined8 ObjHits_DisableObject(); /* #57 */
    short seqType;
    char counter;
    uint resId;
    int model;
    int placement;
    int state;
    undefined8 audioHandle;

    state = *(int*)&((GameObject*)param_9)->extra;
    placement = *(int*)&((GameObject*)param_9)->anim.placementData;
    model = (int)((GameObject*)param_9)->anim.modelInstance->extraSetupData;
    FUN_80017a98();
    FUN_80017a90();
    FUN_80017a98();
    FUN_80017a90();
    audioHandle = ObjHits_DisableObject(param_9);
    if ((*(ushort*)&((GameObject*)param_9)->anim.flags & 0x2000) != 0)
    {
        *(float*)(state + 8) = lbl_803E40E8;
        if (((GameObject*)param_9)->anim.modelState != NULL)
        {
            ((GameObject*)param_9)->anim.modelState->flags = OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        }
    }
    if ((int)*(short*)(state + 0x10) != 0xffffffff)
    {
        FUN_80017698((int)*(short*)(state + 0x10), 1);
        audioHandle = FUN_800e842c(param_9);
    }
    resId = (uint) * (short*)(placement + 0x1e);
    if (resId != 0xffffffff)
    {
        audioHandle = FUN_80017698(resId, 1);
    }
    resId = (uint) * (short*)(placement + 0x2c);
    if (0 < (int)resId)
    {
        FUN_80017688(resId);
    }
    seqType = *(short*)(model + 2);
    if (seqType == 4)
    {
        seqType = ((GameObject*)param_9)->anim.seqId;
        if (seqType == 0x3cd)
        {
            model = FUN_80017a98();
            FUN_80294d60(audioHandle, param_2, param_3, param_4, param_5, param_6, param_7, param_8, model, 2);
            resId = FUN_80017a98();
            FUN_80006824(resId, SFXen_treadlpc);
            FUN_80081118((double)lbl_803E40EC, param_9, 1, 0x28);
        }
        else if ((seqType < 0x3cd) && (seqType == 0xb))
        {
            resId = FUN_80017a98();
            audioHandle = FUN_80006824(resId, SFXen_treadlpc);
            model = FUN_80017a98();
            FUN_80294d60(audioHandle, param_2, param_3, param_4, param_5, param_6, param_7, param_8, model, 4);
            FUN_80081118((double)lbl_803E40EC, param_9, 3, 0x28);
        }
        else
        {
            resId = FUN_80017a98();
            FUN_80006824(resId, SFXen_waterblock_stop);
            FUN_80081118((double)lbl_803E40EC, param_9, 0xff, 0x28);
        }
    }
    else if ((seqType < 4) && (seqType == 1))
    {
        seqType = ((GameObject*)param_9)->anim.seqId;
        if (seqType == 0x319)
        {
            FUN_80006824(param_9, SFXwp_gprop2_c);
            FUN_80017698(0x3e9, 1);
            *(undefined2*)(state + 0x3c) = 0x4b0;
            FUN_80081118((double)lbl_803E40EC, param_9, 0xff, 0x28);
        }
        else
        {
            if (seqType < 0x319)
            {
                if (seqType == 0x5a)
                {
                    FUN_80006824(param_9, SFXen_treadlpc);
                    FUN_80081118((double)lbl_803E40EC, param_9, 2, 0x28);
                    goto LAB_801725bc;
                }
                if ((seqType < 0x5a) && (seqType == 0x22))
                {
                    FUN_80006824(param_9, SFXen_treadlpc);
                    FUN_80081118((double)lbl_803E40EC, param_9, 0xff, 0x28);
                    goto LAB_801725bc;
                }
            }
            else if (seqType == 0x6a6)
            {
                resId = FUN_80017690(0x86a);
                counter = (char)resId;
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

void staff_func0F(void)
{
}

void staff_func0E(void)
{
}

void staff_func0B(void)
{
}

void staff_setScale(void)
{
}

void staff_render(void)
{
}

void staff_hitDetect(void)
{
}

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
int staff_getExtraSize(void) { return 0xc0; }
int staff_getObjectTypeId(void) { return 0x9; }
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
void staff_func10(int* obj, s32 v);
void staff_setHitReactValue(int* obj, s32 v);
void staff_addHitReactValue(int* obj, s32 delta);
extern s16 staff_getHitReactValue(int* obj);
void staff_getHitGeometryPoints(int* obj, f32* outA, f32* outB);
void staff_func15(int* obj, s16 idx, f32 f1, f32 f2);
extern s32 staff_func16(int* obj);
extern void fireball_free();
extern void fireball_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);
extern void fireball_hitDetect();
extern void fireball_update();
extern void fireball_init();
void flamethrowerspe_setScale(int* obj, s16 a, s16 b, f32 f1, f32 f2, f32 f3);
extern void flamethrowerspe_func0B(int* obj);
extern void flamethrowerspe_render(void);
extern void flamethrowerspe_update();
extern void flamethrowerspe_init();
extern void shield_free();
extern void shield_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);
extern void shield_update();

void restartmarker_init(int* obj, int* state);

extern void dll_F7_free();
extern void dll_F7_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);
extern void dll_F7_update();
extern void dll_F7_init();
void staffFn_80170380(int* obj, int cmd);
extern int* Obj_GetActiveModel(int obj);

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

typedef struct StaffState
{
    u8 pad00[0x54];
    f32 geometryPointAX;
    u8 pad58[4];
    f32 geometryPointAY;
    u8 pad60[4];
    f32 geometryPointAZ;
    u8 pad68[4];
    f32 geometryPointBX;
    u8 pad70[4];
    f32 geometryPointBY;
    u8 pad78[4];
    f32 geometryPointBZ;
    u8 pad80[8];
    s16 hitReactValue;
    u8 pad8A[0x28];
    s16 fieldB2;
    u8 padB4[5];
    s8 fieldB9;
} StaffState;

s16 staff_getHitReactValue(int* obj) { return ((StaffState*)((int**)obj)[0xb8 / 4])->hitReactValue; }
u8 fn_8016F16C(int* obj);

s32 staff_func16(int* obj) { return ((StaffState*)((int**)obj)[0xb8 / 4])->fieldB9; }


void StaticCamera_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void baddieinterestp_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void curve_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void gcbaddieshield_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);

void flamethrowerspe_render(void);
void fn_801719F8(void) { objRenderFn_8003b8f4(lbl_803E3420); }

void StaticCamera_free(int x);

void objSetAnimField48to0(int* obj)
{
    s32 v = 0x0;
    *(s32*)((char*)((int**)obj)[0xb8 / 4] + 0x48) = v;
}

void flamethrowerspe_func0B(int* obj);

extern void quakeSpellFn_8016cee8(int* obj, int* x);
void playerRenderQuakeSpell(int* obj) { quakeSpellFn_8016cee8(obj, ((GameObject*)obj)->ownerObj); }

#pragma dont_inline on
void staffSetGlow(int* obj, u8 a, u8 b)
{
    u8* state = (u8*)((int**)obj)[0xb8 / 4];
    state[0xbb] = a;
    state[0xba] = b;
}
#pragma dont_inline reset

void staff_func10(int* obj, s32 v)
{
    ((StaffState*)((int**)obj)[0xb8 / 4])->fieldB2 = (s16)v;
}

void staff_setHitReactValue(int* obj, s32 v)
{
    s16* p = &((StaffState*)((int**)obj)[0xb8 / 4])->hitReactValue;
    if (v > 0xff) v = 0xff;
    *p = (s16)v;
}

void collectible_func0E(int* obj, u32 v);

extern void staff_setupSwipe(int p1, int p2, int p3, int p4);
extern int getHudHiddenFrameCount(void);

void staff_modelMtxFn(int* obj, int p4, int p5)
{
    int* inner = (int*)*(int*)&((GameObject*)obj)->extra;
    staff_setupSwipe((int)obj, (int)inner, p5, p4);
    if (getHudHiddenFrameCount() != 0)
    {
        *(u8*)((char*)inner + 0xbc) = 1;
    }
    else
    {
        *(u8*)((char*)inner + 0xbc) = 0;
    }
}

void flamethrowerspe_setScale(int* obj, s16 a, s16 b, f32 f1, f32 f2, f32 f3);

void staff_addHitReactValue(int* obj, s32 delta)
{
    s16* p = &((StaffState*)((int**)obj)[0xb8 / 4])->hitReactValue;
    s32 v;
    *p = (s16)(*p + delta);
    v = *p;
    if (v < 0)
    {
        v = 0;
    }
    else if (v > 0xff)
    {
        v = 0xff;
    }
    *p = (s16)v;
}

void staff_getHitGeometryPoints(int* obj, f32* outA, f32* outB)
{
    StaffState* state = ((StaffState**)(obj))[0xb8 / 4];
    outA[0] = state->geometryPointAX;
    outA[1] = state->geometryPointAY;
    outA[2] = state->geometryPointAZ;
    outB[0] = state->geometryPointBX;
    outB[1] = state->geometryPointBY;
    outB[2] = state->geometryPointBZ;
}

void gcbaddieshield_init(int* obj, void* initData);

void mikabombshadow_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);

void staff_func15(int* obj, s16 idx, f32 f1, f32 f2)
{
    u8* slot = (u8*)((int**)obj)[0xb8 / 4];
    u8* state = slot;
    if ((state[0x14] & 0x2) != 0)
    {
        slot = state + 0x18;
        if ((slot[0x14] & 0x2) != 0)
        {
            slot += 0x18;
            if ((slot[0x14] & 0x2) != 0)
            {
            }
        }
    }
    slot[0x14] = (u8)(slot[0x14] | 0x3);
    *(f32*)(slot + 0x4) = f1;
    *(f32*)(slot + 0x8) = f2;
    *(s16*)(slot + 0xc) = 0;
    *(s16*)(slot + 0xe) = 0;
    *(s16*)(slot + 0x12) = 0;
    *(s16*)(slot + 0x10) = idx;
    *(void**)(state + 0x48) = slot;
}

int* fn_801702D4(int* obj, f32 fv);

extern void mm_free(int* p);

void gcbaddieshield_update(int* obj);

void staff_free(int* obj)
{
    u8* p;
    int i;
    i = 0;
    p = ((GameObject*)obj)->extra;
    for (; i < 3; i++)
    {
        mm_free(*(int**)p);
        p += 0x18;
    }
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void fireball_free(int* obj);

extern int textureFree(int tex);
extern void* lbl_803DDAA0;
extern void* lbl_803DDAA8[2];

void depthoffieldpoint_init(int* obj);

void depthoffieldpoint_update(int* obj);

void staff_release(void)
{
    void** p;
    int i;
    if (lbl_803DDAA8[0] != NULL)
    {
        for (i = 0, p = lbl_803DDAA8; i < 2; i++)
        {
            textureFree((int)*p);
            *p = NULL;
            p++;
        }
    }
    if (lbl_803DDAA0 != NULL)
    {
        Resource_Release(lbl_803DDAA0);
        lbl_803DDAA0 = NULL;
    }
}


void mikabombshadow_init(int* obj);

void StaticCamera_init(int* obj, int* params, int flag);

void flamethrowerspe_init(int* obj, int* params);

void animatedobj_free(int* obj, int seqFlag);

extern int mmAlloc(int size, int a, int b);
extern f32 lbl_803E3328;
extern u8 lbl_803AC6B8[];

void staff_init(int* obj)
{
    int* state = ((GameObject*)obj)->extra;
    ObjHitsPriorityState* hitState;
    int* p;
    int i;
    *(u8*)((char*)state + 0xaa) = 1;
    *(s16*)((char*)state + 0xb0) = 2;
    *(f32*)((char*)state + 0x50) = lbl_803E3328;
    hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    if (hitState != NULL)
    {
        hitState->trackContactMask = 0x109;
    }
    i = 0;
    p = state;
    for (; i < 3; i++)
    {
        *p = mmAlloc(0xEA60, 0x1a, 0);
        *(s16*)((char*)p + 0x10) = -1;
        p = (int*)((char*)p + 0x18);
    }
    lbl_803AC6B8[0x20] = 0;
    *(int*)(lbl_803AC6B8 + 0x1c) = 0;
}


void dll_F7_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);

extern f32 lbl_803E32B4;
extern f32 lbl_803E3320;
extern f32 lbl_803E3288;
extern f32 lbl_803E3324;

void staffDoGrowShrinkAnim(int* obj, u8 grow, u8 flag2)
{
    extern void Sfx_PlayFromObject(int* obj, int sfx); /* #57 */
    int* state = ((GameObject*)obj)->extra;
    if (grow != 0)
    {
        if (((StaffDoGrowShrinkAnimState*)state)->unk50 < lbl_803E32B4)
        {
            Sfx_PlayFromObject(obj, SFXsc_text_appears_lp);
        }
        if (flag2 == 0)
        {
            ((StaffDoGrowShrinkAnimState*)state)->unk50 = lbl_803E3320;
        }
        else
        {
            ((StaffDoGrowShrinkAnimState*)state)->unk50 = lbl_803E3288;
        }
    }
    else
    {
        if (((StaffDoGrowShrinkAnimState*)state)->unk50 > lbl_803E32B4)
        {
            Sfx_PlayFromObject(obj, SFXsc_nolock);
        }
        if (flag2 == 0)
        {
            ((StaffDoGrowShrinkAnimState*)state)->unk50 = lbl_803E3324;
        }
        else
        {
            ((StaffDoGrowShrinkAnimState*)state)->unk50 = lbl_803E3328;
        }
    }
}

void dll_F7_init(int* obj, int* params);

void fireball_hitDetect(int* obj);

void dim2roofrub_init(int* obj, int* params);

void animatedobj_init(int* obj, int* params);

void flamethrowerspe_update(int* obj);

extern void CameraShake_Start(f32 a, f32 b, f32 c);

void mikabomb_update(int* obj);

void mikabomb_init(int* obj);

extern void PSMTXTrans(f32* m, f32 x, f32 y, f32 z);
extern void PSMTXConcat(f32 * a, f32 * b, f32 * out);
extern void PSMTXRotRad(f32* m, int axis, f32 rad);
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;

void animatedobj_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);

void dim2roofrub_render(int* obj, int p2, int p3, int p4, int p5);

void dim2roofrub_update(int* obj);

void fireball_init(int* obj);
extern f32 mathSinf(f32 v);
extern f32 mathCosf(f32 x);

void fireball_update(int* obj);

void fireball_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);

void shield_update(int* obj);

extern void Sfx_PlayAtPositionFromObject(int* obj, f32 x, f32 y, f32 z, int sfx);

void dll_F7_update(int* obj);

extern s16 lbl_803DBD50[4];
extern s16* lbl_803DDAA4;
extern void* textureLoad(int id, int flag);

void staff_initialise(void)
{
    s16* p = (s16*)lbl_803208A0;
    int n = 0;
    int i;
    int j;
    for (i = 0; i < 5; i++)
    {
        for (j = 0; j < 7; j++)
        {
            if (*p == 0)
            {
                *p = 0xc3;
            }
            p++;
        }
        n += 6;
    }
    lbl_803DDAA4 = lbl_803DBD50;
    if (lbl_803DDAA8[0] == NULL)
    {
        for (i = 0; i < 2; i++)
        {
            lbl_803DDAA8[i] = textureLoad(lbl_803DDAA4[i], 0);
        }
    }
    if (lbl_803DDAA0 == NULL)
    {
        lbl_803DDAA0 = Resource_Acquire(90, 1);
    }
}

void shield_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);

extern void quakeSpellTextureFn_8007366c(int param);
extern f32* Camera_GetViewMatrix(void);
extern void PSMTXScale(f32* m, f32 x, f32 y, f32 z);
extern void GXLoadPosMtxImm(f32* m, int id);
extern void GXLoadTexMtxImm(f32* m, int id, int type);
extern void GXDrawTorus(f32 rc, u8 numc, u8 numt);
extern void* memcpy(void* dst, const void* src, unsigned int n);
extern f32 lbl_803E3300;

void quakeSpellTextureFn_8016dbf4(void)
{
    f32 mResult[12];
    f32 mScale[12];
    f32 mRot[12];
    f32 mTrans[12];
    f32 mView[12];

    if (lbl_803AC6B8[0x20] != 0)
    {
        f32 s;
        f32 z;
        quakeSpellTextureFn_8007366c((int)*(f32*)(lbl_803AC6B8 + 0x18));
        memcpy(mView, Camera_GetViewMatrix(), 0x30);
        PSMTXRotRad(mRot, 'x', lbl_803E3300);
        s = *(f32*)(lbl_803AC6B8 + 0xc);
        PSMTXScale(mScale, s, s * *(f32*)(lbl_803AC6B8 + 0x14), s);
        PSMTXConcat(mScale, mRot, mScale);
        PSMTXTrans(mTrans, *(f32*)(lbl_803AC6B8 + 0) - playerMapOffsetX,
                   *(f32*)(lbl_803AC6B8 + 4),
                   *(f32*)(lbl_803AC6B8 + 8) - playerMapOffsetZ);
        PSMTXConcat(mView, mTrans, mView);
        PSMTXConcat(mView, mScale, mResult);
        GXLoadPosMtxImm(mResult, 0);
        PSMTXConcat(mView, mRot, mResult);
        z = lbl_803E32B4;
        mResult[3] = z;
        mResult[7] = z;
        mResult[11] = z;
        GXLoadTexMtxImm(mResult, 30, 0);
        GXDrawTorus(*(f32*)(lbl_803AC6B8 + 0x10), 10, 20);
    }
}

extern f32 lbl_803E32A8;
extern f32 lbl_803E3290;
extern f32 lbl_803E32F4;
extern f32 lbl_803E32F8;
extern f32 lbl_803E32FC;
extern f32 lbl_803E32D0;

typedef struct QuakePartVec
{
    u16 h0, h1, h2;
    f32 scale;
    f32 x, y, z;
} QuakePartVec;

void superQuakeFn_8016d9fc(f32* pos)
{
    extern void Obj_FreeObject(int* obj); /* #57 */
    int* player;

    if (lbl_803AC6B8[0x20] != 0)
    {
        Obj_FreeObject(*(int**)(lbl_803AC6B8 + 0x1c));
        *(int**)(lbl_803AC6B8 + 0x1c) = NULL;
    }
    *(f32*)(lbl_803AC6B8 + 0) = pos[0];
    *(f32*)(lbl_803AC6B8 + 4) = lbl_803E32A8 + pos[1];
    *(f32*)(lbl_803AC6B8 + 8) = pos[2];
    *(f32*)(lbl_803AC6B8 + 0x18) = lbl_803E32F4;
    *(f32*)(lbl_803AC6B8 + 0xc) = lbl_803E3288;
    *(f32*)(lbl_803AC6B8 + 0x10) = lbl_803E3290;
    *(f32*)(lbl_803AC6B8 + 0x14) = lbl_803E3288;
    CameraShake_Start(lbl_803E32F8, lbl_803E32A8, lbl_803E32FC);
    player = (int*)Obj_GetPlayerObject();
    if (player != NULL && Obj_IsLoadingLocked() != 0)
    {
        QuakePartVec v;
        void* setup;
        lbl_803AC6B8[0x20] = 1;
        v.x = *(f32*)(lbl_803AC6B8 + 0);
        v.y = *(f32*)(lbl_803AC6B8 + 4);
        v.z = *(f32*)(lbl_803AC6B8 + 8);
        v.scale = lbl_803E3288;
        v.h0 = 0;
        v.h2 = 0;
        v.h1 = 0;
        (*gPartfxInterface)->spawnObject(player, 0x565, &v, 0x200000, -1, NULL);
        setup = Obj_AllocObjectSetup(36, 0x63c);
        *((u8*)setup + 4) = 1;
        *((u8*)setup + 6) = 0xff;
        *((u8*)setup + 5) = 2;
        *((u8*)setup + 7) = 0xff;
        ((ObjPlacement*)setup)->posX = *(f32*)(lbl_803AC6B8 + 0);
        ((ObjPlacement*)setup)->posY = *(f32*)(lbl_803AC6B8 + 4);
        ((ObjPlacement*)setup)->posZ = *(f32*)(lbl_803AC6B8 + 8);
        *(int**)(lbl_803AC6B8 + 0x1c) = Obj_SetupObject(setup, 5, ((GameObject*)player)->anim.mapEventSlot, -1,
                                                        ((GameObject*)player)->anim.parent);
        if (GameBit_Get(0xc55) != 0)
        {
            ((ObjAnimComponent*)*(int*)(lbl_803AC6B8 + 0x1c))->bankIndex = 1;
        }
        ObjHitbox_SetSphereRadius(*(int*)(lbl_803AC6B8 + 0x1c), 1);
        ObjHits_SetHitVolumeSlot(*(int*)(lbl_803AC6B8 + 0x1c), 17, 5, 0);
        *(f32*)(*(int*)(lbl_803AC6B8 + 0x1c) + 8) = lbl_803E32D0;
        ((GameObject*)*(int*)(lbl_803AC6B8 + 0x1c))->anim.alpha = 0xff;
    }
}

typedef struct SwipeColorTable
{
    u32 w[16];
} SwipeColorTable;

/* per-swipe trail record (stride 0x18, 3 records) */
typedef struct SwipeRecord
{
    u8* vertexData;
    u8 pad04[0xc - 0x4];
    u16 startIndex;
    u16 endIndex;
    u8 pad10[2];
    s16 vertexCount;
    u8 flags;
    u8 pad15[0x18 - 0x15];
} SwipeRecord;

extern SwipeColorTable lbl_802C2220;
void staffDrawSwipe(int* obj, int* swipe);

void staff_hitDetectGeometry(int* obj)
{
    ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    int* swipe = ((GameObject*)obj)->extra;
    SwipeColorTable tbl = lbl_802C2220;

    staffDrawSwipe(obj, swipe);
    if (hitState->contactFlags != 0 && getHudHiddenFrameCount() == 0)
    {
        int t = hitState->contactHitVolume;
        int idx;
        if (t < 0)
        {
            idx = 0;
        }
        else if (t > 35)
        {
            idx = 35;
        }
        else
        {
            idx = t;
        }
        if (idx == 14)
        {
            Sfx_PlayAtPositionFromObject(obj, hitState->contactPosX, hitState->contactPosY,
                                         hitState->contactPosZ, 186);
            (*gWaterfxInterface)->spawnSplashBurst(
                obj, hitState->contactPosX, hitState->contactPosY, hitState->contactPosZ, lbl_803E32B4);
            ((void (*)(f32, f32, f32, s16, f32, int))(*gWaterfxInterface)->spawnRipple)(
                hitState->contactPosX, hitState->contactPosY, hitState->contactPosZ, 0, lbl_803E32B4, 2);
        }
        else
        {
            QuakePartVec v;
            v.scale = lbl_803E3288;
            v.h2 = 0;
            v.h1 = 0;
            v.h0 = 0;
            v.x = hitState->contactPosX;
            v.y = hitState->contactPosY;
            v.z = hitState->contactPosZ;
            ((void (*)(int, int, void*, int, int, u8*))(*(int**)lbl_803DDAA0)[1])(0, 1, &v, 0x401, -1,
                (u8*)&tbl + (((u8*)lbl_803208E8)[idx] << 4));
            Sfx_PlayAtPositionFromObject(obj, hitState->contactPosX, hitState->contactPosY,
                                         hitState->contactPosZ, (u16)((s16*)lbl_803208A0)[idx]);
        }
    }
}
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

extern void selectTexture(void* tex, int x);
extern void textureSetupFn_800799c0(void);
extern void geomDrawFn_800796f0(void);
extern void textRenderSetupFn_80079804(void);
extern void GXSetBlendMode(int a, int b, int c, int d);
extern void GXSetAlphaCompare(int a, int b, int c, int d, int e);
extern void GXSetCullMode(int a);
extern void GXClearVtxDesc(void);
extern void GXSetVtxDesc(int a, int b);
extern void GXSetCurrentMtx(int a);
extern void GXBegin(int type, int fmt, int n);
extern f32 lbl_803E3294;

#pragma opt_common_subs off
void staffDrawSwipe(int* obj, int* swipe)
{
    SwipeRecord* swp;
    int i;

    selectTexture(lbl_803DDAA8[*(s8*)((char*)swipe + 0xb9)], 0);
    textureSetupFn_800799c0();
    geomDrawFn_800796f0();
    textRenderSetupFn_80079804();
    gxSetZMode_(1, 3, 0);
    GXSetBlendMode(1, 4, 1, 5);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    GXSetCullMode(0);
    GXClearVtxDesc();
    GXSetVtxDesc(9, 1);
    GXSetVtxDesc(11, 1);
    GXSetVtxDesc(13, 1);
    GXLoadPosMtxImm(Camera_GetViewMatrix(), 0);
    GXSetCurrentMtx(0);

    i = 0;
    swp = (SwipeRecord*)swipe;
    for (; i < 3; i++)
    {
        if ((swp->flags & 2) && swp->vertexCount >= 4)
        {
            u8* vp;
            int j;
            f32 v1, v0, u;
            j = swp->startIndex;
            vp = swp->vertexData + j * 20;
            u = lbl_803E3294;
            v0 = lbl_803E32B4;
            v1 = lbl_803E3288;
            for (; j < swp->endIndex - 2; j += 2)
            {
                GXBegin(128, 2, 4);
                swipePos3f32(*(f32*)(vp + 0) - playerMapOffsetX, *(f32*)(vp + 4), *(f32*)(vp + 8) - playerMapOffsetZ);
                swipeColor4u8(255, 255, 255, (u8) * (s16*)(vp + 0x10));
                swipeTexCoord2f32(u, v0);
                swipePos3f32(*(f32*)(vp + 0x14) - playerMapOffsetX, *(f32*)(vp + 0x18),
                             *(f32*)(vp + 0x1c) - playerMapOffsetZ);
                swipeColor4u8(255, 255, 255, (u8) * (s16*)(vp + 0x24));
                swipeTexCoord2f32(u, v1);
                swipePos3f32(*(f32*)(vp + 0x3c) - playerMapOffsetX, *(f32*)(vp + 0x40),
                             *(f32*)(vp + 0x44) - playerMapOffsetZ);
                swipeColor4u8(255, 255, 255, (u8) * (s16*)(vp + 0x4c));
                swipeTexCoord2f32(u, v1);
                swipePos3f32(*(f32*)(vp + 0x28) - playerMapOffsetX, *(f32*)(vp + 0x2c),
                             *(f32*)(vp + 0x30) - playerMapOffsetZ);
                swipeColor4u8(255, 255, 255, (u8) * (s16*)(vp + 0x38));
                swipeTexCoord2f32(u, v0);
                vp += 0x28;
            }
        }
        swp++;
    }
}

extern int objGetAnimState80A(int obj);
extern f32 lbl_803E330C;
extern f32 lbl_803E3310;
extern f32 lbl_803E332C;
extern f32 lbl_803E32E0;
extern f32 lbl_803E32E4;
extern f32 lbl_803E32E8;
extern f32 lbl_803E32EC;
extern f32 lbl_803E32F0;

void staff_update(int* obj)
{
    extern void Obj_FreeObject(int* obj); /* #57 */
    u8* state = ((GameObject*)obj)->extra;
    SwipeRecord* swp;
    int n;
    int* model = Obj_GetActiveModel((int)obj);
    *(u16*)((char*)model + 0x18) &= ~0x8;
    ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(
        (int)obj, *(f32*)(state + 0x50), timeDelta, NULL);

    swp = (SwipeRecord*)state;
    for (n = 3; n != 0; n--)
    {
        if (swp->flags & 2)
        {
            int j;
            u8* vp;
            j = swp->startIndex;
            vp = swp->vertexData + j * 20;
            for (; j < swp->endIndex; j += 2)
            {
                if ((u8*)swp == *(u8**)(state + 0x48))
                {
                    f32 k = lbl_803E32F4;
                    f32 t = lbl_803E330C * *(f32*)(state + 0x98) - *(f32*)(vp + 0xc);
                    f32 v;
                    t = k * (t * lbl_803E3310);
                    if (t < lbl_803E32B4)
                    {
                        v = lbl_803E32B4;
                    }
                    else if (t > k)
                    {
                        v = k;
                    }
                    else
                    {
                        v = t;
                    }
                    *(s16*)(vp + 0x10) = k - v;
                    *(s16*)(vp + 0x24) = *(s16*)(vp + 0x10);
                }
                else
                {
                    *(s16*)(vp + 0x10) = -(lbl_803E332C * timeDelta - (f32)(int) * (s16*)(vp + 0x10));
                    *(s16*)(vp + 0x24) = *(s16*)(vp + 0x10);
                }
                {
                    int c = *(s16*)(vp + 0x10);
                    if (c < 0)
                    {
                        c = 0;
                    }
                    else if (c > 255)
                    {
                        c = 255;
                    }
                    *(s16*)(vp + 0x10) = (s16)c;
                    c = *(s16*)(vp + 0x24);
                    if (c < 0)
                    {
                        c = 0;
                    }
                    else if (c > 255)
                    {
                        c = 255;
                    }
                    *(s16*)(vp + 0x24) = (s16)c;
                }
                if (*(s16*)(vp + 0x10) <= 0 && *(s16*)(vp + 0x24) <= 0)
                {
                    swp->vertexCount += -2;
                    swp->startIndex += 2;
                }
                vp += 0x28;
            }
            if ((u8*)swp != *(u8**)(state + 0x48) && swp->vertexCount == 0)
            {
                swp->flags &= ~2;
            }
        }
        swp++;
    }

    quakeSpellFn_8016cee8(obj, ((GameObject*)obj)->ownerObj);
    objGetAnimState80A(*(int*)&((GameObject*)obj)->ownerObj);
    state[0xb9] = 0;
    {
        u8* q = lbl_803AC6B8;
        if (q[0x20] != 0)
        {
            f32 sc = *(f32*)(q + 0xc) + lbl_803E32E0;
            f32 w;
            *(f32*)(q + 0xc) = sc;
            ObjHitbox_SetSphereRadius(*(int*)(q + 0x1c), (int)sc);
            ObjHits_SetHitVolumeSlot(*(int*)(q + 0x1c), 17, 5, 0);
            w = *(f32*)(lbl_803AC6B8 + 0x18) + lbl_803E32E4;
            *(f32*)(lbl_803AC6B8 + 0x18) = w;
            *(f32*)(lbl_803AC6B8 + 0x10) = *(f32*)(lbl_803AC6B8 + 0x10) * lbl_803E32E8;
            *(f32*)(lbl_803AC6B8 + 0x14) = *(f32*)(lbl_803AC6B8 + 0x14) * lbl_803E32EC;
            ((GameObject*)*(int*)(q + 0x1c))->anim.alpha = w;
            *(f32*)(*(int*)(q + 0x1c) + 8) += lbl_803E32F0;
            if (*(f32*)(lbl_803AC6B8 + 0x18) < lbl_803E3288)
            {
                q[0x20] = 0;
                Obj_FreeObject(*(int**)(q + 0x1c));
                *(int**)(q + 0x1c) = NULL;
            }
        }
    }
}


extern f32 fastFloorf(f32 v);
extern f32 Curve_EvalBSpline(f32* a, f32 t, f32* out);
extern f32 lbl_803E3304;
extern f32 lbl_803E3308;
extern f32 lbl_803E32A4;
extern f32 lbl_803E32AC;

void staff_setupSwipe(int p1, int p2, int p3, int p4)
{
    u8* model2;
    u8* slot;
    u8* obj;
    u8* swipe;
    ObjWeaponDaTable* weaponDaTable;
    s16* tbl;
    int count;
    int count2;
    int ibase;
    int first;
    u8* vp;
    int idx[4];
    f32 arrE[4];
    f32 arrF[4];
    f32 arrG[4];
    f32 arrH[4];
    f32 arrI[4];
    f32 arrJ[4];
    f32 sinv, cosv, vidx, flb, fla, frac, tmax, prog, angle, acc, step;
    int ang;

    swipe = (u8*)p2;
    obj = (u8*)p4;
    if (*(int**)(swipe + 0x48) != NULL && swipe[0xbc] == 0)
    {
        ang = *(s16*)obj;
        if (*(s16**)&((GameObject*)obj)->anim.parent != NULL)
        {
            ang += **(s16**)&((GameObject*)obj)->anim.parent;
        }
        angle = (lbl_803E3304 * (f32)(int) - ang) / lbl_803E3308;
        cosv = mathSinf(angle);
        sinv = mathCosf(angle);
        model2 = *(u8**)((char*)Obj_GetActiveModel((int)obj) + 0x2c);
        weaponDaTable = ((GameObject*)obj)->anim.weaponDaTable;
        if (weaponDaTable != NULL && weaponDaTable->byteCount > 0)
        {
            f32 sw;
            slot = *(u8**)(swipe + 0x48);
            count = (int)(lbl_803E330C * *(f32*)(model2 + 0x14));
            prog = *(f32*)(slot + 8) * *(f32*)(model2 + 0x14);
            if (slot[0x14] & 1)
            {
                *(f32*)(swipe + 0x8c) = ((GameObject*)obj)->anim.worldPosX;
                *(f32*)(swipe + 0x90) = ((GameObject*)obj)->anim.worldPosY;
                *(f32*)(swipe + 0x94) = ((GameObject*)obj)->anim.worldPosZ;
                *(f32*)(swipe + 0x98) = lbl_803E32B4;
                slot[0x14] &= ~1;
            }
            sw = *(f32*)(swipe + 0x98);
            tmax = *(f32*)(model2 + 4);
            if (sw > prog)
            {
                *(f32*)(swipe + 0x98) = tmax;
                return;
            }
            if (tmax > prog)
            {
                tmax = prog;
            }
            tbl = weaponDaTable->entries;
            if (sw >= lbl_803E32B4)
            {
                fla = fastFloorf(sw * lbl_803E32A4) / lbl_803E32A4;
                fla = fla * lbl_803E330C;
                tmax = tmax * lbl_803E32A4;
                flb = fastFloorf(tmax) / lbl_803E32A4;
                flb = flb * lbl_803E330C;
                ibase = (int)fla;
                frac = fla - (f32)ibase;
                count2 = (int)((flb - fla) / lbl_803E32AC);
                if (count2 == 0)
                {
                    if (*(f32*)(model2 + 4) > prog)
                    {
                        *(f32*)(swipe + 0x98) = *(f32*)(model2 + 4);
                    }
                    return;
                }
                acc = lbl_803E32B4;
                step = lbl_803E3288 / (f32)count2;
                first = 1;
                while (count2 != 0)
                {
                    if (*(u16*)(slot + 0xe) == 2998)
                    {
                        count2 = 0;
                    }
                    else
                    {
                        frac += lbl_803E32AC;
                        if (frac >= lbl_803E3288)
                        {
                            frac -= lbl_803E3288;
                            ibase += 1;
                            first = 1;
                        }
                        acc += step;
                        if (first)
                        {
                            int n;
                            int* pidx;
                            f32 *pE, *pF, *pG, *pH, *pI, *pJ;
                            idx[0] = ibase - 1;
                            idx[1] = ibase;
                            idx[2] = ibase + 1;
                            idx[3] = ibase + 2;
                            if (ibase - 1 < 0)
                            {
                                idx[0] = 0;
                            }
                            if (idx[1] >= count)
                            {
                                idx[1] = count;
                            }
                            if (idx[2] >= count)
                            {
                                idx[2] = count;
                            }
                            if (idx[3] >= count)
                            {
                                idx[3] = count;
                            }
                            pidx = idx;
                            pE = arrE;
                            pF = arrF;
                            pG = arrG;
                            pH = arrH;
                            pI = arrI;
                            pJ = arrJ;
                            for (n = 4; n != 0; n--)
                            {
                                f32 a, b, t1, t2;
                                int ip = *pidx * 12;
                                *pE = (f32) * (s16*)((char*)tbl + ip) / lbl_803E32F4;
                                *pF = (f32) * (s16*)((char*)tbl + ip + 2) / lbl_803E32F4;
                                *pG = (f32) * (s16*)((char*)tbl + ip + 4) / lbl_803E32F4;
                                *pH = (f32) * (s16*)((char*)tbl + ip + 6) / lbl_803E32F4;
                                *pI = (f32) * (s16*)((char*)tbl + ip + 8) / lbl_803E32F4;
                                *pJ = (f32) * (s16*)((char*)tbl + ip + 10) / lbl_803E32F4;
                                a = *pE;
                                b = *pG;
                                t1 = sinv * a - cosv * b;
                                t2 = cosv * a + sinv * b;
                                *pE = t1;
                                *pG = t2;
                                a = *pH;
                                b = *pJ;
                                t2 = cosv * a + sinv * b;
                                t1 = sinv * a - cosv * b;
                                *pH = t1;
                                *pJ = t2;
                                pidx++;
                                pE++;
                                pF++;
                                pG++;
                                pH++;
                                pI++;
                                pJ++;
                            }
                            first = 0;
                        }
                        vp = *(u8**)slot + *(u16*)(slot + 0xe) * 20;
                        *(f32*)(vp + 0) = Curve_EvalBSpline(arrH, frac, NULL);
                        *(f32*)(vp + 4) = Curve_EvalBSpline(arrI, frac, NULL);
                        *(f32*)(vp + 8) = Curve_EvalBSpline(arrJ, frac, NULL);
                        *(f32*)(vp + 0) = *(f32*)(vp + 0) + (acc * (((GameObject*)obj)->anim.worldPosX - *(f32*)(swipe +
                            0x8c)) + *(f32*)(swipe + 0x8c));
                        *(f32*)(vp + 4) = *(f32*)(vp + 4) + (acc * (((GameObject*)obj)->anim.worldPosY - *(f32*)(swipe +
                            0x90)) + *(f32*)(swipe + 0x90));
                        *(f32*)(vp + 8) = *(f32*)(vp + 8) + (acc * (((GameObject*)obj)->anim.worldPosZ - *(f32*)(swipe +
                            0x94)) + *(f32*)(swipe + 0x94));
                        vidx = (f32)ibase + frac;
                        *(f32*)(vp + 0xc) = vidx;
                        {
                            f32 k = lbl_803E32F4;
                            f32 t = flb - *(f32*)(vp + 0xc);
                            f32 v;
                            t = k * (t * lbl_803E3310);
                            if (t < lbl_803E32B4)
                            {
                                v = lbl_803E32B4;
                            }
                            else if (t > k)
                            {
                                v = k;
                            }
                            else
                            {
                                v = t;
                            }
                            *(s16*)(vp + 0x10) = k - v;
                        }
                        *(f32*)(vp + 0x14) = Curve_EvalBSpline(arrE, frac, NULL);
                        *(f32*)(vp + 0x18) = Curve_EvalBSpline(arrF, frac, NULL);
                        *(f32*)(vp + 0x1c) = Curve_EvalBSpline(arrG, frac, NULL);
                        *(f32*)(vp + 0x14) = *(f32*)(vp + 0x14) + (acc * (((GameObject*)obj)->anim.worldPosX - *(f32*)(
                            swipe + 0x8c)) + *(f32*)(swipe + 0x8c));
                        *(f32*)(vp + 0x18) = *(f32*)(vp + 0x18) + (acc * (((GameObject*)obj)->anim.worldPosY - *(f32*)(
                            swipe + 0x90)) + *(f32*)(swipe + 0x90));
                        *(f32*)(vp + 0x1c) = *(f32*)(vp + 0x1c) + (acc * (((GameObject*)obj)->anim.worldPosZ - *(f32*)(
                            swipe + 0x94)) + *(f32*)(swipe + 0x94));
                        *(f32*)(vp + 0x20) = vidx;
                        {
                            f32 k = lbl_803E32F4;
                            f32 t = flb - *(f32*)(vp + 0x20);
                            f32 v;
                            t = k * (t * lbl_803E3310);
                            if (t < lbl_803E32B4)
                            {
                                v = lbl_803E32B4;
                            }
                            else if (t > k)
                            {
                                v = k;
                            }
                            else
                            {
                                v = t;
                            }
                            *(s16*)(vp + 0x24) = k - v;
                        }
                        *(s16*)(slot + 0x12) += 2;
                        *(u16*)(slot + 0xe) += 2;
                        count2 -= 1;
                    }
                }
            }
            else
            {
                if (*(f32*)(model2 + 4) > prog)
                {
                    *(f32*)(swipe + 0x98) = *(f32*)(model2 + 4);
                    return;
                }
                return;
            }
        }
        *(f32*)(swipe + 0x8c) = ((GameObject*)obj)->anim.worldPosX;
        *(f32*)(swipe + 0x90) = ((GameObject*)obj)->anim.worldPosY;
        *(f32*)(swipe + 0x94) = ((GameObject*)obj)->anim.worldPosZ;
        *(f32*)(swipe + 0x98) = *(f32*)(model2 + 4);
    }
}

void staffFn_80170380(int* obj, int cmd);

extern int objFn_80296700(int* obj);
extern void objfx_spawnArcedBurst(int* obj, f32 a, int type, int ba, int one, int n, f32 b, f32 c, f32 d, int x, int y);
extern void fn_802961A4(int* obj, int* type, f32* power);
extern void fn_802960F4(int objc4, u8** out);
extern f32 lbl_803E328C;
extern f32 lbl_803E3298;
extern f32 lbl_803E329C;
extern f32 lbl_803E32A0;
extern f32 lbl_803E32B0;
extern f32 lbl_803E32B8;
extern f32 lbl_803E32BC;
extern f32 lbl_803E32C0;
extern f32 lbl_803E32C4;
extern f32 lbl_803E32C8;
extern f32 lbl_803E32CC;
extern f32 lbl_803E32D4;
extern f32 lbl_803E32D8;
extern f32 lbl_803E32DC;

typedef struct QuakeFxParams
{
    u16 id;
    u16 a;
    u16 b;
    s16 count;
    f32 f0;
    f32 f1;
    f32 f2;
    f32 f3;
} QuakeFxParams;

void quakeSpellFn_8016cee8(int* obj, int* obj2)
{
    QuakeFxParams fxB;
    QuakeFxParams fxA;
    int type;
    f32 power;
    u8* pos2;
    u8* state = ((GameObject*)obj)->extra;
    if (obj != NULL && obj2 != NULL)
    {
        if (state[0xba] != 0)
        {
            f32 v;
            if (objFn_80296700(obj2) != 0)
            {
                power = lbl_803E3288;
                v = lbl_803E3288;
            }
            else
            {
                power = lbl_803E328C;
                v = lbl_803E3290;
            }
            if (state[0xbb] == 7)
            {
                objfx_spawnArcedBurst(obj, lbl_803E3294, state[0xbb], state[0xba], 1, (int)(lbl_803E3298 * v),
                                      lbl_803E3294, lbl_803E3294, lbl_803E329C * power, 0, 0);
            }
            else
            {
                objfx_spawnArcedBurst(obj, lbl_803E3288, state[0xbb], state[0xba], 1, (int)(lbl_803E3298 * v),
                                      lbl_803E3288, lbl_803E3288, lbl_803E329C * power, 0, 0);
            }
        }
        fn_802961A4(obj2, &type, &power);
        fxB.id = 0;
        fxB.a = 0;
        fxB.b = 0;
        fxB.f0 = lbl_803E3288;
        switch (type)
        {
        case 135:
            fxB.count = 21 - (int)(lbl_803E32A0 * (power / lbl_803E3298));
            fxB.f1 = lbl_803E32A4 * (power / lbl_803E32A8 - lbl_803E3294);
            fxB.id = 0xc94;
            (*gPartfxInterface)->spawnObject(obj, 0x7b2, &fxB, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject(obj, 0x7b2, &fxB, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject(obj, 0x7b2, &fxB, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject(obj, 0x7b2, &fxB, 2, -1, NULL);
            fxB.count = 9;
            fxB.f0 = lbl_803E32B0 * (power / lbl_803E32A8) + lbl_803E32AC;
            fxB.f2 = lbl_803E32B4;
            fxB.id = 0xc0e;
            (*gPartfxInterface)->spawnObject(obj, 0x7b3, &fxB, 2, -1, NULL);
            break;
        case 67:
            if (power > lbl_803E32B4)
            {
                fxB.count = (int)(lbl_803E32A0 * (power / lbl_803E3298)) + 6;
                fxB.f1 = lbl_803E32A4 * (power / lbl_803E32A8 - lbl_803E3294);
                fxB.id = 0xc94;
                (*gPartfxInterface)->spawnObject(obj, 0x7b4, &fxB, 2, -1, NULL);
                (*gPartfxInterface)->spawnObject(obj, 0x7b4, &fxB, 2, -1, NULL);
                fxB.count = 9;
                fxB.f0 = lbl_803E32B0 * (power / lbl_803E32A8) + lbl_803E32AC;
                fxB.f2 = lbl_803E32B4;
                fxB.id = 0xc0e;
                (*gPartfxInterface)->spawnObject(obj, 0x7b3, &fxB, 2, -1, NULL);
            }
            break;
        case 136:
            fxB.f0 = lbl_803E3288;
            fxB.count = 35;
            fxB.f2 = lbl_803E32B4;
            fxB.f1 = lbl_803E32B8;
            fxB.id = 0xc0e;
            (*gPartfxInterface)->spawnObject(obj, 0x7b3, &fxB, 2, -1, NULL);
            fxB.count = 18;
            fxB.f2 = lbl_803E32BC;
            (*gPartfxInterface)->spawnObject(obj, 0x7b3, &fxB, 2, -1, NULL);
            break;
        case 127:
            fxB.f0 = lbl_803E32C0;
            fxB.count = 10;
            fxB.f2 = lbl_803E32BC;
            fxB.f1 = lbl_803E32B8;
            fxB.id = 0xc0e;
            (*gPartfxInterface)->spawnObject(obj, 0x7b3, &fxB, 2, -1, NULL);
            break;
        case 133:
            if (power > lbl_803E32B4)
            {
                if (GameBit_Get(0xc55) != 0)
                {
                    fxB.count = 21 - (int)(lbl_803E32A0 * (power / lbl_803E32B8));
                    fxB.f1 = lbl_803E32C4 * (lbl_803E3290 - power / lbl_803E32B8);
                    fxB.id = 0xc75;
                }
                else
                {
                    fxB.count = 21 - (int)(lbl_803E32A0 * (power / lbl_803E32A8));
                    fxB.f1 = lbl_803E32C4 * (lbl_803E3290 - power / lbl_803E32A8);
                    fxB.id = 0xc94;
                }
                (*gPartfxInterface)->spawnObject(obj, 0x7b2, &fxB, 2, -1, NULL);
                (*gPartfxInterface)->spawnObject(obj, 0x7b2, &fxB, 2, -1, NULL);
                (*gPartfxInterface)->spawnObject(obj, 0x7b2, &fxB, 2, -1, NULL);
                (*gPartfxInterface)->spawnObject(obj, 0x7b2, &fxB, 2, -1, NULL);
                fxB.count = 9;
                if (GameBit_Get(0xc55) != 0)
                {
                    fxB.f0 = lbl_803E32B0 * (power / lbl_803E32B8) + lbl_803E32AC;
                    fxB.id = 0xc75;
                }
                else
                {
                    fxB.f0 = lbl_803E32B0 * (power / lbl_803E32A8) + lbl_803E32AC;
                    fxB.id = 0xc0e;
                }
                fxB.f2 = lbl_803E32B4;
                (*gPartfxInterface)->spawnObject(obj, 0x7b3, &fxB, 2, -1, NULL);
            }
            break;
        case 1135:
            if (power > lbl_803E32B4)
            {
                fxB.count = 21 - (int)(lbl_803E32A0 * (power / lbl_803E32C8));
                fxB.f1 = lbl_803E32C4 * (lbl_803E3290 - power / lbl_803E32C8);
                fxB.id = 0xc94;
                (*gPartfxInterface)->spawnObject(obj, 0x7b2, &fxB, 2, -1, NULL);
                (*gPartfxInterface)->spawnObject(obj, 0x7b2, &fxB, 2, -1, NULL);
                (*gPartfxInterface)->spawnObject(obj, 0x7b2, &fxB, 2, -1, NULL);
                (*gPartfxInterface)->spawnObject(obj, 0x7b2, &fxB, 2, -1, NULL);
                fxB.count = 9;
                fxB.f0 = lbl_803E32B0 * (power / lbl_803E32C8) + lbl_803E32AC;
                fxB.f2 = lbl_803E32B4;
                fxB.id = 0xc0e;
                (*gPartfxInterface)->spawnObject(obj, 0x7b3, &fxB, 2, -1, NULL);
            }
            break;
        case 1128:
            if (power > lbl_803E32B4)
            {
                fxA.count = 21 - (int)(lbl_803E32A0 * (power / lbl_803E32C8));
                fxA.id = 0xc95;
                fn_802960F4(*(int*)&((GameObject*)obj)->ownerObj, &pos2);
                fxB.f1 = *(f32*)(pos2 + 0xc);
                fxB.f2 = *(f32*)(pos2 + 0x10);
                fxB.f3 = *(f32*)(pos2 + 0x14);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)obj)->ownerObj,
                                                 0x7b9, &fxB, 0x200001, -1, &fxA);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)obj)->ownerObj,
                                                 0x7b9, &fxB, 0x200001, -1, &fxA);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)obj)->ownerObj,
                                                 0x7b9, &fxB, 0x200001, -1, &fxA);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)obj)->ownerObj,
                                                 0x7b9, &fxB, 0x200001, -1, &fxA);
                fxA.count = 9;
                fxA.id = 0xc95;
                fxA.f0 = lbl_803E32CC * (power / lbl_803E32C8) + lbl_803E32AC;
                fxB.f1 = *(f32*)(pos2 + 0xc);
                fxB.f2 = *(f32*)(pos2 + 0x10);
                fxB.f3 = *(f32*)(pos2 + 0x14);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)obj)->ownerObj,
                                                 0x7ba, &fxB, 0x200001, -1, &fxA);
            }
            break;
        case 134:
            {
                f32 h;
                u16 idv;
                if (GameBit_Get(0xc55) != 0)
                {
                    idv = 0xc75;
                }
                else
                {
                    idv = 0xc0e;
                }
                fxB.id = idv;
                h = *(f32*)((char*)obj2 + 0x98);
                if (h < lbl_803E32D0)
                {
                    fxB.f1 = lbl_803E32D4;
                    fxB.count = 9;
                    fxB.f0 = lbl_803E3288;
                    fxB.f2 = lbl_803E32B4;
                    (*gPartfxInterface)->spawnObject(obj, 0x7b3, &fxB, 2, -1, NULL);
                }
                else if (h < lbl_803E32D8)
                {
                    fxB.f1 = lbl_803E32C4 * (lbl_803E32DC * (h - lbl_803E32D0) - lbl_803E3294);
                    fxB.count = 9;
                    fxB.f0 = lbl_803E3288;
                    fxB.f2 = lbl_803E32B4;
                    (*gPartfxInterface)->spawnObject(obj, 0x7b3, &fxB, 2, -1, NULL);
                }
                break;
            }
        }
    }
}
