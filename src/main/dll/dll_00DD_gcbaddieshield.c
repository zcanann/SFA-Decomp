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
extern f32 lbl_803E31F8;
extern f32 lbl_803E3388;
extern void objShadowFn_80062498(int* obj, int p2, int p3, u8 frames);
extern f32 lbl_803E31FC;
extern f32 lbl_803E3200;
extern f32 lbl_803E3204;
extern f32 lbl_803E3208;
extern f32 lbl_803E320C;
extern f32 lbl_803E3210;
extern void selectTexture(void* tex, int x);

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
    undefined* puVar1;

    *param_1 = -*(short*)(param_2 + 0x1c);
    param_1[1] = -*(short*)(param_2 + 0x1e);
    param_1[2] = -*(short*)(param_2 + 0x20);
    puVar1 = *(undefined**)(param_1 + 0x5c);
    *puVar1 = *(undefined*)(param_2 + 0x19);
    *(float*)(puVar1 + 4) =
        (float)((double)CONCAT44(0x43300000, (uint) * (byte*)(param_2 + 0x1a)) - DOUBLE_803e3e88);
    puVar1[1] = 0;
    if (param_3 == 0)
    {
        ObjGroup_AddObject((int)param_1, 7);
    }
    return;
}

void FUN_8016d188(int param_1, int param_2)
{
    float fVar1;
    int iVar2;
    uint uVar3;
    int iVar4;
    double dVar5;
    int local_58;
    float local_54;
    int local_50;
    undefined2 local_4c[3];
    short local_46;
    float local_44;
    undefined2 local_34;
    undefined2 local_32;
    undefined2 local_30;
    short local_2e;
    float local_2c;
    float local_28;
    float local_24;
    undefined4 local_20;
    longlong local_18;

    iVar4 = *(int*)&((GameObject*)param_1)->extra;
    if ((param_1 != 0) && (param_2 != 0))
    {
        if (*(char*)(iVar4 + 0xba) != '\0')
        {
            iVar2 = FUN_80294d10(param_2);
            if (iVar2 == 0)
            {
                local_54 = lbl_803E3F24;
                fVar1 = lbl_803E3F28;
            }
            else
            {
                local_54 = lbl_803E3F20;
                fVar1 = lbl_803E3F20;
            }
            if (*(byte*)(iVar4 + 0xbb) == 7)
            {
                dVar5 = (double)lbl_803E3F2C;
                local_18 = (longlong)(int)(lbl_803E3F30 * fVar1);
                FUN_800810f8(dVar5, dVar5, dVar5, (double)(lbl_803E3F34 * local_54), param_1, 7,
                             (uint) * (byte*)(iVar4 + 0xba), 1, (int)(lbl_803E3F30 * fVar1), 0, 0);
            }
            else
            {
                dVar5 = (double)lbl_803E3F20;
                local_18 = (longlong)(int)(lbl_803E3F30 * fVar1);
                FUN_800810f8(dVar5, dVar5, dVar5, (double)(lbl_803E3F34 * local_54), param_1,
                             (uint) * (byte*)(iVar4 + 0xbb), (uint) * (byte*)(iVar4 + 0xba), 1,
                             (int)(lbl_803E3F30 * fVar1), 0, 0);
            }
        }
        FUN_80294c60(param_2, &local_50, &local_54);
        local_34 = 0;
        local_32 = 0;
        local_30 = 0;
        local_2c = lbl_803E3F20;
        if (local_50 == 0x87)
        {
            iVar4 = (int)(lbl_803E3F38 * (local_54 / lbl_803E3F30));
            local_18 = (longlong)iVar4;
            local_2e = 0x15 - (short)iVar4;
            local_28 = lbl_803E3F3C * (local_54 / lbl_803E3F40 - lbl_803E3F2C);
            local_34 = 0xc94;
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &local_34, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &local_34, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &local_34, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &local_34, 2, -1, NULL);
            local_2e = 9;
            local_2c = lbl_803E3F48 * (local_54 / lbl_803E3F40) + lbl_803E3F44;
            local_24 = lbl_803E3F4C;
            local_34 = 0xc0e;
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b3, &local_34, 2, -1, NULL);
        }
        else if (local_50 < 0x87)
        {
            if (local_50 == 0x7f)
            {
                local_2c = lbl_803E3F58;
                local_2e = 10;
                local_24 = lbl_803E3F54;
                local_28 = lbl_803E3F50;
                local_34 = 0xc0e;
                (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b3, &local_34, 2, -1, NULL);
            }
            else if (local_50 < 0x7f)
            {
                if ((local_50 == 0x43) && (lbl_803E3F4C < local_54))
                {
                    iVar4 = (int)(lbl_803E3F38 * (local_54 / lbl_803E3F30));
                    local_18 = (longlong)iVar4;
                    local_2e = (short)iVar4 + 6;
                    local_28 = lbl_803E3F3C * (local_54 / lbl_803E3F40 - lbl_803E3F2C);
                    local_34 = 0xc94;
                    (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b4, &local_34, 2, -1, NULL);
                    (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b4, &local_34, 2, -1, NULL);
                    local_2e = 9;
                    local_2c = lbl_803E3F48 * (local_54 / lbl_803E3F40) + lbl_803E3F44;
                    local_24 = lbl_803E3F4C;
                    local_34 = 0xc0e;
                    (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b3, &local_34, 2, -1, NULL);
                }
            }
            else if (local_50 == 0x85)
            {
                if (lbl_803E3F4C < local_54)
                {
                    uVar3 = FUN_80017690(0xc55);
                    if (uVar3 == 0)
                    {
                        fVar1 = local_54 / lbl_803E3F40;
                        iVar4 = (int)(lbl_803E3F38 * fVar1);
                        local_2e = (short)iVar4;
                        local_34 = 0xc94;
                    }
                    else
                    {
                        fVar1 = local_54 / lbl_803E3F50;
                        iVar4 = (int)(lbl_803E3F38 * fVar1);
                        local_2e = (short)iVar4;
                        local_34 = 0xc75;
                    }
                    local_18 = (longlong)iVar4;
                    local_28 = lbl_803E3F5C * (lbl_803E3F28 - fVar1);
                    local_2e = 0x15 - local_2e;
                    (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &local_34, 2, -1, NULL);
                    (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &local_34, 2, -1, NULL);
                    (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &local_34, 2, -1, NULL);
                    (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &local_34, 2, -1, NULL);
                    local_2e = 9;
                    uVar3 = FUN_80017690(0xc55);
                    if (uVar3 == 0)
                    {
                        local_34 = 0xc0e;
                        fVar1 = lbl_803E3F40;
                    }
                    else
                    {
                        local_34 = 0xc75;
                        fVar1 = lbl_803E3F50;
                    }
                    local_2c = lbl_803E3F48 * (local_54 / fVar1) + lbl_803E3F44;
                    local_24 = lbl_803E3F4C;
                    (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b3, &local_34, 2, -1, NULL);
                }
            }
            else if (0x84 < local_50)
            {
                uVar3 = FUN_80017690(0xc55);
                if (uVar3 == 0)
                {
                    local_34 = 0xc0e;
                }
                else
                {
                    local_34 = 0xc75;
                }
                fVar1 = *(float*)(param_2 + 0x98);
                if (lbl_803E3F68 <= fVar1)
                {
                    if (fVar1 < lbl_803E3F70)
                    {
                        local_28 = lbl_803E3F5C * (lbl_803E3F74 * (fVar1 - lbl_803E3F68) - lbl_803E3F2C);
                        local_2e = 9;
                        local_2c = lbl_803E3F20;
                        local_24 = lbl_803E3F4C;
                        (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b3, &local_34, 2, -1, NULL);
                    }
                }
                else
                {
                    local_28 = lbl_803E3F6C;
                    local_2e = 9;
                    local_2c = lbl_803E3F20;
                    local_24 = lbl_803E3F4C;
                    (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b3, &local_34, 2, -1, NULL);
                }
            }
        }
        else if (local_50 == 0x468)
        {
            if (lbl_803E3F4C < local_54)
            {
                iVar4 = (int)(lbl_803E3F38 * (local_54 / lbl_803E3F60));
                local_18 = (longlong)iVar4;
                local_46 = 0x15 - (short)iVar4;
                local_4c[0] = 0xc95;
                FUN_80294c48(*(int*)&((GameObject*)param_1)->ownerObj, &local_58);
                local_28 = *(float*)(local_58 + 0xc);
                local_24 = *(float*)(local_58 + 0x10);
                local_20 = *(undefined4*)(local_58 + 0x14);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)param_1)->ownerObj, 0x7b9, &local_34,
                                                 0x200001, -1, local_4c);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)param_1)->ownerObj, 0x7b9, &local_34,
                                                 0x200001, -1, local_4c);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)param_1)->ownerObj, 0x7b9, &local_34,
                                                 0x200001, -1, local_4c);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)param_1)->ownerObj, 0x7b9, &local_34,
                                                 0x200001, -1, local_4c);
                local_46 = 9;
                local_4c[0] = 0xc95;
                local_44 = lbl_803E3F64 * (local_54 / lbl_803E3F60) + lbl_803E3F44;
                local_28 = *(float*)(local_58 + 0xc);
                local_24 = *(float*)(local_58 + 0x10);
                local_20 = *(undefined4*)(local_58 + 0x14);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)param_1)->ownerObj, 0x7ba, &local_34,
                                                 0x200001, -1, local_4c);
            }
        }
        else if (local_50 < 0x468)
        {
            if (local_50 < 0x89)
            {
                local_2e = 0x23;
                local_24 = lbl_803E3F4C;
                local_28 = lbl_803E3F50;
                local_34 = 0xc0e;
                (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b3, &local_34, 2, -1, NULL);
                local_2e = 0x12;
                local_24 = lbl_803E3F54;
                (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b3, &local_34, 2, -1, NULL);
            }
        }
        else if ((local_50 == 0x46f) && (lbl_803E3F4C < local_54))
        {
            iVar4 = (int)(lbl_803E3F38 * (local_54 / lbl_803E3F60));
            local_18 = (longlong)iVar4;
            local_2e = 0x15 - (short)iVar4;
            local_28 = lbl_803E3F5C * (lbl_803E3F28 - local_54 / lbl_803E3F60);
            local_34 = 0xc94;
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &local_34, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &local_34, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &local_34, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b2, &local_34, 2, -1, NULL);
            local_2e = 9;
            local_2c = lbl_803E3F48 * (local_54 / lbl_803E3F60) + lbl_803E3F44;
            local_24 = lbl_803E3F4C;
            local_34 = 0xc0e;
            (*gPartfxInterface)->spawnObject((void*)param_1, 0x7b3, &local_34, 2, -1, NULL);
        }
    }
    return;
}

void FUN_8016d994(int param_1, undefined param_2, undefined param_3)
{
    int iVar1;

    iVar1 = *(int*)&((GameObject*)param_1)->extra;
    *(undefined*)(iVar1 + 0xbb) = param_2;
    *(undefined*)(iVar1 + 0xba) = param_3;
    return;
}

void FUN_8016e8cc(undefined8 param_1, undefined8 param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  int param_9)
{
    short sVar1;
    int iVar2;
    int* piVar3;
    uint uVar4;
    int iVar5;
    int* piVar6;
    double dVar7;
    double dVar8;
    undefined8 local_18;

    piVar6 = ((GameObject*)param_9)->extra;
    iVar2 = FUN_80017a54(param_9);
    *(ushort*)(iVar2 + 0x18) = *(ushort*)(iVar2 + 0x18) & ~0x8;
    FUN_8002fc3c((double)(float)piVar6[0x14], (double)lbl_803DC074);
    iVar2 = 3;
    piVar3 = piVar6;
    do
    {
        if ((*(byte*)(piVar3 + 5) & 2) != 0)
        {
            uVar4 = (uint) * (ushort*)(piVar3 + 3);
            iVar5 = *piVar3 + uVar4 * 0x14;
            for (; (int)uVar4 < (int)(uint) * (ushort*)((int)piVar3 + 0xe); uVar4 = uVar4 + 2)
            {
                if (piVar3 == (int*)piVar6[0x12])
                {
                    param_3 = (double)lbl_803E3F8C;
                    dVar7 = (double)(float)(param_3 *
                        (double)((lbl_803E3FA4 * (float)piVar6[0x26] -
                            *(float*)(iVar5 + 0xc)) * lbl_803E3FA8));
                    dVar8 = (double)lbl_803E3F4C;
                    if ((dVar8 <= dVar7) && (dVar8 = dVar7, param_3 < dVar7))
                    {
                        dVar8 = param_3;
                    }
                    *(short*)(iVar5 + 0x10) = (short)(int)(param_3 - dVar8);
                    *(undefined2*)(iVar5 + 0x24) = *(undefined2*)(iVar5 + 0x10);
                }
                else
                {
                    param_3 = (double)lbl_803E3FC4;
                    *(short*)(iVar5 + 0x10) =
                        (short)(int)-(float)(param_3 * (double)lbl_803DC074 -
                            (double)(f32)(s32)((int)*(short*)(iVar5 + 0x10)));
                    *(undefined2*)(iVar5 + 0x24) = *(undefined2*)(iVar5 + 0x10);
                }
                sVar1 = *(short*)(iVar5 + 0x10);
                if (sVar1 < 0)
                {
                    sVar1 = 0;
                }
                else if (0xff < sVar1)
                {
                    sVar1 = 0xff;
                }
                *(short*)(iVar5 + 0x10) = sVar1;
                sVar1 = *(short*)(iVar5 + 0x24);
                if (sVar1 < 0)
                {
                    sVar1 = 0;
                }
                else if (0xff < sVar1)
                {
                    sVar1 = 0xff;
                }
                *(short*)(iVar5 + 0x24) = sVar1;
                if ((*(short*)(iVar5 + 0x10) < 1) && (*(short*)(iVar5 + 0x24) < 1))
                {
                    *(short*)((int)piVar3 + 0x12) = *(short*)((int)piVar3 + 0x12) + -2;
                    *(short*)(piVar3 + 3) = *(short*)(piVar3 + 3) + 2;
                }
                iVar5 = iVar5 + 0x28;
            }
            if ((piVar3 != (int*)piVar6[0x12]) && (*(short*)((int)piVar3 + 0x12) == 0))
            {
                *(byte*)(piVar3 + 5) = *(byte*)(piVar3 + 5) & 0xfd;
            }
        }
        piVar3 = piVar3 + 6;
        iVar2 = iVar2 + -1;
    }
    while (iVar2 != 0);
    FUN_8016d188(param_9, *(int*)&((GameObject*)param_9)->ownerObj);
    FUN_80294d6c(*(int*)&((GameObject*)param_9)->ownerObj);
    *(undefined*)((int)piVar6 + 0xb9) = 0;
    if (DAT_803ad338 != '\0')
    {
        DAT_803ad324 = DAT_803ad324 + lbl_803E3F78;
        ObjHitbox_SetSphereRadius(DAT_803ad334, (short)(int)DAT_803ad324);
        ObjHits_SetHitVolumeSlot(DAT_803ad334, 0x11, 5, 0);
        DAT_803ad330 = DAT_803ad330 + lbl_803E3F7C;
        dVar8 = (double)DAT_803ad330;
        DAT_803ad328 = DAT_803ad328 * lbl_803E3F80;
        DAT_803ad32c = DAT_803ad32c * lbl_803E3F84;
        ((GameObject*)DAT_803ad334)->anim.alpha = (char)(int)DAT_803ad330;
        ((GameObject*)DAT_803ad334)->anim.rootMotionScale = ((GameObject*)DAT_803ad334)->anim.rootMotionScale +
            lbl_803E3F88;
        if ((double)DAT_803ad330 < (double)lbl_803E3F20)
        {
            DAT_803ad338 = '\0';
            FUN_80017ac8((double)DAT_803ad330, dVar8, param_3, param_4, param_5, param_6, param_7, param_8,
                         DAT_803ad334);
            DAT_803ad334 = 0;
        }
    }
    return;
}

void FUN_80170048(void)
{
    float fVar1;
    uint uVar2;
    int iVar3;
    int* piVar4;
    uint uVar5;
    int iVar6;
    int* piVar7;
    int* piVar8;
    float* pfVar9;
    double dVar10;
    double dVar11;
    double dVar12;
    double dVar13;
    double dVar14;
    undefined8 uVar15;
    undefined8 local_78;
    undefined8 local_70;

    uVar15 = FUN_80286838();
    uVar2 = (uint)((ulonglong)uVar15 >> 0x20);
    pfVar9 = (float*)&DAT_80321678;
    piVar7 = *(int**)(uVar2 + 0xb8);
    iVar3 = FUN_80017a98();
    iVar6 = 0;
    if (iVar3 != 0)
    {
        iVar6 = FUN_80294cf8(iVar3);
    }
    fVar1 = lbl_803E4064;
    switch ((uint)uVar15 & 0xff)
    {
    case 0:
        if (*piVar7 != 0)
        {
            FUN_800175cc((double)lbl_803E4040, *piVar7, '\0');
        }
        fVar1 = lbl_803E4048;
        if (lbl_803E4044 != (float)piVar7[2])
        {
            piVar7[4] = (int)lbl_803E4048;
            piVar7[1] = (int)fVar1;
            if (iVar6 != 0)
            {
                FUN_8016d994(iVar6, 7, 0);
            }
        }
        piVar7[2] = (int)lbl_803E4044;
        piVar7[3] = (int)lbl_803E404C;
        FUN_80006810(uVar2, 0x42c);
        FUN_80006810(uVar2, 0x42d);
        break;
    case 1:
        if (lbl_803E4044 == (float)piVar7[2])
        {
            if (iVar6 != 0)
            {
                FUN_8016d994(iVar6, 7, 8);
            }
            if (*piVar7 == 0)
            {
                piVar4 = FUN_80017624(0, '\x01');
                *piVar7 = (int)piVar4;
            }
            if (*piVar7 != 0)
            {
                FUN_800175b0(*piVar7, 2);
                FUN_800175ec((double)*(float*)(uVar2 + 0xc),
                             (double)(*(float*)(uVar2 + 0x10) - lbl_803E4050),
                             (double)*(float*)(uVar2 + 0x14), (int*)*piVar7);
                FUN_8001759c(*piVar7, 0, 0xff, 0xff, 0xff);
                FUN_80017588(*piVar7, 0, 0xff, 0xff, 0xff);
                FUN_800175d0((double)lbl_803E4054, (double)lbl_803E4058, *piVar7);
                FUN_800175bc(*piVar7, 1);
                FUN_800175cc((double)lbl_803E4044, *piVar7, '\x01');
                FUN_8001753c(*piVar7, 0, 0);
                FUN_800175d8(*piVar7, 1);
            }
            fVar1 = lbl_803E4044;
            if (lbl_803E4044 == (float)piVar7[2])
            {
                piVar7[4] = (int)lbl_803E4048;
                piVar7[1] = (int)fVar1;
            }
            piVar7[2] = (int)lbl_803E4048;
            dVar12 = (double)lbl_803E405C;
            piVar7[3] = (int)lbl_803E405C;
            iVar3 = 0;
            piVar8 = &DAT_80321688;
            dVar11 = (double)lbl_803E4040;
            dVar14 = (double)lbl_803E4060;
            piVar4 = piVar7;
            dVar13 = DOUBLE_803e4068;
            do
            {
                *(undefined2*)(piVar4 + 0xd) = 0xc000;
                dVar10 = (double)fcos16Precise();
                piVar7[9] = (int)(*pfVar9 * (float)((double)(float)(dVar12 + dVar10) * dVar11));
                piVar7[5] = *piVar8;
                uVar5 = randomGetRange(0x78, 0x7f);
                local_78 = (double)CONCAT44(0x43300000, iVar3 * uVar5 ^ 0x80000000);
                *(short*)(piVar4 + 0xf) = (short)(int)(dVar14 + (double)(float)(local_78 - dVar13));
                piVar4 = (int*)((int)piVar4 + 2);
                pfVar9 = pfVar9 + 1;
                piVar7 = piVar7 + 1;
                piVar8 = piVar8 + 1;
                iVar3 = iVar3 + 1;
            }
            while (iVar3 < 4);
            FUN_80006824(uVar2, 0x42c);
            FUN_80006824(uVar2, 0x42d);
        }
        break;
    case 2:
        if (iVar6 != 0)
        {
            FUN_8016d994(iVar6, 7, 0);
        }
        if (lbl_803E4044 != (float)piVar7[2])
        {
            piVar7[4] = (int)lbl_803E4064;
        }
        piVar7[2] = (int)lbl_803E4044;
        piVar7[3] = (int)lbl_803E404C;
        if (*piVar7 != 0)
        {
            FUN_800175cc((double)lbl_803E4040, *piVar7, '\0');
        }
        FUN_80006810(uVar2, 0x42c);
        FUN_80006810(uVar2, 0x42d);
        break;
    case 3:
        if (iVar6 != 0)
        {
            FUN_8016d994(iVar6, 7, 8);
        }
        if (*piVar7 == 0)
        {
            piVar4 = FUN_80017624(0, '\x01');
            *piVar7 = (int)piVar4;
        }
        if (*piVar7 != 0)
        {
            FUN_800175b0(*piVar7, 2);
            FUN_800175ec((double)*(float*)(uVar2 + 0xc),
                         (double)(*(float*)(uVar2 + 0x10) - lbl_803E4050),
                         (double)*(float*)(uVar2 + 0x14), (int*)*piVar7);
            FUN_8001759c(*piVar7, 0, 0xff, 0xff, 0xff);
            FUN_80017588(*piVar7, 0, 0xff, 0xff, 0xff);
            FUN_800175d0((double)lbl_803E4054, (double)lbl_803E4058, *piVar7);
            FUN_800175bc(*piVar7, 1);
            FUN_800175cc((double)lbl_803E4044, *piVar7, '\x01');
            FUN_8001753c(*piVar7, 0, 0);
            FUN_800175d8(*piVar7, 1);
        }
        if (lbl_803E4044 == (float)piVar7[2])
        {
            piVar7[4] = (int)lbl_803E4064;
        }
        piVar7[2] = (int)lbl_803E4064;
        dVar14 = (double)lbl_803E405C;
        piVar7[3] = (int)lbl_803E405C;
        iVar3 = 0;
        piVar8 = &DAT_80321688;
        dVar13 = (double)lbl_803E4040;
        piVar4 = piVar7;
        do
        {
            *(undefined2*)(piVar7 + 0xd) = 0;
            dVar11 = (double)fcos16Precise();
            piVar4[9] = (int)(*pfVar9 * (float)((double)(float)(dVar14 + dVar11) * dVar13));
            piVar4[5] = *piVar8;
            piVar7 = (int*)((int)piVar7 + 2);
            pfVar9 = pfVar9 + 1;
            piVar4 = piVar4 + 1;
            piVar8 = piVar8 + 1;
            iVar3 = iVar3 + 1;
        }
        while (iVar3 < 4);
        FUN_80006824(uVar2, 0x42d);
        FUN_80006824(uVar2, 0x42c);
        break;
    case 4:
        piVar7[2] = (int)lbl_803E4064;
        dVar14 = (double)lbl_803E405C;
        piVar7[3] = (int)lbl_803E405C;
        piVar7[4] = (int)fVar1;
        iVar3 = 0;
        pfVar9 = (float*)&DAT_80321698;
        piVar8 = &DAT_803216a8;
        dVar11 = (double)lbl_803E4040;
        dVar12 = (double)lbl_803E4060;
        piVar4 = piVar7;
        dVar13 = DOUBLE_803e4068;
        do
        {
            *(undefined2*)(piVar7 + 0xd) = 0xc000;
            dVar10 = (double)fcos16Precise();
            piVar4[9] = (int)(*pfVar9 * (float)((double)(float)(dVar14 + dVar10) * dVar11));
            piVar4[5] = *piVar8;
            uVar5 = randomGetRange(0x78, 0x7f);
            local_70 = (double)CONCAT44(0x43300000, iVar3 * uVar5 ^ 0x80000000);
            *(short*)(piVar7 + 0xf) = (short)(int)(dVar12 + (double)(float)(local_70 - dVar13));
            piVar7 = (int*)((int)piVar7 + 2);
            pfVar9 = pfVar9 + 1;
            piVar4 = piVar4 + 1;
            piVar8 = piVar8 + 1;
            iVar3 = iVar3 + 1;
        }
        while (iVar3 < 4);
        FUN_80006824(uVar2, 0x42d);
        FUN_80006824(uVar2, 0x42c);
        break;
    case 5:
        piVar7[2] = (int)lbl_803E4044;
        piVar7[3] = (int)lbl_803E404C;
        piVar7[4] = (int)lbl_803E4064;
        FUN_80006810(uVar2, 0x42c);
        FUN_80006810(uVar2, 0x42d);
        break;
    case 6:
        iVar3 = 0;
        pfVar9 = (float*)&DAT_80321698;
        piVar8 = &DAT_803216a8;
        dVar13 = (double)lbl_803E405C;
        dVar14 = (double)lbl_803E4040;
        piVar4 = piVar7;
        do
        {
            *(undefined2*)(piVar7 + 0xd) = 0x4000;
            dVar11 = (double)fcos16Precise();
            piVar4[9] = (int)(*pfVar9 * (float)((double)(float)(dVar13 + dVar11) * dVar14));
            piVar4[5] = *piVar8;
            piVar7 = (int*)((int)piVar7 + 2);
            pfVar9 = pfVar9 + 1;
            piVar4 = piVar4 + 1;
            piVar8 = piVar8 + 1;
            iVar3 = iVar3 + 1;
        }
        while (iVar3 < 4);
        break;
    case 7:
        if (iVar6 != 0)
        {
            FUN_8016d994(iVar6, 7, 0);
        }
        if (*piVar7 != 0)
        {
            FUN_800175cc((double)lbl_803E4040, *piVar7, '\0');
        }
        fVar1 = lbl_803E4044;
        piVar7[2] = (int)lbl_803E4044;
        piVar7[3] = (int)fVar1;
        piVar7[4] = (int)fVar1;
        piVar7[1] = (int)fVar1;
        *(byte*)(piVar7 + 0x17) = *(byte*)(piVar7 + 0x17) | 1;
        *(byte*)((int)piVar7 + 0x5d) = *(byte*)((int)piVar7 + 0x5d) | 1;
        *(byte*)((int)piVar7 + 0x5e) = *(byte*)((int)piVar7 + 0x5e) | 1;
        *(byte*)((int)piVar7 + 0x5f) = *(byte*)((int)piVar7 + 0x5f) | 1;
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
    short sVar1;
    char cVar2;
    uint uVar3;
    int iVar4;
    int iVar5;
    int iVar6;
    undefined8 uVar7;

    iVar6 = *(int*)&((GameObject*)param_9)->extra;
    iVar5 = *(int*)&((GameObject*)param_9)->anim.placementData;
    iVar4 = (int)((GameObject*)param_9)->anim.modelInstance->extraSetupData;
    FUN_80017a98();
    FUN_80017a90();
    FUN_80017a98();
    FUN_80017a90();
    uVar7 = ObjHits_DisableObject(param_9);
    if ((*(ushort*)&((GameObject*)param_9)->anim.flags & 0x2000) != 0)
    {
        *(float*)(iVar6 + 8) = lbl_803E40E8;
        if (((GameObject*)param_9)->anim.modelState != NULL)
        {
            ((GameObject*)param_9)->anim.modelState->flags = OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        }
    }
    if ((int)*(short*)(iVar6 + 0x10) != 0xffffffff)
    {
        FUN_80017698((int)*(short*)(iVar6 + 0x10), 1);
        uVar7 = FUN_800e842c(param_9);
    }
    uVar3 = (uint) * (short*)(iVar5 + 0x1e);
    if (uVar3 != 0xffffffff)
    {
        uVar7 = FUN_80017698(uVar3, 1);
    }
    uVar3 = (uint) * (short*)(iVar5 + 0x2c);
    if (0 < (int)uVar3)
    {
        FUN_80017688(uVar3);
    }
    sVar1 = *(short*)(iVar4 + 2);
    if (sVar1 == 4)
    {
        sVar1 = ((GameObject*)param_9)->anim.seqId;
        if (sVar1 == 0x3cd)
        {
            iVar4 = FUN_80017a98();
            FUN_80294d60(uVar7, param_2, param_3, param_4, param_5, param_6, param_7, param_8, iVar4, 2);
            uVar3 = FUN_80017a98();
            FUN_80006824(uVar3, SFXen_treadlpc);
            FUN_80081118((double)lbl_803E40EC, param_9, 1, 0x28);
        }
        else if ((sVar1 < 0x3cd) && (sVar1 == 0xb))
        {
            uVar3 = FUN_80017a98();
            uVar7 = FUN_80006824(uVar3, SFXen_treadlpc);
            iVar4 = FUN_80017a98();
            FUN_80294d60(uVar7, param_2, param_3, param_4, param_5, param_6, param_7, param_8, iVar4, 4);
            FUN_80081118((double)lbl_803E40EC, param_9, 3, 0x28);
        }
        else
        {
            uVar3 = FUN_80017a98();
            FUN_80006824(uVar3, SFXen_waterblock_stop);
            FUN_80081118((double)lbl_803E40EC, param_9, 0xff, 0x28);
        }
    }
    else if ((sVar1 < 4) && (sVar1 == 1))
    {
        sVar1 = ((GameObject*)param_9)->anim.seqId;
        if (sVar1 == 0x319)
        {
            FUN_80006824(param_9, SFXwp_gprop2_c);
            FUN_80017698(0x3e9, 1);
            *(undefined2*)(iVar6 + 0x3c) = 0x4b0;
            FUN_80081118((double)lbl_803E40EC, param_9, 0xff, 0x28);
        }
        else
        {
            if (sVar1 < 0x319)
            {
                if (sVar1 == 0x5a)
                {
                    FUN_80006824(param_9, SFXen_treadlpc);
                    FUN_80081118((double)lbl_803E40EC, param_9, 2, 0x28);
                    goto LAB_801725bc;
                }
                if ((sVar1 < 0x5a) && (sVar1 == 0x22))
                {
                    FUN_80006824(param_9, SFXen_treadlpc);
                    FUN_80081118((double)lbl_803E40EC, param_9, 0xff, 0x28);
                    goto LAB_801725bc;
                }
            }
            else if (sVar1 == 0x6a6)
            {
                uVar3 = FUN_80017690(0x86a);
                cVar2 = (char)uVar3;
                if (cVar2 < '\a')
                {
                    cVar2 = cVar2 + '\x01';
                }
                FUN_80017698(0x86a, (int)cVar2);
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











void gcbaddieshield_free(void)
{
}

void gcbaddieshield_hitDetect(void)
{
}

void gcbaddieshield_release(void)
{
}

void gcbaddieshield_initialise(void)
{
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

void shield_hitDetect(void);

void shield_release(void);

void shield_initialise(void);

void shield_free(int obj);












int gcbaddieshield_getExtraSize(void) { return 0x8; }
int gcbaddieshield_getObjectTypeId(void) { return 0x0; }
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




void gcbaddieshield_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
    {
        switch (((GameObject*)obj)->unkF4)
        {
        case 0:
            objRenderFn_8003b8f4(lbl_803E31F8);
            break;
        default:
            break;
        }
    }
}

void flamethrowerspe_render(void);
void fn_801719F8(void) { objRenderFn_8003b8f4(lbl_803E3420); }


void flamethrowerspe_func0B(int* obj);



void staff_modelMtxFn(int* obj, int p4, int p5);




void gcbaddieshield_init(int* obj, void* initData)
{
    int v = *(s16*)((char*)initData + 0x1a);
    *(f32*)((int**)obj)[0xb8 / 4] = (f32)v;
}



void gcbaddieshield_update(int* obj)
{
    extern void Obj_FreeObject(int* obj); /* #57 */
    f32* state = ((GameObject*)obj)->extra;
    state[0] = state[0] - timeDelta;
    if (state[0] <= lbl_803E31FC)
    {
        Obj_FreeObject(obj);
        return;
    }
    *(s16*)obj = (s16)(*(s16*)obj + (s32)(lbl_803E3200 * timeDelta));
    ((GameObject*)obj)->anim.rotZ = (s16)(((GameObject*)obj)->anim.rotZ + (s32)(lbl_803E3204 * timeDelta));
    if (state[0] <= lbl_803E3208)
    {
        ((GameObject*)obj)->anim.alpha = (u8)(s32)(lbl_803E320C * (state[0] * lbl_803E3210));
    }
    else
    {
        ((GameObject*)obj)->anim.alpha = 0xff;
    }
}

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

