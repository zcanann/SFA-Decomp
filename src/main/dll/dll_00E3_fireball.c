/* DLL 0xE3 — fireball / kaldachom spit / pollen-fragment objects [8016984C-801713AC) */
#include "main/dll/xyzanimator.h"
#include "main/dll/genpropswgpipe_struct.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"



extern u32 randomGetRange(int min, int max);
extern undefined4 ObjHitbox_SetSphereRadius();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 FUN_8003b818();


/* pollenfragment extra block (head; timers at 0x20/0x24 stay raw addr args). */



extern EffectInterface** gPartfxInterface;

/*
 * --INFO--
 *
 * Function: kaldachompspit_render
 * EN v1.0 Address: 0x8016984C
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x80169CF8
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: kaldachompspit_init
 * EN v1.0 Address: 0x80169CC4
 * EN v1.0 Size: 552b
 * EN v1.1 Address: 0x8016A170
 * EN v1.1 Size: 560b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void modelLightStruct_setLightKind(int light, int value);
extern void modelLightStruct_setPosition(int light, f32 x, f32 y, f32 z);
extern void modelLightStruct_setupGlow(int light, int a, int r, int g, int b, int alpha, f32 radius);
extern void modelLightStruct_setDistanceAttenuation(int light, f32 near, f32 far);
extern void lightSetField4D(int light, int v);
extern void modelLightStruct_setEnabled(int light, int enabled, f32 scale);



#pragma dont_inline on
#pragma dont_inline reset


/*
 * --INFO--
 *
 * Function: pollenfragment_init
 * EN v1.0 Address: 0x8016B0A4
 * EN v1.0 Size: 208b
 * EN v1.1 Address: 0x8016ACA4
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_8016b228
 * EN v1.0 Address: 0x8016B228
 * EN v1.0 Size: 512b
 * EN v1.1 Address: 0x8016AE70
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/* Trivial 4b 0-arg blr leaves. */










void mikabomb_hitDetect(void);







void mikabomb_free(int obj, int mode);

/* 8b "li r3, N; blr" returners. */
int mikabomb_getExtraSize(void);
int mikabomb_getObjectTypeId(void);

/* render-with-objRenderFn_8003b8f4 pattern. */
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



/* ==== v1.0 recovered functions (drift additions) ==== */



extern f32 timeDelta;
extern u8 framesThisStep;
extern f32 sqrtf(f32 x);
extern int getAngle(f32 a, f32 b);






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





typedef struct FireballPlacement
{
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x2C - 0x22];
    s16 unk2C;
    u8 pad2E[0x30 - 0x2E];
} FireballPlacement;






















typedef struct FireballState
{
    u8 pad0[0x4 - 0x0];
    f32 unk4;
    f32 unk8;
    f32 unkC;
    s32 unk10;
    u8 pad14[0x18 - 0x14];
    u8 unk18;
    u8 pad19[0x24 - 0x19];
    f32 posX;
    s32 posY;
    f32 posZ;
    f32 flightDuration;
    f32 elapsedTime;
    f32 fadeoutTimer;
    f32 startupDelay;
    s16 unk40;
    s16 unk42;
    u8 pad44[0x46 - 0x44];
    u16 spiralPhase;
    u8 pad48[0x50 - 0x48];
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
    u8 stateFlags;
    u8 colorIndex;
    u8 pad72[0x94 - 0x72];
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
} FireballState;


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
extern undefined4 ObjHits_ClearHitVolumes();
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


/*
 * --INFO--
 *
 * Function: staticCamera_free
 * EN v1.0 Address: 0x8016BAC4
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x8016BD54
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void staticCamera_free(int param_1)
{
    ObjGroup_RemoveObject(param_1, 7);
    return;
}

/*
 * --INFO--
 *
 * Function: staticCamera_render
 * EN v1.0 Address: 0x8016BAE8
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8016BD78
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void staticCamera_render(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
    if (visible != 0)
    {
        FUN_8003b818(param_1);
    }
    return;
}

/*
 * --INFO--
 *
 * Function: staticCamera_init
 * EN v1.0 Address: 0x8016BB10
 * EN v1.0 Size: 168b
 * EN v1.1 Address: 0x8016BDB0
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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


/*
 * --INFO--
 *
 * Function: FUN_8016d188
 * EN v1.0 Address: 0x8016D188
 * EN v1.0 Size: 2060b
 * EN v1.1 Address: 0x8016D394
 * EN v1.1 Size: 2820b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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

/*
 * --INFO--
 *
 * Function: FUN_8016d994
 * EN v1.0 Address: 0x8016D994
 * EN v1.0 Size: 16b
 * EN v1.1 Address: 0x8016DE98
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016d994(int param_1, undefined param_2, undefined param_3)
{
    int iVar1;

    iVar1 = *(int*)&((GameObject*)param_1)->extra;
    *(undefined*)(iVar1 + 0xbb) = param_2;
    *(undefined*)(iVar1 + 0xba) = param_3;
    return;
}


/*
 * --INFO--
 *
 * Function: FUN_8016e8cc
 * EN v1.0 Address: 0x8016E8CC
 * EN v1.0 Size: 1068b
 * EN v1.1 Address: 0x8016F0A8
 * EN v1.1 Size: 756b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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


/*
 * --INFO--
 *
 * Function: FUN_80170048
 * EN v1.0 Address: 0x80170048
 * EN v1.0 Size: 2352b
 * EN v1.1 Address: 0x8017082C
 * EN v1.1 Size: 1804b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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


/*
 * --INFO--
 *
 * Function: checkpoint4_render
 * EN v1.0 Address: 0x80170F68
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x80171EA4
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern f32 lbl_803E3420;

void checkpoint4_render(int param_1);

/*
 * --INFO--
 *
 * Function: checkpoint4_init
 * EN v1.0 Address: 0x80170F88
 * EN v1.0 Size: 308b
 * EN v1.1 Address: 0x80171ED0
 * EN v1.1 Size: 392b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void checkpoint4_init(Checkpoint4Object* checkpoint, Checkpoint4Placement* placement);


/*
 * --INFO--
 *
 * Function: sideload_update
 * EN v1.0 Address: 0x801710BC
 * EN v1.0 Size: 352b
 * EN v1.1 Address: 0x80172058
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */



void mikabombshadow_update(int* obj);


void curve_init(ObjAnimComponent* obj, CurvePlacementParams* params);



/*
 * --INFO--
 *
 * Function: FUN_801713ac
 * EN v1.0 Address: 0x801713AC
 * EN v1.0 Size: 956b
 * EN v1.1 Address: 0x80172308
 * EN v1.1 Size: 744b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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
    iVar4 = *(int*)(*(int*)&((GameObject*)param_9)->anim.modelInstance + 0x18);
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

/* Trivial 4b 0-arg blr leaves. */
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

void fireball_release(void)
{
}

void fireball_initialise(void)
{
}

void flamethrowerspe_modelMtxFn(void);

void flamethrowerspe_free(void);

void flamethrowerspe_hitDetect(void);

void flamethrowerspe_release(void);

void flamethrowerspe_initialise(void);

void shield_hitDetect(void);

void shield_release(void);

void shield_initialise(void);

extern void ModelLightStruct_free(void* p);

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


/* 8b "li r3, N; blr" returners. */
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
int fireball_getExtraSize(void) { return 0x74; }
int fireball_getObjectTypeId(void) { return 0x0; }
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


/* Pattern wrappers. */
s16 staff_getHitReactValue(int* obj);
u8 fn_8016F16C(int* obj) { return *(u8*)((char*)((int**)obj)[0xb8 / 4] + 0x71); }
u8 collectible_func0F(int* obj);

/* 16b chained patterns. */
s32 staff_func16(int* obj);

/* render-with-objRenderFn_8003b8f4 pattern. */

void StaticCamera_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void baddieinterestp_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void curve_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void gcbaddieshield_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);

/* render-with-fn(lbl) (no visibility check). */
void flamethrowerspe_render(void);
void fn_801719F8(void) { objRenderFn_8003b8f4(lbl_803E3420); }

/* ObjGroup_RemoveObject(x, N) wrappers. */
void StaticCamera_free(int x);

/* misc 8b leaves */

/* misc 16b 4-insn patterns. */

void flamethrowerspe_func0B(int* obj);


/* state-byte setters / leaf writers. */
#pragma dont_inline on
#pragma dont_inline reset

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

void fireball_free(int* obj)
{
    int* inner = ((int**)obj)[0xb8 / 4];
    void* ptr = *(void**)inner;
    if (ptr != NULL)
    {
        ModelLightStruct_free(ptr);
    }
    (*gExpgfxInterface)->freeSource2((u32)obj);
    ObjGroup_RemoveObject((int)obj, 2);
}



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


extern void modelLightStruct_setEnabled(int handle, int flag, f32 v);
extern f32 lbl_803E3330;

int Fireball_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int i;
    int* state = ((GameObject*)obj)->extra;
    if (((FireballState*)state)->stateFlags & 8)
    {
        return 0;
    }
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        u8 cmd = animUpdate->eventIds[i];
        if (cmd == 1)
        {
            if (*(void**)state != NULL)
            {
                modelLightStruct_setEnabled(*(int*)state, 1, lbl_803E3330);
            }
            ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        }
        else if (cmd == 2)
        {
            if (*(void**)state != NULL)
            {
                modelLightStruct_setEnabled(*(int*)state, 0, lbl_803E3330);
            }
            ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        }
    }
    return 0;
}

extern int cmbsrc_getColorIndex(int* p);
extern void projectileParticleFxFn_80099660(int* obj, f32 v, int kind);
extern f32 lbl_803E3354;
extern f32 lbl_803E3358;

void fireball_hitDetect(int* obj)
{
    extern void modelLightStruct_setDiffuseColor(int* light, int r, int g, int b, int a); /* #57 */
    extern undefined4 ObjHits_EnableObject(); /* #57 */
    int* state = ((GameObject*)obj)->extra;
    int* target;
    if (((GameObject*)obj)->anim.seqId == 0x83e) return;
    if (((FireballState*)state)->stateFlags & 8) return;
    target = (int*)(*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->lastHitObject;
    if (target == NULL) return;
    if (*(s16*)((char*)target + 0x46) == 0x6e8)
    {
        int idx = cmbsrc_getColorIndex(target);
        if ((s8)idx != -1)
        {
            ((FireballState*)state)->colorIndex = (u8)idx;
            if (*(void**)state != NULL)
            {
                u8* pal = (u8*)lbl_80320978;
                int c = ((FireballState*)state)->colorIndex * 3;
                modelLightStruct_setDiffuseColor(*(int**)state, pal[c], pal[c + 1], pal[c + 2], 0);
            }
        }
        ObjHits_EnableObject(obj);
    }
    else
    {
        u8 v;
        ((FireballState*)state)->fadeoutTimer = lbl_803E3358;
        v = ((FireballState*)state)->colorIndex;
        if (v == 0)
        {
            projectileParticleFxFn_80099660(obj, lbl_803E3354, 3);
        }
        else if (v == 1)
        {
            projectileParticleFxFn_80099660(obj, lbl_803E3354, 0);
        }
        else
        {
            projectileParticleFxFn_80099660(obj, lbl_803E3354, 6);
        }
        ((GameObject*)obj)->anim.alpha = 0;
        if (*(void**)state != NULL)
        {
            ModelLightStruct_free(*(void**)state);
            *(void**)state = NULL;
        }
    }
    ObjGroup_RemoveObject((int)obj, 2);
}

extern void objSetSlot(int* obj, int slot);

void dim2roofrub_init(int* obj, int* params);


void animatedobj_init(int* obj, int* params);


void flamethrowerspe_update(int* obj);


void mikabomb_update(int* obj);

void mikabomb_init(int* obj);


#pragma opt_loop_invariants off
void baddieinterestp_update(int* obj);
#pragma opt_loop_invariants reset


#pragma opt_loop_invariants off
void animatedobj_update(int* obj);
#pragma opt_loop_invariants reset


void animatedobj_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);





void dim2roofrub_render(int* obj, int p2, int p3, int p4, int p5);


void dim2roofrub_update(int* obj);

extern void lightSetFieldBC_8001db14(int light, int v);
extern void modelLightStruct_setPosition(int light, f32 a, f32 b, f32 c);
extern void modelLightStruct_setDistanceAttenuation(int light, f32 a, f32 b);
extern void modelLightStruct_setupGlow(int light, int a, int r, int g, int b, int e, f32 f);
extern void modelLightStruct_setGlowProjectionRadius(int light, f32 a);
extern void modelLightStruct_setLightKind(int light, int v);
extern f32 lbl_803E3378;
extern f32 lbl_803E337C;
extern f32 lbl_803E3380;

void fireball_init(int* obj)
{
    extern int objCreateLight(int* obj, int arg); /* #57 */
    extern void modelLightStruct_setDiffuseColor(int* light, int r, int g, int b, int a); /* #57 */
    int* state = ((GameObject*)obj)->extra;
    int* params = *(int**)&((GameObject*)obj)->anim.placementData;

    if (((FireballPlacement*)params)->unk1C != 0)
    {
        ((FireballState*)state)->stateFlags |= 8;
    }
    else
    {
        u8* p;
        int i;
        ((FireballState*)state)->unk40 = (s16)randomGetRange(600, 900);
        ((FireballState*)state)->unk42 = (s16)randomGetRange(-600, 600);
        ((FireballState*)state)->colorIndex = 0;
        {
            int* r54 = *(int**)&((GameObject*)obj)->anim.hitReactState;
            if (r54 != NULL)
            {
                *(s16*)&((ObjHitsPriorityState*)r54)->trackContactMask = 257;
            }
        }
        if (*(void**)state == NULL)
        {
            *(int*)state = objCreateLight(obj, 1);
            if (*(void**)state != NULL)
            {
                int c;
                modelLightStruct_setLightKind(*(int*)state, 2);
                lightSetField4D(*(int*)state, 0);
                modelLightStruct_setPosition(*(int*)state, lbl_803E3330, lbl_803E3330, lbl_803E3330);
                lightSetFieldBC_8001db14(*(int*)state, 1);
                c = ((FireballState*)state)->colorIndex * 3;
                modelLightStruct_setDiffuseColor(*(int**)state, ((u8*)lbl_80320978)[c],
                                                 ((u8*)lbl_80320978 + 1)[c], ((u8*)lbl_80320978 + 2)[c], 0);
                modelLightStruct_setDistanceAttenuation(*(int*)state, lbl_803E3358, lbl_803E3378);
                c = ((FireballState*)state)->colorIndex * 3;
                modelLightStruct_setupGlow(*(int*)state, 0, ((u8*)lbl_80320978)[c], ((u8*)lbl_80320978 + 1)[c],
                                           ((u8*)lbl_80320978 + 2)[c], 32, lbl_803E337C);
                modelLightStruct_setGlowProjectionRadius(*(int*)state, lbl_803E337C);
            }
        }
        ((GameObject*)obj)->anim.alpha = 200;
        p = (u8*)state;
        for (i = 0; i < 5; i++)
        {
            *(u16*)(p + 0x48) = randomGetRange(-32767, 32767);
            *(u16*)(p + 0x52) = randomGetRange(-1024, 1024);
            *(u16*)(p + 0x5c) = randomGetRange(-32767, 32767);
            *(u16*)(p + 0x66) = randomGetRange(-1024, 1024);
            p += 2;
        }
        ((GameObject*)obj)->animEventCallback = (void*)Fireball_SeqFn;
        ObjGroup_AddObject((int)obj, 2);
        if (((GameObject*)obj)->anim.seqId != 2110 && ((FireballPlacement*)params)->unk1A != 0)
        {
            ((FireballState*)state)->startupDelay = lbl_803E3380;
        }
    }
}

extern f32 Vec3_Length(f32 * v);
extern int hitDetectFn_800658a4(int* obj, f32 x, f32 y, f32 z, f32* out, int flag);
extern WaterfxInterface** gWaterfxInterface;
extern f32 mathSinf(f32 v);
extern f32 mathCosf(f32 x);
extern void fn_8016F260(int* obj, int* state, int* other);
extern f32 lbl_803E3334;
extern f32 lbl_803E3338;
extern f32 lbl_803E333C;
extern f32 lbl_803E335C;
extern f32 lbl_803E3360;
extern f32 lbl_803E3364;
extern f32 lbl_803E3368;
extern f32 lbl_803E336C;

void fireball_update(int* obj)
{
    extern void Sfx_PlayFromObject(int* obj, int sfx); /* #57 */
    extern void Obj_FreeObject(int* obj); /* #57 */
    extern undefined8 ObjHits_DisableObject(); /* #57 */
    int* state = ((GameObject*)obj)->extra;
    int* other = *(int**)&((GameObject*)obj)->unkF8;
    int* params = *(int**)&((GameObject*)obj)->anim.placementData;

    if ((((FireballState*)state)->stateFlags & 8) != 0)
    {
        return;
    }
    ((FireballState*)state)->startupDelay -= timeDelta;
    if (((FireballState*)state)->startupDelay < *(f32*)&lbl_803E3330)
    {
        ((FireballState*)state)->startupDelay = lbl_803E3330;
    }
    if (((GameObject*)obj)->anim.seqId == 2110)
    {
        if (*(void**)state != NULL)
        {
            modelLightStruct_setEnabled(*(int*)state, 0, lbl_803E3330);
        }
        ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        return;
    }
    if (lbl_803E3330 == ((FireballState*)state)->elapsedTime)
    {
        ((FireballState*)state)->flightDuration = lbl_803E335C / Vec3_Length(&((GameObject*)obj)->anim.velocityX);
    }
    ((FireballState*)state)->elapsedTime += timeDelta;
    if (((FireballState*)state)->elapsedTime > ((FireballState*)state)->flightDuration)
    {
        ObjHits_SetHitVolumeSlot(obj, 14, *(s8*)((char*)params + 0x19) != 0 ? 3 : 1, 0);
    }
    if ((((FireballState*)state)->stateFlags & 1) == 0)
    {
        ((FireballState*)state)->posX = ((GameObject*)obj)->anim.localPosX;
        *(f32*)&((FireballState*)state)->posY = ((GameObject*)obj)->anim.localPosY;
        ((FireballState*)state)->posZ = ((GameObject*)obj)->anim.localPosZ;
        ((FireballState*)state)->stateFlags |= 1;
    }
    {
        int* r54 = *(int**)&((GameObject*)obj)->anim.hitReactState;
        if (((ObjHitsPriorityState*)r54)->contactFlags != 0)
        {
            if (*(s8*)&((ObjHitsPriorityState*)r54)->contactHitVolume != 14)
            {
                Sfx_PlayFromObject(obj, 179);
            }
            else
            {
                Sfx_PlayFromObject(obj, 186);
                (*gWaterfxInterface)->spawnSplashBurst(
                    obj, ((GameObject*)obj)->anim.localPosX,
                    ((GameObject*)obj)->anim.localPosY, ((GameObject*)obj)->anim.localPosZ,
                    lbl_803E3360);
                ((void (*)(f32, f32, f32, s16, f32, int))(*gWaterfxInterface)->spawnRipple)(
                    ((GameObject*)obj)->anim.localPosX,
                    ((GameObject*)obj)->anim.localPosY, ((GameObject*)obj)->anim.localPosZ,
                    *(s16*)obj, lbl_803E3330, 2);
            }
            {
                u8 v = ((FireballState*)state)->colorIndex;
                if (v == 0)
                {
                    projectileParticleFxFn_80099660(obj, lbl_803E3354, 3);
                }
                else if (v == 1)
                {
                    projectileParticleFxFn_80099660(obj, lbl_803E3354, 0);
                }
                else
                {
                    projectileParticleFxFn_80099660(obj, lbl_803E3354, 6);
                }
            }
            ((FireballState*)state)->fadeoutTimer = lbl_803E3358;
            ((GameObject*)obj)->anim.alpha = 0;
            if (*(void**)state != NULL)
            {
                ModelLightStruct_free(*(void**)state);
                *(int*)state = 0;
            }
            ObjGroup_RemoveObject((int)obj, 2);
            ObjHits_DisableObject(obj);
        }
    }
    if (((FireballState*)state)->fadeoutTimer != lbl_803E3330)
    {
        ((GameObject*)obj)->anim.velocityX = lbl_803E3330;
        ((GameObject*)obj)->anim.velocityY = lbl_803E3330;
        ((GameObject*)obj)->anim.velocityZ = lbl_803E3330;
        ObjHits_ClearHitVolumes(obj);
        ((FireballState*)state)->fadeoutTimer -= timeDelta;
        if (((FireballState*)state)->fadeoutTimer <= lbl_803E3330)
        {
            Obj_FreeObject(obj);
        }
    }
    else
    {
        ((GameObject*)obj)->anim.previousLocalPosX = ((GameObject*)obj)->anim.localPosX;
        ((GameObject*)obj)->anim.previousLocalPosY = ((GameObject*)obj)->anim.localPosY;
        ((GameObject*)obj)->anim.previousLocalPosZ = ((GameObject*)obj)->anim.localPosZ;
        if (other != NULL)
        {
            if ((((GameObject*)other)->objectFlags & 0x40) != 0)
            {
                ((GameObject*)obj)->unkF8 = 0;
            }
            else
            {
                fn_8016F260(obj, state, other);
            }
        }
        ((FireballState*)state)->posX += ((GameObject*)obj)->anim.velocityX * timeDelta;
        *(f32*)&((FireballState*)state)->posY += ((GameObject*)obj)->anim.velocityY * timeDelta;
        ((FireballState*)state)->posZ += ((GameObject*)obj)->anim.velocityZ * timeDelta;
        ((FireballState*)state)->spiralPhase += framesThisStep * 1500;
        if ((((FireballState*)state)->stateFlags & 4) != 0)
        {
            f32 ground;
            *(f32*)&((FireballState*)state)->posY -= lbl_803E3364 * timeDelta;
            if (hitDetectFn_800658a4(obj, ((FireballState*)state)->posX, *(f32*)&((FireballState*)state)->posY,
                                     ((FireballState*)state)->posZ, &ground, 0) == 0)
            {
                ground -= lbl_803E3368;
                if (ground < lbl_803E3330 && ground > lbl_803E336C)
                {
                    *(f32*)&((FireballState*)state)->posY -= ground;
                }
            }
        }
        ((GameObject*)obj)->anim.localPosX = ((FireballState*)state)->posX;
        ((GameObject*)obj)->anim.localPosY = *(f32*)&((FireballState*)state)->posY;
        ((GameObject*)obj)->anim.localPosZ = ((FireballState*)state)->posZ;
        if (other != NULL)
        {
            ((GameObject*)obj)->anim.localPosX += lbl_803E3334 *
                mathSinf(lbl_803E3338 * (f32)((FireballState*)state)->spiralPhase / lbl_803E333C);
            ((GameObject*)obj)->anim.localPosZ += lbl_803E3334 *
                mathCosf(lbl_803E3338 * (f32)((FireballState*)state)->spiralPhase / lbl_803E333C);
        }
        if ((((GameObject*)obj)->unkF4 -= framesThisStep) < 0)
        {
            Obj_FreeObject(obj);
        }
    }
}

extern u8 lbl_803DBD58[8];
extern void queueGlowRender(int light);
extern f32 lbl_803E3350;

void fireball_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    int* model;
    u8* state = ((GameObject*)obj)->extra;
    u16 savedRot4;
    u16 savedRot2;
    u8 i;
    f32 savedF8;
    s32 v = visible;
    if (v == 0)
    {
        return;
    }
    if ((((FireballState*)state)->stateFlags & 8) != 0)
    {
        return;
    }
    if (((FireballState*)state)->startupDelay == lbl_803E3330)
    {
        ((ObjAnimComponent*)obj)->bankIndex = 1;
        model = Obj_GetActiveModel((int)obj);
        *(u8*)((char*)*(int**)((char*)model + 0x34) + 8) = lbl_803DBD58[((FireballState*)state)->colorIndex];
        savedRot4 = ((GameObject*)obj)->anim.rotZ;
        savedRot2 = ((GameObject*)obj)->anim.rotY;
        savedF8 = ((GameObject*)obj)->anim.rootMotionScale;
        ((GameObject*)obj)->anim.rootMotionScale = lbl_803E3350;
        for (i = 0; i < 5; i++)
        {
            u8* p = state + i * 2;
            *(u16*)(p + 0x48) += *(u16*)(p + 0x52);
            *(u16*)(p + 0x5c) += *(u16*)(p + 0x66);
            ((GameObject*)obj)->anim.rotZ = (s16) * (u16*)(p + 0x48);
            ((GameObject*)obj)->anim.rotY = (s16) * (u16*)(p + 0x5c);
            *(u16*)((char*)model + 0x18) &= ~0x8;
            ((void (*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E3354);
        }
        ((GameObject*)obj)->anim.rotZ = (s16)savedRot4;
        ((GameObject*)obj)->anim.rotY = (s16)savedRot2;
        ((GameObject*)obj)->anim.rootMotionScale = savedF8;
        ((ObjAnimComponent*)obj)->bankIndex = 0;
        *(u8*)((char*)*(int**)((char*)Obj_GetActiveModel((int)obj) + 0x34) + 8) =
            lbl_803DBD58[((FireballState*)state)->colorIndex];
        ((void (*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E3354);
        if (*(int**)state != NULL)
        {
            if (*(u8*)((char*)*(int**)state + 0x2f8) != 0 && *(u8*)((char*)*(int**)state + 0x4c) != 0)
            {
                u16 sum = *(u8*)((char*)*(int**)state + 0x2f9) + *(s8*)((char*)*(int**)state + 0x2fa);
                if (sum > 12)
                {
                    sum += randomGetRange(-12, 12);
                    if (sum > 255)
                    {
                        sum = 255;
                        *(u8*)((char*)*(int**)state + 0x2fa) = 0;
                    }
                }
                *(u8*)((char*)*(int**)state + 0x2f9) = sum;
            }
            if (*(u8*)((char*)*(int**)state + 0x2f8) != 0 && *(u8*)((char*)*(int**)state + 0x4c) != 0)
            {
                queueGlowRender(*(int*)state);
            }
        }
    }
}

extern f32 lbl_803E3340;

void fn_8016F260(int* obj, int* state, int* other)
{
    f32* pt = (f32*)(*(int*)((char*)other + 0x74) + ((GameObject*)other)->unkE4 * 24);
    if (pt != NULL)
    {
        f32 dx = pt[0] - ((FireballState*)state)->posX;
        f32 dy = pt[1] - lbl_803E3334 - *(f32*)&((FireballState*)state)->posY;
        f32 dz = pt[2] - ((FireballState*)state)->posZ;
        s16 angY;
        s16 angP;
        s16 difY;
        s16 difP;
        s16 targY;
        s16 targP;
        f32 t1;
        f32 t2;
        f32 f;
        f32 c;

        angY = getAngle(((GameObject*)obj)->anim.velocityX, ((GameObject*)obj)->anim.velocityZ);
        t1 = ((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX;
        t2 = ((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ;
        angP = getAngle(((GameObject*)obj)->anim.velocityY, sqrtf(t1 + t2));
        targY = getAngle(dx, dz);
        targP = getAngle(dy, sqrtf(dx * dx + dz * dz));

        difY = targY - (u16)angY;
        if (difY > 0x8000)
        {
            difY -= 0xffff;
        }
        if (difY < -0x8000)
        {
            difY += 0xffff;
        }
        difP = targP - (u16)angP;
        if (difP > 0x8000)
        {
            difP -= 0xffff;
        }
        if (difP < -0x8000)
        {
            difP += 0xffff;
        }
        difY >>= 5;
        if (difY > 364)
        {
            difY = 364;
        }
        if (difY < -364)
        {
            difY = -364;
        }
        difP >>= 4;
        if (difP > 728)
        {
            difP = 728;
        }
        if (difP < -728)
        {
            difP = -728;
        }
        angY += framesThisStep * difY;
        angP += framesThisStep * difP;

        f = lbl_803E3338 * (f32)angY / lbl_803E333C;
        ((GameObject*)obj)->anim.velocityX = mathSinf(f);
        ((GameObject*)obj)->anim.velocityZ = mathCosf(f);
        f = lbl_803E3338 * (f32)angP / lbl_803E333C;
        c = mathSinf(f);
        if (lbl_803E3330 != mathCosf(f))
        {
            c = c / mathCosf(f);
        }
        ((GameObject*)obj)->anim.velocityY = c;

        c = lbl_803E3340 / sqrtf(((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ +
            (((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX +
                ((GameObject*)obj)->anim.velocityY * ((GameObject*)obj)->anim.velocityY));
        ((GameObject*)obj)->anim.velocityX *= c;
        ((GameObject*)obj)->anim.velocityY *= c;
        ((GameObject*)obj)->anim.velocityZ *= c;
    }
}

extern f32 fcos16(u16 angle);

void shield_update(int* obj);



/* dll_F7 (bouncing prop) object extra-state */


void dll_F7_update(int* obj);


void staff_initialise(void);



void shield_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);







/* per-swipe trail record (stride 0x18, 3 records) */


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

extern void selectTexture(void* tex, int x);

#pragma opt_common_subs off


void staff_update(int* obj);








void staffFn_80170380(int* obj, int cmd);



