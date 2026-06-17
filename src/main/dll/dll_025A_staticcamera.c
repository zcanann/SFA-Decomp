/* DLL 0x25A — static camera object [8016984C-801713AC) */
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

#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/genprops.h"
#include "main/effect_interfaces.h"

typedef struct StaticCameraState
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
} StaticCameraState;

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
extern f32 lbl_803E31E8;
extern f32 lbl_803E33A0;
extern void selectTexture(void* tex, int x);

void staticCamera_free(int obj)
{
    ObjGroup_RemoveObject(obj, 7);
    return;
}

void staticCamera_render(int obj, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
    if (visible != 0)
    {
        FUN_8003b818(obj);
    }
    return;
}

void staticCamera_init(short* obj, int params, int deferAdd)
{
    undefined* camData;

    *obj = -*(short*)(params + 0x1c);
    obj[1] = -*(short*)(params + 0x1e);
    obj[2] = -*(short*)(params + 0x20);
    camData = *(undefined**)(obj + 0x5c);
    *camData = *(undefined*)(params + 0x19);
    *(float*)(camData + 4) =
        (float)((double)CONCAT44(0x43300000, (uint) * (byte*)(params + 0x1a)) - DOUBLE_803e3e88);
    camData[1] = 0;
    if (deferAdd == 0)
    {
        ObjGroup_AddObject((int)obj, 7);
    }
    return;
}

void FUN_8016d188(int obj, int src)
{
    float scale;
    int mode;
    uint soundFlag;
    int extra;
    double spawnD;
    int ownerData;
    float strength;
    int spawnType;
    undefined2 spawnArgs2[3];
    short argFrame2;
    float local_44;
    undefined2 spawnArgs;
    undefined2 local_32;
    undefined2 local_30;
    short argFrame;
    float local_2c;
    float local_28;
    float local_24;
    undefined4 local_20;
    longlong frameLL;

    extra = *(int*)&((GameObject*)obj)->extra;
    if ((obj != 0) && (src != 0))
    {
        if (*(char*)(extra + 0xba) != '\0')
        {
            mode = FUN_80294d10(src);
            if (mode == 0)
            {
                strength = lbl_803E3F24;
                scale = lbl_803E3F28;
            }
            else
            {
                strength = lbl_803E3F20;
                scale = lbl_803E3F20;
            }
            if (*(byte*)(extra + 0xbb) == 7)
            {
                spawnD = (double)lbl_803E3F2C;
                frameLL = (longlong)(int)(lbl_803E3F30 * scale);
                FUN_800810f8(spawnD, spawnD, spawnD, (double)(lbl_803E3F34 * strength), obj, 7,
                             (uint) * (byte*)(extra + 0xba), 1, (int)(lbl_803E3F30 * scale), 0, 0);
            }
            else
            {
                spawnD = (double)lbl_803E3F20;
                frameLL = (longlong)(int)(lbl_803E3F30 * scale);
                FUN_800810f8(spawnD, spawnD, spawnD, (double)(lbl_803E3F34 * strength), obj,
                             (uint) * (byte*)(extra + 0xbb), (uint) * (byte*)(extra + 0xba), 1,
                             (int)(lbl_803E3F30 * scale), 0, 0);
            }
        }
        FUN_80294c60(src, &spawnType, &strength);
        spawnArgs = 0;
        local_32 = 0;
        local_30 = 0;
        local_2c = lbl_803E3F20;
        if (spawnType == 0x87)
        {
            extra = (int)(lbl_803E3F38 * (strength / lbl_803E3F30));
            frameLL = (longlong)extra;
            argFrame = 0x15 - (short)extra;
            local_28 = lbl_803E3F3C * (strength / lbl_803E3F40 - lbl_803E3F2C);
            spawnArgs = 0xc94;
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &spawnArgs, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &spawnArgs, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &spawnArgs, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &spawnArgs, 2, -1, NULL);
            argFrame = 9;
            local_2c = lbl_803E3F48 * (strength / lbl_803E3F40) + lbl_803E3F44;
            local_24 = lbl_803E3F4C;
            spawnArgs = 0xc0e;
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b3, &spawnArgs, 2, -1, NULL);
        }
        else if (spawnType < 0x87)
        {
            if (spawnType == 0x7f)
            {
                local_2c = lbl_803E3F58;
                argFrame = 10;
                local_24 = lbl_803E3F54;
                local_28 = lbl_803E3F50;
                spawnArgs = 0xc0e;
                (*gPartfxInterface)->spawnObject((void*)obj, 0x7b3, &spawnArgs, 2, -1, NULL);
            }
            else if (spawnType < 0x7f)
            {
                if ((spawnType == 0x43) && (lbl_803E3F4C < strength))
                {
                    extra = (int)(lbl_803E3F38 * (strength / lbl_803E3F30));
                    frameLL = (longlong)extra;
                    argFrame = (short)extra + 6;
                    local_28 = lbl_803E3F3C * (strength / lbl_803E3F40 - lbl_803E3F2C);
                    spawnArgs = 0xc94;
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x7b4, &spawnArgs, 2, -1, NULL);
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x7b4, &spawnArgs, 2, -1, NULL);
                    argFrame = 9;
                    local_2c = lbl_803E3F48 * (strength / lbl_803E3F40) + lbl_803E3F44;
                    local_24 = lbl_803E3F4C;
                    spawnArgs = 0xc0e;
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x7b3, &spawnArgs, 2, -1, NULL);
                }
            }
            else if (spawnType == 0x85)
            {
                if (lbl_803E3F4C < strength)
                {
                    soundFlag = FUN_80017690(0xc55);
                    if (soundFlag == 0)
                    {
                        scale = strength / lbl_803E3F40;
                        extra = (int)(lbl_803E3F38 * scale);
                        argFrame = (short)extra;
                        spawnArgs = 0xc94;
                    }
                    else
                    {
                        scale = strength / lbl_803E3F50;
                        extra = (int)(lbl_803E3F38 * scale);
                        argFrame = (short)extra;
                        spawnArgs = 0xc75;
                    }
                    frameLL = (longlong)extra;
                    local_28 = lbl_803E3F5C * (lbl_803E3F28 - scale);
                    argFrame = 0x15 - argFrame;
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &spawnArgs, 2, -1, NULL);
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &spawnArgs, 2, -1, NULL);
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &spawnArgs, 2, -1, NULL);
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &spawnArgs, 2, -1, NULL);
                    argFrame = 9;
                    soundFlag = FUN_80017690(0xc55);
                    if (soundFlag == 0)
                    {
                        spawnArgs = 0xc0e;
                        scale = lbl_803E3F40;
                    }
                    else
                    {
                        spawnArgs = 0xc75;
                        scale = lbl_803E3F50;
                    }
                    local_2c = lbl_803E3F48 * (strength / scale) + lbl_803E3F44;
                    local_24 = lbl_803E3F4C;
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x7b3, &spawnArgs, 2, -1, NULL);
                }
            }
            else if (0x84 < spawnType)
            {
                soundFlag = FUN_80017690(0xc55);
                if (soundFlag == 0)
                {
                    spawnArgs = 0xc0e;
                }
                else
                {
                    spawnArgs = 0xc75;
                }
                scale = *(float*)(src + 0x98);
                if (lbl_803E3F68 <= scale)
                {
                    if (scale < lbl_803E3F70)
                    {
                        local_28 = lbl_803E3F5C * (lbl_803E3F74 * (scale - lbl_803E3F68) - lbl_803E3F2C);
                        argFrame = 9;
                        local_2c = lbl_803E3F20;
                        local_24 = lbl_803E3F4C;
                        (*gPartfxInterface)->spawnObject((void*)obj, 0x7b3, &spawnArgs, 2, -1, NULL);
                    }
                }
                else
                {
                    local_28 = lbl_803E3F6C;
                    argFrame = 9;
                    local_2c = lbl_803E3F20;
                    local_24 = lbl_803E3F4C;
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x7b3, &spawnArgs, 2, -1, NULL);
                }
            }
        }
        else if (spawnType == 0x468)
        {
            if (lbl_803E3F4C < strength)
            {
                extra = (int)(lbl_803E3F38 * (strength / lbl_803E3F60));
                frameLL = (longlong)extra;
                argFrame2 = 0x15 - (short)extra;
                spawnArgs2[0] = 0xc95;
                FUN_80294c48(*(int*)&((GameObject*)obj)->ownerObj, &ownerData);
                local_28 = *(float*)(ownerData + 0xc);
                local_24 = *(float*)(ownerData + 0x10);
                local_20 = *(undefined4*)(ownerData + 0x14);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)obj)->ownerObj, 0x7b9, &spawnArgs,
                                                 0x200001, -1, spawnArgs2);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)obj)->ownerObj, 0x7b9, &spawnArgs,
                                                 0x200001, -1, spawnArgs2);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)obj)->ownerObj, 0x7b9, &spawnArgs,
                                                 0x200001, -1, spawnArgs2);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)obj)->ownerObj, 0x7b9, &spawnArgs,
                                                 0x200001, -1, spawnArgs2);
                argFrame2 = 9;
                spawnArgs2[0] = 0xc95;
                local_44 = lbl_803E3F64 * (strength / lbl_803E3F60) + lbl_803E3F44;
                local_28 = *(float*)(ownerData + 0xc);
                local_24 = *(float*)(ownerData + 0x10);
                local_20 = *(undefined4*)(ownerData + 0x14);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)obj)->ownerObj, 0x7ba, &spawnArgs,
                                                 0x200001, -1, spawnArgs2);
            }
        }
        else if (spawnType < 0x468)
        {
            if (spawnType < 0x89)
            {
                argFrame = 0x23;
                local_24 = lbl_803E3F4C;
                local_28 = lbl_803E3F50;
                spawnArgs = 0xc0e;
                (*gPartfxInterface)->spawnObject((void*)obj, 0x7b3, &spawnArgs, 2, -1, NULL);
                argFrame = 0x12;
                local_24 = lbl_803E3F54;
                (*gPartfxInterface)->spawnObject((void*)obj, 0x7b3, &spawnArgs, 2, -1, NULL);
            }
        }
        else if ((spawnType == 0x46f) && (lbl_803E3F4C < strength))
        {
            extra = (int)(lbl_803E3F38 * (strength / lbl_803E3F60));
            frameLL = (longlong)extra;
            argFrame = 0x15 - (short)extra;
            local_28 = lbl_803E3F5C * (lbl_803E3F28 - strength / lbl_803E3F60);
            spawnArgs = 0xc94;
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &spawnArgs, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &spawnArgs, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &spawnArgs, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &spawnArgs, 2, -1, NULL);
            argFrame = 9;
            local_2c = lbl_803E3F48 * (strength / lbl_803E3F60) + lbl_803E3F44;
            local_24 = lbl_803E3F4C;
            spawnArgs = 0xc0e;
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b3, &spawnArgs, 2, -1, NULL);
        }
    }
    return;
}

void FUN_8016d994(int obj, undefined type, undefined count)
{
    int extra;

    extra = *(int*)&((GameObject*)obj)->extra;
    *(undefined*)(extra + 0xbb) = type;
    *(undefined*)(extra + 0xba) = count;
    return;
}

void FUN_8016e8cc(undefined8 param_1, undefined8 param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  int obj)
{
    short channel;
    int iVar2;
    int* group;
    uint idx;
    int entry;
    int* extra;
    double dVar7;
    double dVar8;
    undefined8 fadeLL;

    extra = ((GameObject*)obj)->extra;
    iVar2 = FUN_80017a54(obj);
    *(ushort*)(iVar2 + 0x18) = *(ushort*)(iVar2 + 0x18) & ~0x8;
    FUN_8002fc3c((double)(float)extra[0x14], (double)lbl_803DC074);
    iVar2 = 3;
    group = extra;
    do
    {
        if ((*(byte*)(group + 5) & 2) != 0)
        {
            idx = (uint) * (ushort*)(group + 3);
            entry = *group + idx * 0x14;
            for (; (int)idx < (int)(uint) * (ushort*)((int)group + 0xe); idx = idx + 2)
            {
                if (group == (int*)extra[0x12])
                {
                    param_3 = (double)lbl_803E3F8C;
                    dVar7 = (double)(float)(param_3 *
                        (double)((lbl_803E3FA4 * (float)extra[0x26] -
                            *(float*)(entry + 0xc)) * lbl_803E3FA8));
                    dVar8 = (double)lbl_803E3F4C;
                    if ((dVar8 <= dVar7) && (dVar8 = dVar7, param_3 < dVar7))
                    {
                        dVar8 = param_3;
                    }
                    *(short*)(entry + 0x10) = (short)(int)(param_3 - dVar8);
                    *(undefined2*)(entry + 0x24) = *(undefined2*)(entry + 0x10);
                }
                else
                {
                    param_3 = (double)lbl_803E3FC4;
                    *(short*)(entry + 0x10) =
                        (short)(int)-(float)(param_3 * (double)lbl_803DC074 -
                            (double)(f32)(s32)((int)*(short*)(entry + 0x10)));
                    *(undefined2*)(entry + 0x24) = *(undefined2*)(entry + 0x10);
                }
                channel = *(short*)(entry + 0x10);
                if (channel < 0)
                {
                    channel = 0;
                }
                else if (0xff < channel)
                {
                    channel = 0xff;
                }
                *(short*)(entry + 0x10) = channel;
                channel = *(short*)(entry + 0x24);
                if (channel < 0)
                {
                    channel = 0;
                }
                else if (0xff < channel)
                {
                    channel = 0xff;
                }
                *(short*)(entry + 0x24) = channel;
                if ((*(short*)(entry + 0x10) < 1) && (*(short*)(entry + 0x24) < 1))
                {
                    *(short*)((int)group + 0x12) = *(short*)((int)group + 0x12) + -2;
                    *(short*)(group + 3) = *(short*)(group + 3) + 2;
                }
                entry = entry + 0x28;
            }
            if ((group != (int*)extra[0x12]) && (*(short*)((int)group + 0x12) == 0))
            {
                *(byte*)(group + 5) = *(byte*)(group + 5) & 0xfd;
            }
        }
        group = group + 6;
        iVar2 = iVar2 + -1;
    }
    while (iVar2 != 0);
    FUN_8016d188(obj, *(int*)&((GameObject*)obj)->ownerObj);
    FUN_80294d6c(*(int*)&((GameObject*)obj)->ownerObj);
    *(undefined*)((int)extra + 0xb9) = 0;
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
    float defScale;
    uint base;
    int iVar3;
    int* piVar4;
    uint roll;
    int subObj;
    int* piVar7;
    int* colorTbl;
    float* scaleTbl;
    double dVar10;
    double dVar11;
    double dVar12;
    double dVar13;
    double dVar14;
    undefined8 packed;
    undefined8 rngLL0;
    undefined8 rngLL1;

    packed = FUN_80286838();
    base = (uint)((ulonglong)packed >> 0x20);
    scaleTbl = (float*)&DAT_80321678;
    piVar7 = *(int**)(base + 0xb8);
    iVar3 = FUN_80017a98();
    subObj = 0;
    if (iVar3 != 0)
    {
        subObj = FUN_80294cf8(iVar3);
    }
    defScale = lbl_803E4064;
    switch ((uint)packed & 0xff)
    {
    case 0:
        if (*piVar7 != 0)
        {
            FUN_800175cc((double)lbl_803E4040, *piVar7, '\0');
        }
        defScale = lbl_803E4048;
        if (lbl_803E4044 != (float)piVar7[2])
        {
            piVar7[4] = (int)lbl_803E4048;
            piVar7[1] = (int)defScale;
            if (subObj != 0)
            {
                FUN_8016d994(subObj, 7, 0);
            }
        }
        piVar7[2] = (int)lbl_803E4044;
        piVar7[3] = (int)lbl_803E404C;
        FUN_80006810(base, 0x42c);
        FUN_80006810(base, 0x42d);
        break;
    case 1:
        if (lbl_803E4044 == (float)piVar7[2])
        {
            if (subObj != 0)
            {
                FUN_8016d994(subObj, 7, 8);
            }
            if (*piVar7 == 0)
            {
                piVar4 = FUN_80017624(0, '\x01');
                *piVar7 = (int)piVar4;
            }
            if (*piVar7 != 0)
            {
                FUN_800175b0(*piVar7, 2);
                FUN_800175ec((double)*(float*)(base + 0xc),
                             (double)(*(float*)(base + 0x10) - lbl_803E4050),
                             (double)*(float*)(base + 0x14), (int*)*piVar7);
                FUN_8001759c(*piVar7, 0, 0xff, 0xff, 0xff);
                FUN_80017588(*piVar7, 0, 0xff, 0xff, 0xff);
                FUN_800175d0((double)lbl_803E4054, (double)lbl_803E4058, *piVar7);
                FUN_800175bc(*piVar7, 1);
                FUN_800175cc((double)lbl_803E4044, *piVar7, '\x01');
                FUN_8001753c(*piVar7, 0, 0);
                FUN_800175d8(*piVar7, 1);
            }
            defScale = lbl_803E4044;
            if (lbl_803E4044 == (float)piVar7[2])
            {
                piVar7[4] = (int)lbl_803E4048;
                piVar7[1] = (int)defScale;
            }
            piVar7[2] = (int)lbl_803E4048;
            dVar12 = (double)lbl_803E405C;
            piVar7[3] = (int)lbl_803E405C;
            iVar3 = 0;
            colorTbl = &DAT_80321688;
            dVar11 = (double)lbl_803E4040;
            dVar14 = (double)lbl_803E4060;
            piVar4 = piVar7;
            dVar13 = DOUBLE_803e4068;
            do
            {
                *(undefined2*)(piVar4 + 0xd) = 0xc000;
                dVar10 = (double)fcos16Precise();
                piVar7[9] = (int)(*scaleTbl * (float)((double)(float)(dVar12 + dVar10) * dVar11));
                piVar7[5] = *colorTbl;
                roll = randomGetRange(0x78, 0x7f);
                rngLL0 = (double)CONCAT44(0x43300000, iVar3 * roll ^ 0x80000000);
                *(short*)(piVar4 + 0xf) = (short)(int)(dVar14 + (double)(float)(rngLL0 - dVar13));
                piVar4 = (int*)((int)piVar4 + 2);
                scaleTbl = scaleTbl + 1;
                piVar7 = piVar7 + 1;
                colorTbl = colorTbl + 1;
                iVar3 = iVar3 + 1;
            }
            while (iVar3 < 4);
            FUN_80006824(base, 0x42c);
            FUN_80006824(base, 0x42d);
        }
        break;
    case 2:
        if (subObj != 0)
        {
            FUN_8016d994(subObj, 7, 0);
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
        FUN_80006810(base, 0x42c);
        FUN_80006810(base, 0x42d);
        break;
    case 3:
        if (subObj != 0)
        {
            FUN_8016d994(subObj, 7, 8);
        }
        if (*piVar7 == 0)
        {
            piVar4 = FUN_80017624(0, '\x01');
            *piVar7 = (int)piVar4;
        }
        if (*piVar7 != 0)
        {
            FUN_800175b0(*piVar7, 2);
            FUN_800175ec((double)*(float*)(base + 0xc),
                         (double)(*(float*)(base + 0x10) - lbl_803E4050),
                         (double)*(float*)(base + 0x14), (int*)*piVar7);
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
        colorTbl = &DAT_80321688;
        dVar13 = (double)lbl_803E4040;
        piVar4 = piVar7;
        do
        {
            *(undefined2*)(piVar7 + 0xd) = 0;
            dVar11 = (double)fcos16Precise();
            piVar4[9] = (int)(*scaleTbl * (float)((double)(float)(dVar14 + dVar11) * dVar13));
            piVar4[5] = *colorTbl;
            piVar7 = (int*)((int)piVar7 + 2);
            scaleTbl = scaleTbl + 1;
            piVar4 = piVar4 + 1;
            colorTbl = colorTbl + 1;
            iVar3 = iVar3 + 1;
        }
        while (iVar3 < 4);
        FUN_80006824(base, 0x42d);
        FUN_80006824(base, 0x42c);
        break;
    case 4:
        piVar7[2] = (int)lbl_803E4064;
        dVar14 = (double)lbl_803E405C;
        piVar7[3] = (int)lbl_803E405C;
        piVar7[4] = (int)defScale;
        iVar3 = 0;
        scaleTbl = (float*)&DAT_80321698;
        colorTbl = &DAT_803216a8;
        dVar11 = (double)lbl_803E4040;
        dVar12 = (double)lbl_803E4060;
        piVar4 = piVar7;
        dVar13 = DOUBLE_803e4068;
        do
        {
            *(undefined2*)(piVar7 + 0xd) = 0xc000;
            dVar10 = (double)fcos16Precise();
            piVar4[9] = (int)(*scaleTbl * (float)((double)(float)(dVar14 + dVar10) * dVar11));
            piVar4[5] = *colorTbl;
            roll = randomGetRange(0x78, 0x7f);
            rngLL1 = (double)CONCAT44(0x43300000, iVar3 * roll ^ 0x80000000);
            *(short*)(piVar7 + 0xf) = (short)(int)(dVar12 + (double)(float)(rngLL1 - dVar13));
            piVar7 = (int*)((int)piVar7 + 2);
            scaleTbl = scaleTbl + 1;
            piVar4 = piVar4 + 1;
            colorTbl = colorTbl + 1;
            iVar3 = iVar3 + 1;
        }
        while (iVar3 < 4);
        FUN_80006824(base, 0x42d);
        FUN_80006824(base, 0x42c);
        break;
    case 5:
        piVar7[2] = (int)lbl_803E4044;
        piVar7[3] = (int)lbl_803E404C;
        piVar7[4] = (int)lbl_803E4064;
        FUN_80006810(base, 0x42c);
        FUN_80006810(base, 0x42d);
        break;
    case 6:
        iVar3 = 0;
        scaleTbl = (float*)&DAT_80321698;
        colorTbl = &DAT_803216a8;
        dVar13 = (double)lbl_803E405C;
        dVar14 = (double)lbl_803E4040;
        piVar4 = piVar7;
        do
        {
            *(undefined2*)(piVar7 + 0xd) = 0x4000;
            dVar11 = (double)fcos16Precise();
            piVar4[9] = (int)(*scaleTbl * (float)((double)(float)(dVar13 + dVar11) * dVar14));
            piVar4[5] = *colorTbl;
            piVar7 = (int*)((int)piVar7 + 2);
            scaleTbl = scaleTbl + 1;
            piVar4 = piVar4 + 1;
            colorTbl = colorTbl + 1;
            iVar3 = iVar3 + 1;
        }
        while (iVar3 < 4);
        break;
    case 7:
        if (subObj != 0)
        {
            FUN_8016d994(subObj, 7, 0);
        }
        if (*piVar7 != 0)
        {
            FUN_800175cc((double)lbl_803E4040, *piVar7, '\0');
        }
        defScale = lbl_803E4044;
        piVar7[2] = (int)lbl_803E4044;
        piVar7[3] = (int)defScale;
        piVar7[4] = (int)defScale;
        piVar7[1] = (int)defScale;
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
                  uint obj)
{
    extern undefined8 ObjHits_DisableObject(); /* #57 */
    short sVar1;
    char count;
    uint uVar3;
    int iVar4;
    int placement;
    int extra;
    undefined8 ret;

    extra = *(int*)&((GameObject*)obj)->extra;
    placement = *(int*)&((GameObject*)obj)->anim.placementData;
    iVar4 = (int)((GameObject*)obj)->anim.modelInstance->extraSetupData;
    FUN_80017a98();
    FUN_80017a90();
    FUN_80017a98();
    FUN_80017a90();
    ret = ObjHits_DisableObject(obj);
    if ((*(ushort*)&((GameObject*)obj)->anim.flags & 0x2000) != 0)
    {
        *(float*)(extra + 8) = lbl_803E40E8;
        if (((GameObject*)obj)->anim.modelState != NULL)
        {
            ((GameObject*)obj)->anim.modelState->flags = OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        }
    }
    if ((int)*(short*)(extra + 0x10) != 0xffffffff)
    {
        FUN_80017698((int)*(short*)(extra + 0x10), 1);
        ret = FUN_800e842c(obj);
    }
    uVar3 = (uint) * (short*)(placement + 0x1e);
    if (uVar3 != 0xffffffff)
    {
        ret = FUN_80017698(uVar3, 1);
    }
    uVar3 = (uint) * (short*)(placement + 0x2c);
    if (0 < (int)uVar3)
    {
        FUN_80017688(uVar3);
    }
    sVar1 = *(short*)(iVar4 + 2);
    if (sVar1 == 4)
    {
        sVar1 = ((GameObject*)obj)->anim.seqId;
        if (sVar1 == 0x3cd)
        {
            iVar4 = FUN_80017a98();
            FUN_80294d60(ret, param_2, param_3, param_4, param_5, param_6, param_7, param_8, iVar4, 2);
            uVar3 = FUN_80017a98();
            FUN_80006824(uVar3, SFXen_treadlpc);
            FUN_80081118((double)lbl_803E40EC, obj, 1, 0x28);
        }
        else if ((sVar1 < 0x3cd) && (sVar1 == 0xb))
        {
            uVar3 = FUN_80017a98();
            ret = FUN_80006824(uVar3, SFXen_treadlpc);
            iVar4 = FUN_80017a98();
            FUN_80294d60(ret, param_2, param_3, param_4, param_5, param_6, param_7, param_8, iVar4, 4);
            FUN_80081118((double)lbl_803E40EC, obj, 3, 0x28);
        }
        else
        {
            uVar3 = FUN_80017a98();
            FUN_80006824(uVar3, SFXen_waterblock_stop);
            FUN_80081118((double)lbl_803E40EC, obj, 0xff, 0x28);
        }
    }
    else if ((sVar1 < 4) && (sVar1 == 1))
    {
        sVar1 = ((GameObject*)obj)->anim.seqId;
        if (sVar1 == 0x319)
        {
            FUN_80006824(obj, SFXwp_gprop2_c);
            FUN_80017698(0x3e9, 1);
            *(undefined2*)(extra + 0x3c) = 0x4b0;
            FUN_80081118((double)lbl_803E40EC, obj, 0xff, 0x28);
        }
        else
        {
            if (sVar1 < 0x319)
            {
                if (sVar1 == 0x5a)
                {
                    FUN_80006824(obj, SFXen_treadlpc);
                    FUN_80081118((double)lbl_803E40EC, obj, 2, 0x28);
                    goto LAB_801725bc;
                }
                if ((sVar1 < 0x5a) && (sVar1 == 0x22))
                {
                    FUN_80006824(obj, SFXen_treadlpc);
                    FUN_80081118((double)lbl_803E40EC, obj, 0xff, 0x28);
                    goto LAB_801725bc;
                }
            }
            else if (sVar1 == 0x6a6)
            {
                uVar3 = FUN_80017690(0x86a);
                count = (char)uVar3;
                if (count < '\a')
                {
                    count = count + '\x01';
                }
                FUN_80017698(0x86a, (int)count);
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
    *(undefined4*)&((GameObject*)obj)->anim.rootMotionScale = *(undefined4*)(*(int*)&((GameObject*)obj)->anim.
        modelInstance + 4);
    ((GameObject*)obj)->unkF4 = 1;
    return;
}







void StaticCamera_hitDetect(void)
{
}

void StaticCamera_update(void)
{
}

void StaticCamera_release(void)
{
}

void StaticCamera_initialise(void)
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












int StaticCamera_getExtraSize(void) { return 0x8; }
int StaticCamera_getObjectTypeId(void) { return 0x0; }
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

void StaticCamera_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E31E8);
}




void flamethrowerspe_render(void);
void fn_801719F8(void) { objRenderFn_8003b8f4(lbl_803E3420); }

void StaticCamera_free(int x) { ObjGroup_RemoveObject(x, 0x7); }
void siderepel_free(int x);

void flamethrowerspe_func0B(int* obj);



void staff_modelMtxFn(int* obj, int p4, int p5);







void gcbaddieshield_update(int* obj);

void staff_free(int* obj);

void fireball_free(int* obj);

void depthoffieldpoint_init(int* obj);

void depthoffieldpoint_update(int* obj);

void staff_release(void);

void mikabombshadow_init(int* obj);

void StaticCamera_init(int* obj, int* params, int flag)
{
    u8* state;
    *(s16*)obj = -*(s16*)((char*)params + 0x1c);
    ((GameObject*)obj)->anim.rotY = -*(s16*)((char*)params + 0x1e);
    ((GameObject*)obj)->anim.rotZ = -*(s16*)((char*)params + 0x20);
    state = ((GameObject*)obj)->extra;
    state[0] = *(u8*)((char*)params + 0x19);
    ((StaticCameraState*)state)->unk4 = (f32)(u32) * (u8*)((char*)params + 0x1a);
    state[1] = 0;
    if (flag == 0)
    {
        ObjGroup_AddObject((int)obj, 7);
    }
}

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

