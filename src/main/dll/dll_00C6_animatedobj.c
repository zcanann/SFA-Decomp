/* DLL 0xC6 — animated object [8016984C-801713AC) */
#include "main/dll/xyzanimator.h"
#include "main/dll/genpropswgpipe_struct.h"
extern int randomGetRange(int lo, int hi);
extern u32 ObjHitbox_SetSphereRadius();
extern u32 FUN_8003b818();

void mikabomb_hitDetect(void);

void mikabomb_free(int obj, int mode);

int mikabomb_getExtraSize(void);
int mikabomb_getObjectTypeId(void);

extern void objRenderFn_8003b8f4(f32);
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
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/genprops.h"
#include "main/dll_000A_expgfx.h"
#include "main/camera_interface.h"
#include "main/objseq.h"
#include "main/objhits.h"
#include "main/sfa_extern_decls.h"
#include "main/dll/dll_00C8_depthoffieldpoint.h"
#include "main/dll/dll_00E3_fireball.h"
#include "main/dll/dll_00E4_flamethrowerspe.h"

#define ANIMATEDOBJ_OBJFLAG_UPDATE_DISABLED 0x8000

typedef struct AnimatedobjPlacement
{
    u8 pad0[0x8 - 0x0];
    f32 posX;
    f32 posY;
    f32 posZ;
    s32 unk14;
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x2C - 0x22];
    s16 unk2C;
    u8 pad2E[0x30 - 0x2E];
} AnimatedobjPlacement;

typedef struct AnimatedobjState
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
    u8 pad118[0x140 - 0x118];
} AnimatedobjState;

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
extern int* Obj_SetupObject(void* setup, int mode, int mapLayer, int objIndex, void* parent);
extern u64 FUN_8002fc3c();
extern void ObjGroup_RemoveObject(u32 obj, int group);
extern void ObjGroup_AddObject(u32 obj, int group);
extern u64 ObjLink_DetachChild();
extern u32 ObjLink_AttachChild();
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
extern void** gTitleMenuControlInterfaceCopy;
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
extern int Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int size, int b);
extern int* Obj_SetupObject(void* setup, int a, int b, int c, void* d);
extern void Sfx_StopObjectChannel(int* obj, int channel);
extern void gcbaddieshield_update(int* obj);








extern void shield_update(int* obj);
extern void dll_F7_update(int* obj);
extern void dll_F7_init(int* obj, int* params);
extern void Sfx_RemoveLoopedObjectSoundForObject(int* obj);

extern void objSetSlot(int* obj, int slot);
extern void Obj_SetModelRenderOpAlpha(int* obj, int alpha);
extern f32 lbl_803E3228;
extern void* ObjList_GetObjects(int* outA, int* outB);
extern f32 lbl_803E322C;
extern void Obj_BuildWorldTransformMatrix(int* obj, f32* m, int p3);
extern void PSMTXTrans(f32* m, f32 x, f32 y, f32 z);
extern void PSMTXConcat(f32 * a, f32 * b, f32 * out);
extern void PSMTXRotRad(f32* m, int axis, f32 rad);
extern void objRenderModel(int* obj);
extern void objSetMtxFn_800412d4(f32 * m);
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 lbl_803E3230;

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
    u8* dest;

    *obj = -*(short*)(params + 0x1c);
    obj[1] = -*(short*)(params + 0x1e);
    obj[2] = -*(short*)(params + 0x20);
    dest = *(u8**)(obj + 0x5c);
    *dest = *(u8*)(params + 0x19);
    *(float*)(dest + 4) =
        (float)((double)(u32) * (u8*)(params + 0x1a));
    dest[1] = 0;
    if (flag == 0)
    {
        ObjGroup_AddObject((int)obj, 7);
    }
    return;
}

void FUN_8016d188(int obj, int fxSource)
{
    float scale;
    int dispatchResult;
    u32 variantFlag;
    int extra;
    double colorD;
    int vecData;
    float value;
    int fxCode;
    u16 fxParams[3];
    short lifetime2;
    float fxFloat44;
    u16 fxColor;
    u16 fxField32;
    u16 fxField30;
    short lifetime;
    float fxFloat2c;
    float fxFloat28;
    float fxFloat24;
    u32 fxField20;
    s64 lTmp;

    extra = *(int*)&((GameObject*)obj)->extra;
    if ((obj != 0) && (fxSource != 0))
    {
        if (*(char*)(extra + 0xba) != '\0')
        {
            dispatchResult = FUN_80294d10(fxSource);
            if (dispatchResult == 0)
            {
                value = lbl_803E3F24;
                scale = lbl_803E3F28;
            }
            else
            {
                value = lbl_803E3F20;
                scale = lbl_803E3F20;
            }
            if (*(u8*)(extra + 0xbb) == 7)
            {
                colorD = (double)lbl_803E3F2C;
                lTmp = (s64)(int)(lbl_803E3F30 * scale);
                FUN_800810f8(colorD, colorD, colorD, (double)(lbl_803E3F34 * value), obj, 7,
                             (u32) * (u8*)(extra + 0xba), 1, (int)(lbl_803E3F30 * scale), 0, 0);
            }
            else
            {
                colorD = (double)lbl_803E3F20;
                lTmp = (s64)(int)(lbl_803E3F30 * scale);
                FUN_800810f8(colorD, colorD, colorD, (double)(lbl_803E3F34 * value), obj,
                             (u32) * (u8*)(extra + 0xbb), (u32) * (u8*)(extra + 0xba), 1,
                             (int)(lbl_803E3F30 * scale), 0, 0);
            }
        }
        FUN_80294c60(fxSource, &fxCode, &value);
        fxColor = 0;
        fxField32 = 0;
        fxField30 = 0;
        fxFloat2c = lbl_803E3F20;
        if (fxCode == 0x87)
        {
            extra = (int)(lbl_803E3F38 * (value / lbl_803E3F30));
            lTmp = (s64)extra;
            lifetime = 0x15 - extra;
            fxFloat28 = lbl_803E3F3C * (value / lbl_803E3F40 - lbl_803E3F2C);
            fxColor = 0xc94;
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &fxColor, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &fxColor, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &fxColor, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &fxColor, 2, -1, NULL);
            lifetime = 9;
            fxFloat2c = lbl_803E3F48 * (value / lbl_803E3F40) + lbl_803E3F44;
            fxFloat24 = lbl_803E3F4C;
            fxColor = 0xc0e;
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b3, &fxColor, 2, -1, NULL);
        }
        else if (fxCode < 0x87)
        {
            if (fxCode == 0x7f)
            {
                fxFloat2c = lbl_803E3F58;
                lifetime = 10;
                fxFloat24 = lbl_803E3F54;
                fxFloat28 = lbl_803E3F50;
                fxColor = 0xc0e;
                (*gPartfxInterface)->spawnObject((void*)obj, 0x7b3, &fxColor, 2, -1, NULL);
            }
            else if (fxCode < 0x7f)
            {
                if ((fxCode == 0x43) && (lbl_803E3F4C < value))
                {
                    extra = (int)(lbl_803E3F38 * (value / lbl_803E3F30));
                    lTmp = (s64)extra;
                    lifetime = extra + 6;
                    fxFloat28 = lbl_803E3F3C * (value / lbl_803E3F40 - lbl_803E3F2C);
                    fxColor = 0xc94;
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x7b4, &fxColor, 2, -1, NULL);
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x7b4, &fxColor, 2, -1, NULL);
                    lifetime = 9;
                    fxFloat2c = lbl_803E3F48 * (value / lbl_803E3F40) + lbl_803E3F44;
                    fxFloat24 = lbl_803E3F4C;
                    fxColor = 0xc0e;
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x7b3, &fxColor, 2, -1, NULL);
                }
            }
            else if (fxCode == 0x85)
            {
                if (lbl_803E3F4C < value)
                {
                    variantFlag = FUN_80017690(0xc55);
                    if (variantFlag == 0)
                    {
                        scale = value / lbl_803E3F40;
                        extra = (int)(lbl_803E3F38 * scale);
                        lifetime = extra;
                        fxColor = 0xc94;
                    }
                    else
                    {
                        scale = value / lbl_803E3F50;
                        extra = (int)(lbl_803E3F38 * scale);
                        lifetime = extra;
                        fxColor = 0xc75;
                    }
                    lTmp = (s64)extra;
                    fxFloat28 = lbl_803E3F5C * (lbl_803E3F28 - scale);
                    lifetime = 0x15 - lifetime;
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &fxColor, 2, -1, NULL);
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &fxColor, 2, -1, NULL);
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &fxColor, 2, -1, NULL);
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &fxColor, 2, -1, NULL);
                    lifetime = 9;
                    variantFlag = FUN_80017690(0xc55);
                    if (variantFlag == 0)
                    {
                        fxColor = 0xc0e;
                        scale = lbl_803E3F40;
                    }
                    else
                    {
                        fxColor = 0xc75;
                        scale = lbl_803E3F50;
                    }
                    fxFloat2c = lbl_803E3F48 * (value / scale) + lbl_803E3F44;
                    fxFloat24 = lbl_803E3F4C;
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x7b3, &fxColor, 2, -1, NULL);
                }
            }
            else if (0x84 < fxCode)
            {
                variantFlag = FUN_80017690(0xc55);
                if (variantFlag == 0)
                {
                    fxColor = 0xc0e;
                }
                else
                {
                    fxColor = 0xc75;
                }
                scale = *(float*)(fxSource + 0x98);
                if (lbl_803E3F68 <= scale)
                {
                    if (scale < lbl_803E3F70)
                    {
                        fxFloat28 = lbl_803E3F5C * (lbl_803E3F74 * (scale - lbl_803E3F68) - lbl_803E3F2C);
                        lifetime = 9;
                        fxFloat2c = lbl_803E3F20;
                        fxFloat24 = lbl_803E3F4C;
                        (*gPartfxInterface)->spawnObject((void*)obj, 0x7b3, &fxColor, 2, -1, NULL);
                    }
                }
                else
                {
                    fxFloat28 = lbl_803E3F6C;
                    lifetime = 9;
                    fxFloat2c = lbl_803E3F20;
                    fxFloat24 = lbl_803E3F4C;
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x7b3, &fxColor, 2, -1, NULL);
                }
            }
        }
        else if (fxCode == 0x468)
        {
            if (lbl_803E3F4C < value)
            {
                extra = (int)(lbl_803E3F38 * (value / lbl_803E3F60));
                lTmp = (s64)extra;
                lifetime2 = 0x15 - extra;
                fxParams[0] = 0xc95;
                FUN_80294c48(*(int*)&((GameObject*)obj)->ownerObj, &vecData);
                fxFloat28 = *(float*)(vecData + 0xc);
                fxFloat24 = *(float*)(vecData + 0x10);
                fxField20 = *(u32*)(vecData + 0x14);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)obj)->ownerObj, 0x7b9, &fxColor,
                                                 0x200001, -1, fxParams);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)obj)->ownerObj, 0x7b9, &fxColor,
                                                 0x200001, -1, fxParams);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)obj)->ownerObj, 0x7b9, &fxColor,
                                                 0x200001, -1, fxParams);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)obj)->ownerObj, 0x7b9, &fxColor,
                                                 0x200001, -1, fxParams);
                lifetime2 = 9;
                fxParams[0] = 0xc95;
                fxFloat44 = lbl_803E3F64 * (value / lbl_803E3F60) + lbl_803E3F44;
                fxFloat28 = *(float*)(vecData + 0xc);
                fxFloat24 = *(float*)(vecData + 0x10);
                fxField20 = *(u32*)(vecData + 0x14);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)obj)->ownerObj, 0x7ba, &fxColor,
                                                 0x200001, -1, fxParams);
            }
        }
        else if (fxCode < 0x468)
        {
            if (fxCode < 0x89)
            {
                lifetime = 0x23;
                fxFloat24 = lbl_803E3F4C;
                fxFloat28 = lbl_803E3F50;
                fxColor = 0xc0e;
                (*gPartfxInterface)->spawnObject((void*)obj, 0x7b3, &fxColor, 2, -1, NULL);
                lifetime = 0x12;
                fxFloat24 = lbl_803E3F54;
                (*gPartfxInterface)->spawnObject((void*)obj, 0x7b3, &fxColor, 2, -1, NULL);
            }
        }
        else if ((fxCode == 0x46f) && (lbl_803E3F4C < value))
        {
            extra = (int)(lbl_803E3F38 * (value / lbl_803E3F60));
            lTmp = (s64)extra;
            lifetime = 0x15 - extra;
            fxFloat28 = lbl_803E3F5C * (lbl_803E3F28 - value / lbl_803E3F60);
            fxColor = 0xc94;
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &fxColor, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &fxColor, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &fxColor, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &fxColor, 2, -1, NULL);
            lifetime = 9;
            fxFloat2c = lbl_803E3F48 * (value / lbl_803E3F60) + lbl_803E3F44;
            fxFloat24 = lbl_803E3F4C;
            fxColor = 0xc0e;
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b3, &fxColor, 2, -1, NULL);
        }
    }
    return;
}

void FUN_8016d994(int obj, u8 flagBB, u8 flagBA)
{
    int extra;

    extra = *(int*)&((GameObject*)obj)->extra;
    *(u8*)(extra + 0xbb) = flagBB;
    *(u8*)(extra + 0xba) = flagBA;
    return;
}

void FUN_8016e8cc(u64 param_1, u64 param_2, double param_3, u64 param_4,
                  u64 param_5, u64 param_6, u64 param_7, u64 param_8,
                  int obj)
{
    short color;
    int groupIdx;
    int* group;
    u32 partIdx;
    int entry;
    int* state;
    double alphaD;
    double clampD;

    state = ((GameObject*)obj)->extra;
    groupIdx = FUN_80017a54(obj);
    *(u16*)(groupIdx + 0x18) = *(u16*)(groupIdx + 0x18) & ~0x8;
    FUN_8002fc3c((double)(float)state[0x14], (double)lbl_803DC074);
    groupIdx = 3;
    group = state;
    do
    {
        if ((*(u8*)(group + 5) & 2) != 0)
        {
            partIdx = (u32) * (u16*)(group + 3);
            entry = *group + partIdx * 0x14;
            for (; partIdx < (int)(u32) * (u16*)((int)group + 0xe); partIdx = partIdx + 2)
            {
                if (group == (int*)state[0x12])
                {
                    param_3 = (double)lbl_803E3F8C;
                    alphaD = (double)(float)(param_3 *
                        (double)((lbl_803E3FA4 * (float)state[0x26] -
                            *(float*)(entry + 0xc)) * lbl_803E3FA8));
                    clampD = (double)lbl_803E3F4C;
                    if ((clampD <= alphaD) && (clampD = alphaD, param_3 < alphaD))
                    {
                        clampD = param_3;
                    }
                    *(short*)(entry + 0x10) = (short)(int)(param_3 - clampD);
                    *(u16*)(entry + 0x24) = *(u16*)(entry + 0x10);
                }
                else
                {
                    param_3 = (double)lbl_803E3FC4;
                    *(short*)(entry + 0x10) =
                        (short)(int)-(float)(param_3 * (double)lbl_803DC074 -
                            (double)(f32)(s32)((int)*(short*)(entry + 0x10)));
                    *(u16*)(entry + 0x24) = *(u16*)(entry + 0x10);
                }
                color = *(short*)(entry + 0x10);
                if (color < 0)
                {
                    color = 0;
                }
                else if (0xff < color)
                {
                    color = 0xff;
                }
                *(short*)(entry + 0x10) = color;
                color = *(short*)(entry + 0x24);
                if (color < 0)
                {
                    color = 0;
                }
                else if (0xff < color)
                {
                    color = 0xff;
                }
                *(short*)(entry + 0x24) = color;
                if ((*(short*)(entry + 0x10) < 1) && (*(short*)(entry + 0x24) < 1))
                {
                    *(short*)((int)group + 0x12) = *(short*)((int)group + 0x12) + -2;
                    *(short*)(group + 3) = *(short*)(group + 3) + 2;
                }
                entry = entry + 0x28;
            }
            if ((group != (int*)state[0x12]) && (*(short*)((int)group + 0x12) == 0))
            {
                *(u8*)(group + 5) = *(u8*)(group + 5) & 0xfd;
            }
        }
        group = group + 6;
        groupIdx = groupIdx + -1;
    }
    while (groupIdx != 0);
    FUN_8016d188(obj, *(int*)&((GameObject*)obj)->ownerObj);
    FUN_80294d6c(*(int*)&((GameObject*)obj)->ownerObj);
    *(u8*)((int)state + 0xb9) = 0;
    if (DAT_803ad338 != '\0')
    {
        DAT_803ad324 = DAT_803ad324 + lbl_803E3F78;
        ObjHitbox_SetSphereRadius(DAT_803ad334, (short)(int)DAT_803ad324);
        ObjHits_SetHitVolumeSlot(DAT_803ad334, 0x11, 5, 0);
        DAT_803ad330 = DAT_803ad330 + lbl_803E3F7C;
        clampD = (double)DAT_803ad330;
        DAT_803ad328 = DAT_803ad328 * lbl_803E3F80;
        DAT_803ad32c = DAT_803ad32c * lbl_803E3F84;
        ((GameObject*)DAT_803ad334)->anim.alpha = (char)(int)DAT_803ad330;
        ((GameObject*)DAT_803ad334)->anim.rootMotionScale = ((GameObject*)DAT_803ad334)->anim.rootMotionScale +
            lbl_803E3F88;
        if ((double)DAT_803ad330 < (double)lbl_803E3F20)
        {
            DAT_803ad338 = '\0';
            FUN_80017ac8((double)DAT_803ad330, clampD, param_3, param_4, param_5, param_6, param_7, param_8,
                         DAT_803ad334);
            DAT_803ad334 = 0;
        }
    }
    return;
}

void FUN_80170048(void)
{
    float scale;
    u32 obj;
    int iTmp;
    int* walk;
    u32 rand;
    int handle;
    int* state;
    int* colorTbl;
    float* scaleTbl;
    double dA;
    double dB;
    double dC;
    double dD;
    double dE;
    u64 packed;
    u64 randBits;
    u64 randBits2;

    packed = FUN_80286838();
    obj = (u32)((u64)packed >> 0x20);
    scaleTbl = (float*)&DAT_80321678;
    state = *(int**)&((GameObject*)obj)->extra;
    iTmp = FUN_80017a98();
    handle = 0;
    if (iTmp != 0)
    {
        handle = FUN_80294cf8(iTmp);
    }
    scale = lbl_803E4064;
    switch ((u32)packed & 0xff)
    {
    case 0:
        if (*state != 0)
        {
            FUN_800175cc((double)lbl_803E4040, *state, '\0');
        }
        scale = lbl_803E4048;
        if (lbl_803E4044 != (float)state[2])
        {
            state[4] = lbl_803E4048;
            state[1] = scale;
            if (handle != 0)
            {
                FUN_8016d994(handle, 7, 0);
            }
        }
        state[2] = lbl_803E4044;
        state[3] = lbl_803E404C;
        FUN_80006810(obj, 0x42c);
        FUN_80006810(obj, 0x42d);
        break;
    case 1:
        if (lbl_803E4044 == (float)state[2])
        {
            if (handle != 0)
            {
                FUN_8016d994(handle, 7, 8);
            }
            if (*state == 0)
            {
                walk = FUN_80017624(0, '\x01');
                *state = (int)walk;
            }
            if (*state != 0)
            {
                FUN_800175b0(*state, 2);
                FUN_800175ec((double)((GameObject*)obj)->anim.localPosX,
                             (double)(((GameObject*)obj)->anim.localPosY - lbl_803E4050),
                             (double)((GameObject*)obj)->anim.localPosZ, (int*)*state);
                FUN_8001759c(*state, 0, 0xff, 0xff, 0xff);
                FUN_80017588(*state, 0, 0xff, 0xff, 0xff);
                FUN_800175d0((double)lbl_803E4054, (double)lbl_803E4058, *state);
                FUN_800175bc(*state, 1);
                FUN_800175cc((double)lbl_803E4044, *state, '\x01');
                FUN_8001753c(*state, 0, 0);
                FUN_800175d8(*state, 1);
            }
            scale = lbl_803E4044;
            if (lbl_803E4044 == (float)state[2])
            {
                state[4] = lbl_803E4048;
                state[1] = scale;
            }
            state[2] = lbl_803E4048;
            dC = (double)lbl_803E405C;
            state[3] = lbl_803E405C;
            iTmp = 0;
            colorTbl = &DAT_80321688;
            dB = (double)lbl_803E4040;
            dE = (double)lbl_803E4060;
            walk = state;
            dD = DOUBLE_803e4068;
            do
            {
                *(u16*)(walk + 0xd) = 0xc000;
                dA = (double)fcos16Precise();
                state[9] = (int)(*scaleTbl * (float)((double)(float)(dC + dA) * dB));
                state[5] = *colorTbl;
                rand = randomGetRange(0x78, 0x7f);
                randBits = (double)(int)(iTmp * rand);
                *(short*)(walk + 0xf) = (short)(int)(dE + (double)(float)(randBits));
                walk = (int*)((int)walk + 2);
                scaleTbl = scaleTbl + 1;
                state = state + 1;
                colorTbl = colorTbl + 1;
                iTmp = iTmp + 1;
            }
            while (iTmp < 4);
            FUN_80006824(obj, 0x42c);
            FUN_80006824(obj, 0x42d);
        }
        break;
    case 2:
        if (handle != 0)
        {
            FUN_8016d994(handle, 7, 0);
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
        FUN_80006810(obj, 0x42c);
        FUN_80006810(obj, 0x42d);
        break;
    case 3:
        if (handle != 0)
        {
            FUN_8016d994(handle, 7, 8);
        }
        if (*state == 0)
        {
            walk = FUN_80017624(0, '\x01');
            *state = (int)walk;
        }
        if (*state != 0)
        {
            FUN_800175b0(*state, 2);
            FUN_800175ec((double)((GameObject*)obj)->anim.localPosX,
                         (double)(((GameObject*)obj)->anim.localPosY - lbl_803E4050),
                         (double)((GameObject*)obj)->anim.localPosZ, (int*)*state);
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
        dE = (double)lbl_803E405C;
        state[3] = lbl_803E405C;
        iTmp = 0;
        colorTbl = &DAT_80321688;
        dD = (double)lbl_803E4040;
        walk = state;
        do
        {
            *(u16*)(state + 0xd) = 0;
            dB = (double)fcos16Precise();
            walk[9] = (int)(*scaleTbl * (float)((double)(float)(dE + dB) * dD));
            walk[5] = *colorTbl;
            state = (int*)((int)state + 2);
            scaleTbl = scaleTbl + 1;
            walk = walk + 1;
            colorTbl = colorTbl + 1;
            iTmp = iTmp + 1;
        }
        while (iTmp < 4);
        FUN_80006824(obj, 0x42d);
        FUN_80006824(obj, 0x42c);
        break;
    case 4:
        state[2] = lbl_803E4064;
        dE = (double)lbl_803E405C;
        state[3] = lbl_803E405C;
        state[4] = scale;
        iTmp = 0;
        scaleTbl = (float*)&DAT_80321698;
        colorTbl = &DAT_803216a8;
        dB = (double)lbl_803E4040;
        dC = (double)lbl_803E4060;
        walk = state;
        dD = DOUBLE_803e4068;
        do
        {
            *(u16*)(state + 0xd) = 0xc000;
            dA = (double)fcos16Precise();
            walk[9] = (int)(*scaleTbl * (float)((double)(float)(dE + dA) * dB));
            walk[5] = *colorTbl;
            rand = randomGetRange(0x78, 0x7f);
            randBits2 = (double)(int)(iTmp * rand);
            *(short*)(state + 0xf) = (short)(int)(dC + (double)(float)(randBits2));
            state = (int*)((int)state + 2);
            scaleTbl = scaleTbl + 1;
            walk = walk + 1;
            colorTbl = colorTbl + 1;
            iTmp = iTmp + 1;
        }
        while (iTmp < 4);
        FUN_80006824(obj, 0x42d);
        FUN_80006824(obj, 0x42c);
        break;
    case 5:
        state[2] = lbl_803E4044;
        state[3] = lbl_803E404C;
        state[4] = lbl_803E4064;
        FUN_80006810(obj, 0x42c);
        FUN_80006810(obj, 0x42d);
        break;
    case 6:
        iTmp = 0;
        scaleTbl = (float*)&DAT_80321698;
        colorTbl = &DAT_803216a8;
        dD = (double)lbl_803E405C;
        dE = (double)lbl_803E4040;
        walk = state;
        do
        {
            *(u16*)(state + 0xd) = 0x4000;
            dB = (double)fcos16Precise();
            walk[9] = (int)(*scaleTbl * (float)((double)(float)(dD + dB) * dE));
            walk[5] = *colorTbl;
            state = (int*)((int)state + 2);
            scaleTbl = scaleTbl + 1;
            walk = walk + 1;
            colorTbl = colorTbl + 1;
            iTmp = iTmp + 1;
        }
        while (iTmp < 4);
        break;
    case 7:
        if (handle != 0)
        {
            FUN_8016d994(handle, 7, 0);
        }
        if (*state != 0)
        {
            FUN_800175cc((double)lbl_803E4040, *state, '\0');
        }
        scale = lbl_803E4044;
        state[2] = lbl_803E4044;
        state[3] = scale;
        state[4] = scale;
        state[1] = scale;
        *(u8*)(state + 0x17) = *(u8*)(state + 0x17) | 1;
        *(u8*)((int)state + 0x5d) = *(u8*)((int)state + 0x5d) | 1;
        *(u8*)((int)state + 0x5e) = *(u8*)((int)state + 0x5e) | 1;
        *(u8*)((int)state + 0x5f) = *(u8*)((int)state + 0x5f) | 1;
    }
    FUN_80286884();
    return;
}

void mikabombshadow_update(int* obj);

void FUN_801713ac(u64 param_1, double param_2, double param_3, u64 param_4,
                  u64 param_5, u64 param_6, u64 param_7, u64 param_8,
                  u32 obj)
{
    extern u64 ObjHits_DisableObject(); /* #57 */
    short seqVal;
    char counter;
    u32 sndHandle;
    int iTmp;
    int placement;
    int extra;
    u64 hitState;

    extra = *(int*)&((GameObject*)obj)->extra;
    placement = *(int*)&((GameObject*)obj)->anim.placementData;
    iTmp = (int)((GameObject*)obj)->anim.modelInstance->extraSetupData;
    FUN_80017a98();
    FUN_80017a90();
    FUN_80017a98();
    FUN_80017a90();
    hitState = ObjHits_DisableObject(obj);
    if ((*(u16*)&((GameObject*)obj)->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA) != 0)
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
        hitState = FUN_800e842c(obj);
    }
    sndHandle = (u32) * (short*)(placement + 0x1e);
    if (sndHandle != 0xffffffff)
    {
        hitState = FUN_80017698(sndHandle, 1);
    }
    sndHandle = (u32) * (short*)(placement + 0x2c);
    if (0 < sndHandle)
    {
        FUN_80017688(sndHandle);
    }
    seqVal = *(short*)(iTmp + 2);
    if (seqVal == 4)
    {
        seqVal = ((GameObject*)obj)->anim.seqId;
        if (seqVal == 0x3cd)
        {
            iTmp = FUN_80017a98();
            FUN_80294d60(hitState, param_2, param_3, param_4, param_5, param_6, param_7, param_8, iTmp, 2);
            sndHandle = FUN_80017a98();
            FUN_80006824(sndHandle, SFXen_treadlpc);
            FUN_80081118((double)lbl_803E40EC, obj, 1, 0x28);
        }
        else if ((seqVal < 0x3cd) && (seqVal == 0xb))
        {
            sndHandle = FUN_80017a98();
            hitState = FUN_80006824(sndHandle, SFXen_treadlpc);
            iTmp = FUN_80017a98();
            FUN_80294d60(hitState, param_2, param_3, param_4, param_5, param_6, param_7, param_8, iTmp, 4);
            FUN_80081118((double)lbl_803E40EC, obj, 3, 0x28);
        }
        else
        {
            sndHandle = FUN_80017a98();
            FUN_80006824(sndHandle, SFXen_waterblock_stop);
            FUN_80081118((double)lbl_803E40EC, obj, 0xff, 0x28);
        }
    }
    else if ((seqVal < 4) && (seqVal == 1))
    {
        seqVal = ((GameObject*)obj)->anim.seqId;
        if (seqVal == 0x319)
        {
            FUN_80006824(obj, SFXwp_gprop2_c);
            FUN_80017698(0x3e9, 1);
            *(u16*)(extra + 0x3c) = 0x4b0;
            FUN_80081118((double)lbl_803E40EC, obj, 0xff, 0x28);
        }
        else
        {
            if (seqVal < 0x319)
            {
                if (seqVal == 0x5a)
                {
                    FUN_80006824(obj, SFXen_treadlpc);
                    FUN_80081118((double)lbl_803E40EC, obj, 2, 0x28);
                    goto LAB_801725bc;
                }
                if ((seqVal < 0x5a) && (seqVal == 0x22))
                {
                    FUN_80006824(obj, SFXen_treadlpc);
                    FUN_80081118((double)lbl_803E40EC, obj, 0xff, 0x28);
                    goto LAB_801725bc;
                }
            }
            else if (seqVal == 0x6a6)
            {
                sndHandle = FUN_80017690(0x86a);
                counter = sndHandle;
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
















int animatedobj_getExtraSize(void) { return 0x140; }

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

void fn_801719F8(void) { objRenderFn_8003b8f4(lbl_803E3420); }

void gcbaddieshield_update(int* obj);




void mikabombshadow_init(int* obj);

void StaticCamera_init(int* obj, int* params, int flag);


void animatedobj_free(int* obj, int seqFlag)
{
    extern void Obj_FreeObject(u8* obj); /* #57 */
    (*gObjectTriggerInterface)
        ->freeState(((GameObject*)obj)->extra);
    ((void (*)(int*, int, int, int, int))((void**)*(void**)gTitleMenuControlInterfaceCopy)[2])(obj, 0xffff, 0, 0, 0);
    Sfx_RemoveLoopedObjectSoundForObject(obj);
    Sfx_StopObjectChannel(obj, 0x7f);
    if (((GameObject*)obj)->anim.seqId == 0x774 && ((GameObject*)obj)->childCount != 0)
    {
        Obj_FreeObject(((GameObject*)obj)->childObjs[0]);
        ObjLink_DetachChild(obj, *(int*)&((GameObject*)obj)->childObjs[0]);
    }
    if (seqFlag != 0)
    {
        clearCurSeqNo();
    }
}

void dll_F7_init(int* obj, int* params);


void animatedobj_init(int* obj, int* params)
{
    int* state;
    int f4;
    objSetSlot(obj, 0x64);
    state = ((GameObject*)obj)->extra;
    ((AnimatedobjState*)state)->unk6A = ((AnimatedobjPlacement*)params)->unk1A;
    ((AnimatedobjState*)state)->unk6E = -1;
    {
        f32 d = lbl_803E3228;
        ((AnimatedobjState*)state)->unk24 = d / (d + (f32)(u32) * (u8*)((char*)params + 0x24));
    }
    ((AnimatedobjState*)state)->unk28 = -1;
    ((AnimatedobjState*)state)->unk98 = 0;
    ((AnimatedobjState*)state)->unk94 = 0;
    ((AnimatedobjState*)state)->unk116 = 0;
    ((AnimatedobjState*)state)->unk114 = 0;
    ((AnimatedobjState*)state)->unkE8 = 0;
    f4 = ((GameObject*)obj)->unkF4;
    if (f4 == 0 && ((AnimatedobjPlacement*)params)->unk18 != 1)
    {
        (*gObjectTriggerInterface)
            ->loadAnimData((u8*)state, (u8*)params);
        ((GameObject*)obj)->unkF4 = ((AnimatedobjPlacement*)params)->unk18 + 1;
    }
    else if (f4 != 0 && ((AnimatedobjPlacement*)params)->unk18 != f4 - 1)
    {
        (*gObjectTriggerInterface)->freeState((u8*)state);
        if (((AnimatedobjPlacement*)params)->unk18 != -1)
        {
            (*gObjectTriggerInterface)
                ->loadAnimData((u8*)state, (u8*)params);
        }
        ((GameObject*)obj)->unkF4 = ((AnimatedobjPlacement*)params)->unk18 + 1;
    }
    {
        ObjModelState* modelState = ((GameObject*)obj)->anim.modelState;
        if (modelState != NULL)
        {
            modelState->shadowTintA = 0x64;
            ((GameObject*)obj)->anim.modelState->shadowTintB = 0x96;
        }
    }
    Obj_SetModelRenderOpAlpha(obj, 0xff);
}


void mikabomb_init(int* obj);

#pragma opt_loop_invariants on
void animatedobj_update(int* obj)
{
    extern void Obj_FreeObject(u8* obj); /* #57 */
    ObjSeqState* seq = ((GameObject*)obj)->extra;
    int* params = *(int**)&((GameObject*)obj)->anim.placementData;

    if (params != NULL && ((AnimatedobjPlacement*)params)->unk18 != -1)
    {
        int res;
        int count;
        res = (*gObjectTriggerInterface)->update((u8*)obj, timeDelta);
        if (res != 0 && ((GameObject*)obj)->seqIndex == -2)
        {
            int slot8 = *(s8*)((char*)seq + 0x57);
            int* match = NULL;
            int* list;
            int slot;
            int cnt;
            list = ObjList_GetObjects(&res, &count);
            cnt = 0;
            res = 0;
            slot = slot8;
            slot |= slot8;
            for (; res < count; res++)
            {
                int* other = (int*)*list;
                if (((GameObject*)other)->seqIndex == slot8)
                {
                    match = other;
                }
                if (((GameObject*)other)->seqIndex == -2 && ((GameObject*)other)->anim.classId == 0x10)
                {
                    ObjSeqState* otherSeq = *(ObjSeqState**)&((GameObject*)other)->extra;
                    if (slot == (s8)otherSeq->slot)
                    {
                        cnt++;
                    }
                }
                list++;
            }
            if (cnt <= 1 && match != NULL && ((GameObject*)match)->seqIndex != -1)
            {
                ((GameObject*)match)->seqIndex = -1;
                (*gObjectTriggerInterface)->endSequence(slot);
            }
            ((GameObject*)obj)->seqIndex = -1;
            ((GameObject*)obj)->objectFlags |= ANIMATEDOBJ_OBJFLAG_UPDATE_DISABLED;
            ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        }
        switch (((GameObject*)obj)->anim.seqId)
        {
        case 0x774:
        {
            int i;
            for (i = 0; i < seq->eventCount; i++)
            {
                int b = seq->eventIds[i];
                switch (b)
                {
                case 0xa:
                    if ((u8)Obj_IsLoadingLocked() != 0)
                    {
                        void* alloc;
                        int* child;
                        alloc = Obj_AllocObjectSetup(0x18, 0x69);
                        child = Obj_SetupObject(alloc, 4, -1, -1, 0);
                        ObjLink_AttachChild(obj, child, 0);
                        ObjAnim_SetCurrentMove((int)child, 0, lbl_803E322C, 0);
                        ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(
                            (int)child, lbl_803E3228, timeDelta, NULL);
                    }
                    break;
                case 0xb:
                    if (((GameObject*)obj)->childCount != 0)
                    {
                        Obj_FreeObject(((GameObject*)obj)->childObjs[0]);
                        ObjLink_DetachChild(obj, *(int*)&((GameObject*)obj)->childObjs[0]);
                    }
                    break;
                }
            }
            break;
        }
        }
    }
}
#pragma opt_loop_invariants reset

void animatedobj_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    f32 mWorld[12];
    f32 mTransPlayer[12];
    f32 mWorldCombined[12];
    f32 mTransNeg[12];
    f32 mRotY[12];
    f32 mRotZ[12];
    f32 mTransPos[12];
    f32 mCam[12];
    f32 mA[12];
    f32 mB[12];
    f32 mC[12];
    f32 mD[12];
    f32 mFinal[12];

    ObjSeqState* seq = ((GameObject*)obj)->extra;
    if ((seq->unk7F & 4) != 0)
    {
        int* prm;
        s16* cam;
        Obj_BuildWorldTransformMatrix(obj, mWorld, 0);
        prm = *(int**)&((GameObject*)obj)->anim.placementData;
        PSMTXTrans(mTransPlayer, -(((AnimatedobjPlacement*)prm)->posX - playerMapOffsetX),
                   -((AnimatedobjPlacement*)prm)->posY,
                   -(((AnimatedobjPlacement*)prm)->posZ - playerMapOffsetZ));
        PSMTXConcat(mTransPlayer, mWorld, mWorldCombined);
        cam = (s16*)(*gCameraInterface)->getCamera();
        ((GameObject*)cam)->anim.rotY += 0x8000;
        ((GameObject*)cam)->anim.rootMotionScale = lbl_803E3228;
        Obj_BuildWorldTransformMatrix((int*)cam, mCam, 0);
        ((GameObject*)cam)->anim.rotY += 0x8000;
        ((GameObject*)cam)->anim.rootMotionScale = lbl_803E322C;
        PSMTXTrans(mTransNeg, -mCam[3], -mCam[7], -mCam[11]);
        PSMTXRotRad(mRotY, 'y', lbl_803E3230);
        PSMTXRotRad(mRotZ, 'z', lbl_803E3230);
        PSMTXTrans(mTransPos, mCam[3], mCam[7], mCam[11]);
        PSMTXConcat(mTransNeg, mCam, mA);
        PSMTXConcat(mRotY, mA, mB);
        PSMTXConcat(mRotZ, mB, mC);
        PSMTXConcat(mTransPos, mC, mD);
        PSMTXConcat(mD, mWorldCombined, mFinal);
        objSetMtxFn_800412d4(mFinal);
        objRenderModel(obj);
    }
    else
    {
        ((void (*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E3228);
    }
}



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
