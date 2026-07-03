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

extern int* Obj_SetupObject(void* setup, int mode, int mapLayer, int objIndex, void* parent);
extern void ObjGroup_RemoveObject(u32 obj, int group);
extern void ObjGroup_AddObject(u32 obj, int group);
extern u64 ObjLink_DetachChild();
extern u32 ObjLink_AttachChild();
extern u32 fcos16Precise();
extern void** gTitleMenuControlInterfaceCopy;
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

void mikabombshadow_update(int* obj);
















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
