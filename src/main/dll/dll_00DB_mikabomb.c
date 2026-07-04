/*
 * mikabomb (DLL 0x00DB) - aggregate object DLL.
 *
 * Owns the mikabomb projectile (mikabomb_*) and the staticCamera group
 * helper, plus the ObjectDescriptor tables that register a large set of
 * sibling objects living in adjacent DLLs (kaldachompspit, pinponspike,
 * pollen / pollenfragment, mikabombshadow, staticCamera, gcbaddieshield,
 * baddieinterestp, animatedobj, dim2roofrub, depthoffieldpoint, staff,
 * fireball, flamethrowerspe, shield, curve, restartmarker, checkpoint4
 * and dll_F7).
 *
 * mikabomb: a thrown bomb that arcs under gravity (velocity * timeDelta
 * each tick, vertical speed clamped), fades its alpha out over its
 * lifetime, and on impact with the player (or when it reaches the ground
 * plane sampled at init) plays SFXen_weetinklp22, expands its hit sphere,
 * kicks a camera shake and spawns its explosion effect before freeing.
 * Resource 0x5b is acquired at init.
 */
#include "main/dll/xyzanimator.h"
#include "main/dll/genpropswgpipe_struct.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/genprops.h"
#include "main/dll_000A_expgfx.h"
#include "main/resource.h"
#include "main/objprint.h"
#include "main/dll/dll_00C8_depthoffieldpoint.h"
#include "main/dll/dll_00E3_fireball.h"
#include "main/dll/dll_00E4_flamethrowerspe.h"
#include "main/obj_placement.h"

/* object group this object joins while active */
#define MIKABOMB_OBJGROUP 7
extern int randomGetRange(int lo, int hi);
extern u32 ObjHitbox_SetSphereRadius();
extern u32 ObjHits_SetHitVolumeSlot();
extern ModgfxInterface** gModgfxInterface;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E31C0;
extern f32 timeDelta;
extern void* Obj_GetPlayerObject(void);
extern void ObjGroup_RemoveObject(u32 obj, int group);
extern void ObjGroup_AddObject(u32 obj, int group);
extern int Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int size, int b);
extern void Sfx_StopObjectChannel(int* obj, int channel);
extern void gcbaddieshield_update(int* obj);








extern void shield_update(int* obj);
extern void dll_F7_update(int* obj);
extern void dll_F7_init(int* obj, int* params);
extern int fn_80065684(int a, f32 b, f32 val, f32 d, f32* out, int e);
extern u32 lbl_803E31A0;
extern f32 gMikaBombHitSphereRadiusScale;
extern f32 gMikaBombCameraShakeMagnitude;
extern f32 gMikaBombCameraShakeDuration;
extern f32 gMikaBombCameraShakeFalloff;
extern f32 lbl_803E31C4;
extern f32 lbl_803E31C8;
extern f32 gMikaBombGravityAccel;
extern f32 gMikaBombMinFallVelocity;
extern f32 lbl_803E31D4;
extern void CameraShake_Start(f32 magnitude, f32 duration, f32 falloff);
extern int loadObjectAtObject(int* obj, void* params);

void mikabomb_hitDetect(void)
{
}

void mikabomb_free(int obj, int mode)
{
    void** inner = ((GameObject*)obj)->extra;
    if (inner[0] != NULL && mode == 0)
    {
        Obj_FreeObject(inner[0]);
        inner[0] = NULL;
    }
    (*gModgfxInterface)->detachSource((void*)obj);
}

int mikabomb_getExtraSize(void) { return 0x10; }
int mikabomb_getObjectTypeId(void) { return 0x0; }

void mikabomb_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E31C0);
}

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

typedef struct MikabombState
{
    int* shadowObj; /* 0x00: spawned shadow-bomb object */
    f32 groundY;    /* 0x04: ground-plane Y sampled at init */
    void* resource; /* 0x08: Resource_Acquire(0x5b) handle (effect vtable) */
    u8 exploded;    /* 0x0C: set once the bomb has detonated */
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
} MikabombState;

void staticCamera_free(int obj)
{
    ObjGroup_RemoveObject(obj, MIKABOMB_OBJGROUP);
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

void staticCamera_init(short* obj, int params, int deferAdd)
{
    u8* camData;

    *obj = -*(short*)(params + 0x1c);
    obj[1] = -*(short*)(params + 0x1e);
    obj[2] = -*(short*)(params + 0x20);
    camData = *(u8**)(obj + 0x5c);
    *camData = *(u8*)(params + 0x19);
    *(float*)(camData + 4) =
        (float)((double)(u32) * (u8*)(params + 0x1a));
    camData[1] = 0;
    if (deferAdd == 0)
    {
        ObjGroup_AddObject((int)obj, MIKABOMB_OBJGROUP);
    }
    return;
}

void mikabombshadow_update(int* obj);

void mikabomb_release(void)
{
}

void mikabomb_initialise(void)
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

void mikabombshadow_init(int* obj);

void StaticCamera_init(int* obj, int* params, int flag);

void mikabomb_update(int* obj)
{
    extern void objMove(int* obj, f32 x, f32 y, f32 z); /* #57 */
    extern void Sfx_PlayFromObject(int* obj, int sfx); /* #57 */
    extern void Obj_FreeObject(int* obj); /* #57 */
    extern void ObjHits_EnableObject(); /* #57 */
    extern void ObjHits_DisableObject(); /* #57 */
    int* state = ((GameObject*)obj)->extra;
    u32 timer = ((GameObject*)obj)->anim.alpha;

    if (timer < 0xff)
    {
        f32 t = timer;
        f32 dec;
        if (t - (dec = lbl_803E31C4 * timeDelta) > lbl_803E31C8)
        {
            ((GameObject*)obj)->anim.alpha = timer - dec;
        }
        else
        {
            Sfx_StopObjectChannel(obj, 0x7f);
            ((GameObject*)obj)->anim.alpha = 0;
            Obj_FreeObject(obj);
            return;
        }
    }
    else
    {
        ((GameObject*)obj)->anim.velocityY -= gMikaBombGravityAccel * timeDelta;
        if (((GameObject*)obj)->anim.velocityY < *(f32*)&gMikaBombMinFallVelocity)
        {
            ((GameObject*)obj)->anim.velocityY = gMikaBombMinFallVelocity;
        }
        objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta,
                ((GameObject*)obj)->anim.velocityY * timeDelta,
                ((GameObject*)obj)->anim.velocityZ * timeDelta);
    }

    if (((GameObject*)obj)->anim.alpha == 0xff || ((MikabombState*)state)->exploded != 0)
    {
        u32 localB;
        u32 localA;
        ObjHits_SetHitVolumeSlot(obj, 5, 1, 0);
        ObjHits_EnableObject(obj);
        if (((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->lastHitObject != 0 &&
            ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->lastHitObject == (int)Obj_GetPlayerObject())
        {
            if (((GameObject*)obj)->anim.alpha == 0xff)
            {
                int* st = ((GameObject*)obj)->extra;
                u32 rnd;
                localB = lbl_803E31A0;
                Sfx_PlayFromObject(obj, SFXen_weetinklp22);
                rnd = randomGetRange(0, 2);
                ((void (*)(int*, u32, int, int, int, u32*))((int*)*(int**)((MikabombState*)st)->resource)[1])(obj, rnd, 0, 2, -1, &localB);
                ObjHitbox_SetSphereRadius(
                    obj, (s32)(gMikaBombHitSphereRadiusScale * (f32)(u32)((GameObject*)obj)->anim.modelInstance->primaryHitboxRadius));
                CameraShake_Start(gMikaBombCameraShakeMagnitude, gMikaBombCameraShakeDuration, gMikaBombCameraShakeFalloff);
                ((GameObject*)obj)->anim.alpha = 0xfe;
                Obj_FreeObject((int*)*st);
                *st = 0;
            }
            ObjHits_DisableObject(obj);
        }
        else
        {
            if (((GameObject*)obj)->anim.localPosY <= ((MikabombState*)state)->groundY &&
                ((GameObject*)obj)->anim.alpha == 0xff)
            {
                int* st = ((GameObject*)obj)->extra;
                u32 rnd;
                localA = lbl_803E31A0;
                Sfx_PlayFromObject(obj, SFXen_weetinklp22);
                rnd = randomGetRange(0, 2);
                ((void (*)(int*, u32, int, int, int, u32*))((int*)*(int**)((MikabombState*)st)->resource)[1])(obj, rnd, 0, 2, -1, &localA);
                ObjHitbox_SetSphereRadius(
                    obj, (s32)(gMikaBombHitSphereRadiusScale * (f32)(u32)((GameObject*)obj)->anim.modelInstance->primaryHitboxRadius));
                CameraShake_Start(gMikaBombCameraShakeMagnitude, gMikaBombCameraShakeDuration, gMikaBombCameraShakeFalloff);
                ((GameObject*)obj)->anim.alpha = 0xfe;
                Obj_FreeObject((int*)*st);
                *st = 0;
                ((MikabombState*)state)->exploded = 1;
            }
        }
    }
}

void mikabomb_init(int* obj)
{
    extern u64 ObjHits_DisableObject(); /* #57 */
    int* state = ((GameObject*)obj)->extra;
    f32 out;
    ObjPlacement* alloc;
    f32 fz;

    ObjHits_DisableObject(obj);
    ((GameObject*)obj)->anim.alpha = 0xff;
    fz = lbl_803E31C8;
    ((GameObject*)obj)->anim.velocityX = fz;
    ((GameObject*)obj)->anim.velocityY = lbl_803E31D4;
    ((GameObject*)obj)->anim.velocityZ = fz;
    ((GameObject*)obj)->anim.rotY = -0x4000;
    ((GameObject*)obj)->anim.rotX = 0;
    ((GameObject*)obj)->anim.rotZ = 0;
    fn_80065684((int)obj, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                ((GameObject*)obj)->anim.localPosZ, &out, 0);
    ((MikabombState*)state)->groundY = ((GameObject*)obj)->anim.localPosY - out;
    if ((u8)Obj_IsLoadingLocked() != 0)
    {
        alloc = Obj_AllocObjectSetup(0x20, 0xc);
        alloc->posX = ((GameObject*)obj)->anim.localPosX;
        alloc->posY = ((GameObject*)obj)->anim.localPosY;
        alloc->posZ = ((GameObject*)obj)->anim.localPosZ;
        alloc->color[0] = 1;
        alloc->color[1] = 1;
        alloc->color[2] = 0xff;
        alloc->color[3] = 0xff;
        *state = loadObjectAtObject(obj, alloc);
        ((GameObject*)*state)->ownerObj = obj;
    }
    else
    {
        *state = 0;
    }
    ((MikabombState*)state)->resource = Resource_Acquire(0x5b, 1);
    ((MikabombState*)state)->exploded = 0;
}

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
