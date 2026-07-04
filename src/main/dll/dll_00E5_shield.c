/*
 * DLL 0x00E5 — the player's energy-shield object plus the bank of
 * ObjectDescriptors this DLL registers (kaldachompspit, pinponspike,
 * pollen, pollenfragment, mikabomb/mikabombshadow, staticcamera,
 * gcbaddieshield, baddieinterestp, animatedobj, dim2roofrub,
 * depthoffieldpoint, staff, fireball, flamethrowerspe, shield, curve,
 * restartmarker, dll_F7, checkpoint4). Most descriptor callbacks live in
 * sibling DLLs and are only referenced here by address.
 *
 * The shield itself (seqId 0x836 uses staff-mode 5, otherwise mode 7) is
 * a four-segment ring driven by staffFn_80170380: each mode sets the
 * per-segment fade/scale targets in ShieldState, drives a point light
 * (modelLightStruct_*) and the 0x42C/0x42D loop sfx, and seeds the
 * fcos16 wobble for the four segments. shield_update advances the fade
 * toward its target, modulates alpha from a random flicker, and updates
 * the segment cosine; shield_render re-renders the four segments with
 * per-segment rotation and (off-HUD) spawns particle fx 2028 at the
 * staff tips.
 *
 * staticCamera_* implements the static-camera placement object (copies
 * negated rotation from its placement and joins object group 7).
 * staffFn_80170380 (vtbl/cmd dispatch 0..7) is shared with the staff
 * object and dispatched via jumptable_80320AA0.
 *
 * TU: 0x8016B230–0x8016B2E0.
 */
#include "main/dll/xyzanimator.h"
#include "main/dll/genpropswgpipe_struct.h"
#include "main/dll/player_objects.h"
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/dll/genprops.h"
#include "main/dll_000A_expgfx.h"
#include "main/objprint.h"
#include "main/objlib.h"
#include "main/dll/dll_00C8_depthoffieldpoint.h"
#include "main/dll/dll_00E3_fireball.h"
#include "main/dll/dll_00E4_flamethrowerspe.h"
#include "main/dll/dll_00E5_shield.h"
#include "main/dll/dll_00F7_dllf7.h"
#include "main/audio/sfx_trigger_ids.h"

/* object group this object joins while active */
#define SHIELD_OBJGROUP 7
extern int randomGetRange(int lo, int hi);
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

typedef struct ShieldState
{
    u8 pad0[0x4 - 0x0];
    f32 fadeValue; /* 0x4: current shield fade, advanced toward fadeTarget by fadeRate*dt */
    f32 fadeTarget; /* 0x8 */
    f32 fadeRate; /* 0xC */
    s32 fadeMax; /* 0x10: divisor for alpha (fadeValue/fadeMax) */
    /* Per-segment parameters for the four ring segments, laid out
     * structure-of-arrays (each array indexed by segment 0..3). */
    f32 segScale[4]; /* 0x14: per-segment scale (feeds anim.rootMotionScale) */
    f32 segAlpha[4]; /* 0x24: per-segment alpha factor (feeds anim.alpha) */
    s16 segPhase[4]; /* 0x34: fcos16 wobble phase, advanced by segRate*dt */
    s16 segSeed[4]; /* 0x3C: random per-segment cosine seed */
    s16 segRotX[4]; /* 0x44: per-segment X rotation */
    s16 segRotY[4]; /* 0x4C: per-segment Y rotation */
    s16 segRotZ[4]; /* 0x54: per-segment Z rotation */
    u8 flags0; /* 0x5C: segment-0 "fully faded" bit0 */
    u8 flags1; /* 0x5D */
    u8 flags2; /* 0x5E */
    u8 flags3; /* 0x5F */
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

STATIC_ASSERT(offsetof(ShieldState, fadeValue) == 0x04);
STATIC_ASSERT(offsetof(ShieldState, fadeMax) == 0x10);
STATIC_ASSERT(offsetof(ShieldState, segScale) == 0x14);
STATIC_ASSERT(offsetof(ShieldState, segAlpha) == 0x24);
STATIC_ASSERT(offsetof(ShieldState, segPhase) == 0x34);
STATIC_ASSERT(offsetof(ShieldState, segSeed) == 0x3C);
STATIC_ASSERT(offsetof(ShieldState, segRotX) == 0x44);
STATIC_ASSERT(offsetof(ShieldState, segRotY) == 0x4C);
STATIC_ASSERT(offsetof(ShieldState, segRotZ) == 0x54);
STATIC_ASSERT(offsetof(ShieldState, flags0) == 0x5C);

extern int* Obj_SetupObject(void* setup, int mode, int mapLayer, int objIndex, void* parent);
extern int Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int size, int b);
extern void ModelLightStruct_free(void* p);
extern int Sfx_StopFromObject(int obj, int sfxId);
extern void gcbaddieshield_update(int* obj);











extern int* Obj_GetActiveModel(int obj);
extern void postRenderSetAlphaBlendState(void);
extern void ObjModel_SetPostRenderCallback(int* model, void* callback);
extern int getHudHiddenFrameCount(void);
extern void vecRotateZXY(int* obj, f32* p);
extern f32 fcos16(u16 angle);
extern void Sfx_SetObjectSfxVolume(s16* obj, int sfx, int vol, f32 ratio);
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
extern const f32 lbl_803E33C8;
extern f32 lbl_803E33CC;

void staticCamera_free(int obj)
{
    ObjGroup_RemoveObject(obj, SHIELD_OBJGROUP);
}

void staticCamera_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        FUN_8003b818(obj);
    }
}

void staticCamera_init(short* state, int placement, int addToGroup)
{
    u8* dst;

    *state = -*(short*)(placement + 0x1c);
    state[1] = -*(short*)(placement + 0x1e);
    state[2] = -*(short*)(placement + 0x20);
    dst = *(u8**)(state + 0x5c);
    *dst = *(u8*)(placement + 0x19);
    *(float*)(dst + 4) = (f32)(u32) * (u8*)(placement + 0x1a);
    dst[1] = 0;
    if (addToGroup == 0)
    {
        ObjGroup_AddObject((int)state, SHIELD_OBJGROUP);
    }
}

void mikabombshadow_update(int* obj);

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
    Sfx_StopFromObject(obj, SFXTRIG_lrope_powerup);
    Sfx_StopFromObject(obj, SFXTRIG_lockon3_on);
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

void dim2roofrub_free(int* obj);

void staff_func10(int* obj, s32 v);
void staff_setHitReactValue(int* obj, s32 v);
void staff_addHitReactValue(int* obj, s32 delta);
void staff_getHitGeometryPoints(int* obj, f32* outA, f32* outB);
void staff_func15(int* obj, s16 idx, f32 f1, f32 f2);

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

void staffSetGlow(int* obj, u8 a, u8 b);

int* fn_801702D4(int* obj, f32 fv)
{
    void* alloc;
    int* new_obj;
    if ((u8)Obj_IsLoadingLocked() == 0) return NULL;
    alloc = Obj_AllocObjectSetup(36, 2102);
    ((ObjPlacement*)alloc)->posX = ((GameObject*)obj)->anim.worldPosX;
    ((ObjPlacement*)alloc)->posY = ((GameObject*)obj)->anim.worldPosY;
    ((ObjPlacement*)alloc)->posZ = ((GameObject*)obj)->anim.worldPosZ;
    ((ObjPlacement*)alloc)->color[0] = 1;
    ((ObjPlacement*)alloc)->color[1] = 1;
    ((ObjPlacement*)alloc)->color[3] = 255;
    new_obj = Obj_SetupObject(alloc, 5, -1, -1, 0);
    if (new_obj != NULL)
    {
        ((GameObject*)new_obj)->anim.rootMotionScale = fv;
    }
    return new_obj;
}

void gcbaddieshield_update(int* obj);




void mikabombshadow_init(int* obj);

void StaticCamera_init(int* obj, int* params, int flag);





void mikabomb_init(int* obj);

void baddieinterestp_update(int* obj);



void shield_update(int* obj)
{
    f32* tbl = lbl_80320A28;
    f32* state = ((GameObject*)obj)->extra;

    if (state[1] != state[2])
    {
        state[1] = state[3] * timeDelta + state[1];
        if (state[3] > lbl_803E33AC)
        {
            if (state[1] >= state[2])
            {
                state[1] = state[2];
            }
            ((ShieldState*)state)->flags0 &= ~1;
            ((ShieldState*)state)->flags1 &= ~1;
            ((ShieldState*)state)->flags2 &= ~1;
            ((ShieldState*)state)->flags3 &= ~1;
        }
        else
        {
            if (state[1] <= state[2])
            {
                state[1] = state[2];
                ((ShieldState*)state)->flags0 |= 1;
                ((ShieldState*)state)->flags1 |= 1;
                ((ShieldState*)state)->flags2 |= 1;
                ((ShieldState*)state)->flags3 |= 1;
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
    Sfx_SetObjectSfxVolume((s16*)obj, SFXTRIG_lockon3_on, (s32)(lbl_803E33E8 * (state[1] / state[4])), lbl_803E33A8);
    if (((GameObject*)obj)->anim.alpha != 0)
    {
        ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
    }
    else
    {
        ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
    }
    {
        s16* ps;
        f32* t8;
        f32* pf;
        f32* t12;
        f32* t4;
        int i;
        i = 0;
        ps = (s16*)state;
        t8 = tbl + 8;
        pf = state;
        t12 = tbl + 12;
        t4 = tbl + 4;
        for (; i < 4; i++)
        {
            ps[26] = (f32)ps[30] * timeDelta + ps[26];
            if (((GameObject*)obj)->anim.seqId == 2102)
            {
                f32 c = fcos16(ps[26]);
                c = c * lbl_803E33EC + lbl_803E33C4;
                pf[9] = *t8 * c;
                pf[5] = *t12;
            }
            else
            {
                f32 c = fcos16(ps[26]);
                f32 sum = lbl_803E33C4 + c;
                c = sum * lbl_803E33A8;
                pf[9] = *tbl * c;
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


typedef struct ShieldFxVec
{
    u8 pad[8];
    f32 alpha;
    f32 pos[3];
} ShieldFxVec;

void shield_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    u8* state = ((GameObject*)obj)->extra;
    s32 v = visible;
    if (v != 0)
    {
        u8 i;
        u8 j;
        s16 saved0;
        f32 savedF8;
        s16 saved2;
        s16 saved4;
        u8 hud;
        int* model;
        f32 dt;
        ShieldFxVec s;
        u8 savedB36;
        model = Obj_GetActiveModel((int)obj);
        savedF8 = ((GameObject*)obj)->anim.rootMotionScale;
        savedB36 = ((GameObject*)obj)->anim.alpha;
        saved0 = ((GameObject*)obj)->anim.rotX;
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
                if ((state[i + 0x5c] & 1) == 0)
                {
                    u32 k = i;
                    u32 off = k * 2;
                    ((GameObject*)obj)->anim.rotX = *(s16*)(state + off + 0x44);
                    ((GameObject*)obj)->anim.rotY = *(s16*)(state + off + 0x4c);
                    ((GameObject*)obj)->anim.rotZ = *(s16*)(state + off + 0x54);
                    *(s16*)(state + off + 0x44) = dt * lbl_803DBD78[k] + (f32) * (s16*)(state + off + 0x44);
                    *(s16*)(state + off + 0x4c) = dt * lbl_803DBD80[k] + (f32) * (s16*)(state + off + 0x4c);
                    *(s16*)(state + off + 0x54) = dt * lbl_803DBD88[k] + (f32) * (s16*)(state + off + 0x54);
                    {
                        u8* r = state + k * 4;
                        ((GameObject*)obj)->anim.rootMotionScale = *(f32*)(r + 0x24) * savedF8 *
                            (((ShieldState*)state)->fadeValue / *(f32*)&((ShieldState*)state)->fadeMax);
                        *(u8*)((char*)obj + 0x37) = *(f32*)(r + 0x14) * savedB36;
                    }
                    *(u16*)((char*)model + 0x18) &= ~0x8;
                    ((void (*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E33C4);
                }
            }
        }
        else
        {
            i = 0;
            for (; i < 4; i++)
            {
                if ((state[i + 0x5c] & 1) == 0)
                {
                    u32 k = i;
                    u32 off = k * 2 + 0x44;
                    ((GameObject*)obj)->anim.rotX = *(s16*)(state + off);
                    *(s16*)(state + off) = dt * lbl_803DBD70[k] + (f32) * (s16*)(state + off);
                    {
                        u8* r = state + k * 4;
                        ((GameObject*)obj)->anim.rootMotionScale = *(f32*)(r + 0x24) * savedF8;
                        *(u8*)((char*)obj + 0x37) = *(f32*)(r + 0x14) * savedB36;
                    }
                    *(u16*)((char*)model + 0x18) &= ~0x8;
                    ((void (*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E33C4);
                    if (hud == 0)
                    {
                        f32 cD;
                        f32 cC;
                        f32 cB;
                        f32 cA;
                        j = 0;
                        cA = lbl_803E33D8;
                        cB = lbl_803E33DC;
                        cC = lbl_803E33AC;
                        cD = lbl_803E33C4;
                        for (; j < 2; j++)
                        {
                            f32 f8v = ((GameObject*)obj)->anim.rootMotionScale;
                            s.pos[0] = cA * f8v;
                            s.pos[1] = cB * f8v;
                            s.pos[2] = cC;
                            ((GameObject*)obj)->anim.rotX += 32767;
                            vecRotateZXY(obj, s.pos);
                            s.pos[0] += ((GameObject*)obj)->anim.localPosX;
                            s.pos[1] += ((GameObject*)obj)->anim.localPosY;
                            s.pos[2] += ((GameObject*)obj)->anim.localPosZ;
                            s.alpha = cD;
                            (*gPartfxInterface)->spawnObject(obj, 2028, &s, 0x200001, -1,
                                                             NULL);
                        }
                    }
                }
            }
        }
        ((GameObject*)obj)->anim.rootMotionScale = savedF8;
        ((GameObject*)obj)->anim.alpha = savedB36;
        ((GameObject*)obj)->anim.rotX = saved0;
        ((GameObject*)obj)->anim.rotY = saved2;
        ((GameObject*)obj)->anim.rotZ = saved4;
    }
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

void staffFn_80170380(int* obj, int cmd)
{
    extern int objCreateLight(int* obj, int arg); /* #57 */
    extern void modelLightStruct_setDiffuseColor(int* light, int r, int g, int b, int a); /* #57 */
    extern void Sfx_PlayFromObject(int* obj, int sfx); /* #57 */
    f32* tbl = lbl_80320A28;
    u8* state = ((GameObject*)obj)->extra;
    int* glow;
    int* player = Obj_GetPlayerObject();
    glow = NULL;
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
            ((ShieldState*)state)->fadeTarget = v;
            ((ShieldState*)state)->fadeRate = v;
            *(f32*)&((ShieldState*)state)->fadeMax = v;
            ((ShieldState*)state)->fadeValue = v;
        }
        ((ShieldState*)state)->flags0 |= 1;
        ((ShieldState*)state)->flags1 |= 1;
        ((ShieldState*)state)->flags2 |= 1;
        ((ShieldState*)state)->flags3 |= 1;
        break;
    case 0:
        if (*(int**)state != NULL)
        {
            modelLightStruct_setEnabled(*(int*)state, 0, lbl_803E33A8);
        }
        if (lbl_803E33AC != ((ShieldState*)state)->fadeTarget)
        {
            f32 v = lbl_803E33B0;
            *(f32*)&((ShieldState*)state)->fadeMax = v;
            ((ShieldState*)state)->fadeValue = v;
            if (glow != NULL)
            {
                staffSetGlow(glow, 7, 0);
            }
        }
        ((ShieldState*)state)->fadeTarget = lbl_803E33AC;
        ((ShieldState*)state)->fadeRate = lbl_803E33B4;
        Sfx_StopFromObject((int)obj, SFXTRIG_lrope_powerup);
        Sfx_StopFromObject((int)obj, SFXTRIG_lockon3_on);
        break;
    case 1:
        if (lbl_803E33AC == ((ShieldState*)state)->fadeTarget)
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
                if (v1 == ((ShieldState*)state)->fadeTarget)
                {
                    *(f32*)&((ShieldState*)state)->fadeMax = lbl_803E33B0;
                    ((ShieldState*)state)->fadeValue = v1;
                }
            }
            ((ShieldState*)state)->fadeTarget = lbl_803E33B0;
            {
                f32 amp = lbl_803E33C4;
                u8* hw;
                u8* w;
                f32* t1;
                int i;
                f32 k;
                /* kc inlined as lbl_803E33C8 (created after bias) */
                ((ShieldState*)state)->fadeRate = amp;
                i = 0;
                hw = state;
                w = state;
                t1 = (f32*)((char*)tbl + 0x10);
                k = lbl_803E33A8;
                /* kc inlined below */
                for (; i < 4; i++)
                {
                    f32 c;
                    f32 sum;
                    *(s16*)(hw + 0x34) = -0x4000;
                    c = fcos16((u16) * (s16*)(hw + 0x34));
                    sum = amp + c;
                    c = sum * k;
                    *(f32*)(w + 0x24) = *tbl * c;
                    *(f32*)(w + 0x14) = *t1;
                    *(s16*)(hw + 0x3c) = (f32)(int)(i * randomGetRange(0x78, 0x7f)) + lbl_803E33C8;
                    hw += 2;
                    tbl += 1;
                    w += 4;
                    t1 += 1;
                }
            }
            Sfx_PlayFromObject(obj, SFXTRIG_lrope_powerup);
            Sfx_PlayFromObject(obj, SFXTRIG_lockon3_on);
        }
        break;
    case 2:
        if (glow != NULL)
        {
            staffSetGlow(glow, 7, 0);
        }
        if (lbl_803E33AC != ((ShieldState*)state)->fadeTarget)
        {
            *(f32*)&((ShieldState*)state)->fadeMax = lbl_803E33CC;
        }
        ((ShieldState*)state)->fadeTarget = lbl_803E33AC;
        ((ShieldState*)state)->fadeRate = lbl_803E33B4;
        if (*(int**)state != NULL)
        {
            modelLightStruct_setEnabled(*(int*)state, 0, lbl_803E33A8);
        }
        Sfx_StopFromObject((int)obj, SFXTRIG_lrope_powerup);
        Sfx_StopFromObject((int)obj, SFXTRIG_lockon3_on);
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
        if (lbl_803E33AC == ((ShieldState*)state)->fadeTarget)
        {
            *(f32*)&((ShieldState*)state)->fadeMax = lbl_803E33CC;
        }
        ((ShieldState*)state)->fadeTarget = lbl_803E33CC;
        {
            f32 amp = lbl_803E33C4;
            int i;
            u8* hw;
            u8* w;
            f32* t0;
            f32* t1;
            f32 k;
            ((ShieldState*)state)->fadeRate = amp;
            i = 0;
            hw = state;
            w = state;
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
                *(f32*)(w + 0x24) = *tbl * c;
                *(f32*)(w + 0x14) = *t1;
                hw += 2;
                tbl += 1;
                w += 4;
                t1 += 1;
            }
        }
        Sfx_PlayFromObject(obj, SFXTRIG_lockon3_on);
        Sfx_PlayFromObject(obj, SFXTRIG_lrope_powerup);
        break;
    case 5:
        ((ShieldState*)state)->fadeTarget = lbl_803E33AC;
        ((ShieldState*)state)->fadeRate = lbl_803E33B4;
        *(f32*)&((ShieldState*)state)->fadeMax = lbl_803E33CC;
        Sfx_StopFromObject((int)obj, SFXTRIG_lrope_powerup);
        Sfx_StopFromObject((int)obj, SFXTRIG_lockon3_on);
        break;
    case 4:
        {
            f32 v = lbl_803E33CC;
            f32 amp;
            ((ShieldState*)state)->fadeTarget = v;
            amp = lbl_803E33C4;
            ((ShieldState*)state)->fadeRate = amp;
            *(f32*)&((ShieldState*)state)->fadeMax = v;
            {
                int i;
                u8* hw;
                f32* t0;
                u8* w;
                f32* t1;
                f32 k;
                /* kc inlined as lbl_803E33C8 (created after bias) */
                i = 0;
                hw = state;
                t0 = (f32*)((char*)tbl + 0x20);
                w = state;
                t1 = (f32*)((char*)tbl + 0x30);
                k = lbl_803E33A8;
                /* kc inlined below */
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
                    *(s16*)(hw + 0x3c) = (f32)(int)(i * randomGetRange(0x78, 0x7f)) + lbl_803E33C8;
                    hw += 2;
                    t0 += 1;
                    w += 4;
                    t1 += 1;
                }
            }
            Sfx_PlayFromObject(obj, SFXTRIG_lockon3_on);
            Sfx_PlayFromObject(obj, SFXTRIG_lrope_powerup);
            break;
        }
    case 6:
        {
            int i;
            u8* hw;
            f32* t0;
            u8* w;
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
