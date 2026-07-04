/*
 * DLL 0xE3 - fireball object (a homing magic projectile) and the shared
 * object-descriptor table for this DLL's object pool.
 *
 * The matched code here is the fireball family: it spawns a model light
 * (objCreateLight) tinted per colorIndex from lbl_80320978, flies for
 * flightDuration computed from its launch velocity, optionally homes onto
 * a target hit-volume (fn_8016F260) on a spiral (spiralPhase), runs ground
 * collision when stateFlags bit 4 is set, and on contact plays an impact
 * SFX / particle burst, frees its light and fades out. seqId 2110 hides the
 * object; seqId 0x6e8 contact recolors it from the combat source palette.
 * stateFlags: bit0 = launch position latched, bit1 = (unused here),
 * bit3 = disabled/no-update, bit4 = affected by gravity+ground snap.
 *
 * The remaining ObjectDescriptor / data tables are the DLL's pooled object
 * registry (kaldachompspit, pinponspike, pollen, pollenfragment, mikabomb,
 * mikabombshadow, staticcamera, gcbaddieshield, baddieinterestp, animatedobj,
 * dim2roofrub, depthoffieldpoint, staff, flamethrowerspe, shield, curve,
 * restartmarker, dll_F7, checkpoint4) whose bodies live in their own DLL TUs.
 */
#include "main/dll/xyzanimator.h"
#include "main/dll/genpropswgpipe_struct.h"
#include "main/game_object.h"
#include "main/dll/genprops.h"
#include "main/dll_000A_expgfx.h"
#include "main/vecmath.h"
#include "main/dll/dll_00C8_depthoffieldpoint.h"
#include "main/dll/dll_00E3_fireball.h"
#include "main/dll/dll_00E4_flamethrowerspe.h"
#include "main/audio/sfx_trigger_ids.h"

/* object group this object joins while active */
#define FIREBALL_OBJGROUP 2

#define FIREBALL_OBJFLAG_FREED 0x40

#define MODEL_LIGHT_KIND_POINT 2

#define FIREBALL_ROT_COUNT 5
extern int randomGetRange(int lo, int hi);
extern u32 ObjHits_SetHitVolumeSlot();
extern void modelLightStruct_setLightKind(int light, int value);
extern void modelLightStruct_setPosition(int light, f32 x, f32 y, f32 z);
extern void modelLightStruct_setupGlow(int light, int a, int r, int g, int b, int alpha, f32 radius);
extern void modelLightStruct_setDistanceAttenuation(int light, f32 near, f32 far);
extern void lightSetField4D(int light, int v);
extern void modelLightStruct_setEnabled(int light, int enabled, f32 scale);

void mikabomb_hitDetect(void);

void mikabomb_free(int obj, int mode);

int mikabomb_getExtraSize(void);
int mikabomb_getObjectTypeId(void);

extern void objRenderFn_8003b8f4(int* obj);

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
extern u8 framesThisStep;
extern f32 sqrtf(f32 x);
extern int getAngle(float y, float x);

typedef struct FireballPlacement
{
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    s16 unk18;
    s16 startupDelayEnabled; /* 0x1A nonzero (and seqId != 2110) => arms FireballState.startupDelay */
    s16 startDisabled;  /* 0x1C nonzero => fireball starts with FIREBALL_FLAG_DISABLED */
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
    f32 posY;
    f32 posZ;
    f32 flightDuration;
    f32 elapsedTime;
    f32 fadeoutTimer;
    f32 startupDelay;
    s16 unk40;
    s16 unk42;
    u8 pad44[0x46 - 0x44];
    u16 spiralPhase;
    u16 rotZBase[FIREBALL_ROT_COUNT];  /* 0x48 */
    u16 rotZDelta[FIREBALL_ROT_COUNT]; /* 0x52 */
    u16 rotYBase[FIREBALL_ROT_COUNT];  /* 0x5C */
    u16 rotYDelta[FIREBALL_ROT_COUNT]; /* 0x66 */
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

/* FireballState.stateFlags bits (see file header comment) */
#define FIREBALL_FLAG_POS_LATCHED 0x1 /* launch position has been latched into posX/Y/Z */
#define FIREBALL_FLAG_GRAVITY 0x4     /* affected by gravity + ground snap */
#define FIREBALL_FLAG_DISABLED 0x8    /* disabled / no-update */

#define FIREBALL_OBJFLAG_FREED 0x40

extern u32 ObjHits_ClearHitVolumes();
extern void ObjGroup_RemoveObject(u32 obj, int group);
extern void ObjGroup_AddObject(u32 obj, int group);
extern void ModelLightStruct_free(void* p);
extern void gcbaddieshield_update(int* obj);








extern void shield_update(int* obj);
extern void dll_F7_update(int* obj);
extern void dll_F7_init(int* obj, int* params);
extern int* Obj_GetActiveModel(int obj);
extern const f32 lbl_803E3330;
extern int cmbsrc_getColorIndex(int* p);
extern void projectileParticleFxFn_80099660(int* obj, f32 v, int kind);
extern const f32 lbl_803E3354;
extern const f32 lbl_803E3358;
extern void lightSetFieldBC_8001db14(int light, int v);
extern void modelLightStruct_setGlowProjectionRadius(int light, f32 a);
extern const f32 lbl_803E3378;
extern const f32 lbl_803E337C;
extern const f32 lbl_803E3380;
extern int hitDetectFn_800658a4(int* obj, f32 x, f32 y, f32 z, f32* out, int flag);
extern float mathSinf(float x);
extern float mathCosf(float x);
void fn_8016F260(int* obj, int* state, int* other);
extern const f32 gFireballSpiralAmplitude;
extern const f32 gFireballPi;
extern const f32 gFireballAngleScale;
extern const f32 lbl_803E335C;
extern const f32 lbl_803E3360;
extern const f32 lbl_803E3364;
extern const f32 lbl_803E3368;
extern const f32 lbl_803E336C;
extern u8 gFireballColorIndexTable[8];
extern void queueGlowRender(int light);
extern const f32 lbl_803E3350;
extern const f32 lbl_803E3340;

void mikabombshadow_update(int* obj);

void staff_func0F(void);

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

u8 fn_8016F16C(int* obj) { return ((FireballState*)((GameObject*)obj)->extra)->colorIndex; }

void fireball_free(int* obj)
{
    int* inner = (int*)((GameObject*)obj)->extra;
    void* ptr = *(void**)inner;
    if (ptr != NULL)
    {
        ModelLightStruct_free(ptr);
    }
    (*gExpgfxInterface)->freeSource2((u32)obj);
    ObjGroup_RemoveObject((int)obj, FIREBALL_OBJGROUP);
}

void mikabombshadow_init(int* obj);

void StaticCamera_init(int* obj, int* params, int flag);

int Fireball_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int i;
    int* state = ((GameObject*)obj)->extra;
    if (((FireballState*)state)->stateFlags & FIREBALL_FLAG_DISABLED)
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

extern void modelLightStruct_setDiffuseColor(int* light, int r, int g, int b, int a);
extern u32 ObjHits_EnableObject();

void fireball_hitDetect(int* obj)
{
    int* state = ((GameObject*)obj)->extra;
    int* target;
    if (((GameObject*)obj)->anim.seqId == 0x83e) return;
    switch (((FireballState*)state)->stateFlags & FIREBALL_FLAG_DISABLED)
    {
    case 0:
        break;
    default:
        return;
    }
    target = (int*)((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->lastHitObject;
    if (target == NULL) return;
    if (((GameObject*)target)->anim.seqId == 0x6e8)
    {
        int idx = cmbsrc_getColorIndex(target);
        if ((s8)idx != -1)
        {
            ((FireballState*)state)->colorIndex = idx;
            if (*(void**)state != NULL)
            {
                int c = ((FireballState*)state)->colorIndex * 3;
                u8* pal = (u8*)lbl_80320978;
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
    ObjGroup_RemoveObject((int)obj, FIREBALL_OBJGROUP);
}

void mikabomb_init(int* obj);

extern int objCreateLight(int* obj, int arg);

#pragma opt_common_subs off
void fireball_init(int* obj)
{
    int* state = ((GameObject*)obj)->extra;
    int* params = *(int**)&((GameObject*)obj)->anim.placementData;

    if (((FireballPlacement*)params)->startDisabled != 0)
    {
        ((FireballState*)state)->stateFlags |= FIREBALL_FLAG_DISABLED;
    }
    else
    {
        FireballState* fs;
        int i;
        ((FireballState*)state)->unk40 = randomGetRange(600, 900);
        ((FireballState*)state)->unk42 = randomGetRange(-600, 600);
        ((FireballState*)state)->colorIndex = 0;
        {
            ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
            if (hitState != NULL)
            {
                hitState->trackContactMask = 257;
            }
        }
        if (*(void**)state == NULL)
        {
            *(int*)state = objCreateLight(obj, 1);
            if (*(void**)state != NULL)
            {
                int c;
                u8* base1;
                u8* base2;
                modelLightStruct_setLightKind(*(int*)state, MODEL_LIGHT_KIND_POINT);
                lightSetField4D(*(int*)state, 0);
                modelLightStruct_setPosition(*(int*)state, lbl_803E3330, lbl_803E3330, lbl_803E3330);
                lightSetFieldBC_8001db14(*(int*)state, 1);
                c = ((FireballState*)state)->colorIndex * 3;
                modelLightStruct_setDiffuseColor(*(int**)state, ((u8*)lbl_80320978)[c],
                                                 (base1 = (u8*)lbl_80320978 + 1)[((FireballState*)state)->colorIndex * 3],
                                                 (base2 = (u8*)lbl_80320978 + 2)[((FireballState*)state)->colorIndex * 3], 0);
                modelLightStruct_setDistanceAttenuation(*(int*)state, lbl_803E3358, lbl_803E3378);
                c = ((FireballState*)state)->colorIndex * 3;
                modelLightStruct_setupGlow(*(int*)state, 0, ((u8*)lbl_80320978)[c], base1[c],
                                           base2[c], 32, lbl_803E337C);
                modelLightStruct_setGlowProjectionRadius(*(int*)state, lbl_803E337C);
            }
        }
        ((GameObject*)obj)->anim.alpha = 200;
        for (i = 0, fs = (FireballState*)state; i < FIREBALL_ROT_COUNT; i++)
        {
            fs->rotZBase[0] = randomGetRange(-32767, 32767);
            fs->rotZDelta[0] = randomGetRange(-1024, 1024);
            fs->rotYBase[0] = randomGetRange(-32767, 32767);
            fs->rotYDelta[0] = randomGetRange(-1024, 1024);
            fs = (FireballState*)((char*)fs + 2);
        }
        ((GameObject*)obj)->animEventCallback = Fireball_SeqFn;
        ObjGroup_AddObject((int)obj, FIREBALL_OBJGROUP);
        if (((GameObject*)obj)->anim.seqId != 2110 && ((FireballPlacement*)params)->startupDelayEnabled != 0)
        {
            ((FireballState*)state)->startupDelay = lbl_803E3380;
        }
    }
}
#pragma opt_common_subs reset

extern void Sfx_PlayFromObject(int* obj, int sfx);
extern void Obj_FreeObject(int* obj);
extern u64 ObjHits_DisableObject();

void fireball_update(int* obj)
{
    int* state = ((GameObject*)obj)->extra;
#define hitState ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)
    int* other = *(int**)&((GameObject*)obj)->unkF8;
    int* params = *(int**)&((GameObject*)obj)->anim.placementData;

    if ((((FireballState*)state)->stateFlags & FIREBALL_FLAG_DISABLED) != 0)
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
    if ((((FireballState*)state)->stateFlags & FIREBALL_FLAG_POS_LATCHED) == 0)
    {
        ((FireballState*)state)->posX = ((GameObject*)obj)->anim.localPosX;
        ((FireballState*)state)->posY = ((GameObject*)obj)->anim.localPosY;
        ((FireballState*)state)->posZ = ((GameObject*)obj)->anim.localPosZ;
        ((FireballState*)state)->stateFlags |= FIREBALL_FLAG_POS_LATCHED;
    }
    {
        if (hitState->contactFlags != 0)
        {
            if (hitState->contactHitVolume != 14)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_npu_216);
            }
            else
            {
                Sfx_PlayFromObject(obj, SFXTRIG_foot_water_walk_1);
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
            ObjGroup_RemoveObject((int)obj, FIREBALL_OBJGROUP);
            ObjHits_DisableObject(obj);
        }
    }
    if (((FireballState*)state)->fadeoutTimer != *(f32*)&lbl_803E3330)
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
            if ((((GameObject*)other)->objectFlags & FIREBALL_OBJFLAG_FREED) != 0)
            {
                ((GameObject*)obj)->unkF8 = 0;
            }
            else
            {
                fn_8016F260(obj, state, other);
            }
        }
        ((FireballState*)state)->posX += ((GameObject*)obj)->anim.velocityX * timeDelta;
        ((FireballState*)state)->posY += ((GameObject*)obj)->anim.velocityY * timeDelta;
        ((FireballState*)state)->posZ += ((GameObject*)obj)->anim.velocityZ * timeDelta;
        ((FireballState*)state)->spiralPhase += framesThisStep * 1500;
        if ((((FireballState*)state)->stateFlags & FIREBALL_FLAG_GRAVITY) != 0)
        {
            f32 ground;
            ((FireballState*)state)->posY -= lbl_803E3364 * timeDelta;
            if (hitDetectFn_800658a4(obj, ((FireballState*)state)->posX, ((FireballState*)state)->posY,
                                     ((FireballState*)state)->posZ, &ground, 0) == 0)
            {
                ground -= lbl_803E3368;
                if (ground < lbl_803E3330 && ground > lbl_803E336C)
                {
                    ((FireballState*)state)->posY -= ground;
                }
            }
        }
        ((GameObject*)obj)->anim.localPosX = ((FireballState*)state)->posX;
        ((GameObject*)obj)->anim.localPosY = ((FireballState*)state)->posY;
        ((GameObject*)obj)->anim.localPosZ = ((FireballState*)state)->posZ;
        if (other != NULL)
        {
            ((GameObject*)obj)->anim.localPosX += gFireballSpiralAmplitude *
                mathSinf(gFireballPi * (f32)((FireballState*)state)->spiralPhase / gFireballAngleScale);
            ((GameObject*)obj)->anim.localPosZ += gFireballSpiralAmplitude *
                mathCosf(gFireballPi * (f32)((FireballState*)state)->spiralPhase / gFireballAngleScale);
        }
        if ((((GameObject*)obj)->unkF4 -= framesThisStep) < 0)
        {
            Obj_FreeObject(obj);
        }
    }
#undef hitState
}

void fireball_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    int* model;
    u8* state = ((GameObject*)obj)->extra;
    u16 savedRot4;
    u16 savedRot2;
    u8 i;
    f32 savedF8;
    if (visible == 0 || (((FireballState*)state)->stateFlags & FIREBALL_FLAG_DISABLED) != 0 ||
        ((FireballState*)state)->startupDelay != lbl_803E3330)
    {
        return;
    }
    ((ObjAnimComponent*)obj)->bankIndex = 1;
    model = Obj_GetActiveModel(obj);
    *(u8*)((char*)*(int**)((char*)model + 0x34) + 8) = gFireballColorIndexTable[((FireballState*)state)->colorIndex];
    savedRot4 = ((GameObject*)obj)->anim.rotZ;
    savedRot2 = ((GameObject*)obj)->anim.rotY;
    savedF8 = ((GameObject*)obj)->anim.rootMotionScale;
    ((GameObject*)obj)->anim.rootMotionScale = lbl_803E3350;
    for (i = 0; i < FIREBALL_ROT_COUNT; i++)
    {
        FireballState* fs = (FireballState*)(state + i * 2);
        fs->rotZBase[0] += fs->rotZDelta[0];
        fs->rotYBase[0] += fs->rotYDelta[0];
        ((GameObject*)obj)->anim.rotZ = (s16)fs->rotZBase[0];
        ((GameObject*)obj)->anim.rotY = (s16)fs->rotYBase[0];
        *(u16*)((char*)model + 0x18) &= ~0x8;
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E3354);
    }
    ((GameObject*)obj)->anim.rotZ = savedRot4;
    ((GameObject*)obj)->anim.rotY = savedRot2;
    ((GameObject*)obj)->anim.rootMotionScale = savedF8;
    ((ObjAnimComponent*)obj)->bankIndex = 0;
    model = Obj_GetActiveModel(obj);
    *(u8*)((char*)*(int**)((char*)model + 0x34) + 8) =
        gFireballColorIndexTable[((FireballState*)state)->colorIndex];
    ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E3354);
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

void fn_8016F260(int* obj, int* state, int* other)
{
    ObjHitVolumeRuntimeTransform* hitVolume =
        &((GameObject*)other)->anim.hitVolumeTransforms[((GameObject*)other)->hitVolumeIndex];
    if (hitVolume != NULL)
    {
        f32 dx = hitVolume->jointX - ((FireballState*)state)->posX;
        f32 dy = hitVolume->jointY - gFireballSpiralAmplitude - ((FireballState*)state)->posY;
        f32 dz = hitVolume->jointZ - ((FireballState*)state)->posZ;
        s16 angY;
        s16 angP;
        s16 difY;
        s16 difP;
        s16 targY;
        s16 targP;
        f32 t1;
        f32 t2;
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
            difY = (difY - 0x10000) + 1;
        }
        if (difY < -0x8000)
        {
            difY += 0xffff;
        }
        difP = targP - (u16)angP;
        if (difP > 0x8000)
        {
            difP = (difP - 0x10000) + 1;
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

        dx = gFireballPi * angY / gFireballAngleScale;
        ((GameObject*)obj)->anim.velocityX = mathSinf(dx);
        ((GameObject*)obj)->anim.velocityZ = mathCosf(dx);
        dx = gFireballPi * angP / gFireballAngleScale;
        c = mathSinf(dx);
        {
            f32 cosP = mathCosf(dx);
            if (lbl_803E3330 != cosP)
            {
                c = c / cosP;
            }
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
