/*
 * dll_00E2 - the player staff weapon DLL plus the spell/weapon objects it
 * ships alongside (object type 0x9 = gStaffObjDescriptor).
 *
 * The staff drives a procedural swipe trail (staff_setupSwipe builds vertex
 * strips from the weapon's per-frame da-table via B-spline interpolation;
 * staffDrawSwipe / staff_update render and age them through GXWGFifo) and the
 * ground-quake spell (superQuakeFn / quakeSpellTextureFn draw a scaled torus
 * and shake the camera; quakeSpellFn_8016cee8 spawns the hit/charge particle
 * bursts keyed by attack type id). staff_hitDetectGeometry plays per-surface
 * impact sfx/water splashes from the contact hit-volume index, and the
 * grow/shrink lock-on animation is in staffDoGrowShrinkAnim.
 *
 * This translation unit also defines the ObjectDescriptors and small helpers
 * for the neighbouring objects packed into the same module: kaldachompspit,
 * pinponspike, pollen(+fragment), mikabomb(+shadow), static camera, gc baddie
 * shield, baddie interest point, animated obj, dim2roofrub, depth-of-field
 * point, fireball, flamethrowerspe, shield, curve, restart marker, dll_F7 and
 * checkpoint4. The bodies of those neighbours live in their own DLL units; the
 * descriptor tables and shared lbl_ data live here.
 */
#include "main/dll/xyzanimator.h"
#include "main/dll/genpropswgpipe_struct.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/genprops.h"
#include "main/dll_000A_expgfx.h"
#include "main/resource.h"
#include "main/objlib.h"
#include "main/objHitReact.h"
#include "main/objhits.h"
#include "main/gamebits.h"
#include "main/camera.h"
#include "dolphin/gx/GXDraw.h"
#include "string.h"
#include "main/dll/dll_00E2_staff.h"
#include "main/dll/dll_00C8_depthoffieldpoint.h"
#include "main/dll/dll_00E3_fireball.h"
#include "main/dll/dll_00E4_flamethrowerspe.h"
#include "main/audio/sfx_trigger_ids.h"

/* object group the staff joins while active */
#define STAFF_OBJGROUP 7

extern u32 FUN_8003b818();

void mikabomb_hitDetect(void);

void mikabomb_free(int obj, int mode);

int mikabomb_getExtraSize(void);
int mikabomb_getObjectTypeId(void);


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

typedef struct StaffSwipeSlot
{
    void* buffer;
    f32 unk4;
    f32 unk8;
    s16 unkC;
    s16 unkE;
    s16 idx;
    s16 unk12;
    u8 flags;
    u8 pad15[0x18 - 0x15];
} StaffSwipeSlot;

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
    f32 growShrinkAnimRate;
    u8 pad54[0x70 - 0x54];
    u8 unk70;
    u8 pad71[0xAA - 0x71];
    u8 unkAA;
    u8 padAB[0xB0 - 0xAB];
    s16 unkB0;
    u8 padB2[0xB8 - 0xB2];
} StaffDoGrowShrinkAnimState;

extern int* Obj_SetupObject(void* setup, int mode, int mapLayer, int objIndex, void* parent);
extern void gxSetPeControl_ZCompLoc_(u32 zCompLoc);
extern void gxSetZMode_(u32 compareEnable, int compareFunc, u32 updateEnable);

void staticCamera_free(int obj)
{
    ObjGroup_RemoveObject(obj, STAFF_OBJGROUP);
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

void staticCamera_init(s16* obj, int params, int flag)
{
    u8* state;

    *obj = -*(s16*)(params + 0x1c);
    obj[1] = -*(s16*)(params + 0x1e);
    obj[2] = -*(s16*)(params + 0x20);
    state = *(u8**)(obj + 0x5c);
    *state = *(u8*)(params + 0x19);
    *(f32*)(state + 4) = (f32)(u32) * (u8*)(params + 0x1a);
    state[1] = 0;
    if (flag == 0)
    {
        ObjGroup_AddObject((int)obj, STAFF_OBJGROUP);
    }
    return;
}

extern u8 Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int size, int b);

void mikabombshadow_update(int* obj);

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

void dim2roofrub_free(int* obj);

extern void gcbaddieshield_update(int* obj);








extern void shield_update(int* obj);

void restartmarker_init(int* obj, int* state);

extern void dll_F7_update(int* obj);
extern void dll_F7_init(int* obj, int* params);
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

extern u16 lbl_803208A0[];

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
    u8 pad00[0x48];
    void* activeSlot;     /* 0x48: active swipe slot pointer */
    u8 pad4C[4];
    f32 moveSpeed;        /* 0x50: current-move advance speed */
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
    u8 pad8A[2];
    f32 anchorX;
    f32 anchorY;
    f32 anchorZ;
    f32 progress;
    u8 pad9C[0x16];
    s16 fieldB2;
    u8 padB4[5];
    s8 swipeTextureIndex; /* 0xB9 */
    u8 glowEnable;        /* 0xBA */
    u8 glowAttackType;    /* 0xBB */
    u8 hudSuppressed;     /* 0xBC */
} StaffState;

s16 staff_getHitReactValue(int* obj) { return ((StaffState*)(int*)((GameObject*)obj)->extra)->hitReactValue; }

s32 staff_func16(int* obj) { return ((StaffState*)(int*)((GameObject*)obj)->extra)->swipeTextureIndex; }

void objSetAnimField48to0(int* obj)
{
    s32 v = 0x0;
    *(s32*)((char*)(int*)((GameObject*)obj)->extra + 0x48) = v;
}

void playerRenderQuakeSpell(int* obj) { quakeSpellFn_8016cee8(obj, ((GameObject*)obj)->ownerObj); }

#pragma dont_inline on
void staffSetGlow(int* obj, u8 attackType, u8 enable)
{
    u8* state = (u8*)(int*)((GameObject*)obj)->extra;
    ((StaffState*)state)->glowAttackType = attackType;
    ((StaffState*)state)->glowEnable = enable;
}
#pragma dont_inline reset

void staff_func10(int* obj, s32 v)
{
    ((StaffState*)(int*)((GameObject*)obj)->extra)->fieldB2 = v;
}

void staff_setHitReactValue(int* obj, s32 v)
{
    s16* p = &((StaffState*)(int*)((GameObject*)obj)->extra)->hitReactValue;
    if (v > 0xff) v = 0xff;
    *p = v;
}


extern int getHudHiddenFrameCount(void);

void staff_modelMtxFn(int* obj, int p4, int p5)
{
    int* inner = (int*)*(int*)&((GameObject*)obj)->extra;
    staff_setupSwipe((int)obj, (u8*)inner, p5, p4);
    if (getHudHiddenFrameCount() != 0)
    {
        ((StaffState*)inner)->hudSuppressed = 1;
    }
    else
    {
        ((StaffState*)inner)->hudSuppressed = 0;
    }
}

void staff_addHitReactValue(int* obj, s32 delta)
{
    s16* p = &((StaffState*)(int*)((GameObject*)obj)->extra)->hitReactValue;
    s32 clamped;
    *p = (s16)(*p + delta);
    clamped = *p;
    if (clamped < 0)
    {
        clamped = 0;
    }
    else if (clamped > 0xff)
    {
        clamped = 0xff;
    }
    *p = clamped;
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

void staff_func15(int* obj, s16 idx, f32 f1, f32 f2)
{
    StaffSwipeSlot* slot;
    int n;
    StaffSwipeSlot* slots = (StaffSwipeSlot*)(int*)((GameObject*)obj)->extra;
    for (n = 0; n < 3; n++)
    {
        slot = &slots[n];
        if ((slot->flags & 0x2) == 0)
        {
            break;
        }
    }
    slot->flags = (u8)(slot->flags | 0x3);
    slot->unk4 = f1;
    slot->unk8 = f2;
    slot->unkC = 0;
    slot->unkE = 0;
    slot->unk12 = 0;
    slot->idx = idx;
    *(void**)((char*)slots + 0x48) = slot;
}

extern void mm_free(void* p);

void gcbaddieshield_update(int* obj);

void staff_free(int* obj)
{
    StaffSwipeSlot* p;
    int i;
    i = 0;
    p = (StaffSwipeSlot*)((GameObject*)obj)->extra;
    for (; i < 3; i++)
    {
        mm_free(p->buffer);
        p++;
    }
    (*gExpgfxInterface)->freeSource2((u32)obj);
}


extern int textureFree(int tex);
extern void* gStaffSwipeResource;
extern void* gStaffSwipeTextures[2];



void staff_release(void)
{
    void** p;
    int i;
    if (gStaffSwipeTextures[0] != NULL)
    {
        for (i = 0, p = gStaffSwipeTextures; i < 2; i++)
        {
            textureFree((int)*p);
            *p = NULL;
            p++;
        }
    }
    if (gStaffSwipeResource != NULL)
    {
        Resource_Release(gStaffSwipeResource);
        gStaffSwipeResource = NULL;
    }
}

void mikabombshadow_init(int* obj);

void StaticCamera_init(int* obj, int* params, int flag);


extern int mmAlloc(int size, int a, int b);
extern f32 lbl_803E3328;
typedef struct StaffQuakeSpellState
{
    f32 posX;        /* 0x00 */
    f32 posY;        /* 0x04 */
    f32 posZ;        /* 0x08 */
    f32 scale;       /* 0x0C: torus scale (PSMTXScale + hitbox radius) */
    f32 radius;      /* 0x10: GXDrawTorus radius */
    f32 heightScale; /* 0x14: y-axis scale multiplier */
    f32 fade;        /* 0x18: fade/alpha driver (quakeSpellTextureFn arg, anim.alpha) */
    int* object;     /* 0x1C: spawned quake-spell object */
    u8 active;       /* 0x20: spell active flag */
} StaffQuakeSpellState;

extern u8 gStaffQuakeSpellState[];

void staff_init(int* obj)
{
    int* state = ((GameObject*)obj)->extra;
    ObjHitsPriorityState* hitState;
    StaffSwipeSlot* p;
    int i;
    ((StaffDoGrowShrinkAnimState*)state)->unkAA = 1;
    ((StaffDoGrowShrinkAnimState*)state)->unkB0 = 2;
    ((StaffDoGrowShrinkAnimState*)state)->growShrinkAnimRate = lbl_803E3328;
    hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    if (hitState != NULL)
    {
        hitState->trackContactMask = 0x109;
    }
    i = 0;
    p = (StaffSwipeSlot*)state;
    for (; i < 3; i++)
    {
        p->buffer = (void*)mmAlloc(0xEA60, 0x1a, 0);
        p->idx = -1;
        p++;
    }
    ((StaffQuakeSpellState*)gStaffQuakeSpellState)->active = 0;
    ((StaffQuakeSpellState*)gStaffQuakeSpellState)->object = 0;
}

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
        if (((StaffDoGrowShrinkAnimState*)state)->growShrinkAnimRate < lbl_803E32B4)
        {
            Sfx_PlayFromObject(obj, SFXsc_text_appears_lp);
        }
        if (flag2 == 0)
        {
            ((StaffDoGrowShrinkAnimState*)state)->growShrinkAnimRate = lbl_803E3320;
        }
        else
        {
            ((StaffDoGrowShrinkAnimState*)state)->growShrinkAnimRate = lbl_803E3288;
        }
    }
    else
    {
        if (((StaffDoGrowShrinkAnimState*)state)->growShrinkAnimRate > lbl_803E32B4)
        {
            Sfx_PlayFromObject(obj, SFXsc_nolock);
        }
        if (flag2 == 0)
        {
            ((StaffDoGrowShrinkAnimState*)state)->growShrinkAnimRate = lbl_803E3324;
        }
        else
        {
            ((StaffDoGrowShrinkAnimState*)state)->growShrinkAnimRate = lbl_803E3328;
        }
    }
}

void dll_F7_init(int* obj, int* params);



extern void CameraShake_Start(f32 magnitude, f32 duration, f32 falloff);

void mikabomb_init(int* obj);

extern void PSMTXTrans(f32* m, f32 x, f32 y, f32 z);
extern void PSMTXConcat(f32 * a, f32 * b, f32 * out);
extern void PSMTXRotRad(f32* m, int axis, f32 rad);
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;

extern float mathSinf(float x);
extern float mathCosf(float x);


void shield_update(int* obj);

extern void Sfx_PlayAtPositionFromObject(int* obj, f32 x, f32 y, f32 z, int sfx);

void dll_F7_update(int* obj);

extern s16 sStaffSwipeTextureIdTable[4];
extern s16* gStaffSwipeTextureIds;
extern void* textureLoad(int texId, u8 flag);

static inline void staff_initialiseBody(s16* p, int i)
{
    for (; i < 35; i++)
    {
        if (*p == 0)
        {
            *p = 0xc3;
        }
        p++;
    }
    gStaffSwipeTextureIds = sStaffSwipeTextureIdTable;
    if (gStaffSwipeTextures[0] == NULL)
    {
        for (i = 0; i < 2; i++)
        {
            gStaffSwipeTextures[i] = textureLoad(gStaffSwipeTextureIds[i], 0);
        }
    }
    if (gStaffSwipeResource == NULL)
    {
        gStaffSwipeResource = Resource_Acquire(90, 1);
    }
}

void staff_initialise(void)
{
    int i;

    i = 0;
    staff_initialiseBody((s16*)lbl_803208A0, i);
}

extern void quakeSpellTextureFn_8007366c(int param);
extern void PSMTXScale(f32* m, f32 x, f32 y, f32 z);
extern void GXLoadPosMtxImm(f32* m, int id);
extern void GXLoadTexMtxImm(f32* m, int id, int type);
extern f32 gStaffHalfPi;

void quakeSpellTextureFn_8016dbf4(void)
{
    f32 mResult[12];
    f32 mScale[12];
    f32 mRot[12];
    f32 mTrans[12];
    f32 mView[12];

    if (((StaffQuakeSpellState*)gStaffQuakeSpellState)->active != 0)
    {
        f32 scale;
        f32 z;
        quakeSpellTextureFn_8007366c((int)((StaffQuakeSpellState*)gStaffQuakeSpellState)->fade);
        memcpy(mView, Camera_GetViewMatrix(), 0x30);
        PSMTXRotRad(mRot, 'x', gStaffHalfPi);
        scale = ((StaffQuakeSpellState*)gStaffQuakeSpellState)->scale;
        PSMTXScale(mScale, scale, scale * ((StaffQuakeSpellState*)gStaffQuakeSpellState)->heightScale, scale);
        PSMTXConcat(mScale, mRot, mScale);
        PSMTXTrans(mTrans, ((StaffQuakeSpellState*)gStaffQuakeSpellState)->posX - playerMapOffsetX,
                   ((StaffQuakeSpellState*)gStaffQuakeSpellState)->posY,
                   ((StaffQuakeSpellState*)gStaffQuakeSpellState)->posZ - playerMapOffsetZ);
        PSMTXConcat(mView, mTrans, mView);
        PSMTXConcat(mView, mScale, mResult);
        GXLoadPosMtxImm(mResult, 0);
        PSMTXConcat(mView, mRot, mResult);
        z = lbl_803E32B4;
        mResult[3] = z;
        mResult[7] = z;
        mResult[11] = z;
        GXLoadTexMtxImm(mResult, 30, 0);
        GXDrawTorus(((StaffQuakeSpellState*)gStaffQuakeSpellState)->radius, 10, 20);
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

    if (((StaffQuakeSpellState*)gStaffQuakeSpellState)->active != 0)
    {
        Obj_FreeObject(((StaffQuakeSpellState*)gStaffQuakeSpellState)->object);
        ((StaffQuakeSpellState*)gStaffQuakeSpellState)->object = NULL;
    }
    ((StaffQuakeSpellState*)gStaffQuakeSpellState)->posX = pos[0];
    ((StaffQuakeSpellState*)gStaffQuakeSpellState)->posY = lbl_803E32A8 + pos[1];
    ((StaffQuakeSpellState*)gStaffQuakeSpellState)->posZ = pos[2];
    ((StaffQuakeSpellState*)gStaffQuakeSpellState)->fade = lbl_803E32F4;
    ((StaffQuakeSpellState*)gStaffQuakeSpellState)->scale = lbl_803E3288;
    ((StaffQuakeSpellState*)gStaffQuakeSpellState)->radius = lbl_803E3290;
    ((StaffQuakeSpellState*)gStaffQuakeSpellState)->heightScale = lbl_803E3288;
    CameraShake_Start(lbl_803E32F8, lbl_803E32A8, lbl_803E32FC);
    player = Obj_GetPlayerObject();
    if (player != NULL && Obj_IsLoadingLocked() != 0)
    {
        QuakePartVec v;
        void* setup;
        ((StaffQuakeSpellState*)gStaffQuakeSpellState)->active = 1;
        v.x = ((StaffQuakeSpellState*)gStaffQuakeSpellState)->posX;
        v.y = ((StaffQuakeSpellState*)gStaffQuakeSpellState)->posY;
        v.z = ((StaffQuakeSpellState*)gStaffQuakeSpellState)->posZ;
        v.scale = lbl_803E3288;
        v.h0 = 0;
        v.h2 = 0;
        v.h1 = 0;
        (*gPartfxInterface)->spawnObject(player, 0x565, &v, 0x200000, -1, NULL);
        setup = Obj_AllocObjectSetup(36, 0x63c);
        ((ObjPlacement*)setup)->color[0] = 1;
        ((ObjPlacement*)setup)->color[2] = 0xff;
        ((ObjPlacement*)setup)->color[1] = 2;
        ((ObjPlacement*)setup)->color[3] = 0xff;
        ((ObjPlacement*)setup)->posX = ((StaffQuakeSpellState*)gStaffQuakeSpellState)->posX;
        ((ObjPlacement*)setup)->posY = ((StaffQuakeSpellState*)gStaffQuakeSpellState)->posY;
        ((ObjPlacement*)setup)->posZ = ((StaffQuakeSpellState*)gStaffQuakeSpellState)->posZ;
        ((StaffQuakeSpellState*)gStaffQuakeSpellState)->object = Obj_SetupObject(setup, 5, ((GameObject*)player)->anim.mapEventSlot, -1,
                                                        ((GameObject*)player)->anim.parent);
        if (GameBit_Get(0xc55) != 0)
        {
            ((ObjAnimComponent*)((StaffQuakeSpellState*)gStaffQuakeSpellState)->object)->bankIndex = 1;
        }
        ObjHitbox_SetSphereRadius((int)((StaffQuakeSpellState*)gStaffQuakeSpellState)->object, 1);
        ObjHits_SetHitVolumeSlot((int)((StaffQuakeSpellState*)gStaffQuakeSpellState)->object, 17, 5, 0);
        ((GameObject*)((StaffQuakeSpellState*)gStaffQuakeSpellState)->object)->anim.rootMotionScale = lbl_803E32D0;
        ((GameObject*)((StaffQuakeSpellState*)gStaffQuakeSpellState)->object)->anim.alpha = 0xff;
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

extern SwipeColorTable gStaffSwipeColorTable;
void staffDrawSwipe(int* obj, int* swipe);

void staff_hitDetectGeometry(int* obj)
{
    ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    int* swipe = ((GameObject*)obj)->extra;
    SwipeColorTable tbl = gStaffSwipeColorTable;

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
                                         hitState->contactPosZ, SFXTRIG_foot_water_walk_1);
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
            ((void (*)(int, int, void*, int, int, u8*))(*(int**)gStaffSwipeResource)[1])(
                OBJHITREACT_HIT_EFFECT_PARENT_NONE, OBJHITREACT_HIT_EFFECT_MODE, &v,
                OBJHITREACT_HIT_EFFECT_SPAWN_FLAGS, OBJHITREACT_HIT_EFFECT_NO_SOURCE,
                (u8*)&tbl + (((u8*)lbl_803208E8)[idx] << 4));
            Sfx_PlayAtPositionFromObject(obj, hitState->contactPosX, hitState->contactPosY,
                                         hitState->contactPosZ, (u16)((s16*)lbl_803208A0)[idx]);
        }
    }
}

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

extern void selectTexture(u8* tex, int mapId);
extern void textureSetupFn_800799c0(void);
extern void geomDrawFn_800796f0(void);
extern void textRenderSetupFn_80079804(void);
extern void GXSetBlendMode(int a, int b, int c, int d);
extern void GXSetAlphaCompare(int a, int b, int c, int d, int e);
extern void GXSetCullMode(int a);
extern void GXClearVtxDesc(void);
extern void GXSetVtxDesc(int a, int b);
extern void GXSetCurrentMtx(u32 id);
extern void GXBegin(int type, int fmt, int n);

#define GX_BM_BLEND 1
#define GX_BL_ONE 1
#define GX_BL_SRCALPHA 4
#define GX_LO_NOOP 5
#define GX_LEQUAL 3
#define GX_ALWAYS 7
#define GX_AOP_AND 0
#define GX_CULL_NONE 0
#define GX_VA_POS 9
#define GX_VA_CLR0 11
#define GX_VA_TEX0 13
#define GX_DIRECT 1
#define GX_QUADS 128
#define GX_VTXFMT2 2

extern f32 lbl_803E3294;

#pragma opt_common_subs off
void staffDrawSwipe(int* obj, int* swipe)
{
    SwipeRecord* swp;
    int i;

    selectTexture(gStaffSwipeTextures[((StaffState*)swipe)->swipeTextureIndex], 0);
    textureSetupFn_800799c0();
    geomDrawFn_800796f0();
    textRenderSetupFn_80079804();
    gxSetZMode_(1, GX_LEQUAL, 0);
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_ONE, GX_LO_NOOP);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    GXSetCullMode(GX_CULL_NONE);
    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_CLR0, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
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
            for (; j < swp->endIndex - 2; j += 2)
            {
                u = 0.5f;
                v0 = 0.0f;
                v1 = 1.0f;
                GXBegin(GX_QUADS, GX_VTXFMT2, 4);
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
        (int)obj, ((StaffState*)state)->moveSpeed, timeDelta, NULL);

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
                    f32 clamped;
                    t = k * (t * lbl_803E3310);
                    if (t < lbl_803E32B4)
                    {
                        clamped = lbl_803E32B4;
                    }
                    else if (t > k)
                    {
                        clamped = k;
                    }
                    else
                    {
                        clamped = t;
                    }
                    *(s16*)(vp + 0x10) = k - clamped;
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
                    *(s16*)(vp + 0x10) = c;
                    c = *(s16*)(vp + 0x24);
                    if (c < 0)
                    {
                        c = 0;
                    }
                    else if (c > 255)
                    {
                        c = 255;
                    }
                    *(s16*)(vp + 0x24) = c;
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
    ((StaffState*)state)->swipeTextureIndex = 0;
    {
        StaffQuakeSpellState* q = (StaffQuakeSpellState*)gStaffQuakeSpellState;
        if (q->active != 0)
        {
            f32 sc = q->scale + lbl_803E32E0;
            f32 fade;
            q->scale = sc;
            ObjHitbox_SetSphereRadius((int)q->object, sc);
            ObjHits_SetHitVolumeSlot((int)q->object, 17, 5, 0);
            fade = ((StaffQuakeSpellState*)gStaffQuakeSpellState)->fade + lbl_803E32E4;
            ((StaffQuakeSpellState*)gStaffQuakeSpellState)->fade = fade;
            ((StaffQuakeSpellState*)gStaffQuakeSpellState)->radius = ((StaffQuakeSpellState*)gStaffQuakeSpellState)->radius * lbl_803E32E8;
            ((StaffQuakeSpellState*)gStaffQuakeSpellState)->heightScale = ((StaffQuakeSpellState*)gStaffQuakeSpellState)->heightScale * lbl_803E32EC;
            ((GameObject*)q->object)->anim.alpha = fade;
            ((GameObject*)q->object)->anim.rootMotionScale += lbl_803E32F0;
            if (((StaffQuakeSpellState*)gStaffQuakeSpellState)->fade < lbl_803E3288)
            {
                q->active = 0;
                Obj_FreeObject(q->object);
                q->object = NULL;
            }
        }
    }
}

extern float fastFloorf(float x);
extern f32 Curve_EvalBSpline(f32* a, f32 t, f32* out);
extern f32 gStaffPi;
extern f32 gStaffAngleUnitScale;
extern f32 lbl_803E32A4;
extern f32 lbl_803E32AC;

void staff_setupSwipe(int unused1, u8* swipe, int unused3, int objArg)
{
    u8* slot;
    u8* obj;
    u8* model2;
    ObjWeaponDaTable* weaponDaTable;
    s16* tbl;
    int count;
    int count2;
    int ibase;
    int first;
    u8* vp;
    int idx[4];
    f32 ptAx[4];
    f32 ptAy[4];
    f32 ptAz[4];
    f32 ptBx[4];
    f32 ptBy[4];
    f32 ptBz[4];
    f32 sinv, cosv, vidx, flb, tmax, step, fla, angle, frac, acc, prog, m4;
    int ang;

    obj = (u8*)objArg;
    if (((StaffState*)swipe)->activeSlot == NULL || ((StaffState*)swipe)->hudSuppressed != 0)
    {
        return;
    }
    {
        ang = ((GameObject*)obj)->anim.rotX;
        if (*(s16**)&((GameObject*)obj)->anim.parent != NULL)
        {
            ang += **(s16**)&((GameObject*)obj)->anim.parent;
        }
        angle = (gStaffPi * (f32)(int) - ang) / gStaffAngleUnitScale;
        sinv = mathSinf(angle);
        cosv = mathCosf(angle);
        model2 = *(u8**)((char*)Obj_GetActiveModel((int)obj) + 0x2c);
        weaponDaTable = ((GameObject*)obj)->anim.weaponDaTable;
        if (weaponDaTable != NULL && weaponDaTable->byteCount > 0)
        {
            f32 sw;
            slot = (u8*)((StaffState*)swipe)->activeSlot;
            count = (int)(lbl_803E330C * *(f32*)(model2 + 0x14));
            prog = *(f32*)(slot + 8) * *(f32*)(model2 + 0x14);
            if (slot[0x14] & 1)
            {
                ((StaffState*)swipe)->anchorX = ((GameObject*)obj)->anim.worldPosX;
                ((StaffState*)swipe)->anchorY = ((GameObject*)obj)->anim.worldPosY;
                ((StaffState*)swipe)->anchorZ = ((GameObject*)obj)->anim.worldPosZ;
                ((StaffState*)swipe)->progress = lbl_803E32B4;
                slot[0x14] &= ~1;
            }
            sw = ((StaffState*)swipe)->progress;
            m4 = *(f32*)(model2 + 4);
            tmax = m4;
            if (sw > prog)
            {
                ((StaffState*)swipe)->progress = m4;
                return;
            }
            if (m4 > prog)
            {
                tmax = prog;
            }
            tbl = ((GameObject*)obj)->anim.weaponDaTable->entries;
            if (sw >= lbl_803E32B4)
            {
                fla = fastFloorf(sw * lbl_803E32A4) / lbl_803E32A4;
                fla = fla * lbl_803E330C;
                tmax = tmax * lbl_803E32A4;
                flb = fastFloorf(tmax) / lbl_803E32A4;
                flb = flb * lbl_803E330C;
                ibase = fla;
                frac = fla - ibase;
                count2 = (int)((flb - fla) / lbl_803E32AC);
                if (count2 == 0)
                {
                    if (*(f32*)(model2 + 4) > prog)
                    {
                        ((StaffState*)swipe)->progress = *(f32*)(model2 + 4);
                    }
                    return;
                }
                acc = lbl_803E32B4;
                step = lbl_803E3288 / count2;
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
                            int ip;
                            int* pidx;
                            f32 *pAx, *pAy, *pAz, *pBx, *pBy, *pBz;
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
                            pAx = ptAx;
                            pAy = ptAy;
                            pAz = ptAz;
                            pBx = ptBx;
                            pBy = ptBy;
                            pBz = ptBz;
                            for (n = 4; n != 0; n--)
                            {
                                f32 t1, t2;
                                ip = *pidx * 12;
                                *pAx = (f32) * (s16*)((char*)tbl + ip) / lbl_803E32F4;
                                *pAy = (f32) * (s16*)((char*)tbl + ip + 2) / lbl_803E32F4;
                                *pAz = (f32) * (s16*)((char*)tbl + ip + 4) / lbl_803E32F4;
                                *pBx = (f32) * (s16*)((char*)tbl + ip + 6) / lbl_803E32F4;
                                *pBy = (f32) * (s16*)((char*)tbl + ip + 8) / lbl_803E32F4;
                                *pBz = (f32) * (s16*)((char*)tbl + ip + 10) / lbl_803E32F4;
                                t1 = cosv * *pAx - sinv * *pAz;
                                t2 = sinv * *pAx + cosv * *pAz;
                                *pAz = t2;
                                *pAx = t1;
                                t2 = sinv * *pBx + cosv * *pBz;
                                t1 = cosv * *pBx - sinv * *pBz;
                                *pBx = t1;
                                *pBz = t2;
                                pidx++;
                                pAx++;
                                pAy++;
                                pAz++;
                                pBx++;
                                pBy++;
                                pBz++;
                            }
                            first = 0;
                        }
                        vp = *(u8**)slot + *(u16*)(slot + 0xe) * 20;
                        *(f32*)(vp + 0) = Curve_EvalBSpline(ptBx, frac, NULL);
                        *(f32*)(vp + 4) = Curve_EvalBSpline(ptBy, frac, NULL);
                        *(f32*)(vp + 8) = Curve_EvalBSpline(ptBz, frac, NULL);
                        { f32 cur = *(f32*)(vp + 0); f32 bx = ((StaffState*)swipe)->anchorX; *(f32*)(vp + 0) = cur + (bx + acc * (((GameObject*)obj)->anim.worldPosX - bx)); }
                        { f32 cur = *(f32*)(vp + 4); f32 bx = ((StaffState*)swipe)->anchorY; *(f32*)(vp + 4) = cur + (bx + acc * (((GameObject*)obj)->anim.worldPosY - bx)); }
                        { f32 cur = *(f32*)(vp + 8); f32 bx = ((StaffState*)swipe)->anchorZ; *(f32*)(vp + 8) = cur + (bx + acc * (((GameObject*)obj)->anim.worldPosZ - bx)); }
                        vidx = ibase + frac;
                        *(f32*)(vp + 0xc) = vidx;
                        {
                            f32 k = lbl_803E32F4;
                            f32 t = flb - *(f32*)(vp + 0xc);
                            f32 clamped;
                            t = k * (t * lbl_803E3310);
                            if (t < lbl_803E32B4)
                            {
                                clamped = lbl_803E32B4;
                            }
                            else if (t > k)
                            {
                                clamped = k;
                            }
                            else
                            {
                                clamped = t;
                            }
                            *(s16*)(vp + 0x10) = k - clamped;
                        }
                        *(f32*)(vp + 0x14) = Curve_EvalBSpline(ptAx, frac, NULL);
                        *(f32*)(vp + 0x18) = Curve_EvalBSpline(ptAy, frac, NULL);
                        *(f32*)(vp + 0x1c) = Curve_EvalBSpline(ptAz, frac, NULL);
                        { f32 cur = *(f32*)(vp + 0x14); f32 bx = ((StaffState*)swipe)->anchorX; *(f32*)(vp + 0x14) = cur + (bx + acc * (((GameObject*)obj)->anim.worldPosX - bx)); }
                        { f32 cur = *(f32*)(vp + 0x18); f32 bx = ((StaffState*)swipe)->anchorY; *(f32*)(vp + 0x18) = cur + (bx + acc * (((GameObject*)obj)->anim.worldPosY - bx)); }
                        { f32 cur = *(f32*)(vp + 0x1c); f32 bx = ((StaffState*)swipe)->anchorZ; *(f32*)(vp + 0x1c) = cur + (bx + acc * (((GameObject*)obj)->anim.worldPosZ - bx)); }
                        *(f32*)(vp + 0x20) = vidx;
                        {
                            f32 k = lbl_803E32F4;
                            f32 t = flb - *(f32*)(vp + 0x20);
                            f32 clamped;
                            t = k * (t * lbl_803E3310);
                            if (t < lbl_803E32B4)
                            {
                                clamped = lbl_803E32B4;
                            }
                            else if (t > k)
                            {
                                clamped = k;
                            }
                            else
                            {
                                clamped = t;
                            }
                            *(s16*)(vp + 0x24) = k - clamped;
                        }
                        *(s16*)(slot + 0x12) += 2;
                        *(u16*)(slot + 0xe) += 2;
                        count2 -= 1;
                    }
                }
            }
        }
        ((StaffState*)swipe)->anchorX = ((GameObject*)obj)->anim.worldPosX;
        ((StaffState*)swipe)->anchorY = ((GameObject*)obj)->anim.worldPosY;
        ((StaffState*)swipe)->anchorZ = ((GameObject*)obj)->anim.worldPosZ;
        ((StaffState*)swipe)->progress = *(f32*)(model2 + 4);
    }
}

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
    if (obj == NULL || obj2 == NULL)
    {
        return;
    }
    {
        if (((StaffState*)state)->glowEnable != 0)
        {
            f32 burstScale;
            if (objFn_80296700(obj2) != 0)
            {
                power = lbl_803E3288;
                burstScale = lbl_803E3288;
            }
            else
            {
                power = lbl_803E328C;
                burstScale = lbl_803E3290;
            }
            if (((StaffState*)state)->glowAttackType == 7)
            {
                objfx_spawnArcedBurst(obj, lbl_803E3294, ((StaffState*)state)->glowAttackType, ((StaffState*)state)->glowEnable, 1, (int)(lbl_803E3298 * burstScale),
                                      lbl_803E3294, lbl_803E3294, lbl_803E329C * power, 0, 0);
            }
            else
            {
                objfx_spawnArcedBurst(obj, lbl_803E3288, ((StaffState*)state)->glowAttackType, ((StaffState*)state)->glowEnable, 1, (int)(lbl_803E3298 * burstScale),
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
                f32 progress;
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
                progress = ((GameObject*)obj2)->anim.currentMoveProgress;
                if (progress < lbl_803E32D0)
                {
                    fxB.f1 = lbl_803E32D4;
                    fxB.count = 9;
                    fxB.f0 = lbl_803E3288;
                    fxB.f2 = lbl_803E32B4;
                    (*gPartfxInterface)->spawnObject(obj, 0x7b3, &fxB, 2, -1, NULL);
                }
                else if (progress < lbl_803E32D8)
                {
                    fxB.f1 = lbl_803E32C4 * (lbl_803E32DC * (progress - lbl_803E32D0) - lbl_803E3294);
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
