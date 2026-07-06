/*
 * DLL 0xF7 (dll_F7) [8016984C-801713AC)
 *
 * Object-descriptor table unit: it defines the ObjectDescriptor vtables for a
 * batch of small map objects (kaldachompspit, pinponspike, pollen, pollen
 * fragment, mikabomb/shadow, staticCamera, gcbaddieshield, baddieInterestP,
 * animatedobj, dim2roofrub, depthOfFieldPoint, staff, fireball, flamethrowerspe,
 * shield, curve, restartMarker, checkpoint4) plus the static-data tables they
 * reference. Most per-object callbacks live in sibling DLL TUs; only a handful
 * of functions are defined here.
 *
 * The "dll_F7" object itself is a bouncing breakable prop: dll_F7_init acquires
 * its two model resources (0x5b/0x5a), dll_F7_update runs the hit/bounce logic
 * (hitsRemaining countdown, bounce offset/velocity damping, spawns a debris/
 * pickup object on break) and grants the placement's game bit on destruction.
 * The trailing GXWGFifo swipe* helpers are inlined display-list writers.
 */
#include "main/dll/xyzanimator.h"
#include "main/dll/genpropswgpipe_struct.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/genprops.h"
#include "main/mapEvent.h"
#include "main/objhits.h"
#include "main/resource.h"
#include "main/objprint.h"
#include "main/objlib.h"
#include "main/gamebits.h"
#include "main/dll/dll_00C8_depthoffieldpoint.h"
#include "main/dll/dll_00E3_fireball.h"
#include "main/dll/dll_00E4_flamethrowerspe.h"
#include "main/audio/sfx_trigger_ids.h"

/* object groups: static camera prop / dllf7 object */
#define STATICCAMERA_OBJGROUP 7
#define DLLF7_OBJGROUP 0x3e

#define DLLF7_OBJFLAG_HITDETECT_DISABLED 0x2000

void mikabomb_hitDetect(void);

extern ModgfxInterface** gModgfxInterface;

void mikabomb_free(int obj, int mode);

int mikabomb_getExtraSize(void);
int mikabomb_getObjectTypeId(void);

extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);

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

typedef struct DllF7Placement
{
    u8 pad0[0x14 - 0x0];
    s32 mapEventId;
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 completeGameBit;
    s16 unk20;
    u8 pad22[0x2C - 0x22];
    s16 unk2C;
    u8 pad2E[0x30 - 0x2E];
} DllF7Placement;

/* Spawn-setup buffer seeded by dll_F7_update for the gas-cloud child (obj id
 * 0xb): position head plus the class-specific fields (see the target stb/sth). */
typedef struct DllF7GasSetup
{
    u8 pad0[0x8 - 0x0];
    f32 posX;                /* 0x08 */
    f32 posY;                /* 0x0c */
    f32 posZ;                /* 0x10 */
    u8 pad14[0x1a - 0x14];
    u8 field1A;              /* 0x1a */
    u8 pad1B;                /* 0x1b */
    s16 field1C;             /* 0x1c */
    u8 pad1E[0x24 - 0x1e];
    s16 field24;             /* 0x24 */
    u8 pad26[0x2c - 0x26];
    s16 field2C;             /* 0x2c */
} DllF7GasSetup;

typedef struct DllF7Vec
{
    u8 b[16];
} DllF7Vec;

typedef struct DllF7HitBlock
{
    DllF7Vec params;
    s16 a;
    s16 b;
    s16 c;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} DllF7HitBlock;

extern DllF7Vec lbl_802C2260;

/* dll_F7 (bouncing prop) object extra-state */
typedef struct DllF7State
{
    f32 bounceOffset;
    f32 bounceVelocity;
    u8 byte8;
    s8 byte9;
    s8 hitsRemaining;
    s8 byteB;
} DllF7State;

extern int* Obj_SetupObject(void* setup, int mode, int mapLayer, int objIndex, void* parent);

void staticCamera_free(int obj)
{
    ObjGroup_RemoveObject(obj, STATICCAMERA_OBJGROUP);
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

void staticCamera_init(short* obj, int placement, int addToGroup)
{
    u8* colorState;

    *obj = -*(short*)(placement + 0x1c);
    obj[1] = -*(short*)(placement + 0x1e);
    obj[2] = -*(short*)(placement + 0x20);
    colorState = *(u8**)(obj + 0x5c);
    *colorState = *(u8*)(placement + 0x19);
    *(float*)(colorState + 4) = (f32)(u32) * (u8*)(placement + 0x1a);
    colorState[1] = 0;
    if (addToGroup == 0)
    {
        ObjGroup_AddObject((int)obj, STATICCAMERA_OBJGROUP);
    }
    return;
}

extern int Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int size, int b);
extern const f32 lbl_803E3400;
extern const f32 lbl_803E3404;
extern f32 lbl_803E3408;
extern f32 lbl_803E340C;
extern f32 lbl_803E3410;
extern f32 lbl_803E3414;
extern f32 lbl_803E3418;
extern void fn_8003B5E0(int a, int b, int c, u8 d);
extern void Sfx_PlayAtPositionFromObject(int* obj, f32 x, f32 y, f32 z, int sfx);
extern void Obj_SetActiveModelIndex(int* obj, int idx);
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;

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

void shield_hitDetect(void);

void shield_release(void);

void shield_initialise(void);

void dll_F7_hitDetect(void)
{
}

void dll_F7_release(void)
{
}

void dll_F7_initialise(void)
{
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
int shield_getExtraSize(void);
int shield_getObjectTypeId(void);
int dll_F7_getExtraSize(void) { return 0xc; }
int dll_F7_getObjectTypeId(void) { return 0x2; }

extern void* gDllF7Resource5B;
extern void* gDllF7Resource5A;

void dll_F7_free(int obj)
{
    (*gModgfxInterface)->detachSource((void*)obj);
    Resource_Release(gDllF7Resource5B);
    Resource_Release(gDllF7Resource5A);
    gDllF7Resource5B = NULL;
    gDllF7Resource5A = NULL;
    ObjGroup_RemoveObject(obj, DLLF7_OBJGROUP);
}

void dim2roofrub_free(int* obj);

extern void gcbaddieshield_update(int* obj);


void staff_func10(int* obj, s32 v);
void staff_setHitReactValue(int* obj, s32 v);
void staff_addHitReactValue(int* obj, s32 delta);
void staff_getHitGeometryPoints(int* obj, f32* outA, f32* outB);
void staff_func15(int* obj, s16 idx, f32 f1, f32 f2);






extern void shield_update(int* obj);

void restartmarker_init(int* obj, int* state);

void dll_F7_update(int* obj);
void dll_F7_init(int* obj, int* params);

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

void dll_F7_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    DllF7State* state = ((GameObject*)obj)->extra;
    if (state->byte9 == 0 && visible != 0)
    {
        f32 v = state->bounceOffset;
        if (v != lbl_803E3400)
        {
            fn_8003B5E0(0xc8, 0, 0, v);
        }
        ((void (*)(int*, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p2, p3, p4, p5, lbl_803E3404);
    }
}

void dll_F7_init(int* obj, int* params)
{
    int* state = ((GameObject*)obj)->extra;
    ObjGroup_AddObject((int)obj, DLLF7_OBJGROUP);
    *(s16*)obj = (s16)((s8) * (s8*)((char*)params + 0x18) << 8);
    ((GameObject*)obj)->objectFlags |= DLLF7_OBJFLAG_HITDETECT_DISABLED;
    gDllF7Resource5B = Resource_Acquire(0x5b, 1);
    gDllF7Resource5A = Resource_Acquire(0x5a, 1);
    {
        ObjModelState* modelState = ((GameObject*)obj)->anim.modelState;
        if (modelState != NULL)
        {
            modelState->flags |= 0x810;
        }
    }
    *(u8*)&((DllF7State*)state)->hitsRemaining = 2;
    *(u8*)&((DllF7State*)state)->byteB = *(u8*)((char*)params + 0x19);
    if (((DllF7State*)state)->byteB == 0)
    {
        int r = (*gMapEventInterface)->shouldNotSaveTime(((DllF7Placement*)params)->mapEventId);
        if (r == 0)
        {
            ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
            hitState->flags &= ~1;
            *(u8*)&((DllF7State*)state)->byte9 = 1;
            ((DllF7State*)state)->byte8 = 0;
        }
    }
}

void dll_F7_update(int* obj)
{
    extern void Sfx_PlayFromObject(int* obj, int sfx); /* #57 */
    extern u32 ObjGroup_FindNearestObject(); /* #57 */
    DllF7State* state = ((GameObject*)obj)->extra;
    DllF7HitBlock blk;
    f32 radius;
    u32 hitVolume;

    blk.params = lbl_802C2260;
    if (state->byte9 != 0)
    {
        int* params = *(int**)&((GameObject*)obj)->anim.placementData;
        if (state->byteB == 0 &&
            (*gMapEventInterface)->shouldNotSaveTime(((DllF7Placement*)params)->mapEventId) != 0)
        {
            state->byte9 = 0;
            state->byte8 = 1;
            state->hitsRemaining = 2;
            ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->flags |= OBJHITS_PRIORITY_STATE_ENABLED;
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
        }
        else
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        }
        return;
    }
    if (ObjHits_GetPriorityHitWithPosition((int)obj, 0, 0, &hitVolume, &blk.x, &blk.y, &blk.z) != 0)
    {
        if ((state->hitsRemaining -= hitVolume) > 0)
        {
            Sfx_PlayAtPositionFromObject(obj, blk.x, blk.y, blk.z, SFXTRIG_crtsmsh6);
            Obj_SetActiveModelIndex(obj, 2 - state->hitsRemaining);
            state->bounceOffset = lbl_803E3404;
            state->bounceVelocity = lbl_803E3408;
            blk.x += playerMapOffsetX;
            blk.z += playerMapOffsetZ;
            blk.scale = lbl_803E3404;
            blk.c = 0;
            blk.b = 0;
            blk.a = 0;
            ((void (*)(int, int, s16*, int, int, DllF7Vec*))((int*)*(int**)gDllF7Resource5A)[
                1])(0, 1, (s16*)((int)&blk + 16), 1025, -1, &blk.params);
        }
    }
    if (state->hitsRemaining <= 0)
    {
        int* params = *(int**)&((GameObject*)obj)->anim.placementData;
        if (state->byteB == 0)
        {
            (*gMapEventInterface)->addTime(((DllF7Placement*)params)->mapEventId, lbl_803E340C);
        }
        state->byte9 = 1;
        state->byte8 = 0;
        Sfx_PlayFromObject(obj, SFXTRIG_dsmk2_c);
        ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
        if ((int)((DllF7Placement*)params)->completeGameBit != -1)
        {
            GameBit_Set((int)((DllF7Placement*)params)->completeGameBit, 1);
        }
        if (state->byteB == 0 && (u8)Obj_IsLoadingLocked() != 0)
        {
            s16* alloc = Obj_AllocObjectSetup(0x30, 0xb);
            ((DllF7GasSetup*)alloc)->field1C = -1;
            ((DllF7GasSetup*)alloc)->posX = ((GameObject*)obj)->anim.localPosX;
            ((DllF7GasSetup*)alloc)->posY = lbl_803E3410 + ((GameObject*)obj)->anim.localPosY;
            ((DllF7GasSetup*)alloc)->posZ = ((GameObject*)obj)->anim.localPosZ;
            ((DllF7GasSetup*)alloc)->field1A = 3;
            ((DllF7GasSetup*)alloc)->field2C = -1;
            ((DllF7GasSetup*)alloc)->field24 = -1;
            Obj_SetupObject(alloc, 5, ((GameObject*)obj)->anim.mapEventSlot, -1, ((GameObject*)obj)->anim.parent);
        }
        else
        {
            int* near;
            radius = lbl_803E3414;
            near = (int*)ObjGroup_FindNearestObject(4, obj, &radius);
            if (near != NULL)
            {
                ((GameObject*)near)->anim.localPosX = ((GameObject*)near)->anim.worldPosX = ((GameObject*)obj)->anim.
                    localPosX;
                ((GameObject*)near)->anim.localPosY = ((GameObject*)near)->anim.worldPosY = lbl_803E3410 + ((GameObject
                    *)obj)->anim.localPosY;
                ((GameObject*)near)->anim.localPosZ = ((GameObject*)near)->anim.worldPosZ = ((GameObject*)obj)->anim.
                    localPosZ;
                *(s16*)near = *(s16*)obj;
            }
        }
        ((void (*)(int*, int, int, int, int, int))((int*)*(int**)gDllF7Resource5B)[1])(obj, 1, 0, 2, -1, 0);
    }
    if (state->bounceOffset > lbl_803E3400)
    {
        state->bounceOffset = timeDelta * state->bounceVelocity + state->bounceOffset;
        if (state->bounceOffset < lbl_803E3400)
        {
            state->bounceOffset = lbl_803E3400;
        }
        else if (state->bounceOffset > lbl_803E3418)
        {
            state->bounceOffset = lbl_803E3418 - (state->bounceOffset - lbl_803E3418);
            state->bounceVelocity = -state->bounceVelocity;
        }
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
