/* DLL 0x00ED — collectible / genprops group. TU: 0x80171D14–0x801723DC. */
#include "main/game_object.h"
#include "main/dll/genpropswgpipe_struct.h"
#include "main/dll/genprops.h"
#include "main/dll/path_control_interface.h"
#include "main/audio/sfx_ids.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/gfxemit_state.h"
#include "main/objhits.h"
#include "main/obj_placement.h"
#include "main/dll/collectible_state.h"

extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern u32 ObjHitRegion_FindContainingId(f32 x, f32 y, f32 z);

extern f32 lbl_803DC074;
extern f32 lbl_803E40EC;

extern void* getTrickyObject(void);
extern u32 GameBit_Get(int eventId);

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

void shield_free(int obj);

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
extern void saveGame_saveObjectPos(int obj);
extern void staff_setupSwipe(int p1, int p2, int p3, int p4);
extern u8 framesThisStep;
extern f32 timeDelta;
extern void objMove(int* obj, f32 x, f32 y, f32 z);
extern void GameBit_Set(int eventId, int value);
extern f32 mathSinf(f32 v);
extern f32 mathCosf(f32 x);
extern f32 sqrtf(f32 x);
extern void playerAddHealth(void* player, int amount);
extern void gameBitIncrement(int eventId);
extern void saveGame_unsaveObjectPos(int* obj);
extern f32 lbl_803E3450;
extern f32 lbl_803E3454;
extern f32 lbl_803E345C;
extern f32 lbl_803E3460;
extern f32 lbl_803E3464;
extern f32 lbl_803E3468;
extern f32 lbl_803E346C;
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017a88();
extern undefined4 ObjMsg_SendToObject();
extern int ObjTrigger_IsSet();
extern double FUN_80293900();
extern undefined4 DAT_803dc070;
extern f64 DOUBLE_803e4108;
extern f32 lbl_803E40F4;
extern f32 lbl_803E40F8;
extern f32 lbl_803E40FC;
extern f32 lbl_803E4100;
extern f32 lbl_803E4104;
extern uint GameBit_Get(int);
extern f32 mathSinf(f32 x);
extern f32 lbl_803E3458;
extern f32 lbl_803E3484;
extern f32 lbl_803E3488;
extern f32 lbl_803E348C;
extern void fn_8003B608(s16 a, s16 b, s16 c);
extern u8* fn_802972A8(void);
extern f32 Vec_xzDistance(f32 * a, f32 * b);
extern int fn_8029622C(u8 * player);
extern void GameBit_Set(int bit, int value);
extern f32 lbl_803E3490;
extern f32 lbl_803E3478;
extern f32 lbl_803E347C;
extern f32 lbl_803E3480;
extern void fn_801723DC(int obj);
extern int ObjMsg_Pop(int obj, int* outMessage, int* outParam, int* outSender);
extern uint GameBit_Get(int eventId);
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_AllocQueue();
extern u8 lbl_80320C58[];
extern u32 lbl_803E3440;
extern u8 lbl_803E3444;
extern f32 lbl_803E3494;
extern f32 lbl_803E3498;
extern f32 lbl_803E349C;
extern f32 lbl_803E34A0;

u8 collectible_func0F(int* obj) { return *(u8*)((char*)((int**)obj)[0xb8 / 4] + 0x1e); }

s32 staff_func16(int* obj);

void flamethrowerspe_render(void);

int collectible_setScale(int* obj) { return ((GameObject*)obj)->unkF4; }

void objSetAnimField48to0(int* obj);

void flamethrowerspe_func0B(int* obj);

void collectible_func0E(int* obj, u32 v)
{
    *(u8*)((char*)((int**)obj)[0xb8 / 4] + 0x1e) = (u8)v;
}

void collectible_render2(int* obj, f32 f1, f32 f2, f32 f3)
{
    s32 v = 0x8;
    *(u8*)((char*)((int**)obj)[0xb8 / 4] + 0x1d) = (u8)v;
    ((GameObject*)obj)->anim.velocityX = f1;
    ((GameObject*)obj)->anim.velocityY = f2;
    ((GameObject*)obj)->anim.velocityZ = f3;
}

void collectible_func10(int* obj, f32 f1, f32 f2, f32 f3)
{
    char* inner = (char*)((int**)obj)[0xb8 / 4];
    ((GameObject*)obj)->anim.localPosX = f1;
    *(f32*)(inner + 0x24) = f1;
    ((GameObject*)obj)->anim.localPosY = f2;
    *(f32*)(inner + 0x28) = f2;
    ((GameObject*)obj)->anim.localPosZ = f3;
    *(f32*)(inner + 0x2c) = f3;
    if (GameBit_Get(*(s16*)(inner + 0x10)) == 0)
    {
        saveGame_saveObjectPos((int)obj);
    }
}

void collectible_func0B(int* obj, int flag)
{
    char* inner = (char*)((int**)obj)[0xb8 / 4];
    *(u8*)(inner + 0xf) = (u8)flag;
    if (flag != 0)
    {
        ObjHits_DisableObject((u32)obj);
    }
    else
    {
        if (GameBit_Get(*(s16*)(inner + 0x10)) == 0)
        {
            ObjHits_EnableObject((u32)obj);
        }
    }
}

int collectible_modelMtxFn(int* obj)
{
    int* inner = (int*)*(int*)&((GameObject*)obj)->extra;
    if (*(int*)((char*)inner + 0x18) == -2)
    {
        f32 f1 = ((GameObject*)obj)->anim.worldPosX;
        f32 f2 = ((GameObject*)obj)->anim.worldPosY;
        f32 f3 = ((GameObject*)obj)->anim.worldPosZ;
        *(u32*)((char*)inner + 0x18) = (u16)ObjHitRegion_FindContainingId(f1, f2, f3);
    }
    return *(int*)((char*)inner + 0x18);
}

void staff_modelMtxFn(int* obj, int p4, int p5);

void gcbaddieshield_update(int* obj);

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

volatile GenPropsWGPipe GXWGFifo : (0xCC008000);

static inline void swipePos3f32(const f32 x, const f32 y, const f32 z);

static inline void swipeColor4u8(const u8 r, const u8 g, const u8 b, const u8 a);

static inline void swipeTexCoord2f32(const f32 s, const f32 t);

#pragma opt_common_subs off

void staff_update(int* obj);

void fn_80171E5C(int* obj)
{
    extern void itemPickupDoParticleFx(int* obj, f32 f, int a, int b); /* #57 */
    extern void Sfx_PlayFromObject(int* obj, int sfx); /* #57 */
    extern void* Obj_GetPlayerObject(void); /* #57 */
    u8* state = ((GameObject*)obj)->extra;
    u8* params = *(u8**)&((GameObject*)obj)->anim.placementData;
    u8* setup2 = ((GameObject*)obj)->anim.modelInstance->extraSetupData;
    Obj_GetPlayerObject();
    getTrickyObject();
    Obj_GetPlayerObject();
    getTrickyObject();
    ObjHits_DisableObject((u32)obj);
    if (((GameObject*)obj)->anim.flags & 0x2000)
    {
        *(f32*)(state + 8) = lbl_803E3450;
        if (((GameObject*)obj)->anim.modelState != NULL)
        {
            ((GameObject*)obj)->anim.modelState->flags = OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        }
    }
    if (*(s16*)(state + 0x10) != -1)
    {
        GameBit_Set(*(s16*)(state + 0x10), 1);
        saveGame_unsaveObjectPos(obj);
    }
    if (*(s16*)(params + 0x1e) != -1)
    {
        GameBit_Set(*(s16*)(params + 0x1e), 1);
    }
    if (*(s16*)(params + 0x2c) > 0)
    {
        gameBitIncrement(*(s16*)(params + 0x2c));
    }
    switch (*(s16*)(setup2 + 2))
    {
    case 1:
        switch (((GameObject*)obj)->anim.seqId)
        {
        case 90:
            Sfx_PlayFromObject(obj, 73);
            itemPickupDoParticleFx(obj, lbl_803E3454, 2, 40);
            break;
        case 793:
            Sfx_PlayFromObject(obj, 362);
            GameBit_Set(1001, 1);
            *(s16*)(state + 0x3c) = 1200;
            itemPickupDoParticleFx(obj, lbl_803E3454, 255, 40);
            break;
        case 1702:
            {
                s8 c = GameBit_Get(2154);
                if (c < 7)
                {
                    c = c + 1;
                }
                GameBit_Set(2154, c);
                itemPickupDoParticleFx(obj, lbl_803E3454, 6, 40);
                Sfx_PlayFromObject(obj, 73);
                break;
            }
        case 34:
            Sfx_PlayFromObject(obj, 73);
            itemPickupDoParticleFx(obj, lbl_803E3454, 255, 40);
            break;
        default:
            Sfx_PlayFromObject(obj, 88);
            itemPickupDoParticleFx(obj, lbl_803E3454, 255, 40);
            break;
        }
        break;
    case 4:
        switch (((GameObject*)obj)->anim.seqId)
        {
        case 11:
            Sfx_PlayFromObject(Obj_GetPlayerObject(), 73);
            playerAddHealth(Obj_GetPlayerObject(), 4);
            itemPickupDoParticleFx(obj, lbl_803E3454, 3, 40);
            break;
        case 973:
            playerAddHealth(Obj_GetPlayerObject(), 2);
            Sfx_PlayFromObject(Obj_GetPlayerObject(), 73);
            itemPickupDoParticleFx(obj, lbl_803E3454, 1, 40);
            break;
        default:
            Sfx_PlayFromObject(Obj_GetPlayerObject(), 88);
            itemPickupDoParticleFx(obj, lbl_803E3454, 255, 40);
            break;
        }
        break;
    default:
        Sfx_PlayFromObject(obj, 88);
        itemPickupDoParticleFx(obj, lbl_803E3454, 255, 40);
        break;
    }
    ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
    ((GameObject*)obj)->unkF4 = 1;
}

void fn_80172144(int* obj)
{
    u8* state = ((GameObject*)obj)->extra;
    if (((GameObject*)obj)->anim.seqId == 1702)
    {
        objMove(obj, lbl_803E345C, ((GameObject*)obj)->anim.velocityY * (f32)(u32)framesThisStep, lbl_803E345C);
    }
    else
    {
        u8 n = framesThisStep;
        objMove(obj, ((GameObject*)obj)->anim.velocityX * (f32)(u32)n,
                ((GameObject*)obj)->anim.velocityY * (f32)(u32)n,
                ((GameObject*)obj)->anim.velocityZ * (f32)(u32)n);
    }
    (*gPathControlInterface)->update(obj, state + 0x50, timeDelta);
    (*gPathControlInterface)->apply(obj, state + 0x50);
    (*gPathControlInterface)->advance(obj, state + 0x50, timeDelta);
    if (*(s8*)(state + 0x2b1) != 0)
    {
        f32 nx = -((GameObject*)obj)->anim.velocityX;
        f32 ny = -((GameObject*)obj)->anim.velocityY;
        f32 nz = -((GameObject*)obj)->anim.velocityZ;
        f32 len = sqrtf(nx * nx + ny * ny + nz * nz);
        if (lbl_803E345C != len)
        {
            f32 inv = lbl_803E3454 / len;
            nx = nx * inv;
            ny = ny * inv;
            nz = nz * inv;
        }
        {
            f32 px = *(f32*)(state + 0xb8);
            f32 py = *(f32*)(state + 0xbc);
            f32 pz = *(f32*)(state + 0xc0);
            f32 d = lbl_803E3460 * (nx * px + ny * py + nz * pz);
            ((GameObject*)obj)->anim.velocityX = px * d;
            ((GameObject*)obj)->anim.velocityY = py * d;
            ((GameObject*)obj)->anim.velocityZ = pz * d;
        }
        ((GameObject*)obj)->anim.velocityX -= nx;
        ((GameObject*)obj)->anim.velocityY -= ny;
        ((GameObject*)obj)->anim.velocityZ -= nz;
        ((GameObject*)obj)->anim.velocityY *= len;
        ((GameObject*)obj)->anim.velocityY *= lbl_803E3464;
        ((GameObject*)obj)->anim.velocityX *= len;
        ((GameObject*)obj)->anim.velocityZ *= len;
        state[0x1d] -= 1;
        if (state[0x1d] == 0)
        {
            f32 z;
            state[0x1d] = 0;
            z = lbl_803E345C;
            ((GameObject*)obj)->anim.velocityX = z;
            ((GameObject*)obj)->anim.velocityY = z;
            ((GameObject*)obj)->anim.velocityZ = z;
        }
    }
    else
    {
        ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY * lbl_803E3468;
        ((GameObject*)obj)->anim.velocityY = -(lbl_803E346C * timeDelta - ((GameObject*)obj)->anim.velocityY);
    }
}

void staff_setupSwipe(int p1, int p2, int p3, int p4);

#pragma opt_common_subs reset

#pragma scheduling on
#pragma peephole on
void FUN_801723dc(int param_1)
{
    float fVar1;
    float fVar2;
    uint uVar3;
    int iVar4;
    double dVar5;
    double dVar6;
    double dVar7;
    double dVar8;
    double dVar9;

    GfxEmitState* state = ((GameObject*)param_1)->extra;
    iVar4 = (int)state;
    if (((GameObject*)param_1)->anim.seqId == 0x6a6)
    {
        FUN_80017a88((double)lbl_803E40F4,
                     (double)(((GameObject*)param_1)->anim.velocityY *
                         (float)((double)CONCAT44(0x43300000, (uint)DAT_803dc070) - DOUBLE_803e4108))
                     , (double)lbl_803E40F4, param_1);
    }
    else
    {
        uVar3 = (uint)DAT_803dc070;
        FUN_80017a88((double)(((GameObject*)param_1)->anim.velocityX *
                         (float)((double)CONCAT44(0x43300000, uVar3) - DOUBLE_803e4108)),
                     (double)(((GameObject*)param_1)->anim.velocityY *
                         (float)((double)CONCAT44(0x43300000, uVar3) - DOUBLE_803e4108)),
                     (double)(((GameObject*)param_1)->anim.velocityZ *
                         (float)((double)CONCAT44(0x43300000, uVar3) - DOUBLE_803e4108)), param_1);
    }
    (*gPathControlInterface)->update((void*)param_1, state->pathState, lbl_803DC074);
    (*gPathControlInterface)->apply((void*)param_1, state->pathState);
    (*gPathControlInterface)->advance((void*)param_1, state->pathState, lbl_803DC074);
    if (*(char*)&((GfxEmitState*)iVar4)->unk2B1 == '\0')
    {
        ((GameObject*)param_1)->anim.velocityY = ((GameObject*)param_1)->anim.velocityY * lbl_803E4100;
        ((GameObject*)param_1)->anim.velocityY = -(lbl_803E4104 * lbl_803DC074 - ((GameObject*)param_1)->anim.
            velocityY);
    }
    else
    {
        dVar8 = -(double)((GameObject*)param_1)->anim.velocityX;
        dVar7 = -(double)((GameObject*)param_1)->anim.velocityY;
        dVar9 = -(double)((GameObject*)param_1)->anim.velocityZ;
        dVar6 = FUN_80293900((double)(float)(dVar9 * dVar9 +
            (double)(float)(dVar8 * dVar8 +
                (double)(float)(dVar7 * dVar7))));
        if ((double)lbl_803E40F4 != dVar6)
        {
            dVar5 = (double)(float)((double)lbl_803E40EC / dVar6);
            dVar8 = (double)(float)(dVar8 * dVar5);
            dVar7 = (double)(float)(dVar7 * dVar5);
            dVar9 = (double)(float)(dVar9 * dVar5);
        }
        fVar1 = *(float*)(iVar4 + 0xbc);
        fVar2 = *(float*)(iVar4 + 0xc0);
        dVar5 = (double)(lbl_803E40F8 *
            (float)(dVar9 * (double)fVar2 +
                (double)(float)(dVar8 * (double)*(float*)(iVar4 + 0xb8) +
                    (double)(float)(dVar7 * (double)fVar1))));
        ((GameObject*)param_1)->anim.velocityX = (float)((double)*(float*)(iVar4 + 0xb8) * dVar5);
        ((GameObject*)param_1)->anim.velocityY = (float)((double)fVar1 * dVar5);
        ((GameObject*)param_1)->anim.velocityZ = (float)((double)fVar2 * dVar5);
        ((GameObject*)param_1)->anim.velocityX = (float)((double)((GameObject*)param_1)->anim.velocityX - dVar8);
        ((GameObject*)param_1)->anim.velocityY = (float)((double)((GameObject*)param_1)->anim.velocityY - dVar7);
        ((GameObject*)param_1)->anim.velocityZ = (float)((double)((GameObject*)param_1)->anim.velocityZ - dVar9);
        ((GameObject*)param_1)->anim.velocityY = (float)((double)((GameObject*)param_1)->anim.velocityY * dVar6);
        ((GameObject*)param_1)->anim.velocityY = ((GameObject*)param_1)->anim.velocityY * lbl_803E40FC;
        ((GameObject*)param_1)->anim.velocityX = (float)((double)((GameObject*)param_1)->anim.velocityX * dVar6);
        ((GameObject*)param_1)->anim.velocityZ = (float)((double)((GameObject*)param_1)->anim.velocityZ * dVar6);
        *(char*)&((GfxEmitState*)iVar4)->unk1D = *(char*)&((GfxEmitState*)iVar4)->unk1D + -1;
        if (*(char*)&((GfxEmitState*)iVar4)->unk1D == '\0')
        {
            ((GfxEmitState*)iVar4)->unk1D = 0;
            fVar1 = lbl_803E40F4;
            ((GameObject*)param_1)->anim.velocityX = lbl_803E40F4;
            ((GameObject*)param_1)->anim.velocityY = fVar1;
            ((GameObject*)param_1)->anim.velocityZ = fVar1;
        }
    }
    return;
}

#pragma scheduling off
void collectible_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
    ObjGroup_RemoveObject(obj, 4);
    return;
}

#pragma scheduling on
int collectible_getExtraSize(void)
{
    return 0x2b8;
}

int collectible_getObjectTypeId(void)
{
    return 0x13;
}

void collectible_hitDetect(void)
{
}

#pragma scheduling off
#pragma peephole off
int collectible_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    extern void objfx_spawnDirectionalBurst(int obj, int a, f32 fa, int b, int c, int d, f32 fb, int e, int f); /* #57 */
    int* state = ((GameObject*)obj)->extra;
    f32 buf[6];
    int j;
    int i;
    f32 s_val;
    f32 c_val;
    f32 vy;

    if (((GfxEmitState*)state)->enableGameBit != -1)
    {
        ((GfxEmitState*)state)->enableGameBitClear = (u8)(GameBit_Get((s32)((GfxEmitState*)state)->enableGameBit) == 0);
    }
    if (((GfxEmitState*)state)->enableGameBitClear == 0)
    {
        switch (((GameObject*)obj)->anim.seqId)
        {
        case 0x6a6:
            objfx_spawnDirectionalBurst(obj, 5, lbl_803E3454, 6, 1, 0x14, lbl_803E3458, 0, 0);
            break;
        }
    }

    animUpdate->sequenceEventActive = 0;
    for (i = 0; i < (s32)animUpdate->eventCount; i++)
    {
        u8 cmd = animUpdate->eventIds[i];
        if (cmd == 1)
        {
            s_val = lbl_803E3484 * mathCosf(lbl_803E3488);
            c_val = lbl_803E3484 * mathSinf(lbl_803E3488);
            *(u8*)((char*)((GameObject*)obj)->extra + 0x1d) = 8;
            ((GameObject*)obj)->anim.velocityX = c_val;
            ((GameObject*)obj)->anim.velocityY = (vy = lbl_803E3460);
            ((GameObject*)obj)->anim.velocityZ = s_val;
            *(u8*)((char*)((GameObject*)obj)->extra + 0x1d) = 8;
            ((GameObject*)obj)->anim.velocityX = lbl_803E348C;
            ((GameObject*)obj)->anim.velocityY = vy;
            ((GameObject*)obj)->anim.velocityZ = lbl_803E345C;
        }
        else if (cmd == 2)
        {
            *(u8*)((char*)state + 0x3e) = 1;
        }
        else if (cmd == 3)
        {
            f32 z;
            j = 0;
            z = lbl_803E345C;
            for (; j < 10; j++)
            {
                buf[3] = z;
                buf[4] = z;
                buf[5] = z;
                (*gPartfxInterface)->spawnObject((void*)obj, 0x7ef, buf, 1,
                                                 -1, NULL);
            }
        }
    }
    return 0;
}

void fn_80172824(int obj, u8* state)
{
    extern void fn_80171E5C(int obj); /* #57 */
    extern u8* Obj_GetPlayerObject(void); /* #57 */
    u8* player;
    s16* attach;
    u8* focus;
    f32 dist;
    f32 dy;

    attach = ((GameObject*)obj)->anim.placementData;
    player = Obj_GetPlayerObject();
    if (player == NULL)
    {
        return;
    }
    if ((state[0x37] & 1) != 0)
    {
        return;
    }
    focus = fn_802972A8();
    if (focus == NULL)
    {
        focus = player;
    }
    dist = Vec_xzDistance(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)focus)->anim.worldPosX);
    dy = ((GameObject*)focus)->anim.worldPosY - ((GameObject*)obj)->anim.worldPosY;
    if (dy < lbl_803E345C)
    {
        dy = -dy;
    }
    if (dy < lbl_803E3490 && dist < *(f32*)(state + 4) && fn_8029622C(player) != 0)
    {
        ((GfxEmitState*)state)->unk48 = -1;
        switch (((GameObject*)obj)->anim.seqId)
        {
        case 0xb:
            if (GameBit_Get(0x90e) == 0)
            {
                ObjMsg_SendToObject(player, 0x7000a, obj, state + 0x48);
                GameBit_Set(0x90e, 1);
            }
            else
            {
                fn_80171E5C(obj);
            }
            state[0x37] |= 1;
            break;
        case 0x319:
            fn_80171E5C(obj);
            state[0x37] |= 1;
            break;
        case 0x49:
        case 0x2da:
        case 0x3cd:
            if (GameBit_Get(0x90f) == 0)
            {
                ObjMsg_SendToObject(player, 0x7000a, obj, state + 0x48);
                GameBit_Set(0x90f, 1);
            }
            else
            {
                fn_80171E5C(obj);
            }
            state[0x37] |= 1;
            break;
        case 0x6a6:
            if (GameBit_Get(0x9a8) == 0)
            {
                ObjMsg_SendToObject(player, 0x7000a, obj, state + 0x48);
                GameBit_Set(0x9a8, 1);
            }
            else
            {
                fn_80171E5C(obj);
            }
            state[0x37] |= 1;
            break;
        default:
            if (ObjTrigger_IsSet(obj) != 0)
            {
                GameBit_Set(0xa7b, 1);
                ((GfxEmitState*)state)->unk48 = attach[0xf];
                ObjMsg_SendToObject(player, 0x7000a, obj, state + 0x48);
                state[0x37] |= 1;
                if (((GameObject*)obj)->anim.modelState != NULL)
                {
                    ((GameObject*)obj)->anim.modelState->flags = OBJ_MODEL_STATE_SHADOW_FADE_OUT;
                }
            }
            break;
        }
    }
    *(f32*)state = dist;
}

void collectible_update(int obj)
{
    extern void fn_80172144(int obj); /* #57 */
    extern void Obj_FreeObject(int obj); /* #57 */
    extern void itemPickupDoParticleFx(int obj, f32 scale, int a, int b); /* #57 */
    extern void fn_80171E5C(int obj); /* #57 */
    extern u8* Obj_GetPlayerObject(void); /* #57 */
    extern void objfx_spawnDirectionalBurst(int obj, int a, f32 fa, int b, int c, int d, f32 fb, int e, int f); /* #57 */
    u8* state = ((GameObject*)obj)->extra;
    ObjHitsPriorityState* hitState;
    int msgParam;
    int msg;
    int t;
    f32 timer;
    f32 zero;

    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
    timer = ((GfxEmitState*)state)->delayTimer;
    zero = lbl_803E345C;
    if (timer != zero)
    {
        ((GfxEmitState*)state)->delayTimer = timer - timeDelta;
        if (((GfxEmitState*)state)->delayTimer <= zero)
        {
            ((GfxEmitState*)state)->delayTimer = zero;
            ObjHits_DisableObject((u32)obj);
            if ((((GameObject*)obj)->anim.flags & 0x2000) != 0)
            {
                Obj_FreeObject(obj);
            }
        }
        return;
    }
    if (((GfxEmitState*)state)->enableGameBit != -1)
    {
        state[0x1e] = (u8)(GameBit_Get((s32)((GfxEmitState*)state)->enableGameBit) == 0);
    }
    if (state[0x1e] != 0 || state[0xf] != 0)
    {
        return;
    }
    switch (((GameObject*)obj)->anim.seqId)
    {
    case 0x6a6:
        objfx_spawnDirectionalBurst(obj, 5, lbl_803E3454, 6, 1, 0x14, lbl_803E3458, 0, 0);
        break;
    }
    timer = ((GfxEmitState*)state)->intervalTimer;
    zero = lbl_803E345C;
    if (timer != zero)
    {
        ((GfxEmitState*)state)->intervalTimer = timer - timeDelta;
        if (((GfxEmitState*)state)->intervalTimer <= zero)
        {
            if ((((GameObject*)obj)->anim.flags & 0x2000) != 0)
            {
                ((GfxEmitState*)state)->delayTimer = lbl_803E3450;
                if (((GameObject*)obj)->anim.modelState != NULL)
                {
                    ((GameObject*)obj)->anim.modelState->flags = OBJ_MODEL_STATE_SHADOW_FADE_OUT;
                }
                itemPickupDoParticleFx(obj, lbl_803E3454, 255, 40);
            }
            ((GfxEmitState*)state)->intervalTimer = lbl_803E345C;
            return;
        }
    }
    while (ObjMsg_Pop(obj, &msg, &msgParam, NULL) != 0)
    {
        switch (msg)
        {
        case 0x7000b:
            fn_80171E5C(obj);
            break;
        }
    }
    switch (((GameObject*)obj)->anim.seqId)
    {
    case 0x319:
        t = ((GfxEmitState*)state)->hideFrames;
        if (t != 0)
        {
            ((GfxEmitState*)state)->hideFrames -= framesThisStep;
            if (((GfxEmitState*)state)->hideFrames <= 0)
            {
                ((GfxEmitState*)state)->hideFrames = 0;
                state[0x37] &= ~1;
                ((GameObject*)obj)->anim.alpha = 255;
                ((GameObject*)obj)->unkF4 = 0;
            }
        }
        break;
    }
    if (((GameObject*)obj)->unkF4 != 0)
    {
        if (((GameObject*)obj)->anim.hitReactState != NULL)
        {
            hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
            hitState->flags |= 0x100;
        }
        ObjHits_DisableObject((u32)obj);
        if (((GfxEmitState*)state)->hideGameBit != -1 && GameBit_Get((s32)((GfxEmitState*)state)->hideGameBit) == 0)
        {
            ((GameObject*)obj)->unkF4 = 0;
        }
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~8;
        fn_801723DC(obj);
        if (state[0x1d] != 0)
        {
            fn_80172144(obj);
        }
        if (state[0x3e] != 0)
        {
            state[0x3e]--;
            if (state[0x3e] == 0)
            {
                ((GfxEmitState*)state)->unk48 = -1;
                ObjMsg_SendToObject(Obj_GetPlayerObject(), 0x7000a, obj, state + 0x48);
            }
        }
        else
        {
            fn_80172824(obj, state);
        }
    }
}

void collectible_render(int obj, int a, int b, int c, int d, s8 visible)
{
    extern void objRenderFn_8003b8f4(int obj, int a, int b, int c, int d, f32 e); /* #57 */
    extern void objfx_spawnDirectionalBurst(int obj, int a, f32 fa, int b, int c, int d, f32 fb, int e, int f); /* #57 */
    int state = *(int*)&((GameObject*)obj)->extra;
    if (visible != 0 && ((GfxEmitState*)state)->delayTimer == lbl_803E345C && ((GameObject*)obj)->unkF4 == 0
        && (((GameObject*)obj)->anim.seqId == 0x156 || ((GfxEmitState*)state)->enableGameBitClear == 0))
    {
        if ((((ObjAnimComponent*)obj)->modelInstance->flags & 0x10000) != 0 && ((GfxEmitState*)state)->useColor != 0)
        {
            fn_8003B608(((GfxEmitState*)state)->colorR, ((GfxEmitState*)state)->colorG, ((GfxEmitState*)state)->colorB);
        }
        objRenderFn_8003b8f4(obj, a, b, c, d, lbl_803E3454);
        if (((GameObject*)obj)->anim.seqId == 0xa8)
        {
            objfx_spawnDirectionalBurst(obj, 7, lbl_803E3454, 5, 1, 10, lbl_803E348C, 0, 0x20000000);
        }
    }
}

void fn_801723DC(int obj)
{
    extern void itemPickupDoParticleFx(int obj, f32 scale, int a, int b); /* #57 */
    extern void Sfx_PlayFromObject(int obj, int sfx); /* #57 */
    u8* state = ((GameObject*)obj)->extra;

    switch (((GameObject*)obj)->anim.seqId)
    {
    case 0xb:
        if ((((GfxEmitState*)state)->spinTimer -= framesThisStep) <= 0)
        {
            ((GfxEmitState*)state)->spinSpeed = (f32)(int)
            randomGetRange(600, 800);
            ((GfxEmitState*)state)->spinTimer = (s16)randomGetRange(180, 240);
            Sfx_PlayFromObject(obj, SFXwp_whiz3_c);
        }
        ((GameObject*)obj)->anim.rotY = ((GfxEmitState*)state)->spinSpeed;
        ((GfxEmitState*)state)->spinSpeed *= lbl_803E3478;
        if (((GameObject*)obj)->anim.rotY < 10 && ((GameObject*)obj)->anim.rotY > -10)
        {
            ((GameObject*)obj)->anim.rotY = 0;
        }
        break;
    case 0x12d:
    case 0x135:
    case 0x137:
    case 0x156:
    case 0x246:
        *(s16*)obj = lbl_803E347C * timeDelta + (f32) * (s16*)obj;
        break;
    case 0x22:
        *(s16*)obj = lbl_803E347C * timeDelta + (f32) * (s16*)obj;
        itemPickupDoParticleFx(obj, lbl_803E3454, 10, 1);
        break;
    case 0x27f:
        if (*(f32*)state < lbl_803E347C)
        {
            if ((int)randomGetRange(0, 10) == 0)
            {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x423, NULL, 2,
                                                 -1, NULL);
            }
            *(s16*)obj += (s16)(lbl_803E3480 * timeDelta);
        }
        break;
    case 0x5e8:
        *(s16*)obj = lbl_803E347C * timeDelta + (f32) * (s16*)obj;
        itemPickupDoParticleFx(obj, lbl_803E3454, 9, 1);
        break;
    }
}

/* segment pragma-stack balance (re-split): */

/* IDENTITY NOTE: this TU contains the COLLECTIBLE/MAGICDUST family; the
 * real texframeanimator_* symbols live in MMP_asteroid.c (symbols.txt-
 * verified). File rename parked as a repo-owner proposal. */

void collectible_init(int obj, int setup)
{
    ObjAnimComponent* objAnim;
    u8* state;
    int setupObj;
    int setupModelIndex;
    u8* data;
    u32 pathWord;
    u8 pathByte;

    objAnim = (ObjAnimComponent*)obj;
    state = ((GameObject*)obj)->extra;
    pathWord = lbl_803E3440;
    pathByte = lbl_803E3444;
    ObjGroup_AddObject(obj, 4);
    ObjMsg_AllocQueue(obj, 2);
    ((GameObject*)obj)->anim.rotX = (s16)((u8) * (u8*)(setup + 0x1b) << 8);
    ((GameObject*)obj)->anim.rotY = (s16)((u8) * (u8*)(setup + 0x22) << 8);
    ((GameObject*)obj)->anim.rotZ = (s16)((u8) * (u8*)(setup + 0x23) << 8);
    setupObj = (int)objAnim->modelInstance;
    ((GameObject*)obj)->anim.rootMotionScale = *(f32*)(setupObj + 4);
    ((GameObject*)obj)->animEventCallback = (void*)collectible_SeqFn;
    setupModelIndex = *(s8*)(setup + 0x26);
    objAnim->bankIndex = (s8)setupModelIndex;
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }
    ((GameObject*)obj)->objectFlags = ((GameObject*)obj)->objectFlags | 0x2000;
    ((CollectibleState*)state)->unkC = *(u8*)(setup + 0x19);
    ((CollectibleState*)state)->unkD = *(u8*)(setup + 0x1a);
    ((CollectibleState*)state)->unkF = 0;
    ((CollectibleState*)state)->unk18 = -2;
    ((CollectibleState*)state)->unk1D = 0;
    ((CollectibleState*)state)->visibilityGameBit = *(s16*)(setup + 0x24);
    ((CollectibleState*)state)->mapId = ((ObjPlacement*)setup)->mapId;
    ((CollectibleState*)state)->basePosX = ((GameObject*)obj)->anim.localPosX;
    ((CollectibleState*)state)->basePosY = ((GameObject*)obj)->anim.localPosY;
    ((CollectibleState*)state)->basePosZ = ((GameObject*)obj)->anim.localPosZ;
    ((CollectibleState*)state)->unk36 = *(u8*)(setup + 0x27);
    ((CollectibleState*)state)->unk3E = 0;
    if (((CollectibleState*)state)->visibilityGameBit != -1)
    {
        ((CollectibleState*)state)->gameBitValue = (u8)(
            (u32)__cntlzw(GameBit_Get(((CollectibleState*)state)->visibilityGameBit)) >> 5);
    }
    ((CollectibleState*)state)->hideGameBit = *(s16*)(setup + 0x1c);
    if (((CollectibleState*)state)->hideGameBit != -1)
    {
        *(u32*)&((GameObject*)obj)->unkF4 = GameBit_Get(((CollectibleState*)state)->hideGameBit);
    }
    else
    {
        *(u32*)&((GameObject*)obj)->unkF4 = 0;
    }
    if (((GameObject*)obj)->unkF4 == 0)
    {
        data = ((GameObject*)obj)->anim.modelInstance->extraSetupData;
        if (data != 0)
        {
            ((CollectibleState*)state)->scale = (f32) * (s8*)(data + 8);
        }
        else
        {
            ((CollectibleState*)state)->scale = lbl_803E3494;
        }
        data = (u8*)((GameObject*)obj)->anim.modelInstance->hitVolumes;
        if (data != 0)
        {
            ((CollectibleState*)state)->scale = (f32)(s32)(((ObjDefHitVolume*)data)->bounds[0] << 2);
        }
        if (((((ObjAnimComponent*)obj)->modelInstance->flags & 0x10000) != 0) &&
            (((CollectibleState*)state)->unk36 != 0))
        {
            ((CollectibleState*)state)->unk38 = *(u8*)(setup + 0x28);
            ((CollectibleState*)state)->unk39 = *(u8*)(setup + 0x29);
            ((CollectibleState*)state)->unk3A = *(u8*)(setup + 0x2a);
        }
        switch (((GameObject*)obj)->anim.seqId)
        {
        case 0xb:
            ((CollectibleState*)state)->unk40 = lbl_803E345C;
            ((CollectibleState*)state)->unk44 = lbl_803E3498;
            break;
        case 0x3cd:
            ((CollectibleState*)state)->unk40 = lbl_803E349C;
            ((CollectibleState*)state)->unk44 = lbl_803E3498;
            break;
        default:
            ((CollectibleState*)state)->unk40 = lbl_803E34A0;
            break;
        }
        (*gPathControlInterface)->init(state + 0x50, 0, 0x40006, 1);
        (*gPathControlInterface)->setup(state + 0x50, 1, lbl_80320C58, &pathWord, &pathByte);
        (*gPathControlInterface)->attachObject((void*)obj, state + 0x50);
    }
}

void collectible_release(void)
{
}

void collectible_initialise(void)
{
}
