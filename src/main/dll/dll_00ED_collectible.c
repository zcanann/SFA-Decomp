/*
 * DLL 0x00ED — collectible / genprops object group. TU: 0x80171D14–0x801723DC.
 *
 * Hosts the pick-up "collectible" object (the magicdust/scarab family) plus
 * the ObjectDescriptor tables for a batch of sibling genprops objects whose
 * bodies live in other TUs (mikabomb, mikabombshadow, StaticCamera,
 * gcbaddieshield, baddieinterestp, animatedobj, dim2roofrub, depthoffieldpoint,
 * staff, fireball, flamethrowerspe, shield, curve, restartmarker, dll_F7,
 * checkpoint4).
 *
 * collectible behaviour (init/update/render/SeqFn): each instance is gated by
 * placement game bits (visibilityGameBit / hideGameBit). On player proximity
 * (Vec_xzDistance vs a per-object radius) it is picked up by anim.seqId: health
 * items add health, dust items bump counters, others message the player object
 * (ObjMsg 0x7000a / 0x7000b) and play a pickup sfx + particle fx. Picked-up
 * objects fade their shadow (OBJ_MODEL_STATE_SHADOW_FADE_OUT), set their hide
 * game bit, and unsave their saved position. Per-seqId spin/bob motion and a
 * bounce/path-follow physics step (gPathControlInterface) run while idle.
 */
#include "main/game_object.h"
#include "main/dll/genpropswgpipe_struct.h"
#include "main/dll/genprops.h"
#include "main/dll/path_control_interface.h"
#include "main/audio/sfx_ids.h"
#include "main/dll_000A_expgfx.h"
#include "main/objhits.h"
#include "main/obj_placement.h"
#include "main/dll/collectible_state.h"
#include "main/gameplay_runtime.h"
#include "main/gamebits.h"
#include "main/sfa_extern_decls.h"
#include "main/dll/dll_00ED_collectible.h"
#include "main/dll/DIM/dll_00C7_dim2roofrub.h"
#include "main/dll/dll_00E4_flamethrowerspe.h"
#include "main/dll/dll_00C8_depthoffieldpoint.h"
#include "main/dll/dll_00E3_fireball.h"
#include "main/audio/sfx_trigger_ids.h"
#define COLLECTIBLE_OBJFLAG_HITDETECT_DISABLED 0x2000
#define COLLECTIBLE_OBJGROUP 4
extern void ObjGroup_RemoveObject();
extern void ObjGroup_AddObject(u32 obj, int group);
extern u32 ObjHitRegion_FindContainingId(f32 x, f32 y, f32 z);
extern void saveGame_saveObjectPos(int obj);
extern u8 framesThisStep;
extern f32 timeDelta;
extern void objMove(int* obj, f32 x, f32 y, f32 z);
extern float mathSinf(float x);
extern float mathCosf(float x);
extern f32 sqrtf(f32 x);
extern void playerAddHealth(void* player, int amount);
extern int gameBitIncrement(int bit);
extern void saveGame_unsaveObjectPos(int* obj);
extern f32 gCollectibleDespawnTimerDuration;
extern f32 lbl_803E3454;
extern f32 lbl_803E345C;
extern f32 lbl_803E3460;
extern f32 gCollectibleBounceDamping;
extern f32 gCollectibleAirFriction;
extern f32 gCollectibleGravity;
extern u32 ObjMsg_SendToObject();
extern int ObjTrigger_IsSet();
extern f32 lbl_803E3458;
extern f32 gCollectibleLaunchSpeed;
extern f32 gCollectibleLaunchAngle;
extern f32 lbl_803E348C;
extern void fn_8003B608(s16 a, s16 b, s16 c);
extern u8* fn_802972A8(void);
extern f32 Vec_xzDistance(f32* a, f32* b);
extern int fn_8029622C(u8 * player);
extern f32 gCollectiblePickupRange;
extern f32 gCollectibleSpinDamping;
extern f32 gCollectibleSpinRate;
extern f32 gCollectibleRotRate;

extern int ObjMsg_Pop(int obj, int* outMessage, int* outParam, int* outSender);
extern void ObjMsg_AllocQueue();
extern u8 lbl_80320C58[];
extern u32 lbl_803E3440;
extern u8 lbl_803E3444;
extern f32 gCollectibleDefaultScale;
extern f32 gCollectibleLifetimeTimer;
extern f32 lbl_803E349C;
extern f32 lbl_803E34A0;
extern void gcbaddieshield_update(int* obj);













extern void staff_func10(int* obj, s32 v);
extern void staff_setHitReactValue(int* obj, s32 v);
extern void staff_addHitReactValue(int* obj, s32 delta);
extern void staff_getHitGeometryPoints(int* obj, f32* outA, f32* outB);
extern void staff_func15(int* obj, s16 idx, f32 f1, f32 f2);
extern void staffFn_80170380(int* obj, int cmd);




















extern void shield_init(int* obj, void* initData);
extern void shield_update(int* obj);



extern void mikabombshadow_update(int* obj);
extern void restartmarker_init(int* obj, int* state);
extern void dll_F7_init(int* obj, int* params);
extern void dll_F7_update(int* obj);

/* ObjMsg slots: collectible notifies the player it is in range, player
   replies to trigger the pickup. */
#define COLLECTIBLE_MSG_IN_RANGE 0x7000a
#define COLLECTIBLE_MSG_PICKUP 0x7000b

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

u8 collectible_func0F(int* obj) { return *(u8*)((char*)((GameObject*)obj)->extra + 0x1e); }

int collectible_setScale(int* obj) { return ((GameObject*)obj)->unkF4; }

void collectible_func0E(int* obj, u32 v)
{
    *(u8*)((char*)((GameObject*)obj)->extra + 0x1e) = v;
}

void collectible_render2(int* obj, f32 f1, f32 f2, f32 f3)
{
    s32 v = 0x8;
    *(u8*)((char*)((GameObject*)obj)->extra + 0x1d) = v;
    ((GameObject*)obj)->anim.velocityX = f1;
    ((GameObject*)obj)->anim.velocityY = f2;
    ((GameObject*)obj)->anim.velocityZ = f3;
}

void collectible_func10(int* obj, f32 f1, f32 f2, f32 f3)
{
    char* inner = (char*)((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.localPosX = f1;
    ((CollectibleState*)inner)->basePosX = f1;
    ((GameObject*)obj)->anim.localPosY = f2;
    ((CollectibleState*)inner)->basePosY = f2;
    ((GameObject*)obj)->anim.localPosZ = f3;
    ((CollectibleState*)inner)->basePosZ = f3;
    if (GameBit_Get(((CollectibleState*)inner)->hideGameBit) == 0)
    {
        saveGame_saveObjectPos((int)obj);
    }
}

void collectible_func0B(int* obj, int flag)
{
    char* inner = (char*)((GameObject*)obj)->extra;
    ((CollectibleState*)inner)->disabled = flag;
    if (flag != 0)
    {
        ObjHits_DisableObject((u32)obj);
    }
    else
    {
        if (GameBit_Get(((CollectibleState*)inner)->hideGameBit) == 0)
        {
            ObjHits_EnableObject((u32)obj);
        }
    }
}

int collectible_modelMtxFn(int* obj)
{
    int* inner = (int*)*(int*)&((GameObject*)obj)->extra;
    if (((CollectibleState*)inner)->hitRegionId == -2)
    {
        f32 f1 = ((GameObject*)obj)->anim.worldPosX;
        f32 f2 = ((GameObject*)obj)->anim.worldPosY;
        f32 f3 = ((GameObject*)obj)->anim.worldPosZ;
        *(u32*)&((CollectibleState*)inner)->hitRegionId = (u16)ObjHitRegion_FindContainingId(f1, f2, f3);
    }
    return ((CollectibleState*)inner)->hitRegionId;
}

GenPropsWGPipe GXWGFifo : (0xCC008000);

#pragma opt_common_subs off

void collectible_applyPickup(int* obj)
{
    extern void itemPickupDoParticleFx(int* obj, f32 f, int a, int b); /* #57 */
    extern void Sfx_PlayFromObject(int* obj, int sfx); /* #57 */
    u8* state = ((GameObject*)obj)->extra;
    u8* params = *(u8**)&((GameObject*)obj)->anim.placementData;
    u8* setup2 = ((GameObject*)obj)->anim.modelInstance->extraSetupData;
    Obj_GetPlayerObject();
    getTrickyObject();
    Obj_GetPlayerObject();
    getTrickyObject();
    ObjHits_DisableObject((u32)obj);
    if (((GameObject*)obj)->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA)
    {
        ((CollectibleState*)state)->despawnTimer = gCollectibleDespawnTimerDuration;
        if (((GameObject*)obj)->anim.modelState != NULL)
        {
            ((GameObject*)obj)->anim.modelState->flags = OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        }
    }
    if (((CollectibleState*)state)->hideGameBit != -1)
    {
        GameBit_Set(((CollectibleState*)state)->hideGameBit, 1);
        saveGame_unsaveObjectPos(obj);
    }
    if (((CollectibleSetup*)params)->collectGameBit != -1)
    {
        GameBit_Set(((CollectibleSetup*)params)->collectGameBit, 1);
    }
    if (((CollectibleSetup*)params)->counterGameBit > 0)
    {
        gameBitIncrement(((CollectibleSetup*)params)->counterGameBit);
    }
    switch (*(s16*)(setup2 + 2))
    {
    case 1:
        switch (((GameObject*)obj)->anim.seqId)
        {
        case 90:
            Sfx_PlayFromObject(obj, SFXTRIG_lockoff22);
            itemPickupDoParticleFx(obj, lbl_803E3454, 2, 40);
            break;
        case 793:
            Sfx_PlayFromObject(obj, SFXTRIG_bapt11_c);
            GameBit_Set(1001, 1);
            ((CollectibleState*)state)->hideFrames = 1200;
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
                Sfx_PlayFromObject(obj, SFXTRIG_lockoff22);
                break;
            }
        case 34:
            Sfx_PlayFromObject(obj, SFXTRIG_lockoff22);
            itemPickupDoParticleFx(obj, lbl_803E3454, 255, 40);
            break;
        default:
            Sfx_PlayFromObject(obj, SFXTRIG_cam90_c);
            itemPickupDoParticleFx(obj, lbl_803E3454, 255, 40);
            break;
        }
        break;
    case 4:
        switch (((GameObject*)obj)->anim.seqId)
        {
        case 11:
            Sfx_PlayFromObject(Obj_GetPlayerObject(), SFXTRIG_lockoff22);
            playerAddHealth(Obj_GetPlayerObject(), 4);
            itemPickupDoParticleFx(obj, lbl_803E3454, 3, 40);
            break;
        case 973:
            playerAddHealth(Obj_GetPlayerObject(), 2);
            Sfx_PlayFromObject(Obj_GetPlayerObject(), SFXTRIG_lockoff22);
            itemPickupDoParticleFx(obj, lbl_803E3454, 1, 40);
            break;
        default:
            Sfx_PlayFromObject(Obj_GetPlayerObject(), SFXTRIG_cam90_c);
            itemPickupDoParticleFx(obj, lbl_803E3454, 255, 40);
            break;
        }
        break;
    default:
        Sfx_PlayFromObject(obj, SFXTRIG_cam90_c);
        itemPickupDoParticleFx(obj, lbl_803E3454, 255, 40);
        break;
    }
    ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
    ((GameObject*)obj)->unkF4 = 1;
}

void collectible_updateLooseMotion(int* obj)
{
    u8* state = ((GameObject*)obj)->extra;
    if (((GameObject*)obj)->anim.seqId == 1702)
    {
        objMove(obj, lbl_803E345C, ((GameObject*)obj)->anim.velocityY * (f32)(u32)framesThisStep, lbl_803E345C);
    }
    else
    {
        int n = framesThisStep;
        objMove(obj, ((GameObject*)obj)->anim.velocityX * (f32)(u32)n,
                ((GameObject*)obj)->anim.velocityY * (f32)(u32)n,
                ((GameObject*)obj)->anim.velocityZ * (f32)(u32)n);
    }
    (*gPathControlInterface)->update(obj, state + 0x50, timeDelta);
    (*gPathControlInterface)->apply(obj, state + 0x50);
    (*gPathControlInterface)->advance(obj, state + 0x50, timeDelta);
    if (*(s8*)&((CollectibleState*)state)->bounceHitFlag != 0)
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
        ((GameObject*)obj)->anim.velocityY *= gCollectibleBounceDamping;
        ((GameObject*)obj)->anim.velocityX *= len;
        ((GameObject*)obj)->anim.velocityZ *= len;
        ((CollectibleState*)state)->bounceTimer -= 1;
        if (((CollectibleState*)state)->bounceTimer == 0)
        {
            f32 z;
            ((CollectibleState*)state)->bounceTimer = 0;
            z = lbl_803E345C;
            ((GameObject*)obj)->anim.velocityX = z;
            ((GameObject*)obj)->anim.velocityY = z;
            ((GameObject*)obj)->anim.velocityZ = z;
        }
    }
    else
    {
        ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY * gCollectibleAirFriction;
        ((GameObject*)obj)->anim.velocityY = -(gCollectibleGravity * timeDelta - ((GameObject*)obj)->anim.velocityY);
    }
}

#pragma opt_common_subs reset

void collectible_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
    ObjGroup_RemoveObject(obj, COLLECTIBLE_OBJGROUP);
    return;
}

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

    if (((CollectibleState*)state)->visibilityGameBit != -1)
    {
        ((CollectibleState*)state)->visibilityBitClear = (u8)(GameBit_Get((s32)((CollectibleState*)state)->visibilityGameBit) == 0);
    }
    if (((CollectibleState*)state)->visibilityBitClear == 0)
    {
        switch (((GameObject*)obj)->anim.seqId)
        {
        case 0x6a6:
            objfx_spawnDirectionalBurst(obj, 5, lbl_803E3454, 6, 1, 0x14, lbl_803E3458, 0, 0);
            break;
        }
    }

    animUpdate->sequenceEventActive = 0;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        u8 cmd = animUpdate->eventIds[i];
        if (cmd == 1)
        {
            s_val = gCollectibleLaunchSpeed * mathCosf(gCollectibleLaunchAngle);
            c_val = gCollectibleLaunchSpeed * mathSinf(gCollectibleLaunchAngle);
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
            ((CollectibleState*)state)->delayedMsgTimer = 1;
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

void collectible_checkProximityPickup(int obj, u8* state)
{
    extern void collectible_applyPickup(int obj); /* #57 */
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
    if (dy < gCollectiblePickupRange && dist < ((CollectibleState*)state)->scale && fn_8029622C(player) != 0)
    {
        ((CollectibleState*)state)->pickupMsgValue = -1;
        switch (((GameObject*)obj)->anim.seqId)
        {
        case 0xb:
            if (GameBit_Get(0x90e) == 0)
            {
                ObjMsg_SendToObject(player, COLLECTIBLE_MSG_IN_RANGE, obj, state + 0x48);
                GameBit_Set(0x90e, 1);
            }
            else
            {
                collectible_applyPickup(obj);
            }
            state[0x37] |= 1;
            break;
        case 0x319:
            collectible_applyPickup(obj);
            state[0x37] |= 1;
            break;
        case 0x49:
        case 0x2da:
        case 0x3cd:
            if (GameBit_Get(0x90f) == 0)
            {
                ObjMsg_SendToObject(player, COLLECTIBLE_MSG_IN_RANGE, obj, state + 0x48);
                GameBit_Set(0x90f, 1);
            }
            else
            {
                collectible_applyPickup(obj);
            }
            state[0x37] |= 1;
            break;
        case 0x6a6:
            if (GameBit_Get(0x9a8) == 0)
            {
                ObjMsg_SendToObject(player, COLLECTIBLE_MSG_IN_RANGE, obj, state + 0x48);
                GameBit_Set(0x9a8, 1);
            }
            else
            {
                collectible_applyPickup(obj);
            }
            state[0x37] |= 1;
            break;
        default:
            if (ObjTrigger_IsSet(obj) != 0)
            {
                GameBit_Set(0xa7b, 1);
                ((CollectibleState*)state)->pickupMsgValue = attach[0xf];
                ObjMsg_SendToObject(player, COLLECTIBLE_MSG_IN_RANGE, obj, state + 0x48);
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
    extern void collectible_updateLooseMotion(int obj); /* #57 */
    extern void Obj_FreeObject(int obj); /* #57 */
    extern void itemPickupDoParticleFx(int obj, f32 scale, int a, int b); /* #57 */
    extern void collectible_applyPickup(int obj); /* #57 */
    extern void objfx_spawnDirectionalBurst(int obj, int a, f32 fa, int b, int c, int d, f32 fb, int e, int f); /* #57 */
    u8* state = ((GameObject*)obj)->extra;
    ObjHitsPriorityState* hitState;
    int msgParam;
    int msg;
    int t;
    f32 timer;
    f32 zero;

    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    timer = ((CollectibleState*)state)->despawnTimer;
    zero = lbl_803E345C;
    if (timer != zero)
    {
        ((CollectibleState*)state)->despawnTimer = timer - timeDelta;
        if (((CollectibleState*)state)->despawnTimer <= zero)
        {
            ((CollectibleState*)state)->despawnTimer = zero;
            ObjHits_DisableObject((u32)obj);
            if ((((GameObject*)obj)->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA) != 0)
            {
                Obj_FreeObject(obj);
            }
        }
        return;
    }
    if (((CollectibleState*)state)->visibilityGameBit != -1)
    {
        ((CollectibleState*)state)->visibilityBitClear = (u8)(GameBit_Get((s32)((CollectibleState*)state)->visibilityGameBit) == 0);
    }
    if (((CollectibleState*)state)->visibilityBitClear != 0 || state[0xf] != 0)
    {
        return;
    }
    switch (((GameObject*)obj)->anim.seqId)
    {
    case 0x6a6:
        objfx_spawnDirectionalBurst(obj, 5, lbl_803E3454, 6, 1, 0x14, lbl_803E3458, 0, 0);
        break;
    }
    timer = ((CollectibleState*)state)->lifetimeTimer;
    zero = lbl_803E345C;
    if (timer != zero)
    {
        ((CollectibleState*)state)->lifetimeTimer = timer - timeDelta;
        if (((CollectibleState*)state)->lifetimeTimer <= zero)
        {
            if ((((GameObject*)obj)->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA) != 0)
            {
                ((CollectibleState*)state)->despawnTimer = gCollectibleDespawnTimerDuration;
                if (((GameObject*)obj)->anim.modelState != NULL)
                {
                    ((GameObject*)obj)->anim.modelState->flags = OBJ_MODEL_STATE_SHADOW_FADE_OUT;
                }
                itemPickupDoParticleFx(obj, lbl_803E3454, 255, 40);
            }
            ((CollectibleState*)state)->lifetimeTimer = lbl_803E345C;
            return;
        }
    }
    while (ObjMsg_Pop(obj, &msg, &msgParam, NULL) != 0)
    {
        switch (msg)
        {
        case COLLECTIBLE_MSG_PICKUP:
            collectible_applyPickup(obj);
            break;
        }
    }
    switch (((GameObject*)obj)->anim.seqId)
    {
    case 0x319:
        t = ((CollectibleState*)state)->hideFrames;
        if (t != 0)
        {
            ((CollectibleState*)state)->hideFrames -= framesThisStep;
            if (((CollectibleState*)state)->hideFrames <= 0)
            {
                ((CollectibleState*)state)->hideFrames = 0;
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
            hitState->flags |= OBJHITS_PRIORITY_STATE_HIT_EXCLUDED;
        }
        ObjHits_DisableObject((u32)obj);
        if (((CollectibleState*)state)->hideGameBit != -1 && GameBit_Get((s32)((CollectibleState*)state)->hideGameBit) == 0)
        {
            ((GameObject*)obj)->unkF4 = 0;
        }
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
        collectible_updateIdleMotion(obj);
        if (((CollectibleState*)state)->bounceTimer != 0)
        {
            collectible_updateLooseMotion(obj);
        }
        if (state[0x3e] != 0)
        {
            state[0x3e]--;
            if (state[0x3e] == 0)
            {
                ((CollectibleState*)state)->pickupMsgValue = -1;
                ObjMsg_SendToObject(Obj_GetPlayerObject(), COLLECTIBLE_MSG_IN_RANGE, obj, state + 0x48);
            }
        }
        else
        {
            collectible_checkProximityPickup(obj, state);
        }
    }
}

void collectible_render(int obj, int a, int b, int c, int d, s8 visible)
{
    extern void objfx_spawnDirectionalBurst(int obj, int a, f32 fa, int b, int c, int d, f32 fb, int e, int f); /* #57 */
    int state = *(int*)&((GameObject*)obj)->extra;
    if (visible != 0 && ((CollectibleState*)state)->despawnTimer == lbl_803E345C && ((GameObject*)obj)->unkF4 == 0
        && (((GameObject*)obj)->anim.seqId == 0x156 || ((CollectibleState*)state)->visibilityBitClear == 0))
    {
        if ((((ObjAnimComponent*)obj)->modelInstance->flags & 0x10000) != 0 && ((CollectibleState*)state)->useColor != 0)
        {
            fn_8003B608(((CollectibleState*)state)->colorR, ((CollectibleState*)state)->colorG, ((CollectibleState*)state)->colorB);
        }
        objRenderFn_8003b8f4(obj, a, b, c, d, lbl_803E3454);
        if (((GameObject*)obj)->anim.seqId == 0xa8)
        {
            objfx_spawnDirectionalBurst(obj, 7, lbl_803E3454, 5, 1, 10, lbl_803E348C, 0, 0x20000000);
        }
    }
}

void collectible_updateIdleMotion(int obj)
{
    extern void itemPickupDoParticleFx(int obj, f32 scale, int a, int b); /* #57 */
    u8* state = ((GameObject*)obj)->extra;

    switch (((GameObject*)obj)->anim.seqId)
    {
    case 0xb:
        if ((((CollectibleState*)state)->spinTimer -= framesThisStep) <= 0)
        {
            ((CollectibleState*)state)->spinSpeed = (f32)(int)
            randomGetRange(600, 800);
            ((CollectibleState*)state)->spinTimer = randomGetRange(180, 240);
            Sfx_PlayFromObject(obj, SFXwp_whiz3_c);
        }
        ((GameObject*)obj)->anim.rotY = ((CollectibleState*)state)->spinSpeed;
        ((CollectibleState*)state)->spinSpeed *= gCollectibleSpinDamping;
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
        ((GameObject*)obj)->anim.rotX = gCollectibleSpinRate * timeDelta + (f32)((GameObject*)obj)->anim.rotX;
        break;
    case 0x22:
        ((GameObject*)obj)->anim.rotX = gCollectibleSpinRate * timeDelta + (f32)((GameObject*)obj)->anim.rotX;
        itemPickupDoParticleFx(obj, lbl_803E3454, 10, 1);
        break;
    case 0x27f:
        if (*(f32*)state < gCollectibleSpinRate)
        {
            if ((int)randomGetRange(0, 10) == 0)
            {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x423, NULL, 2,
                                                 -1, NULL);
            }
            ((GameObject*)obj)->anim.rotX += (s16)(gCollectibleRotRate * timeDelta);
        }
        break;
    case 0x5e8:
        ((GameObject*)obj)->anim.rotX = gCollectibleSpinRate * timeDelta + (f32)((GameObject*)obj)->anim.rotX;
        itemPickupDoParticleFx(obj, lbl_803E3454, 9, 1);
        break;
    }
}

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
    ObjGroup_AddObject(obj, COLLECTIBLE_OBJGROUP);
    ObjMsg_AllocQueue(obj, 2);
    ((GameObject*)obj)->anim.rotX = (s16)((u8)((CollectibleSetup*)setup)->rotXByte << 8);
    ((GameObject*)obj)->anim.rotY = (s16)((u8)((CollectibleSetup*)setup)->rotYByte << 8);
    ((GameObject*)obj)->anim.rotZ = (s16)((u8)((CollectibleSetup*)setup)->rotZByte << 8);
    setupObj = (int)objAnim->modelInstance;
    ((GameObject*)obj)->anim.rootMotionScale = *(f32*)(setupObj + 4);
    ((GameObject*)obj)->animEventCallback = collectible_SeqFn;
    setupModelIndex = ((CollectibleSetup*)setup)->modelIndex;
    objAnim->bankIndex = setupModelIndex;
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }
    ((GameObject*)obj)->objectFlags = ((GameObject*)obj)->objectFlags | COLLECTIBLE_OBJFLAG_HITDETECT_DISABLED;
    ((CollectibleState*)state)->unkC = ((CollectibleSetup*)setup)->unkC;
    ((CollectibleState*)state)->unkD = ((CollectibleSetup*)setup)->unkD;
    ((CollectibleState*)state)->disabled = 0;
    ((CollectibleState*)state)->hitRegionId = -2;
    ((CollectibleState*)state)->bounceTimer = 0;
    ((CollectibleState*)state)->visibilityGameBit = ((CollectibleSetup*)setup)->visibilityGameBit;
    ((CollectibleState*)state)->mapId = ((ObjPlacement*)setup)->mapId;
    ((CollectibleState*)state)->basePosX = ((GameObject*)obj)->anim.localPosX;
    ((CollectibleState*)state)->basePosY = ((GameObject*)obj)->anim.localPosY;
    ((CollectibleState*)state)->basePosZ = ((GameObject*)obj)->anim.localPosZ;
    ((CollectibleState*)state)->useColor = ((CollectibleSetup*)setup)->useColor;
    ((CollectibleState*)state)->delayedMsgTimer = 0;
    if (((CollectibleState*)state)->visibilityGameBit != -1)
    {
        ((CollectibleState*)state)->visibilityBitClear = (u8)(
            (u32)__cntlzw(GameBit_Get(((CollectibleState*)state)->visibilityGameBit)) >> 5);
    }
    ((CollectibleState*)state)->hideGameBit = ((CollectibleSetup*)setup)->hideGameBit;
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
            ((CollectibleState*)state)->scale = gCollectibleDefaultScale;
        }
        data = (u8*)((GameObject*)obj)->anim.modelInstance->hitVolumes;
        if (data != 0)
        {
            ((CollectibleState*)state)->scale = (f32)(s32)(((ObjDefHitVolume*)data)->bounds[0] << 2);
        }
        if (((((ObjAnimComponent*)obj)->modelInstance->flags & 0x10000) != 0) &&
            (((CollectibleState*)state)->useColor != 0))
        {
            ((CollectibleState*)state)->colorR = ((CollectibleSetup*)setup)->colorR;
            ((CollectibleState*)state)->colorG = ((CollectibleSetup*)setup)->colorG;
            ((CollectibleState*)state)->colorB = ((CollectibleSetup*)setup)->colorB;
        }
        switch (((GameObject*)obj)->anim.seqId)
        {
        case 0xb:
            ((CollectibleState*)state)->unk40 = lbl_803E345C;
            ((CollectibleState*)state)->lifetimeTimer = gCollectibleLifetimeTimer;
            break;
        case 0x3cd:
            ((CollectibleState*)state)->unk40 = lbl_803E349C;
            ((CollectibleState*)state)->lifetimeTimer = gCollectibleLifetimeTimer;
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
