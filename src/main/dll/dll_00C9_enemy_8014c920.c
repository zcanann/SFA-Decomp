/*
 * DLL 0xC9 - the generic enemy/baddie controller. It runs several romlist
 * enemy types, including GCRobotPatrol ("GCRobotPatr[ol]"), the floating
 * patrol robot of CloudRunner Fortress (placed in fortress.romlist).
 * GCRobotPatrol carries the GCRobotLight scanning beam (DLL 0x150,
 * dll_0150_gcrobotlightbea.c) as childObjs[0] and reads that child's
 * "player caught in the beam" hit flag to react - the sharp-claw disguise
 * fools the beam. ("GC" = GameCube; see the dll_0150 header.)
 */
#include "main/object_descriptor.h"
#include "main/camera_interface.h"
#include "main/dll/objfx_api.h"
#include "main/dll/dll_005A_staffcollisionfunc03.h"
#include "main/object_render.h"
#include "main/objanim.h"
#include "main/game_object.h"
#include "main/dll/player_api.h"
#include "main/dll/baddie_setmove.h"
#include "main/obj_group.h"
#include "main/obj_link.h"
#include "main/objprint_character_api.h"
#include "main/object.h"
#include "main/object_api.h"
#include "main/model.h"
#include "main/mm.h"
#include "main/objseq.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/dll_00C9_enemy.h"
#include "main/dll/dll_00CA_icebaddie.h"
#include "main/dll/tricky_state.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/obj_placement.h"
#include "main/objhits.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/path_control_interface.h"
#include "main/mapEventTypes.h"
#include "main/resource.h"
#include "main/vecmath.h"
#include "main/dll/duster.h"
#include "main/gamebits.h"
#include "main/dll/tricky_api.h"
#include "main/lightmap_api.h"
#include "main/frame_timing.h"
#include "main/model.h"
#include "main/model_engine.h"
#include "main/model_light.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "main/dll/hagabon_mk2.h"
#include "main/dll/duster_wb.h"
#include "main/dll/weevil.h"
#include "main/dll/hoodedzyck.h"
#include "main/dll/snowworm.h"
#include "main/dll/kooshy.h"
#include "main/dll/mikaladon.h"
#include "main/dll/baddiewhirlpool.h"
#include "main/dll/newseqobj_baddie.h"
#include "main/dll/fireflyLantern.h"
#include "main/dll/firecrawler_baddie.h"
#include "main/dll/seqobj11e_baddie.h"
#include "main/dll/wispbaddie_baddie.h"
#include "main/dll/seqobj11d_baddie.h"
#include "main/dll/magicPlant.h"
#include "main/dll/seqObj11D.h"
#include "main/dll/dll_00C4_tricky.h"
#include "main/dll/fall_ladders.h"
#include "string.h"

extern int lbl_803DBC58[2];
extern f32 lbl_803DBC60;
extern f32 lbl_803DBC64;
extern f32 lbl_803DBC68;

typedef struct BaddieAfterUpdateBonesCbState
{
    u8 pad0[0x2B0 - 0x0];
    s16 unk2B0;
    u16 unk2B2;
    u8 pad2B4[0x2D8 - 0x2B4];
    f32 freezeRecoverTimer;
    u32 unk2DC;
    u8 pad2E0[0x2F2 - 0x2E0];
    u8 unk2F2;
    u8 unk2F3;
    u8 unk2F4;
    u8 pad2F5[0x36C - 0x2F5];
    s32 tailBoneChain; /* 0x36C: bone chain passed to ObjModelChain_Update for tail sim */
} BaddieAfterUpdateBonesCbState;

typedef struct
{
    f32 dx, dy, dz;
    u8 pad0[2];
    s16 dAngle;
    u8 pad1[3];
    s8 events[8];
    s8 eventCount;
} TrickyMoveResult;

#define ENEMY_OBJFLAG_PARENT_SLACK 0x1000
#define ENEMY_OBJFLAG_FREED        0x40

/* object groups: the enemy's own group / secondary group left on a message */
#define ENEMY_OBJGROUP           3
#define ENEMY_OBJGROUP_SECONDARY 0x50

/* camera mode DLL 0x49 = dll_0049_cameramodecombat */
#define ENEMY_CAMMODE_COMBAT 0x49

/* enemy defNos (anim.seqId) - names read from retail OBJECTS.bin at def+0x91;
   every id below gates to this file's own DLL 0xC9 */
#define ENEMY_SHARPCLAW_GR_OBJ     0x11
#define ENEMY_GUARDCLAW_OBJ        0xd8
#define ENEMY_SHARPCLAW_SN_OBJ     0x13a
#define ENEMY_PINPON_OBJ           0x251
#define ENEMY_RACHNOP_OBJ          0x25d
#define ENEMY_WEEVIL_OBJ           0x369
#define ENEMY_VAMBAT_OBJ           0x3fe
#define ENEMY_BATTLEDROID_OBJ      0x427
#define ENEMY_SPITTINGEBA_OBJ      0x457
#define ENEMY_MUTATEDEBA_OBJ       0x458
#define ENEMY_HOODEDZYCK_OBJ       0x4ac
#define ENEMY_WB_OBJ               0x4d7
#define ENEMY_KOOSHY_OBJ           0x58b
#define ENEMY_SHARPCLAW_CO_OBJ     0x5b7
#define ENEMY_SHARPCLAW_AS_OBJ     0x5b8
#define ENEMY_SHARPCLAW_SH_OBJ     0x5b9
#define ENEMY_SHARPCLAW_SO_OBJ     0x5e1
#define ENEMY_GCROBOTPATROL_OBJ    0x613
#define ENEMY_MIKALADON_OBJ        0x642
#define ENEMY_FIRECRAWLER_OBJ      0x6a2
#define ENEMY_REDEYE_OBJ           0x6a3
#define ENEMY_SHADOWHUNTER_OBJ     0x6a4
#define ENEMY_SWAMPSTRIDER_OBJ     0x6a5
#define ENEMY_BOSSGENERAL_OBJ      0x7a6
#define ENEMY_FIREBAT_OBJ          0x7c6
#define ENEMY_HAGABONMK2_OBJ       0x7c8
#define ENEMY_SNOWWORM_OBJ         0x842
#define ENEMY_SNOWWORM_BABY_OBJ    0x84b
#define ENEMY_WHIRLPOOL_OBJ        0x851

extern f32 lbl_803E256C;
extern f32 lbl_803E2570;
extern f32 lbl_803E2574;
extern f32 lbl_803E2578;
extern f32 lbl_803E257C;
extern f32 lbl_803E25CC;
extern f32 lbl_803E25D0;
extern f32 lbl_803E25D4;
extern f32 lbl_803E2598;

extern f32 lbl_803E25DC;
extern f32 lbl_803E25B8;
extern f32 lbl_803E25EC;
extern f32 lbl_803E25F0;
extern f32 lbl_803E25F4;
extern f32 lbl_803E25D8;
extern f32 lbl_803E25C4;
extern f32 lbl_803E25E8;
extern StaffCollisionInterface** lbl_803DDA50;
extern f32 lbl_803E25F8;
extern f32 lbl_803E25FC;

void baddie_updateEngagementState(int* obj, int* sub);
void baddieTurnTowardTarget(int* node, int* sub);
typedef struct
{
    f32 x, y, z;
} TrickyVec3;

extern f32 enemyRespawnDistanceSq;
extern u8 lbl_8031DBD8[];
extern u8 lbl_8031DBE4[];
extern f32 enemySightRange;

extern u32 gEnemySelfAngleFlagClearMask[];
extern u32 gEnemyTargetAngleFlagClearMask[];

f32 sidekickToy_accelerateTowardTarget3D(GameObject* obj, f32 tx, f32 ty, f32 tz, f32 accel, f32 speedScale, f32 maxVel,
                                         f32 drag)
{
    f32 dx = tx - obj->anim.worldPosX;
    f32 dy = ty - obj->anim.worldPosY;
    f32 dz = tz - obj->anim.worldPosZ;
    f32 dist = sqrtf(dx * dx + dy * dy + dz * dz);
    if (dist > accel)
    {
        obj->anim.velocityX = obj->anim.velocityX + timeDelta * (speedScale * (dx / dist));
        obj->anim.velocityY = obj->anim.velocityY + timeDelta * (speedScale * (dy / dist));
        obj->anim.velocityZ = obj->anim.velocityZ + timeDelta * (speedScale * (dz / dist));
    }
    else if (dist > lbl_803E2574)
    {
        obj->anim.velocityX = obj->anim.velocityX + timeDelta * (speedScale * (dx / accel));
        obj->anim.velocityY = obj->anim.velocityY + timeDelta * (speedScale * (dy / accel));
        obj->anim.velocityZ = obj->anim.velocityZ + timeDelta * (speedScale * (dz / accel));
    }
    if (obj->anim.velocityX < -maxVel)
    {
        obj->anim.velocityX = -maxVel;
    }
    else if (obj->anim.velocityX > maxVel)
    {
        obj->anim.velocityX = maxVel;
    }
    if (obj->anim.velocityY < -maxVel)
    {
        obj->anim.velocityY = -maxVel;
    }
    else if (obj->anim.velocityY > maxVel)
    {
        obj->anim.velocityY = maxVel;
    }
    if (obj->anim.velocityZ < -maxVel)
    {
        obj->anim.velocityZ = -maxVel;
    }
    else if (obj->anim.velocityZ > maxVel)
    {
        obj->anim.velocityZ = maxVel;
    }
    if (lbl_803E2574 != drag)
    {
        obj->anim.velocityX = obj->anim.velocityX * powfBitEstimate(drag, timeDelta);
        obj->anim.velocityY = obj->anim.velocityY * powfBitEstimate(drag, timeDelta);
        obj->anim.velocityZ = obj->anim.velocityZ * powfBitEstimate(drag, timeDelta);
    }
    return dy;
}

/* sidekickToy_accelerateTowardTargetXZ: xz-plane physics step toward a target. Computes the planar
 * distance to (tx,ty,tz), then nudges the obj's xz velocity (offsets 0x24,
 * 0x2c) by timeDelta * speedScale * unitDir, clamped at +/-maxVel, with an
 * optional drag pass. Returns the y-delta. */
f32 sidekickToy_accelerateTowardTargetXZ(GameObject* obj, f32 tx, f32 ty, f32 tz, f32 accel, f32 speedScale, f32 maxVel,
                                         f32 drag)
{
    f32 dx = tx - obj->anim.worldPosX;
    f32 dy = ty - obj->anim.worldPosY;
    f32 dz = tz - obj->anim.worldPosZ;
    f32 dist = sqrtf(dx * dx + dz * dz);
    if (dist > accel)
    {
        obj->anim.velocityX = obj->anim.velocityX + timeDelta * (speedScale * (dx / dist));
        obj->anim.velocityZ = obj->anim.velocityZ + timeDelta * (speedScale * (dz / dist));
    }
    else if (dist > lbl_803E2574)
    {
        obj->anim.velocityX = obj->anim.velocityX + timeDelta * (speedScale * (dx / accel));
        obj->anim.velocityZ = obj->anim.velocityZ + timeDelta * (speedScale * (dz / accel));
    }
    if (obj->anim.velocityX < -maxVel)
    {
        obj->anim.velocityX = -maxVel;
    }
    else if (obj->anim.velocityX > maxVel)
    {
        obj->anim.velocityX = maxVel;
    }
    if (obj->anim.velocityZ < -maxVel)
    {
        obj->anim.velocityZ = -maxVel;
    }
    else if (obj->anim.velocityZ > maxVel)
    {
        obj->anim.velocityZ = maxVel;
    }
    if (lbl_803E2574 != drag)
    {
        obj->anim.velocityX = obj->anim.velocityX * powfBitEstimate(drag, timeDelta);
        obj->anim.velocityZ = obj->anim.velocityZ * powfBitEstimate(drag, timeDelta);
    }
    return dy;
}

void fn_8014CD1C(GameObject* node, void* sub, int divisor, f32 fa, f32 fb, u8 useScaledRoll)
{
    f32 dt;
    int angle;
    s32 delta;
    f32 delta_f;
    s16 newVal;

    dt = timeDelta / (f32)(u32)(u16)divisor;
    if (dt > lbl_803E256C)
        dt = lbl_803E256C;

    angle = (u16)getAngle(-((TrickyState*)sub)->lookDirX, -((TrickyState*)sub)->lookDirZ);
    delta = angle - (u16)((GameObject*)node)->anim.rotX;
    delta_f = delta;
    if (delta_f > lbl_803E25B8)
        delta_f = lbl_803E25EC + delta_f;
    if (delta_f < lbl_803E25F4)
        delta_f = lbl_803E25F0 + delta_f;
    delta_f *= dt;
    newVal = (s16)(*(s16*)(int)node + (s32)delta_f);
    ((GameObject*)node)->anim.rotX = newVal;

    if (fa != lbl_803E2574)
    {
        if (useScaledRoll != 0)
        {
            ((GameObject*)node)->anim.rotZ = (s16)(((GameObject*)node)->anim.rotZ + (s32)(fa * (delta_f * dt)));
        }
        else
        {
            ((GameObject*)node)->anim.rotZ = (s16)(oneOverTimeDelta * (delta_f * fa));
            {
                s16 v = ((GameObject*)node)->anim.rotZ;
                if (v > 0x2000)
                    ((GameObject*)node)->anim.rotZ = 0x2000;
                else if (v < -0x2000)
                    ((GameObject*)node)->anim.rotZ = -0x2000;
            }
        }
    }

    if (lbl_803E2574 != fb)
    {
        f32 dz2 = ((TrickyState*)sub)->lookDirZ * ((TrickyState*)sub)->lookDirZ;
        f32 dx2 = ((TrickyState*)sub)->lookDirX * ((TrickyState*)sub)->lookDirX;
        f32 hyp = sqrtf(dz2 + dx2);
        int angle2 = (u16)getAngle(((TrickyState*)sub)->lookDirY * fb, hyp);
        s32 d2 = angle2 - (u16)((GameObject*)node)->anim.rotY;
        f32 d2f = d2;
        s16 newVal2;
        if (d2f > lbl_803E25B8)
            d2f = lbl_803E25EC + d2f;
        if (d2f < lbl_803E25F4)
            d2f = lbl_803E25F0 + d2f;
        newVal2 = (s16)(*(s16*)((int)node + 2) + (s32)(d2f * dt));
        ((GameObject*)node)->anim.rotY = newVal2;
    }
}

void baddieTurnTowardPoint(GameObject* node, int state, f32 targetX, f32 targetZ, int divisor, int angleBias)
{
    s32 delta;
    f32 dt;
    s16 newVal;
    f32 t0 = node->anim.localPosX - targetX;
    f32 t1 = node->anim.localPosZ - targetZ;
    delta = getAngle(t0, t1);
    delta = (s16)(delta - (u16)node->anim.rotX);
    if (delta > 0x8000)
        delta = (s16)(delta - 0xFFFF);
    if ((s16)delta < -0x8000)
        delta = (s16)(delta + 0xFFFF);
    delta += angleBias;
    dt = timeDelta / (f32)(u32)(u16)divisor;
    if (dt > lbl_803E256C)
        dt = lbl_803E256C;
    newVal = (s16)(*(s16*)node + (s32)((f32)(s16)delta * dt));
    node->anim.rotX = newVal;
}

void fn_8014D08C(GameObject* obj, int state, u8 moveId, f32 rateScale, int moveControlFlags, u8 stateByte)
{
    ObjHitsPriorityState* hitState;

    ((BaddieState*)state)->unk308 = lbl_803E256C / (lbl_803E2570 * rateScale);
    *(u8*)(state + 0x323) = stateByte;
    ObjAnim_SetCurrentMove((int)obj, moveId, lbl_803E2574, moveControlFlags);
    hitState = (ObjHitsPriorityState*)(obj)->anim.hitReactState;
    if (hitState != NULL)
    {
        hitState->suppressOutgoingHits = 0;
    }
}

void baddieAfterUpdateBonesCb(GameObject* obj, int* bones)
{
    BaddieAfterUpdateBonesCbState* state = obj->extra;
    int v = *bones;
    switch (obj->anim.seqId)
    {
    case ENEMY_HAGABONMK2_OBJ:
        ObjModelChain_Update(bones, v, (ObjModelChain*)state->tailBoneChain, crawler_rotateVectorYaw);
        break;
    default:
        ObjModelChain_Update(bones, v, (ObjModelChain*)state->tailBoneChain, NULL);
        break;
    }
}

int enemy_getExtraSize(void)
{
    return 0x370;
}
int enemy_getObjectTypeId(void)
{
    return 0x14b;
}

typedef struct EnemyPlacement
{
    u8 pad0[0x8 - 0x0];
    f32 posX;
    f32 posY;
    f32 posZ;
    u8 pad14[0x18 - 0x14];
    s16 gameBit;
    s16 gameBit2;
    u8 pad1C[0x28 - 0x1C];
    s8 objectFlagBits; /* 0x28: low 3 bits OR'd into GameObject.objectFlags */
    u8 aggroRangeByte; /* 0x29 */
    s8 rotXByte;
    u8 flags2B;         /* 0x2B: bit 3 (0x8) reloads spawn position before the trigger sequence */
    s16 respawnEnabled; /* 0x2C: when 0, the off-screen respawn path is skipped */
    s8 triggerSeqId;
    u8 healthByte; /* 0x2F */
    u8 pad30[0x32 - 0x30];
    u8 hitPoints; /* 0x32: spawn hit-point count -> EnemyState.current (health numerator) */
    u8 pad33[0x34 - 0x33];
    u16 unk34;
    u8 pad36[0x38 - 0x36];
} EnemyPlacement;

void enemy_free(GameObject* obj, int flag)
{
    u8* child;
    int i;
    int n;
    u8* state;

    state = (obj)->extra;

    if (*(void**)&((EnemyState*)state)->tailSimHandle != NULL)
    {
        ObjModelChain_Free((ObjModelChain*)((EnemyState*)state)->tailSimHandle);
    }
    if (((EnemyState*)state)->modelLight != NULL)
    {
        ModelLightStruct_free(((EnemyState*)state)->modelLight);
        ((EnemyState*)state)->modelLight = NULL;
    }
    if (*(void**)state != NULL)
    {
        mm_free((void*)*(int*)state);
        *(int*)state = 0;
    }
    switch ((obj)->anim.seqId)
    {
    case ENEMY_HAGABONMK2_OBJ:
        hagabonMK2_stopLoopSfx((int)obj, state);
        break;
    case ENEMY_WHIRLPOOL_OBJ:
        if ((int)ObjGroup_ContainsObject((u32)obj, ENEMY_OBJGROUP_SECONDARY) != 0)
        {
            ObjGroup_RemoveObject((int)obj, ENEMY_OBJGROUP_SECONDARY);
        }
        break;
    }
    n = (obj)->childCount;
    for (i = 0; i < n; i++)
    {
        child = (obj)->childObjs[0];
        if (child != NULL)
        {
            ObjLink_DetachChild(obj, (GameObject*)child);
            if (flag == 0 || (((GameObject*)child)->objectFlags & 0x10) == 0)
            {
                Obj_FreeObject((GameObject*)child);
            }
        }
    }
    (*gExpgfxInterface)->freeSource((int)obj);
    ObjGroup_RemoveObject((int)obj, ENEMY_OBJGROUP);
}

void enemy_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    EnemyState* state = ((GameObject*)obj)->extra;
    if (visible != 0)
    {
        switch (((GameObject*)obj)->userData1)
        {
        case 0:
            objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E256C);
            {
                u32 flags = *(u32*)&state->flags2E8;
                if ((flags & 3) != 0)
                {
                    if ((flags & 1) != 0)
                    {
                        *(u32*)&state->flags2E8 = flags & ~1LL;
                        *(u32*)&state->flags2E8 = *(u32*)&state->flags2E8 | 2;
                    }
                    if (state->modelLight == NULL)
                    {
                        state->modelLight = objCreateLight(0, 1);
                    }
                    objParticleFn_80099d84((GameObject*)obj, lbl_803E256C, 3, state->particleScale,
                                           state->modelLight);
                }
            }
            if ((*(u32*)&state->flags2E8 & 4) != 0)
            {
                if (state->modelLight == NULL)
                {
                    state->modelLight = objCreateLight(0, 1);
                }
                objParticleFn_80099d84((GameObject*)obj, lbl_803E256C, 4, state->particleScale,
                                       state->modelLight);
            }
            if ((*(u32*)&state->flags2E8 & 0x40) != 0)
            {
                Sfx_KeepAliveLoopedObjectSound((int)obj, SFXTRIG_forcecryslp11);
                objParticleFn_80099d84((GameObject*)obj, lbl_803E256C, 5, state->particleScale, 0);
            }
            if ((*(u32*)&state->flags2E8 & 0x80) != 0)
            {
                Sfx_KeepAliveLoopedObjectSound((int)obj, SFXTRIG_forcecryslp11);
                objParticleFn_80099d84((GameObject*)obj, lbl_803E25F8, 6, state->particleScale, 0);
            }
            if ((*(u32*)&state->flags2E8 & 0x100) != 0)
            {
                objParticleFn_80099d84((GameObject*)obj, lbl_803E25FC, 7, state->particleScale, 0);
            }
            break;
        }
    }
}

void enemy_hitDetect(GameObject* obj)
{
    u8* state = obj->extra;
    ObjHitsPriorityState* childHitState;

    if (((EnemyState*)state)->modelLight != NULL &&
        modelLightStruct_getActiveState(((EnemyState*)state)->modelLight) == 0)
    {
        ModelLightStruct_free(((EnemyState*)state)->modelLight);
        ((EnemyState*)state)->modelLight = NULL;
    }
    ((EnemyState*)state)->lastHitObject = ((ObjHitsPriorityState*)obj->anim.hitReactState)->lastHitObject;
    if (((ObjHitsPriorityState*)obj->anim.hitReactState)->lastHitObject != 0)
    {
        ((ObjHitsPriorityState*)obj->anim.hitReactState)->suppressOutgoingHits = 1;
    }
    if (obj->childObjs[0] != NULL && *(void**)(*(int*)&obj->childObjs[0] + 0x54) != NULL &&
        (childHitState = *(ObjHitsPriorityState**)(*(int*)&obj->childObjs[0] + 0x54))->lastHitObject != 0)
    {
        ((ObjHitsPriorityState*)obj->anim.hitReactState)->suppressOutgoingHits = 1;
    }
    if (*(void**)&((EnemyState*)state)->tailSimHandle != NULL)
    {
        ObjModelChain_AdvancePhase((ObjModelChain*)((EnemyState*)state)->tailSimHandle);
    }
}

void enemy_update(int obj)
{
    u8* player;
    u8* state;
    u8* setup;
    u8* tricky;
    u32 flags;
    u8* s2;
    f32 fz;

    state = ((GameObject*)obj)->extra;
    setup = *(u8**)&((GameObject*)obj)->anim.placementData;
    tricky = (u8*)getTrickyObject();
    if (getCurUiDll() == 4)
    {
        return;
    }
    if ((((EnemyState*)state)->flags2E4 & 0x8000006) != 0)
    {
        if (objPosToMapBlockIdx(((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                ((GameObject*)obj)->anim.localPosZ) == -1)
        {
            return;
        }
    }
    else
    {
        if (isInBounds(((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosZ) == 0)
        {
            return;
        }
    }
    if (objIsFrozen((u8*)obj) != 0)
    {
        baddie_updateWhileFrozen((GameObject*)(obj), state, 1);
        return;
    }
    if (((EnemyState*)state)->trackedObj == NULL)
    {
        ((EnemyState*)state)->trackedObj = Obj_GetPlayerObject();
    }
    else if ((((GameObject*)((EnemyState*)state)->trackedObj)->objectFlags & ENEMY_OBJFLAG_FREED) != 0)
    {
        ((EnemyState*)state)->trackedObj = Obj_GetPlayerObject();
    }
    ((EnemyState*)state)->initialFlags = *(int*)&((EnemyState*)state)->controlFlags;
    baddieInstantiateWeapon((GameObject*)(obj), (int)state);
    flags = ((EnemyState*)state)->controlFlags;
    if ((flags & 1) != 0 && (flags & 2) == 0)
    {
        if (((EnemyPlacement*)setup)->triggerSeqId == -1)
        {
            return;
        }
        if (setup != NULL && (((EnemyPlacement*)setup)->flags2B & 8) != 0)
        {
            ((GameObject*)obj)->anim.localPosX = ((ObjPlacement*)setup)->posX;
            ((GameObject*)obj)->anim.localPosY = ((ObjPlacement*)setup)->posY;
            ((GameObject*)obj)->anim.localPosZ = ((ObjPlacement*)setup)->posZ;
        }
        (*gObjectTriggerInterface)->runSequence(((EnemyPlacement*)setup)->triggerSeqId, (void*)obj, -1);
        ((EnemyState*)state)->controlFlags |= 2;
        *(u32*)&((EnemyState*)state)->controlFlags = *(u32*)&((EnemyState*)state)->controlFlags & ~1LL;
        return;
    }
    if (((GameObject*)obj)->userData1 != 0)
    {
        if (((EnemyPlacement*)setup)->gameBit2 != -1)
        {
            if (mainGetBit(((EnemyPlacement*)setup)->gameBit2) == 0)
            {
                return;
            }
            if ((((EnemyState*)state)->controlFlags & 0x800) != 0)
            {
                return;
            }
            if ((((EnemyState*)state)->controlFlags & 0x1000) == 0)
            {
                return;
            }
            player = (u8*)Obj_GetPlayerObject();
            if (((EnemyPlacement*)setup)->gameBit != -1)
            {
                if (mainGetBit(((EnemyPlacement*)setup)->gameBit) != 0)
                {
                    return;
                }
            }
            if (player != NULL)
            {
                if (vec3f_distanceSquared((f32*)(player + 0x18), &((EnemyPlacement*)setup)->posX) >
                    enemyRespawnDistanceSq)
                {
                    enemy_init((GameObject*)(obj), setup, 0);
                    ((EnemyState*)state)->controlFlags |= 0x1000;
                    *(u32*)&((EnemyState*)state)->initialFlags &= ~0x1000LL;
                }
                else
                {
                    return;
                }
            }
            else
            {
                return;
            }
        }
        else if (((EnemyPlacement*)setup)->gameBit != -1)
        {
            if (mainGetBit(((EnemyPlacement*)setup)->gameBit) != 0)
            {
                return;
            }
            if ((((EnemyState*)state)->controlFlags & 0x800) != 0)
            {
                return;
            }
            player = (u8*)Obj_GetPlayerObject();
            if (player != NULL)
            {
                if (vec3f_distanceSquared((f32*)(player + 0x18), &((EnemyPlacement*)setup)->posX) >
                    enemyRespawnDistanceSq)
                {
                    enemy_init((GameObject*)(obj), setup, 0);
                    ((EnemyState*)state)->controlFlags |= 0x1000;
                    *(u32*)&((EnemyState*)state)->initialFlags &= ~0x1000LL;
                }
                else
                {
                    return;
                }
            }
            else
            {
                return;
            }
        }
        else
        {
            if (*(u32*)&((ObjPlacement*)setup)->mapId == 0xFFFFFFFF)
            {
                return;
            }
            if (((EnemyPlacement*)setup)->respawnEnabled == 0)
            {
                return;
            }
            if ((*gMapEventInterface)->shouldNotSaveTime(((ObjPlacement*)setup)->mapId) != 0)
            {
                if ((((EnemyState*)state)->controlFlags & 0x800) == 0)
                {
                    player = (u8*)Obj_GetPlayerObject();
                    if (player != NULL)
                    {
                        if (vec3f_distanceSquared((f32*)(player + 0x18), &((EnemyPlacement*)setup)->posX) >
                            enemyRespawnDistanceSq)
                        {
                            enemy_init((GameObject*)(obj), setup, 0);
                            ((EnemyState*)state)->controlFlags |= 0x1000;
                            *(u32*)&((EnemyState*)state)->initialFlags &= ~0x1000LL;
                        }
                        else
                        {
                            return;
                        }
                    }
                    else
                    {
                        return;
                    }
                }
                else
                {
                    return;
                }
            }
            else
            {
                return;
            }
        }
    }
    if ((((EnemyState*)state)->controlFlags & 0x8000) != 0)
    {
        hudFn_8011f38c(0);
        (*gPathControlInterface)->attachObject((void*)obj, state + 4);
        ((EnemyState*)state)->controlFlags &= ~0x8003;
        if ((((EnemyState*)state)->flags2E4 & 0x20000) != 0)
        {
            s2 = *(u8**)&((GameObject*)obj)->anim.placementData;
            ((GameObject*)obj)->anim.localPosX = ((EnemyPlacement*)s2)->posX;
            ((GameObject*)obj)->anim.localPosY = ((EnemyPlacement*)s2)->posY;
            ((GameObject*)obj)->anim.localPosZ = ((EnemyPlacement*)s2)->posZ;
            ((GameObject*)obj)->anim.rotZ = 0;
            ((GameObject*)obj)->anim.rotY = 0;
            ((GameObject*)obj)->anim.rotX = ((EnemyPlacement*)s2)->rotXByte << 8;
            fz = lbl_803E2574;
            ((GameObject*)obj)->anim.velocityX = fz;
            ((GameObject*)obj)->anim.velocityY = fz;
            ((GameObject*)obj)->anim.velocityZ = fz;
        }
    }
    if ((((EnemyState*)state)->flags2E4 & 0x80000) != 0)
    {
        if (tricky != NULL && mainGetBit(0x9e) != 0)
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
        }
        else
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_PROMPT_SUPPRESSED;
        }
        if (tricky != NULL && (*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_IN_RANGE) != 0)
        {
            (**(void (**)(u8*, int, int, int))(*(int*)(*(int*)(tricky + 0x68)) + 0x28))(tricky, obj, 1, 2);
        }
    }
    baddie_updateWhileFrozen((GameObject*)(obj), state, 0);
    if ((((EnemyState*)state)->controlFlags & 0x1800) == 0)
    {
        baddieTurnTowardTarget((int*)obj, (int*)state);
        baddie_updateEngagementState((int*)obj, (int*)state);
    }
    enemyObjAnimUpdate((short*)obj, (int)state);
}

void enemy_init(GameObject* obj, u8* setup, int flag)
{
    u8* state = (obj)->extra;
    f32 fz;

    (obj)->userData1 = 0;
    if (flag == 0)
    {
        if (((EnemyPlacement*)setup)->gameBit2 != -1)
        {
            if (((EnemyPlacement*)setup)->gameBit != -1)
            {
                if (mainGetBit(((EnemyPlacement*)setup)->gameBit) == 0)
                {
                    (obj)->userData1 = mainGetBit(((EnemyPlacement*)setup)->gameBit2) == 0;
                }
            }
            else
            {
                (obj)->userData1 = mainGetBit(((EnemyPlacement*)setup)->gameBit2) == 0;
            }
        }
        if (*(u32*)&((ObjPlacement*)setup)->mapId != 0xFFFFFFFF)
        {
            if ((obj)->userData1 == 0)
            {
                if (((EnemyPlacement*)setup)->gameBit != -1)
                {
                    (obj)->userData1 = mainGetBit(((EnemyPlacement*)setup)->gameBit);
                }
                if ((obj)->userData1 == 0)
                {
                    if (((EnemyPlacement*)setup)->respawnEnabled != 0)
                    {
                        if ((*gMapEventInterface)->shouldNotSaveTime(((ObjPlacement*)setup)->mapId) == 0)
                        {
                            (obj)->userData1 = 1;
                        }
                    }
                }
            }
        }
    }
    if ((obj)->userData1 != 0)
    {
        (obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        (obj)->anim.alpha = 0;
    }
    else
    {
        (obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        (obj)->anim.alpha = 255;
    }
    ((EnemyState*)state)->health = ((EnemyPlacement*)setup)->healthByte / lbl_803E257C;
    ((EnemyState*)state)->aggroRange = (f32)(u32)(((EnemyPlacement*)setup)->aggroRangeByte << 3);
    *(int*)&((EnemyState*)state)->controlFlags = 0;
    ((EnemyState*)state)->initialFlags = *(int*)&((EnemyState*)state)->controlFlags;
    (obj)->anim.rotX = ((EnemyPlacement*)setup)->rotXByte << 8;
    (obj)->anim.localPosX = ((ObjPlacement*)setup)->posX;
    (obj)->anim.localPosY = ((ObjPlacement*)setup)->posY;
    (obj)->anim.localPosZ = ((ObjPlacement*)setup)->posZ;
    *(u8*)&(obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
    if (flag == 0)
    {
        *(int*)&((EnemyState*)state)->flags2E4 = 0;
        ((EnemyState*)state)->flags2E8 = 0;
        state[0x2f1] = 0;
        state[0x2f2] = 0;
        ((EnemyState*)state)->unk2EC = 0;
        state[0x2f5] = 0;
        fz = lbl_803E2574;
        ((EnemyState*)state)->animDeltaScale = fz;
        ((EnemyState*)state)->unk304 = fz;
        ((EnemyState*)state)->unk308 = fz;
        ((EnemyState*)state)->particleScale = fz;
        state[0x323] = 0;
        ((EnemyState*)state)->unk310 = fz;
        ((EnemyState*)state)->unk2F8 = 0;
        state[0x33a] = 0;
        state[0x33b] = 0;
        ((EnemyState*)state)->phaseAngle = 0;
        state[0x33c] = 0;
        state[0x33d] = 0;
        ((EnemyState*)state)->unk324 = fz;
        ((EnemyState*)state)->unk328 = fz;
        ((EnemyState*)state)->unk32C = fz;
        ((EnemyState*)state)->unk330 = fz;
        ((EnemyState*)state)->intervalTimer = fz;
        ((EnemyState*)state)->unk2B4 = -1;
        ((EnemyState*)state)->unk2B6 = ((EnemyState*)state)->unk2B4;
        (obj)->objectFlags |= ((EnemyPlacement*)setup)->objectFlagBits & 7;
        ((EnemyState*)state)->current = ((EnemyPlacement*)setup)->hitPoints;
        (obj)->animEventCallback = enemy_SeqFn;
        switch ((obj)->anim.seqId)
        {
        case ENEMY_SHARPCLAW_GR_OBJ:
        case ENEMY_SHARPCLAW_SN_OBJ:
        case ENEMY_SHARPCLAW_CO_OBJ:
        case ENEMY_SHARPCLAW_AS_OBJ:
        case ENEMY_SHARPCLAW_SH_OBJ:
        case ENEMY_SHARPCLAW_SO_OBJ:
        case ENEMY_BOSSGENERAL_OBJ:
            sharpClawInit((int)obj, state);
            break;
        case ENEMY_GUARDCLAW_OBJ:
        case 641:
            guardClaw_init((int*)obj, state);
            break;
        case ENEMY_GCROBOTPATROL_OBJ:
            gcRobotPatrol_init(obj, (int)state);
            break;
        case ENEMY_MIKALADON_OBJ:
            mikaladon_init(obj, (MikaladonState*)state);
            break;
        case ENEMY_VAMBAT_OBJ:
        case ENEMY_FIREBAT_OBJ:
            vambat_init(obj, (int)state);
            break;
        case ENEMY_KOOSHY_OBJ:
            kooshy_init((int)obj, (int)state);
            break;
        case ENEMY_WEEVIL_OBJ:
            weevil_init((int)obj, state);
            break;
        case ENEMY_PINPON_OBJ:
            pinPon_init(obj, state);
            break;
        case ENEMY_RACHNOP_OBJ:
            rachnopInit((int)obj, (int)state);
            break;
        case ENEMY_SPITTINGEBA_OBJ:
            spittingEbaInit((int)obj, (int)state);
            break;
        case ENEMY_WB_OBJ:
            wbInit((int)obj, (int)state);
            break;
        case ENEMY_MUTATEDEBA_OBJ:
            mutatedEbaInit((u32)obj, (int)state);
            break;
        case ENEMY_WHIRLPOOL_OBJ:
            baddie_initWhirlpoolState((int*)obj, (GroundBaddieState*)state);
            break;
        case ENEMY_SNOWWORM_OBJ:
        case ENEMY_SNOWWORM_BABY_OBJ:
            snowworm_init((int*)obj, (int*)state);
            break;
        case ENEMY_HOODEDZYCK_OBJ:
            hoodedZyck_init((int*)obj, (int*)state);
            break;
        case ENEMY_BATTLEDROID_OBJ:
            battleDroidInit((int)obj, (char*)state);
            break;
        case ENEMY_FIRECRAWLER_OBJ:
        case ENEMY_REDEYE_OBJ:
        case ENEMY_SHADOWHUNTER_OBJ:
        case ENEMY_SWAMPSTRIDER_OBJ:
            crawler_initModelVariant((s16*)obj, state);
            break;
        case ENEMY_HAGABONMK2_OBJ:
            hagabonMK2_init((int*)obj, (int*)state);
            break;
        default:
            battleDroidInit((int)obj, (char*)state);
            break;
        }
        ((EnemyState*)state)->max = *(u16*)&((EnemyState*)state)->current;
        if (((EnemyPlacement*)setup)->unk34 != 0)
        {
            *(int*)&((EnemyState*)state)->flags2E4 = *(int*)&((EnemyState*)state)->flags2E4 & -39;
        }
        ObjGroup_AddObject((int)obj, ENEMY_OBJGROUP);
        state[0x2f0] = 7;
        state[0x2ef] = 2;
        if (*(void**)state == NULL)
        {
            *(int*)state = (int)mmAlloc(264, 26, 0);
        }
        if (*(void**)state != NULL)
        {
            memset(*(void**)state, 0, 264);
        }
        if ((*gRomCurveInterface)
                ->initCurve(*(void**)state, (void*)obj, ((EnemyState*)state)->sightRange, (int*)&lbl_803DBC58, -1) == 0)
        {
            ((EnemyState*)state)->controlFlags |= BADDIE_CONTROL_PATH_FOLLOW;
        }
        (*gPathControlInterface)->init(state + 4, 0, 422, 1);
        if ((((EnemyState*)state)->flags2E4 & 8) != 0)
        {
            (*gPathControlInterface)->setLocalPointCollision(state + 4, 1, lbl_8031DBE4, &lbl_803DBC64, 4);
        }
        if ((((EnemyState*)state)->flags2E4 & 4) != 0)
        {
            (*gPathControlInterface)->setup(state + 4, 1, lbl_8031DBD8, &lbl_803DBC60, &lbl_803DBC68);
        }
        (*gPathControlInterface)->attachObject((void*)obj, state + 4);
        if ((((EnemyState*)state)->flags2E4 & 0xc) != 0)
        {
            state[0x25f] = 1;
        }
        if ((((EnemyState*)state)->flags2E4 & 0x8000022) != 0 || ((EnemyPlacement*)setup)->unk34 != 0 ||
            (obj)->anim.seqId == ENEMY_VAMBAT_OBJ || (obj)->anim.seqId == ENEMY_FIREBAT_OBJ)
        {
            ((EnemyState*)state)->flags |= 0x40000;
        }
        else
        {
            ((EnemyState*)state)->flags &= ~0x40000;
        }
        if ((((EnemyState*)state)->flags2E4 & 4) == 0 && (((EnemyState*)state)->flags2E4 & 8) != 0)
        {
            ((EnemyState*)state)->flags &= ~0x3800;
        }
        if ((obj)->userData1 != 0)
        {
            ((EnemyState*)state)->controlFlags |= 0x1000;
            *(u32*)&((EnemyState*)state)->initialFlags = *(u32*)&((EnemyState*)state)->initialFlags & ~0x1000LL;
            ObjHits_DisableObject(obj);
        }
        else if ((((EnemyState*)state)->flags2E4 & 1) != 0)
        {
            ObjHits_EnableObject(obj);
        }
    }
    ((EnemyState*)state)->freezeRecoverTimer = lbl_803E2574;
    if (((EnemyState*)state)->aggroRange > *(f32*)&enemySightRange)
    {
        ((EnemyState*)state)->aggroRange = enemySightRange;
    }
    if (((EnemyState*)state)->sightRange > *(f32*)&enemySightRange)
    {
        ((EnemyState*)state)->sightRange = enemySightRange;
    }
}

void enemy_release(void)
{
    if (lbl_803DDA50 != NULL)
    {
        Resource_Release(lbl_803DDA50);
        lbl_803DDA50 = NULL;
    }
}

void enemy_initialise(void)
{
    if (lbl_803DDA50 == NULL)
        lbl_803DDA50 = Resource_Acquire(0x5a, 1);
}
