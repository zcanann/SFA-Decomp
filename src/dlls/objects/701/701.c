/*
 * DLL 701 (0x2BD) - one of Andross's two hands in the Arwing
 * boss fight. Tracks the Andross body object (id 0x47b77) and the
 * player's Arwing, mirrors the body's facing, and applies a damped
 * spring to its Z position so the hand bobs relative to the body.
 *
 * handState drives an animation/attack state machine (set externally
 * via androsshand_setState): 0/3 idle, 1/2 enter/exit, 4 swipe, 5 grab,
 * 6 shoot (spawns projectiles type 0x7e4 on a timer), 9 dead/hidden.
 * sideFlag selects the left/right hand (mirrors swipe velocity and the
 * part signal). Damage is taken on hit sphere 0 with a cooldown; at 0
 * health the hand explodes (DIMexplosionFn) and goes to state 9. The
 * damage texture index is written into the model's texture slot.
 */
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/frame_timing.h"
#include "main/objtexture.h"
#include "main/pad.h"
#include "main/dll/objfx_api.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/dll/dll_02BC_andross.h"
#include "main/dll/dll_029B_arwingandrossstuff.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/dll_02BD_androsshand.h"
#include "main/object_render.h"
#include "dlls/object_descriptor.h"
#include "main/vecmath.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/dll/ARW/dll_029A_arwarwing.h"
#include "main/obj_path.h"
#include "main/objhits.h"

/* Andross body object id, located once and cached in androssObj. */
#define ANDROSS_OBJ_ID              0x47b77
#define ANDROSSHAND_HIT_VOLUME_SLOT 5

/* Projectile spawned by the hand; retail "AndrossRing" (same 0x7e4 the andross body fires);
   role pinned by arwprojectile_setLifetime/placeForward + AndrossHandShotSetup cast. */
#define ANDROSSHAND_CHILD_OBJ_RING 0x7e4

enum AndrossHandHealth
{
    ANDROSSHAND_HEALTH_NORMAL = 0xf,
    ANDROSSHAND_HEALTH_PHASE2 = 0x12
};

void androsshand_spawnShot(GameObject* obj, AndrossHandState* state, int p3)
{
    f32 pt[3];
    f32 dx, dz, dist;
    int yaw;
    AndrossHandShotSetup* setup;

    if (Obj_IsLoadingLocked())
    {
        ObjPath_GetPointWorldPosition(obj, 0, &pt[0], &pt[1], &pt[2], 0);
        dx = pt[0] - state->arwingObj->anim.localPosX;
        dz = pt[2] - state->arwingObj->anim.localPosZ;
        dist = sqrtf(dx * dx + dz * dz);
        yaw = (u16)getAngle(dx, dz) + 0x8000;
        gAndrossHandShotPitch[0] = (u16)getAngle(pt[1] - state->arwingObj->anim.localPosY, dist) >> 8;
        setup = (AndrossHandShotSetup*)Obj_AllocObjectSetup(0x20, ANDROSSHAND_CHILD_OBJ_RING);
        setup->head.posX = pt[0];
        setup->head.posY = pt[1];
        setup->head.posZ = pt[2];
        setup->yaw = (obj->anim.rotX + yaw) >> 8;
        setup->pitch = gAndrossHandShotPitch[0];
        setup->flag18 = 0;
        setup->head.color[0] = 1;
        setup->head.color[1] = 1;
        obj = loadObjectAtObject(obj, &setup->head);
        if (obj != NULL)
        {
            arwprojectile_setLifetime(obj, gAndrossHandProjectileLifetime[0]);
            arwprojectile_placeForward(obj, gAndrossHandProjectileForwardStep);
        }
    }
}

void androsshand_handleDamage(GameObject* obj, AndrossHandState* state)
{
    u32 hitVol;
    int sphereIdx;
    GameObject* hitObj;
    f32 x;
    f32 y;
    f32 z;
    int cooldown;

    cooldown = state->hitCooldown - framesThisStep;
    if (cooldown < 0)
    {
        cooldown = 0;
    }
    state->hitCooldown = cooldown;
    if (ObjHits_GetPriorityHit(obj, &hitObj, &sphereIdx, &hitVol) != 0 && state->hitCooldown == 0)
    {
        switch (sphereIdx)
        {
        case 0:
            state->health -= 1;
            state->hitCooldown = 6;
            state->zSpringVelocity = gAndrossHandHitImpulse;
            Sfx_PlayFromObject(obj, SFXTRIG_wmap_nameoff);
            if (state->health == 0)
            {
                state->handState = ANDROSSHAND_STATE_DEAD;
                andross_setPartSignal(state->androssObj, 1);
                Sfx_PlayFromObject(obj, SFXTRIG_en_barrelblow11);
                ObjPath_GetPointWorldPosition(obj, 0, &x, &y, &z, 0);
                spawnDimExplosion((u8*)obj, x, y, z, 120.0f, 1, 1, 1, 1, 0, 1, 0);
            }
            break;
        }
    }
    if (state->health != 0)
    {
        if (state->hitCooldown != 0)
        {
            state->damageTextureState = 1;
        }
        else
        {
            state->damageTextureState = 0;
        }
    }
    else
    {
        state->damageTextureState = 2;
    }
    {
        ObjTextureRuntimeSlot* texture = objFindTexture(obj, 0, 0);
        texture->textureId = state->damageTextureState << 8;
    }
}


void androsshand_setState(GameObject* obj, AndrossHandStateId newState, u8 force)
{
    AndrossHandState* state;

    if ((void*)obj == NULL)
    {
        return;
    }
    state = (obj)->extra;
    if (state->handState != ANDROSSHAND_STATE_DEAD || force != 0)
    {
        state->handState = newState;
        if (force != 0)
        {
            if (force == 2)
            {
                state->health = ANDROSSHAND_HEALTH_PHASE2;
            }
            else
            {
                state->health = ANDROSSHAND_HEALTH_NORMAL;
            }
        }
    }
    else
    {
        if ((u8)newState != 0)
        {
            andross_setPartSignal(state->androssObj, 1);
        }
    }
}

int AndrossHand_getExtraSize(void)
{
    return sizeof(AndrossHandState);
}

int AndrossHand_getObjectTypeId(void)
{
    return 0;
}

void AndrossHand_free(void)
{
}

void AndrossHand_render(GameObject* obj, int p2, int p3, int p4, int p5)
{
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void AndrossHand_hitDetect(void)
{
}

f32 gAndrossHandMoveAnimSpeeds[7] = {0.02f, 0.007f, 0.007f, 0.003f, 0.02f, 0.013f, 0.007f};

ObjectDescriptor gAndrossHandObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)AndrossHand_init,
    (ObjectDescriptorCallback)AndrossHand_update,
    (ObjectDescriptorCallback)AndrossHand_hitDetect,
    (ObjectDescriptorCallback)AndrossHand_render,
    (ObjectDescriptorCallback)AndrossHand_free,
    (ObjectDescriptorCallback)AndrossHand_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)AndrossHand_getExtraSize,
};

void AndrossHand_update(GameObject* o)
{
    f32 fScale = gAndrossHandAngleOffset;
    AndrossHandState* state = o->extra;
    u8 changed = 0;
    Vec3f swipeVel;
    Vec3f grabVel;

    if (state->androssObj == NULL)
    {
        state->androssObj = ObjList_FindObjectById(ANDROSS_OBJ_ID);
    }
    if (state->arwingObj == NULL)
    {
        state->arwingObj = (GameObject*)getArwing();
    }
    if (state->startupDelay != 0)
    {
        state->startupDelay -= 1;
        return;
    }

    o->anim.alpha = 0xff;
    o->anim.rotZ = 0;
    o->anim.rotY = 0;
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)o, ANDROSSHAND_HIT_VOLUME_SLOT, 2, -1);
    ObjHits_EnableObject(o);

    if (state->androssObj != NULL)
    {
        f32 prevVel;
        f32 angle;
        f32 cosAngle;

        o->anim.rotX = state->androssObj->anim.rotX;
        if (state->sideFlag != 0)
        {
            fScale *= -1.0f;
        }
        prevVel = state->zSpringVelocity;
        state->zSpringVelocity =
            prevVel + ((-state->zSpringOffset / gAndrossHandSpringOffsetDivisor - prevVel) / gAndrossHandSpringDivisor);
        state->zSpringOffset = state->zSpringOffset + state->zSpringVelocity;

        angle = 3.1415927f * (f32)(s16)(int)((f32)state->androssObj->anim.rotX + fScale) /
                32768.0f;
        fScale = mathSinf(angle);
        cosAngle = mathCosf(angle);
        o->anim.localPosX = gAndrossHandOrbitRadius * fScale + state->androssObj->anim.localPosX;
        o->anim.localPosY = state->androssObj->anim.localPosY + gAndrossHandYOffset;
        o->anim.localPosZ =
            state->zSpringOffset + (gAndrossHandOrbitRadius * cosAngle + state->androssObj->anim.localPosZ);
    }

    {
        u8 cur = *(u8*)&state->handState;
        if ((s8)cur != state->prevState)
        {
            changed = 1;
        }
        *(u8*)&state->prevState = cur;
    }

    switch (state->handState)
    {
    case ANDROSSHAND_STATE_IDLE:
        if (changed)
        {
            AndrossHandState* hand = o->extra;
            ObjAnim_SetCurrentMove(o, 0, 0.0f, 0);
            hand->animSpeed = gAndrossHandMoveAnimSpeeds[0];
        }
        break;
    case ANDROSSHAND_STATE_EXIT:
        if (changed)
        {
            AndrossHandState* hand = o->extra;
            ObjAnim_SetCurrentMove(o, 4, 0.0f, 0);
            hand->animSpeed = gAndrossHandMoveAnimSpeeds[4];
        }
        if (o->anim.currentMoveProgress >= 1.0f)
        {
            state->handState = ANDROSSHAND_STATE_IDLE2;
            state->prevState = ANDROSSHAND_STATE_IDLE2;
        }
        break;
    case ANDROSSHAND_STATE_ENTER:
        if (changed)
        {
            AndrossHandState* hand = o->extra;
            ObjAnim_SetCurrentMove(o, 5, 0.0f, 0);
            hand->animSpeed = gAndrossHandMoveAnimSpeeds[5];
        }
        if (o->anim.currentMoveProgress >= 1.0f)
        {
            state->handState = ANDROSSHAND_STATE_IDLE2;
        }
        break;
    case ANDROSSHAND_STATE_SWIPE:
        if (changed)
        {
            AndrossHandState* hand;
            state->soundGate = 0;
            hand = o->extra;
            ObjAnim_SetCurrentMove(o, 1, 0.0f, 0);
            hand->animSpeed = gAndrossHandMoveAnimSpeeds[1];
        }
        {
            ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)o->anim.hitReactState;
            if (hitState->lastHitObject != 0)
            {
                Vec3f vel;
                swipeVel.x = state->sideFlag ? -20.0f : 20.0f;
                swipeVel.y = 0.0f;
                swipeVel.z = 0.0f;
                vel = swipeVel;
                arwarwing_setVelocity(state->arwingObj, &vel);
                doRumble(5.0f);
            }
        }
        if (o->anim.currentMoveProgress < 0.15)
        {
            state->animSpeed = 0.001f;
        }
        else
        {
            state->animSpeed = 0.007f;
        }
        if (o->anim.currentMoveProgress >= 0.25f && state->soundGate == 0)
        {
            state->soundGate = 1;
            Sfx_PlayFromObject(o, SFXTRIG_and_ring_lp);
        }
        if (o->anim.currentMoveProgress >= 1.0f)
        {
            andross_setPartSignal(state->androssObj, 1);
            state->handState = ANDROSSHAND_STATE_IDLE2;
        }
        androsshand_handleDamage(o, state);
        break;
    case ANDROSSHAND_STATE_GRAB:
        if (changed)
        {
            AndrossHandState* hand;
            state->soundGate = 0;
            hand = o->extra;
            ObjAnim_SetCurrentMove(o, 2, 0.0f, 0);
            hand->animSpeed = gAndrossHandMoveAnimSpeeds[2];
        }
        if (state->sideFlag != 0 && o->anim.currentMoveProgress >= 1.0f)
        {
            andross_setPartSignal(state->androssObj, 1);
            state->handState = ANDROSSHAND_STATE_IDLE2;
        }
        if (o->anim.currentMoveProgress < 0.18)
        {
            state->animSpeed = 0.002f;
        }
        else
        {
            state->animSpeed = 0.007f;
        }
        {
            ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)o->anim.hitReactState;
            if (hitState->lastHitObject != 0)
            {
                Vec3f vel;
                grabVel.x = 0.0f;
                grabVel.y = -10.0f;
                grabVel.z = 0.0f;
                vel = grabVel;
                arwarwing_setVelocity(state->arwingObj, &vel);
                doRumble(5.0f);
            }
        }
        if (o->anim.currentMoveProgress >= 0.25f &&
            o->anim.currentMoveProgress < 0.4f && state->soundGate == 0)
        {
            state->soundGate = 1;
            Sfx_PlayFromObject(o, SFXTRIG_and_chompf);
        }
        if (o->anim.currentMoveProgress >= 0.4f && state->soundGate != 0)
        {
            state->soundGate = 0;
            Sfx_PlayFromObject(o, SFXTRIG_rockshat16);
        }
        if (o->anim.currentMoveProgress >= 1.0f)
        {
            if (state->sideFlag != 0)
            {
                andross_setPartSignal(state->androssObj, 1);
            }
            state->handState = ANDROSSHAND_STATE_IDLE2;
        }
        androsshand_handleDamage(o, state);
        break;
    case ANDROSSHAND_STATE_SHOOT:
        if (changed)
        {
            AndrossHandState* hand = o->extra;
            ObjAnim_SetCurrentMove(o, 3, 0.0f, 0);
            hand->animSpeed = gAndrossHandMoveAnimSpeeds[3];
            state->shotTimer = -1;
        }
        state->shotTimer -= framesThisStep;
        if (o->anim.currentMoveProgress < 0.15)
        {
            state->animSpeed = 0.002f;
        }
        else
        {
            Sfx_KeepAliveLoopedObjectSound(o, SFXTRIG_and_roar1);
            state->animSpeed = 0.002f;
            if (state->shotTimer < 0)
            {
                androsshand_spawnShot(o, state, 0);
                state->shotTimer = gAndrossHandShotInterval;
            }
        }
        if (o->anim.currentMoveProgress >= 1.0f)
        {
            andross_setPartSignal(state->androssObj, 1);
            state->handState = ANDROSSHAND_STATE_IDLE2;
        }
        androsshand_handleDamage(o, state);
        break;
    case ANDROSSHAND_STATE_IDLE2:
        if (changed)
        {
            AndrossHandState* hand = o->extra;
            ObjAnim_SetCurrentMove(o, 0, 0.0f, 0);
            hand->animSpeed = gAndrossHandMoveAnimSpeeds[0];
        }
        break;
    case ANDROSSHAND_STATE_DEAD:
        andross_setPartSignal(state->androssObj, state->sideFlag ? (u8)4 : (u8)2);
        break;
    }

    if (state->handState == ANDROSSHAND_STATE_DEAD)
    {
        o->anim.flags |= OBJANIM_FLAG_HIDDEN;
    }
    else
    {
        o->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
    }
    ObjAnim_AdvanceCurrentMove(o, state->animSpeed, timeDelta, 0);
}

void AndrossHand_init(GameObject* gobj, AndrossHandSetup* setup)
{
    AndrossHandState* state = gobj->extra;

    state->sideFlag = setup->sideFlag;
    state->prevState = -1;
    state->health = ANDROSSHAND_HEALTH_NORMAL;
    state->startupDelay = 5;
    state->handState = ANDROSSHAND_STATE_IDLE2;
    state->prevState = ANDROSSHAND_STATE_IDLE2;
    state = gobj->extra;
    ObjAnim_SetCurrentMove(gobj, 4, 0.0f, 0);
    state->animSpeed = gAndrossHandMoveAnimSpeeds[4];
    gobj->anim.currentMoveProgress = 1.0f;
    ObjHits_SetTargetMask(gobj, 4);
}

int gAndrossHandShotPitch[2];

f32 gAndrossHandOrbitRadius = 400.0f;
f32 gAndrossHandYOffset = -100.0f;
f32 gAndrossHandAngleOffset = -20000.0f;
int gAndrossHandSpringOffsetDivisor = 20;
int gAndrossHandSpringDivisor = 10;
int gAndrossHandShotInterval = 2;
int gAndrossHandHitImpulse = 20;
int gAndrossHandProjectileForwardStep = 10;
int gAndrossHandProjectileLifetime[2] = { 150 };
