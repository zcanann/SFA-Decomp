/*
 * drakormissile (DLL 610) - the homing energy projectile fired by the
 * Drakor boss (dll_024D_bossdrakor calls drakormissile_startActiveLaunch
 * to arm a pooled missile). The extra block (0x38 bytes) holds a model
 * light handle, a state machine (IDLE/FADEOUT/EXPLODING/STRAIGHT/HOMING),
 * a countdown timer and five spiralling trail-render yaw/pitch phases.
 *
 * STRAIGHT missiles fly a precomputed line (voxel trace clamps the timer
 * at the first wall hit); HOMING missiles re-aim each frame toward a
 * predicted player intercept point. Either explodes on contact, timer
 * expiry or proximity, then fades out and frees itself. The trail is
 * drawn as DRAKORMISSILE_RENDER_TRAIL_COUNT spun copies plus the body,
 * with an attached point light and glow.
 */
#include "main/model.h"
#include "main/dll/dll_0262_drakormissile.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/mtx/vec.h"
#include "main/dll/dll_0282_barrelgener.h"
#include "main/frame_timing.h"
#include "main/model_light.h"
#include "main/objfx.h"
#include "sys/objects.h"
#include "main/object_render.h"
#include "main/vecmath_distance_api.h"
#include "main/voxmaps.h"

#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_object_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/vecmath.h"
#include "main/objhits.h"
#include "main/objtype.h"
#include "sys/objects/lifecycle.h"

f32 gDrakorMissileVelocityDamping = 0.9f;
f32 gDrakorMissileSteerGain = 0.1f;
f32 gDrakorMissileInterceptSpeedBias = 0.5f;
f32 gDrakorMissileProximityDetonateDist = 50.0f;


#define DRAKORMISSILE_EXTRA_SIZE     0x38
#define DRAKORMISSILE_OBJECT_TYPE_ID 0x2
#define DRAKORMISSILE_GROUP_ID       0x2

#define DRAKORMISSILE_STATE_IDLE      0
#define DRAKORMISSILE_STATE_FADEOUT   1
#define DRAKORMISSILE_STATE_EXPLODING 2
#define DRAKORMISSILE_STATE_STRAIGHT  3
#define DRAKORMISSILE_STATE_HOMING    4

#define DRAKORMISSILE_ACTIVE_TIMER       0x960
#define DRAKORMISSILE_CLEAR_TIMER        0x80
#define DRAKORMISSILE_TRACE_MISS_TIMER   0x258
#define DRAKORMISSILE_IGNORE_OBJECT_TYPE 0x2ab
#define DRAKORMISSILE_TARGET_MASK        4
#define DRAKORMISSILE_HIT_VOLUME_SLOT    22
#define DRAKORMISSILE_ACTIVE_SFX_A       965
#define DRAKORMISSILE_ACTIVE_SFX_B       966
void drakormissile_abortStraightFlight(GameObject* obj)
{
    DrakorMissileState* state = obj->extra;
    if (state->state == DRAKORMISSILE_STATE_STRAIGHT)
    {
        state->state = DRAKORMISSILE_STATE_EXPLODING;
    }
}

void drakormissile_requestFree(GameObject* obj)
{
    DrakorMissileState* state = (obj)->extra;
    state->flags |= 1;
    if (state->state == DRAKORMISSILE_STATE_FADEOUT)
    {
        Obj_FreeObject(obj);
    }
}

void drakormissile_startActiveLaunch(GameObject* obj)
{
    ModelLightStruct* light;
    DrakorMissileState* state = (obj)->extra;

    ObjHits_EnableObject(obj);
    state->state = DRAKORMISSILE_STATE_HOMING;
    (obj)->anim.rotZ = 0;
    light = objCreateLight(obj, 1);
    if (light != NULL)
    {
        modelLightStruct_setLightKind(light, MODEL_LIGHT_KIND_POINT);
        modelLightStruct_setDiffuseColor(light, 255, 128, 0, 0);
        modelLightStruct_setFieldBC(light, 1);
        modelLightStruct_setDistanceAttenuation(light, 50.0f, 80.0f);
        modelLightStruct_setupGlow(light, 0, 0, 255, 255, 128, 40.0f);
        modelLightStruct_setGlowProjectionRadius(light, 10.0f);
    }
    state->light = light;
    if (state->light != NULL)
    {
        modelLightStruct_setDistanceAttenuation(state->light, 150.0f, 180.0f);
    }
    (obj)->anim.alpha = 255;
    (obj)->anim.rootMotionScale = 0.5f * (obj)->anim.modelInstance->rootMotionScaleBase;
    state->timer = DRAKORMISSILE_ACTIVE_TIMER;
    ObjHits_SetTargetMask(obj, DRAKORMISSILE_TARGET_MASK);
    ObjHits_SetHitVolumeSlot(&obj->anim, DRAKORMISSILE_HIT_VOLUME_SLOT, 1, 0);
    Sfx_PlayFromObject(obj, DRAKORMISSILE_ACTIVE_SFX_A);
    Sfx_PlayFromObject(obj, DRAKORMISSILE_ACTIVE_SFX_B);
}

void drakormissile_startStraightLaunch(GameObject* obj, GameObject* from, GameObject* target, f32 speed)
{
    ModelLightStruct* light;
    f32 dir[3];
    f32 hitDir[3];
    f32 endPos[3];
    s16 startGrid[3];
    s16 endGrid[3];
    s16 hitGrid[3];
    f32 mag;
    f32 horizDist;
    DrakorMissileState* state = (obj)->extra;
    f32 zero = 0.0f;

    dir[0] = target->anim.localPosX - from->anim.localPosX;
    dir[1] = target->anim.localPosY - from->anim.localPosY;
    dir[2] = target->anim.localPosZ - from->anim.localPosZ;
    mag = sqrtf(dir[0] * dir[0] + dir[1] * dir[1] + dir[2] * dir[2]) / speed;
    if (mag != zero)
    {
        dir[0] = dir[0] / mag;
        dir[1] = dir[1] / mag;
        *(f32*)&dir[2] = dir[2] / mag;
    }
    (obj)->anim.localPosX = from->anim.localPosX;
    (obj)->anim.localPosY = from->anim.localPosY;
    (obj)->anim.localPosZ = from->anim.localPosZ;
    (obj)->anim.velocityX = dir[0];
    (obj)->anim.velocityY = dir[1];
    (obj)->anim.velocityZ = dir[2];
    horizDist = sqrtf((obj)->anim.velocityX * (obj)->anim.velocityX + (obj)->anim.velocityZ * (obj)->anim.velocityZ);
    (obj)->anim.rotX = (s16)getAngle((obj)->anim.velocityX, (obj)->anim.velocityZ);
    (obj)->anim.rotY = -getAngle((obj)->anim.velocityY, horizDist);
    (obj)->anim.rotZ = 0;
    ObjHits_EnableObject(obj);
    state->state = DRAKORMISSILE_STATE_STRAIGHT;
    endPos[0] = 600.0f * (obj)->anim.velocityX;
    endPos[1] = 600.0f * (obj)->anim.velocityY;
    endPos[2] = 600.0f * (obj)->anim.velocityZ;
    endPos[0] = (obj)->anim.localPosX + endPos[0];
    endPos[1] = (obj)->anim.localPosY + endPos[1];
    endPos[2] = (obj)->anim.localPosZ + endPos[2];
    voxmaps_worldToGrid(&obj->anim.localPosX, startGrid);
    voxmaps_worldToGrid(endPos, endGrid);
    if (voxmaps_traceLine((VoxPos*)startGrid, (VoxPos*)endGrid, (VoxPos*)hitGrid, NULL, 0) == 0)
    {
        voxmaps_gridToWorld(endPos, hitGrid);
        hitDir[0] = endPos[0] - (obj)->anim.localPosX;
        hitDir[1] = endPos[1] - (obj)->anim.localPosY;
        *(f32*)&hitDir[2] = endPos[2] - (obj)->anim.localPosZ;
        state->timer = (int)(sqrtf(hitDir[0] * hitDir[0] + hitDir[1] * hitDir[1] + hitDir[2] * hitDir[2]) / speed);
    }
    else
    {
        state->timer = DRAKORMISSILE_TRACE_MISS_TIMER;
    }
    if (state->light != NULL)
    {
        ModelLightStruct_free(state->light);
        state->light = NULL;
    }
    light = objCreateLight(obj, 1);
    if (light != NULL)
    {
        modelLightStruct_setLightKind(light, MODEL_LIGHT_KIND_POINT);
        modelLightStruct_setDiffuseColor(light, 0, 255, 255, 0);
        modelLightStruct_setFieldBC(light, 1);
        modelLightStruct_setDistanceAttenuation(light, 50.0f, 80.0f);
        modelLightStruct_setupGlow(light, 0, 0, 255, 255, 128, 40.0f);
        modelLightStruct_setGlowProjectionRadius(light, 10.0f);
    }
    state->light = light;
    (obj)->anim.alpha = 255;
    (obj)->anim.rootMotionScale = 0.5f * (obj)->anim.modelInstance->rootMotionScaleBase;
    Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_173);
}

int drakormissile_isFadingOut(GameObject* obj)
{
    DrakorMissileState* state = obj->extra;
    return state->state == DRAKORMISSILE_STATE_FADEOUT;
}

int drakormissile_getExtraSize(void)
{
    return DRAKORMISSILE_EXTRA_SIZE;
}

int drakormissile_getObjectTypeId(void)
{
    return DRAKORMISSILE_OBJECT_TYPE_ID;
}

void drakormissile_free(GameObject* obj)
{
    DrakorMissileState* state = (obj)->extra;
    ModelLightStruct* light = state->light;
    if (light != NULL)
    {
        ModelLightStruct_free(light);
        state->light = NULL;
    }
    objFreeObjectType(obj, DRAKORMISSILE_GROUP_ID);
}

void drakormissile_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    f32 one = 1.0f;
    s16 savedRotZ;
    s16 savedRotY;
    int i;
    DrakorMissileState* state = (obj)->extra;
    ObjAnimComponent* objAnim = &obj->anim;
    if (visible != 0 && state->state != DRAKORMISSILE_STATE_FADEOUT)
    {
        f32 savedScale;
        ObjModel* model;
        savedRotZ = (obj)->anim.rotZ;
        savedRotY = (obj)->anim.rotY;
        savedScale = (obj)->anim.rootMotionScale;
        objAnim->bankIndex = 1;
        model = Obj_GetActiveModel(obj);
        i = 0;
        for (; i < DRAKORMISSILE_RENDER_TRAIL_COUNT; i++)
        {
            state->trailYaw[i] += state->trailYawStep[i];
            state->trailPitch[i] += state->trailPitchStep[i];
            (obj)->anim.rotZ = state->trailYaw[i];
            (obj)->anim.rotY = state->trailPitch[i];
            model->bufferFlags &= ~8;
            objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, one);
        }
        (obj)->anim.rotZ = savedRotZ;
        (obj)->anim.rotY = savedRotY;
        (obj)->anim.rootMotionScale = savedScale;
        objAnim->bankIndex = 0;
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, one);
        if (state->light != NULL && modelLightStruct_getActiveState(state->light) != 0)
        {
            queueGlowRender(state->light);
        }
    }
}

void drakormissile_hitDetect(void)
{
}

void drakormissile_update(GameObject* o)
{
    DrakorMissileState* state = o->extra;
    int moving;
    Vec toTarget;
    Vec dir;
    GameObject* hitObj;
    int hit;
    GameObject* lastHit;
    int result;
    GameObject* player;
    f32 mag;
    int expired;
    int nearHit;
    int rem;
    moving = 0;
    switch (state->state)
    {
    case DRAKORMISSILE_STATE_STRAIGHT:
        moving = 1;
        objMove(o, o->anim.velocityX * timeDelta, o->anim.velocityY * timeDelta,
                o->anim.velocityZ * timeDelta);
        break;
    case DRAKORMISSILE_STATE_EXPLODING:
        o->anim.alpha = 0;
        if (state->timer == 0)
        {
            ObjHits_DisableObject(o);
        }
        state->timer += framesThisStep;
        if (state->timer > DRAKORMISSILE_CLEAR_TIMER)
        {
            ObjHits_DisableObject(o);
            Sfx_StopFromObject(o, SFXTRIG_dn_boar1_c_173);
            Sfx_StopFromObject(o, DRAKORMISSILE_ACTIVE_SFX_A);
            state->state = DRAKORMISSILE_STATE_FADEOUT;
        }
        break;
    case DRAKORMISSILE_STATE_HOMING:
        player = Obj_GetPlayerObject();
        if (player->anim.velocityX != (mag = 0.0f) ||
            player->anim.velocityY != mag || player->anim.velocityZ != mag)
        {
            mag = PSVECMag(&player->anim.velocity);
        }
        mag = gDrakorMissileInterceptSpeedBias + mag;
        Obj_PredictInterceptPoint(player, mag, &o->anim.localPos, &toTarget);
        PSVECSubtract(&toTarget, &o->anim.localPos, &dir);
        PSVECNormalize(&dir, &dir);
        PSVECScale(&dir, &dir, mag * gDrakorMissileSteerGain);
        PSVECScale(&o->anim.velocity, &o->anim.velocity, gDrakorMissileVelocityDamping);
        PSVECAdd(&o->anim.velocity, &dir, &o->anim.velocity);
        mag = sqrtf(o->anim.velocityX * o->anim.velocityX +
                    o->anim.velocityZ * o->anim.velocityZ);
        {
            int tmpAng = getAngle(o->anim.velocityX, o->anim.velocityZ);
            o->anim.rotX = tmpAng;
            tmpAng = getAngle(o->anim.velocityY, mag);
            o->anim.rotY = tmpAng;
        }
        objMove(o, o->anim.velocityX * timeDelta, o->anim.velocityY * timeDelta,
                o->anim.velocityZ * timeDelta);
        moving = 1;
        break;
    case DRAKORMISSILE_STATE_FADEOUT:
    {
        f32 life = state->fadeTime + timeDelta;
        state->fadeTime = life;
        if (life > 60.0f)
        {
        Obj_FreeObject(o);
            return;
        }
        break;
    }
    case DRAKORMISSILE_STATE_IDLE:
        break;
    }
    if (moving)
    {
        lastHit = (GameObject*)((ObjHitsPriorityState*)o->anim.hitReactState)->lastHitObject;
        hitObj = NULL;
        hit = ObjHits_GetPriorityHit((GameObject*)(o), &hitObj, 0, 0);
        expired = 0;
        rem = state->timer - framesThisStep;
        state->timer = rem;
        if (rem < 0 || hit != 0)
        {
            expired = 1;
        }
        nearHit = 0;
        if (lastHit != NULL && lastHit->anim.romDefNo != DRAKORMISSILE_IGNORE_OBJECT_TYPE)
        {
            nearHit = 1;
        }
        result = expired | nearHit;
        result |= ((ObjHitsPriorityState*)o->anim.hitReactState)->contactFlags;
        if (state->state == DRAKORMISSILE_STATE_HOMING)
        {
            player = Obj_GetPlayerObject();
            if (Vec_distance(&o->anim.worldPosX, &player->anim.worldPosX) <
                gDrakorMissileProximityDetonateDist)
            {
                result |= 1;
            }
        }
        if (hitObj != NULL && hitObj->anim.romDefNo == DRAKORMISSILE_IGNORE_OBJECT_TYPE)
        {
            result = 0;
        }
        if (result != 0)
        {
            state->state = DRAKORMISSILE_STATE_EXPLODING;
            state->timer = 0;
            if ((((ObjHitsPriorityState*)o->anim.hitReactState)->flags & 8) != 0)
            {
                Sfx_PlayFromObject((GameObject*)(u32)o, SFXTRIG_wp_blaserrecoil16);
            }
            if (o->anim.mapEventSlot == 2)
            {
                spawnExplosion(o, 50.0f, 3, 0, 0, 0, 0, 0, 3);
            }
            else
            {
                spawnExplosion(o, 50.0f, 1, 0, 0, 0, 0, 0, 3);
            }
            if (state->light != NULL)
            {
                ModelLightStruct_free(state->light);
                state->light = NULL;
            }
        }
        ((ObjHitsPriorityState*)o->anim.hitReactState)->skeletonHitMask = 0x10;
        ((ObjHitsPriorityState*)o->anim.hitReactState)->objectHitMask = 0x10;
    }
    if (state->light != NULL && modelLightStruct_getActiveState(state->light))
    {
        modelLightStruct_updateGlowAlpha(state->light);
    }
}

void drakormissile_init(GameObject* obj, DrakorMissileSetup* setup)
{
    DrakorMissileState* state = (obj)->extra;
    int i;
    ((ObjHitsPriorityState*)(obj)->anim.hitReactState)->hitVolumePriority = 0x13;
    ((ObjHitsPriorityState*)(obj)->anim.hitReactState)->hitVolumeId = 1;
    ((ObjHitsPriorityState*)(obj)->anim.hitReactState)->flags &= ~1;
    (obj)->anim.localPosX = setup->base.posX;
    (obj)->anim.localPosY = setup->base.posY;
    (obj)->anim.localPosZ = setup->base.posZ;
    (obj)->anim.velocityX = (f32)(u32)setup->velocityX;
    (obj)->anim.velocityY = (f32)(u32)setup->velocityY;
    (obj)->anim.velocityZ = (f32)(u32)setup->velocityZ;
    if ((obj)->anim.hitReactState != NULL)
    {
        ((ObjHitsPriorityState*)(obj)->anim.hitReactState)->trackContactMask = 1;
    }
    objAddObjectType(obj, DRAKORMISSILE_GROUP_ID);
    state->state = DRAKORMISSILE_STATE_IDLE;
    state->flags = 0;
    state->timer = 0;
    state->light = 0;
    state->fadeTime = 0.0f;
    for (i = 0; i < DRAKORMISSILE_RENDER_TRAIL_COUNT; i++)
    {
        state->trailYaw[i] = randomGetRange(-0x7fff, 0x7fff);
        state->trailYawStep[i] = randomGetRange(-0x400, 0x400);
        state->trailPitch[i] = randomGetRange(-0x7fff, 0x7fff);
        state->trailPitchStep[i] = randomGetRange(-0x400, 0x400);
    }
}

void drakormissile_release(void)
{
}

void drakormissile_initialise(void)
{
}

ObjectDescriptor14 gDrakorMissileObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_14_SLOTS,
    (ObjectDescriptorCallback)drakormissile_initialise,
    (ObjectDescriptorCallback)drakormissile_release,
    0,
    (ObjectDescriptorCallback)drakormissile_init,
    (ObjectDescriptorCallback)drakormissile_update,
    (ObjectDescriptorCallback)drakormissile_hitDetect,
    (ObjectDescriptorCallback)drakormissile_render,
    (ObjectDescriptorCallback)drakormissile_free,
    (ObjectDescriptorCallback)drakormissile_getObjectTypeId,
    drakormissile_getExtraSize,
    (ObjectDescriptorCallback)drakormissile_isFadingOut,
    (ObjectDescriptorCallback)drakormissile_startStraightLaunch,
    (ObjectDescriptorCallback)drakormissile_requestFree,
    (ObjectDescriptorCallback)drakormissile_abortStraightFlight,
};
