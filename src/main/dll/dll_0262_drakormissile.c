/*
 * drakormissile (DLL 0x262) - the homing energy projectile fired by the
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
#include "main/dll/DR/dr_shared.h"
#include "main/game_object.h"

#include "main/audio/sfx_ids.h"

#define MODEL_LIGHT_KIND_POINT 2

#define DRAKORMISSILE_EXTRA_SIZE 0x38
#define DRAKORMISSILE_OBJECT_TYPE_ID 0x2
#define DRAKORMISSILE_GROUP_ID 0x2

#define DRAKORMISSILE_STATE_IDLE 0
#define DRAKORMISSILE_STATE_FADEOUT 1
#define DRAKORMISSILE_STATE_EXPLODING 2
#define DRAKORMISSILE_STATE_STRAIGHT 3
#define DRAKORMISSILE_STATE_HOMING 4

#define DRAKORMISSILE_RENDER_TRAIL_COUNT 5

/*
 * The 0x38-byte object extra block. The trail is drawn as
 * DRAKORMISSILE_RENDER_TRAIL_COUNT spun copies; each copy i keeps its own
 * yaw/pitch phase and per-frame spin step.
 */
typedef struct DrakorMissileState
{
    void* light;                                     /* 0x00 */
    u8 state;                                         /* 0x04 */
    u8 flags;                                         /* 0x05 */
    u8 pad06[2];                                      /* 0x06 */
    int timer;                                        /* 0x08 */
    f32 fadeTime;                                     /* 0x0c */
    u16 trailYaw[DRAKORMISSILE_RENDER_TRAIL_COUNT];   /* 0x10 */
    u16 trailYawStep[DRAKORMISSILE_RENDER_TRAIL_COUNT]; /* 0x1a */
    u16 trailPitch[DRAKORMISSILE_RENDER_TRAIL_COUNT]; /* 0x24 */
    u16 trailPitchStep[DRAKORMISSILE_RENDER_TRAIL_COUNT]; /* 0x2e */
} DrakorMissileState;

#define DRAKORMISSILE_SETUP_POS_X 0x08
#define DRAKORMISSILE_SETUP_POS_Y 0x0c
#define DRAKORMISSILE_SETUP_POS_Z 0x10
#define DRAKORMISSILE_SETUP_VEL_X 0x18
#define DRAKORMISSILE_SETUP_VEL_Y 0x19
#define DRAKORMISSILE_SETUP_VEL_Z 0x1a

#define DRAKORMISSILE_ACTIVE_TIMER 0x960
#define DRAKORMISSILE_CLEAR_TIMER 0x80
#define DRAKORMISSILE_TRACE_MISS_TIMER 0x258
#define DRAKORMISSILE_IGNORE_OBJECT_TYPE 0x2ab
#define DRAKORMISSILE_TARGET_MASK 4
#define DRAKORMISSILE_HIT_VOLUME_SLOT 22
#define DRAKORMISSILE_ACTIVE_SFX_A 965
#define DRAKORMISSILE_ACTIVE_SFX_B 966

int drakormissile_getExtraSize(void) { return DRAKORMISSILE_EXTRA_SIZE; }

int drakormissile_getObjectTypeId(void) { return DRAKORMISSILE_OBJECT_TYPE_ID; }

void drakormissile_hitDetect(void)
{
}

void drakormissile_initialise(void)
{
}

void drakormissile_release(void)
{
}

#pragma opt_common_subs off
void drakormissile_startActiveLaunch(int obj)
{
    void* light;
    DrakorMissileState* s = ((GameObject*)obj)->extra;

    ObjHits_EnableObject(obj);
    s->state = DRAKORMISSILE_STATE_HOMING;
    ((GameObject*)obj)->anim.rotZ = 0;
    light = objCreateLight(obj, 1);
    if (light != NULL)
    {
        modelLightStruct_setLightKind(light, MODEL_LIGHT_KIND_POINT);
        modelLightStruct_setDiffuseColor(light, 255, 128, 0, 0);
        lightSetFieldBC_8001db14(light, 1);
        modelLightStruct_setDistanceAttenuation(light, lbl_803E6940, lbl_803E6944);
        modelLightStruct_setupGlow(light, 0, 0, 255, 255, 128, lbl_803E6948);
        modelLightStruct_setGlowProjectionRadius(light, lbl_803E694C);
    }
    s->light = light;
    if (s->light != NULL)
    {
        modelLightStruct_setDistanceAttenuation(s->light, lbl_803E6950,
                                                lbl_803E6954);
    }
    ((GameObject*)obj)->anim.alpha = 255;
    ((GameObject*)obj)->anim.rootMotionScale =
        lbl_803E6958 * ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
    s->timer = DRAKORMISSILE_ACTIVE_TIMER;
    ObjHits_SetTargetMask(obj, DRAKORMISSILE_TARGET_MASK);
    ObjHits_SetHitVolumeSlot(obj, DRAKORMISSILE_HIT_VOLUME_SLOT, 1, 0);
    Sfx_PlayFromObject(obj, DRAKORMISSILE_ACTIVE_SFX_A);
    Sfx_PlayFromObject(obj, DRAKORMISSILE_ACTIVE_SFX_B);
}
#pragma opt_common_subs reset

#pragma fp_contract off
#pragma opt_common_subs off
void drakormissile_func0B(int obj, int from, int target, f32 speed)
{
    void* light;
    f32 dir[3];
    f32 hitDir[3];
    f32 endPos[3];
    s16 startGrid[3];
    s16 endGrid[3];
    s16 hitGrid[3];
    f32 mag;
    f32 horizDist;
    DrakorMissileState* s = ((GameObject*)obj)->extra;

    dir[0] = ((GameObject*)target)->anim.localPosX - ((GameObject*)from)->anim.localPosX;
    dir[1] = ((GameObject*)target)->anim.localPosY - ((GameObject*)from)->anim.localPosY;
    dir[2] = ((GameObject*)target)->anim.localPosZ - ((GameObject*)from)->anim.localPosZ;
    mag = sqrtf(dir[0] * dir[0] + dir[1] * dir[1] + dir[2] * dir[2]) / speed;
    if (mag != lbl_803E695C)
    {
        *(f32*)&dir[0] = dir[0] / mag;
        *(f32*)&dir[1] = dir[1] / mag;
        *(f32*)&dir[2] = dir[2] / mag;
    }
    ((GameObject*)obj)->anim.localPosX = ((GameObject*)from)->anim.localPosX;
    ((GameObject*)obj)->anim.localPosY = ((GameObject*)from)->anim.localPosY;
    ((GameObject*)obj)->anim.localPosZ = ((GameObject*)from)->anim.localPosZ;
    ((GameObject*)obj)->anim.velocityX = dir[0];
    ((GameObject*)obj)->anim.velocityY = dir[1];
    ((GameObject*)obj)->anim.velocityZ = dir[2];
    horizDist = sqrtf(((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX +
        ((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ);
    ((GameObject*)obj)->anim.rotX = (s16)getAngle(((GameObject*)obj)->anim.velocityX, ((GameObject*)obj)->anim.velocityZ);
    ((GameObject*)obj)->anim.rotY = -getAngle(((GameObject*)obj)->anim.velocityY, horizDist);
    ((GameObject*)obj)->anim.rotZ = 0;
    ObjHits_EnableObject(obj);
    s->state = DRAKORMISSILE_STATE_STRAIGHT;
    endPos[0] = lbl_803E6960 * ((GameObject*)obj)->anim.velocityX;
    endPos[1] = lbl_803E6960 * ((GameObject*)obj)->anim.velocityY;
    endPos[2] = lbl_803E6960 * ((GameObject*)obj)->anim.velocityZ;
    endPos[0] = ((GameObject*)obj)->anim.localPosX + endPos[0];
    endPos[1] = ((GameObject*)obj)->anim.localPosY + endPos[1];
    endPos[2] = ((GameObject*)obj)->anim.localPosZ + endPos[2];
    voxmaps_worldToGrid((f32*)((char*)obj + 0xc), startGrid);
    voxmaps_worldToGrid(endPos, endGrid);
    if (voxmaps_traceLine(startGrid, endGrid, hitGrid, 0, 0) == 0)
    {
        voxmaps_gridToWorld(endPos, hitGrid);
        *(f32*)&hitDir[0] = endPos[0] - ((GameObject*)obj)->anim.localPosX;
        *(f32*)&hitDir[1] = endPos[1] - ((GameObject*)obj)->anim.localPosY;
        *(f32*)&hitDir[2] = endPos[2] - ((GameObject*)obj)->anim.localPosZ;
        s->timer =
            (int)(sqrtf(hitDir[0] * hitDir[0] + hitDir[1] * hitDir[1] + hitDir[2] * hitDir[2]) / speed);
    }
    else
    {
        s->timer = DRAKORMISSILE_TRACE_MISS_TIMER;
    }
    if (s->light != NULL)
    {
        ModelLightStruct_free(s->light);
        s->light = NULL;
    }
    light = objCreateLight(obj, 1);
    if (light != NULL)
    {
        modelLightStruct_setLightKind(light, MODEL_LIGHT_KIND_POINT);
        modelLightStruct_setDiffuseColor(light, 0, 255, 255, 0);
        lightSetFieldBC_8001db14(light, 1);
        modelLightStruct_setDistanceAttenuation(light, lbl_803E6940, lbl_803E6944);
        modelLightStruct_setupGlow(light, 0, 0, 255, 255, 128, lbl_803E6948);
        modelLightStruct_setGlowProjectionRadius(light, lbl_803E694C);
    }
    s->light = light;
    ((GameObject*)obj)->anim.alpha = 255;
    ((GameObject*)obj)->anim.rootMotionScale =
        lbl_803E6958 * ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
    Sfx_PlayFromObject(obj, SFXwp_barrel_bounce2);
}
#pragma fp_contract reset
#pragma opt_common_subs reset

void drakormissile_update(int obj)
{
    DrakorMissileState* s = ((GameObject*)obj)->extra;
    int moving;
    f32 toTarget[3];
    f32 dir[3];
    int hitObj;
    int hit;
    int* lastHit;
    int result;
    int player;
    f32 mag;
    int expired;
    int nearHit;
    int rem;
    extern int modelLightStruct_getActiveState(void *light);

    moving = 0;
    switch (s->state)
    {
    case DRAKORMISSILE_STATE_STRAIGHT:
        moving = 1;
        objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta,
                ((GameObject*)obj)->anim.velocityY * timeDelta,
                ((GameObject*)obj)->anim.velocityZ * timeDelta);
        break;
    case DRAKORMISSILE_STATE_EXPLODING:
        ((GameObject*)obj)->anim.alpha = 0;
        if (s->timer == 0)
        {
            ObjHits_DisableObject(obj);
        }
        s->timer += framesThisStep;
        if (s->timer > DRAKORMISSILE_CLEAR_TIMER)
        {
            ObjHits_DisableObject(obj);
            Sfx_StopFromObject(obj, SFXwp_barrel_bounce2);
            Sfx_StopFromObject(obj, DRAKORMISSILE_ACTIVE_SFX_A);
            s->state = DRAKORMISSILE_STATE_FADEOUT;
        }
        break;
    case DRAKORMISSILE_STATE_HOMING:
        player = (int)Obj_GetPlayerObject();
        if (((GameObject*)player)->anim.velocityX != (mag = lbl_803E695C) || ((GameObject*)player)->anim.velocityY !=
            mag ||
            ((GameObject*)player)->anim.velocityZ != mag)
        {
            mag = PSVECMag((f32*)(player + 0x24));
        }
        mag = lbl_803DC2B8 + mag;
        Obj_PredictInterceptPoint(player, mag, &((GameObject*)obj)->anim.localPosX, toTarget);
        PSVECSubtract(toTarget, (f32*)(obj + 0xc), dir);
        PSVECNormalize(dir, dir);
        PSVECScale(dir, dir, mag * lbl_803DC2B4);
        PSVECScale((f32*)((char*)obj + 0x24), (f32*)((char*)obj + 0x24), lbl_803DC2B0);
        PSVECAdd((f32*)(obj + 0x24), dir, (f32*)(obj + 0x24));
        mag = sqrtf(((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX +
            ((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ);
        {
            int tmpAng = getAngle(((GameObject*)obj)->anim.velocityX, ((GameObject*)obj)->anim.velocityZ);
            ((GameObject*)obj)->anim.rotX = tmpAng;
            tmpAng = getAngle(((GameObject*)obj)->anim.velocityY, mag);
            ((GameObject*)obj)->anim.rotY = tmpAng;
        }
        objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta,
                ((GameObject*)obj)->anim.velocityY * timeDelta,
                ((GameObject*)obj)->anim.velocityZ * timeDelta);
        moving = 1;
        break;
    case DRAKORMISSILE_STATE_FADEOUT:
        {
            f32 life = s->fadeTime + timeDelta;
            s->fadeTime = life;
            if (life > gDrakorMissileFadeOutDuration)
            {
                Obj_FreeObject(obj);
                return;
            }
            break;
        }
    case DRAKORMISSILE_STATE_IDLE:
        break;
    }
    if (moving)
    {
        lastHit = (int*)((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->lastHitObject;
        hitObj = 0;
        hit = ObjHits_GetPriorityHit(obj, &hitObj, 0, 0);
        expired = 0;
        rem = s->timer - framesThisStep;
        s->timer = rem;
        if (rem < 0 || hit != 0)
        {
            expired = 1;
        }
        nearHit = 0;
        if (lastHit != NULL && ((GameObject*)lastHit)->anim.seqId != DRAKORMISSILE_IGNORE_OBJECT_TYPE)
        {
            nearHit = 1;
        }
        result = expired | nearHit;
        result |= ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->contactFlags;
        if (s->state == DRAKORMISSILE_STATE_HOMING)
        {
            player = (int)Obj_GetPlayerObject();
            if (Vec_distance(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX) <
                gDrakorMissileProximityDetonateDist)
            {
                result |= 1;
            }
        }
        if ((void*)hitObj != NULL && ((GameObject*)hitObj)->anim.seqId == DRAKORMISSILE_IGNORE_OBJECT_TYPE)
        {
            result = 0;
        }
        if (result != 0)
        {
            s->state = DRAKORMISSILE_STATE_EXPLODING;
            s->timer = 0;
            if ((((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->flags & 8) != 0)
            {
                Sfx_PlayFromObject(obj, SFXwp_barrel_bounce1);
            }
            if (((GameObject*)obj)->anim.mapEventSlot == 2)
            {
                spawnExplosion(obj, lbl_803E6940, 3, 0, 0, 0, 0, 0, 3);
            }
            else
            {
                spawnExplosion(obj, lbl_803E6940, 1, 0, 0, 0, 0, 0, 3);
            }
            if (s->light != NULL)
            {
                ModelLightStruct_free(s->light);
                s->light = NULL;
            }
        }
        ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->skeletonHitMask = 0x10;
        ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->objectHitMask = 0x10;
    }
    if (s->light != NULL && modelLightStruct_getActiveState(s->light))
    {
        modelLightStruct_updateGlowAlpha(s->light);
    }
}

int drakormissile_setScale(int obj)
{
    DrakorMissileState* s = ((GameObject*)obj)->extra;
    return s->state == DRAKORMISSILE_STATE_FADEOUT;
}

void drakormissile_render2(int obj)
{
    DrakorMissileState* s = ((GameObject*)obj)->extra;
    if (s->state == DRAKORMISSILE_STATE_STRAIGHT)
    {
        s->state = DRAKORMISSILE_STATE_EXPLODING;
    }
}

void drakormissile_modelMtxFn(int obj)
{
    DrakorMissileState* s = ((GameObject*)obj)->extra;
    s->flags |= 1;
    if (s->state == DRAKORMISSILE_STATE_FADEOUT)
    {
        Obj_FreeObject(obj);
    }
}

void drakormissile_free(int obj)
{
    DrakorMissileState* s = ((GameObject*)obj)->extra;
    void* light = s->light;
    if (light != NULL)
    {
        ModelLightStruct_free(light);
        s->light = NULL;
    }
    ObjGroup_RemoveObject(obj, DRAKORMISSILE_GROUP_ID);
}

void drakormissile_render(void* obj, u32 p2, u32 p3, u32 p4, u32 p5, s8 visible)
{
    s16 savedRotZ;
    s16 savedRotY;
    int i;
    DrakorMissileState* s = ((GameObject*)obj)->extra;
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    extern int modelLightStruct_getActiveState(void *light);
    if (visible != 0 && s->state != DRAKORMISSILE_STATE_FADEOUT)
    {
        f32 savedScale;
        int* model;
        char* m;
        savedRotZ = ((GameObject*)obj)->anim.rotZ;
        savedRotY = ((GameObject*)obj)->anim.rotY;
        savedScale = ((GameObject*)obj)->anim.rootMotionScale;
        objAnim->bankIndex = 1;
        model = Obj_GetActiveModel();
        i = 0;
        for (; i < DRAKORMISSILE_RENDER_TRAIL_COUNT; i++)
        {
            s->trailYaw[i] += s->trailYawStep[i];
            s->trailPitch[i] += s->trailPitchStep[i];
            ((GameObject*)obj)->anim.rotZ = s->trailYaw[i];
            ((GameObject*)obj)->anim.rotY = s->trailPitch[i];
            *(u16*)((char*)model + 0x18) &= ~8;
            objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, (double)lbl_803E6964);
        }
        ((GameObject*)obj)->anim.rotZ = savedRotZ;
        ((GameObject*)obj)->anim.rotY = savedRotY;
        ((GameObject*)obj)->anim.rootMotionScale = savedScale;
        objAnim->bankIndex = 0;
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, (double)lbl_803E6964);
        if (s->light != NULL && modelLightStruct_getActiveState(s->light) != 0)
        {
            queueGlowRender(s->light);
        }
    }
}

void drakormissile_init(int obj, char* arg)
{
    DrakorMissileState* s = ((GameObject*)obj)->extra;
    int i;
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumePriority = 0x13;
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumeId = 1;
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->flags &= ~1;
    ((GameObject*)obj)->anim.localPosX = *(f32*)(arg + DRAKORMISSILE_SETUP_POS_X);
    ((GameObject*)obj)->anim.localPosY = *(f32*)(arg + DRAKORMISSILE_SETUP_POS_Y);
    ((GameObject*)obj)->anim.localPosZ = *(f32*)(arg + DRAKORMISSILE_SETUP_POS_Z);
    ((GameObject*)obj)->anim.velocityX = (f32)(u32)(u8)arg[DRAKORMISSILE_SETUP_VEL_X];
    ((GameObject*)obj)->anim.velocityY = (f32)(u32)(u8)arg[DRAKORMISSILE_SETUP_VEL_Y];
    ((GameObject*)obj)->anim.velocityZ = (f32)(u32)(u8)arg[DRAKORMISSILE_SETUP_VEL_Z];
    if (((GameObject*)obj)->anim.hitReactState != NULL)
    {
        ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->trackContactMask = 1;
    }
    ObjGroup_AddObject(obj, DRAKORMISSILE_GROUP_ID);
    s->state = DRAKORMISSILE_STATE_IDLE;
    s->flags = 0;
    s->timer = 0;
    *(int*)&s->light = 0;
    s->fadeTime = lbl_803E695C;
    for (i = 0; i < DRAKORMISSILE_RENDER_TRAIL_COUNT; i++)
    {
        s->trailYaw[i] = randomGetRange(-0x7fff, 0x7fff);
        s->trailYawStep[i] = randomGetRange(-0x400, 0x400);
        s->trailPitch[i] = randomGetRange(-0x7fff, 0x7fff);
        s->trailPitchStep[i] = randomGetRange(-0x400, 0x400);
    }
}
