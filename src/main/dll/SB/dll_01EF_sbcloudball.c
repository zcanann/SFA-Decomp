/*
 * sbcloudball (DLL 0x1EF) - the cloud-ball projectile fired during the
 * ShipBattle (SB) set. On launch it captures its initial velocity, then
 * drifts on that velocity each tick (scaled), faces its travel direction,
 * and arms a contact hitbox. On a hit against the target type, or once it
 * outlives its lifetime / the player clears the wave, it plays a burst
 * effect, fades out (fadeTimer) and frees itself. A trailing particle
 * burst is spawned every frame while alive.
 *
 * This unit also carries the shared SB ObjectDescriptor function set
 * (FireBall / KyteCage / SeqDoor / ShipBattle stubs) so every v1.0 asm
 * symbol has a source definition.
 */
#include "main/dll/partfx_interface.h"
#include "main/dll/shipbattlestate_struct.h"
#include "main/object_render_legacy.h"
#include "main/dll/sbkytecagestate_struct.h"
#include "main/dll/sbfireballstate_struct.h"
#include "main/dll/sbcloudballstate_struct.h"

#include "main/game_object.h"
#include "main/object.h"
#include "main/model_light.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_play_pointer_legacy_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll_000A_expgfx.h"
#include "main/frame_timing.h"
#include "main/object_api.h"
#include "main/objfx.h"
#include "main/vecmath.h"
#include "main/object_descriptor.h"

#define SBCLOUDBALL_OBJFLAG_PARENT_SLACK 0x1000
#define SBCLOUDBALL_PARTFX               0xa8

typedef void (*SBCloudBallTrailBurstFn)(int* obj, f32 scale, int mode, int effectId, int origin, void* velocity);

/*
 * Per-object extra state for the ShipBattle cloud-ball projectile
 * (SB_CloudBall_getExtraSize == 0x24).
 */

STATIC_ASSERT(sizeof(SBCloudBallState) == 0x24);

/*
 * Per-object extra state for the ShipBattle fireball projectile
 * (SB_FireBall_getExtraSize == SB_FIREBALL_EXTRA_SIZE == 0x18).
 */

STATIC_ASSERT(sizeof(SBFireBallState) == 0x18);

/*
 * Per-object extra state for the ShipBattle kyte cage
 * (SB_KyteCage_getExtraSize == 0x8).
 */

STATIC_ASSERT(sizeof(SBKyteCageState) == 0x8);

/*
 * Per-object extra state for the ShipBattle chain segment
 * (ShipBattle_getExtraSize == 0x140). The head is handed to
 * gObjectTriggerInterface (+0x1C/+0x24) - interface-owned record;
 * only the locally-evidenced fields are named.
 */

STATIC_ASSERT(sizeof(ShipBattleState) == 0x140);

/* romlist type id the cloud ball reacts to on contact (plays the shatter sfx) */
#define CLOUDBALL_TARGET_TYPE_ID 142

#define SB_CLOUD_BALL_FADE_TIME 50.0f
#define SB_CLOUD_BALL_VELOCITY_SCALE 2.0f
#define SB_CLOUD_BALL_TRAIL_VEL_SCALE 0.1f
#define SB_CLOUD_BALL_TRAIL_PARTICLE_SCALE 0.22f
extern f32 gSbCloudBallLightAttenNear;
extern f32 gSbCloudBallLightAttenFar;
extern void objfx_spawnFlaggedTrailBurst(void* obj, u8 mode, int effectParam, int f4, int origin, f32 scale);

int SB_CloudBall_getExtraSize(void)
{
    return 0x24;
}
int SB_CloudBall_getObjectTypeId(void)
{
    return 0x0;
}

void SB_CloudBall_free(GameObject* obj)
{
    SBCloudBallState* state = obj->extra;
    (*gExpgfxInterface)->freeSource2((u32)obj);
    {
        int* child = (int*)state->light;
        if (child != NULL)
        {
            ModelLightStruct_free((ModelLightStruct*)child);
            state->light = 0;
        }
    }
}

void SB_CloudBall_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 lbl_803E58EC = 0.0f;
#pragma explicit_zero_data off

void SB_CloudBall_hitDetect(GameObject* obj)
{
    SBCloudBallState* state = obj->extra;
    int* target = (int*)ObjAnim_GetPriorityHitState(&obj->anim)->lastHitObject;

    if ((void*)target == NULL)
        return;
    if (state->fadeTimer != lbl_803E58EC)
        return;
    if (((GameObject*)target)->anim.seqId == CLOUDBALL_TARGET_TYPE_ID)
    {
        Sfx_PlayFromObject((int*)obj, SFXTRIG_wp_gcfir1_c);
    }
    {
        ObjHitsPriorityState* hits = ObjAnim_GetPriorityHitState(&obj->anim);
        hits->flags = (s16)(hits->flags & ~1);
    }
    state->fadeTimer = SB_CLOUD_BALL_FADE_TIME;
    obj->anim.alpha = 0;
    projectileParticleFxFn_80099660Legacy((int*)obj, 1.0f, 2);
}

void SB_CloudBall_update(GameObject* obj)
{
    SBCloudBallState* state = obj->extra;
    void* player = Obj_GetPlayerObject();
    f32 timer = state->fadeTimer;
    f32 zero = lbl_803E58EC;
    if (timer != zero)
    {
        state->fadeTimer = timer - timeDelta;
        if (state->fadeTimer <= zero)
        {
            state->fadeTimer = zero;
            Obj_FreeObject((GameObject*)obj);
        }
    }
    else
    {
        f32 particleVelocity[3];
        f32 velocityScale;
        obj->anim.previousLocalPosX = obj->anim.localPosX;
        obj->anim.previousLocalPosY = obj->anim.localPosY;
        obj->anim.previousLocalPosZ = obj->anim.localPosZ;
        obj->anim.rootMotionScale = 0.005f * (f32)(int)randomGetRange(-0x64, 0x64) + 3.0f;
        if (*(s8*)&state->launched == 0)
        {
            state->velX = obj->anim.velocityX;
            state->velY = obj->anim.velocityY;
            state->velZ = obj->anim.velocityZ;
            state->launched = 1;
            state->posX = obj->anim.localPosX;
            state->posY = obj->anim.localPosY;
            state->posZ = obj->anim.localPosZ;
        }
        velocityScale = SB_CLOUD_BALL_VELOCITY_SCALE;
        state->posX = velocityScale * (state->velX * timeDelta) + state->posX;
        state->posY = velocityScale * (state->velY * timeDelta) + state->posY;
        state->posZ = velocityScale * (state->velZ * timeDelta) + state->posZ;
        obj->anim.localPosX = state->posX;
        obj->anim.localPosY = state->posY;
        obj->anim.localPosZ = state->posZ;
        obj->unkF4 = obj->unkF4 - framesThisStep;
        if (obj->unkF4 < 0 ||
            (player != NULL && (((GameObject*)player)->objectFlags & SBCLOUDBALL_OBJFLAG_PARENT_SLACK) != 0))
        {
            if (state->fadeTimer == lbl_803E58EC)
            {
                obj->anim.alpha = 0;
                state->fadeTimer = SB_CLOUD_BALL_FADE_TIME;
            }
        }
        obj->anim.rotX = (s16)getAngle(obj->anim.localPosX - obj->anim.previousLocalPosX,
                                       obj->anim.localPosZ - obj->anim.previousLocalPosZ);
        ObjAnim_GetPriorityHitState(&obj->anim)->hitVolumePriority = 5;
        ObjAnim_GetPriorityHitState(&obj->anim)->hitVolumeId = 1;
        ObjAnim_GetPriorityHitState(&obj->anim)->objectHitMask = 0x10;
        ObjAnim_GetPriorityHitState(&obj->anim)->skeletonHitMask = 0x10;
        ObjAnim_GetPriorityHitState(&obj->anim)->flags |= 1;
        if (ObjAnim_GetPriorityHitState(&obj->anim)->contactFlags != 0 && state->fadeTimer == lbl_803E58EC)
        {
            projectileParticleFxFn_80099660Legacy((int*)obj, 1.0f, 2);
            state->fadeTimer = SB_CLOUD_BALL_FADE_TIME;
            obj->anim.alpha = 0;
        }
        particleVelocity[0] = SB_CLOUD_BALL_TRAIL_VEL_SCALE * -state->velX;
        particleVelocity[1] = SB_CLOUD_BALL_TRAIL_VEL_SCALE * -state->velY;
        particleVelocity[2] = SB_CLOUD_BALL_TRAIL_VEL_SCALE * -state->velZ;
        ((SBCloudBallTrailBurstFn)objfx_spawnFlaggedTrailBurst)((int*)obj, SB_CLOUD_BALL_TRAIL_PARTICLE_SCALE, 2, 0x156,
                                                                0xf, particleVelocity);
        ((SBCloudBallTrailBurstFn)objfx_spawnFlaggedTrailBurst)((int*)obj, SB_CLOUD_BALL_TRAIL_PARTICLE_SCALE, 2, 0x156,
                                                                0xf, particleVelocity);
        ((SBCloudBallTrailBurstFn)objfx_spawnFlaggedTrailBurst)((int*)obj, SB_CLOUD_BALL_TRAIL_PARTICLE_SCALE, 2, 0x156,
                                                                0xf, particleVelocity);
        (*gPartfxInterface)->spawnObject((void*)obj, SBCLOUDBALL_PARTFX, NULL, 2, -1, NULL);
    }
}

void SB_CloudBall_init(GameObject* obj)
{
    SBCloudBallState* state = obj->extra;

    ObjAnim_GetPriorityHitState(&obj->anim)->flags = (s16)(ObjAnim_GetPriorityHitState(&obj->anim)->flags & ~1);
    ObjAnim_GetPriorityHitState(&obj->anim)->trackContactMask =
        (u16)(ObjAnim_GetPriorityHitState(&obj->anim)->trackContactMask | 1);
    if ((void*)state->light == NULL)
    {
        state->light = (int)objCreateLight(obj, 1);
        if ((void*)state->light != NULL)
        {
            modelLightStruct_setLightKind((ModelLightStruct*)state->light, MODEL_LIGHT_KIND_POINT);
            modelLightStruct_setDiffuseColor((ModelLightStruct*)state->light, 0, 90, 150, 0);
            lightSetFieldBC_8001db14((ModelLightStruct*)state->light, 1);
            modelLightStruct_setDistanceAttenuation((ModelLightStruct*)state->light, gSbCloudBallLightAttenNear,
                                                    gSbCloudBallLightAttenFar);
        }
    }
}

void SB_CloudBall_release(void)
{
}

void SB_CloudBall_initialise(void)
{
}

ObjectDescriptor gSB_CloudBallObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)SB_CloudBall_initialise,
    (ObjectDescriptorCallback)SB_CloudBall_release,
    0,
    (ObjectDescriptorCallback)SB_CloudBall_init,
    (ObjectDescriptorCallback)SB_CloudBall_update,
    (ObjectDescriptorCallback)SB_CloudBall_hitDetect,
    (ObjectDescriptorCallback)SB_CloudBall_render,
    (ObjectDescriptorCallback)SB_CloudBall_free,
    (ObjectDescriptorCallback)SB_CloudBall_getObjectTypeId,
    SB_CloudBall_getExtraSize,
};
