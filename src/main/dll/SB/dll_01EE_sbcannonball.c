/*
 * SB_CannonBall (DLL 0x01EE) - the cannonball fired by the galleon's deck
 * guns (SB_ShipGun) at the player's Cloudrunner in the ShipBattle prologue
 * (SB = the retail "ShipBattle" map). It launches with an initial particle
 * burst, then each frame integrates its own ballistic trajectory (stored in
 * state), trails smoke particles, and carries a point light. On impact it
 * plays a hit sfx, spawns smoke/spark bursts, and arms a cooldown before
 * freeing itself. TU: 0x801E341C-0x801E34C0.
 */
#include "main/game_object.h"
#include "main/dll/sbshipheadstate_struct.h"
#include "main/dll/sbpropellerstate_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/TREX/TREX_levelcontrol.h"

STATIC_ASSERT(sizeof(SBPropellerState) == 0x10);

STATIC_ASSERT(sizeof(SBShipHeadState) == 0x10);

extern f32 timeDelta;
extern u8 framesThisStep;
extern void objRenderFn_8003b8f4(int obj, int p2, int p3, int p4, int p5, f32 scale);

typedef struct SBCannonBallState
{
    f32 velocityX;
    f32 velocityY;
    f32 velocityZ;
    f32 posX;
    f32 posY;
    f32 posZ;
    s16 lifetimeFrames;
    s8 flags;
    u8 pad1B[0x1C - 0x1B];
    f32 impactCooldown;
    void* modelLight;
    u8 pad24[0x28 - 0x24];
} SBCannonBallState;

extern void ModelLightStruct_free(void* effect);
extern f32 lbl_803E58B0;
extern f32 lbl_803E58BC;
extern f64 lbl_803E58C0;
extern void Obj_FreeObject(int* obj);
extern void objfx_spawnFlaggedTrailBurst(int* obj, f32 f, int a, int b, int c, int d);
extern f32 lbl_803E58B4;
extern f32 lbl_803E58B8;
extern u8* objCreateLight(int* obj, int v);
extern void modelLightStruct_setLightKind(u8* p, int v);
extern void modelLightStruct_setDiffuseColor(u8* p, int a, int b, int c, int d);
extern void lightSetFieldBC_8001db14(u8* p, int v);
extern void modelLightStruct_setDistanceAttenuation(u8* obj, f32 a, f32 b);
extern f32 lbl_803E58C8;
extern f32 lbl_803E58CC;
extern f32 lbl_803E58D0;

void SB_CannonBall_release(void)
{
}

void SB_CannonBall_initialise(void)
{
}


int SB_CannonBall_getExtraSize(void) { return SB_CANNONBALL_EXTRA_SIZE; }
int SB_CannonBall_getObjectTypeId(void) { return 0x0; }

void SB_CannonBall_free(GameObject* obj)
{
    SBCannonBallState* state = obj->extra;
    (*gExpgfxInterface)->freeSource2((u32)obj);
    if (state->modelLight != NULL)
    {
        ModelLightStruct_free(state->modelLight);
        state->modelLight = NULL;
    }
}


void SB_CannonBall_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E58B0);
}


void SB_CannonBall_update(GameObject* obj)
{
    SBCannonBallState* state = obj->extra;
#define hitState ((ObjHitsPriorityState*)obj->anim.hitReactState)
    if ((state->flags & SB_CANNONBALL_INITIAL_BURST_FLAG) != 0)
    {
        (*gPartfxInterface)->spawnObject(obj, SB_CANNONBALL_BURST_PARTICLE_ID,
                                         NULL, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject(obj, SB_CANNONBALL_BURST_PARTICLE_ID,
                                         NULL, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject(obj, SB_CANNONBALL_BURST_PARTICLE_ID,
                                         NULL, 1, -1, NULL);
        state->flags = (s8)(
            state->flags & ~SB_CANNONBALL_INITIAL_BURST_FLAG);
    }
    else
    {
        objfx_spawnFlaggedTrailBurst((int*)obj, lbl_803E58BC, SB_CANNONBALL_SETUP_SIZE, SB_CANNONBALL_SETUP_MODEL_ID,
                                     SB_CANNONBALL_SETUP_PARAM, 0);
        objfx_spawnFlaggedTrailBurst((int*)obj, lbl_803E58BC, SB_CANNONBALL_SETUP_SIZE, SB_CANNONBALL_SETUP_MODEL_ID,
                                     SB_CANNONBALL_SETUP_PARAM, 0);
    }
    (*gPartfxInterface)->spawnObject(obj, SB_CANNONBALL_TRAIL_PARTICLE_ID,
                                     NULL, 1, -1, NULL);
    obj->anim.rotY += SB_CANNONBALL_ROTATION_STEP;
    if ((state->flags & SB_CANNONBALL_TRAJECTORY_INITIALIZED_FLAG) == 0)
    {
        state->velocityX = obj->anim.velocityX;
        state->velocityY = obj->anim.velocityY;
        state->velocityZ = obj->anim.velocityZ;
        state->flags = (s8)(
            state->flags | SB_CANNONBALL_TRAJECTORY_INITIALIZED_FLAG);
        state->posX = obj->anim.localPosX;
        state->posY = obj->anim.localPosY;
        state->posZ = obj->anim.localPosZ;
    }
    {
        f64 scale = lbl_803E58C0;
        state->posX = (f32)(
            scale * (f64)(state->velocityX * timeDelta) + state->posX);
        state->posY = (f32)(
            scale * (f64)(state->velocityY * timeDelta) + state->posY);
        state->posZ = (f32)(
            scale * (f64)(state->velocityZ * timeDelta) + state->posZ);
    }
    obj->anim.localPosX = state->posX;
    obj->anim.localPosY = state->posY;
    obj->anim.localPosZ = state->posZ;
    obj->unkF4 = obj->unkF4 - framesThisStep;
    if (obj->unkF4 < 0)
    {
        Obj_FreeObject((int*)obj);
    }
    if (state->lifetimeFrames > SB_CANNONBALL_HITBOX_ENABLE_DELAY)
    {
        hitState->hitVolumePriority = SB_CANNONBALL_HITBOX_TYPE;
        hitState->hitVolumeId = SB_CANNONBALL_HITBOX_PRIORITY;
        hitState->objectHitMask = SB_CANNONBALL_HITBOX_SIZE;
        hitState->skeletonHitMask = SB_CANNONBALL_HITBOX_SIZE;
        hitState->flags |= SB_CANNONBALL_SOLID_HITBOX_FLAG;
    }
    else
    {
        hitState->flags &= ~SB_CANNONBALL_SOLID_HITBOX_FLAG;
    }
    state->lifetimeFrames += framesThisStep;
#undef hitState
}

void SB_CannonBall_hitDetect(GameObject* obj)
{
    extern int Sfx_PlayFromObject();
    SBCannonBallState* state = obj->extra;
    f32 t = state->impactCooldown;
    f32 zero = lbl_803E58B4;

    if (t > zero)
    {
        state->impactCooldown = t - timeDelta;
        if (state->impactCooldown <= zero)
        {
            Obj_FreeObject((int*)obj);
        }
        return;
    }

    {
        ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
        int* target = *(int**)&hitState->lastHitObject;
        s16 type;
        if (target == NULL) return;
        type = ((GameObject*)target)->anim.seqId;
        if (type == SB_CLOUDBALL_ALIAS_OBJECT_TYPE) return;
        if (type == SB_CANNONBALL_ALIAS_OBJECT_TYPE) return;
    }

    if (zero != t) return;

    Sfx_PlayFromObject(obj, SB_CANNONBALL_IMPACT_SFX);
    {
        ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
        hitState->flags = (s16)(hitState->flags & ~SB_CANNONBALL_SOLID_HITBOX_FLAG);
    }
    state->impactCooldown = lbl_803E58B8;
    obj->anim.alpha = SB_CANNONBALL_IMPACT_VISUAL_TIMER;

    {
        int i;
        for (i = SB_CANNONBALL_SMOKE_PARTICLE_COUNT; i != 0; i--)
        {
            (*gPartfxInterface)->spawnObject(
                obj, SB_CANNONBALL_IMPACT_SMOKE_PARTICLE_ID, NULL, 1, -1, NULL);
        }
    }
    {
        int i;
        for (i = SB_CANNONBALL_SPARK_PARTICLE_COUNT; i != 0; i--)
        {
            (*gPartfxInterface)->spawnObject(
                obj, SB_CANNONBALL_IMPACT_SPARK_PARTICLE_ID, NULL, 1, -1, NULL);
        }
    }
}

void SB_CannonBall_init(GameObject* obj)
{
    extern int Sfx_PlayFromObject();
    SBCannonBallState* state = obj->extra;
    if (state->modelLight == NULL)
    {
        state->modelLight = objCreateLight((int*)obj, SB_CANNONBALL_LIGHT_KIND);
        if (state->modelLight != NULL)
        {
            modelLightStruct_setLightKind(state->modelLight, SB_CANNONBALL_LIGHT_FIELD50);
            modelLightStruct_setDiffuseColor(state->modelLight, SB_CANNONBALL_LIGHT_RED,
                                             SB_CANNONBALL_LIGHT_GREEN, SB_CANNONBALL_LIGHT_BLUE,
                                             SB_CANNONBALL_LIGHT_ALPHA);
            lightSetFieldBC_8001db14(state->modelLight, SB_CANNONBALL_LIGHT_FIELD_BC);
            modelLightStruct_setDistanceAttenuation(state->modelLight, lbl_803E58C8,
                                                    lbl_803E58CC);
        }
    }
    {
        ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
        hitState->flags = (s16)(hitState->flags & ~SB_CANNONBALL_SOLID_HITBOX_FLAG);
    }
    obj->anim.rootMotionScale = obj->anim.rootMotionScale * lbl_803E58D0;
    state->flags = (s8)(state->flags | SB_CANNONBALL_INITIAL_BURST_FLAG);
    Sfx_PlayFromObject(obj, SB_CANNONBALL_LAUNCH_SFX);
    Sfx_PlayFromObject(obj, SB_CANNONBALL_LOOP_SFX);
}
