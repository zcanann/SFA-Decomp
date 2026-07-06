/*
 * sbfireball (DLL 0x1ED) - the fire projectile used by the ShipBattle
 * (SB) boss set. A fireball is spawned with an owner (taken from the
 * spawning object's slot), drifts along the velocity captured on its
 * first armed frame, spins, trails particles, and arms a solid hitbox
 * after a short delay. It expires when its life timer runs out, and on
 * a hit bursts a cloud of impact particles before being freed.
 */
#include "main/dll_000A_expgfx.h"
#include "main/dll/sbfireballstate_struct.h"
#include "main/dll/TREX/TREX_levelcontrol.h"
#include "main/game_object.h"
#include "main/dll/TREX/TREX_trex.h"
#include "main/dll/VF/vf_shared.h"

STATIC_ASSERT(sizeof(SBFireBallState) == 0x18);

/* impact-burst particle ids spawned in SB_FireBall_hitDetect */
enum
{
    SB_FIREBALL_HIT_PARTICLE_A = 167,
    SB_FIREBALL_HIT_PARTICLE_B = 171
};

/* count of each impact-burst particle */
enum
{
    SB_FIREBALL_HIT_BURST_A = 50,
    SB_FIREBALL_HIT_BURST_B = 10
};

/* obj->unkF4 life timer set at init, decremented by framesThisStep */
#define SB_FIREBALL_LIFETIME 0x4b0

int SB_FireBall_getExtraSize(void) { return SB_FIREBALL_EXTRA_SIZE; }
int SB_FireBall_getObjectTypeId(void) { return 0x0; }

void SB_FireBall_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void SB_FireBall_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
    {
        objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, 1.0f);
    }
}

void SB_FireBall_hitDetect(int* obj)
{
    ObjHitsPriorityState* hits = ObjAnim_GetPriorityHitState(&((GameObject*)obj)->anim);
    int i;
    if (hits->lastHitObject == 0)
    {
        return;
    }
    hits->flags &= ~1;
    for (i = SB_FIREBALL_HIT_BURST_A; i != 0; i--)
    {
        (*gPartfxInterface)->spawnObject(obj, SB_FIREBALL_HIT_PARTICLE_A, NULL, 1, -1, NULL);
    }
    for (i = SB_FIREBALL_HIT_BURST_B; i != 0; i--)
    {
        (*gPartfxInterface)->spawnObject(obj, SB_FIREBALL_HIT_PARTICLE_B, NULL, 1, -1, NULL);
    }
}

void SB_FireBall_update(GameObject* obj)
{

    extern void objfx_spawnFlaggedTrailBurst(int* obj, f32 f, int a, int b, int c, void* d);
    SBFireBallState* state;
    f32 particleArgs[7];
#define hits (*(ObjHitsPriorityState**)((char*)obj + 0x54))

    state = obj->extra;
    if (state->owner == NULL)
    {
        state->owner = *(void**)&obj->unkF8;
    }

    if (state->owner != NULL)
    {
        obj->anim.rotX = 0;
        obj->anim.rotZ = (s16)(obj->anim.rotZ + framesThisStep * SB_FIREBALL_SPIN_STEP);
        obj->unkF4 -= framesThisStep;
        if (obj->unkF4 < 0)
        {
            Obj_FreeObject((int)obj);
            return;
        }

        if (*(s8*)&state->launched == 0)
        {
            state->velX = obj->anim.velocityX;
            state->velY = obj->anim.velocityY;
            state->velZ = obj->anim.velocityZ;
            state->launched = 1;
        }

        obj->anim.localPosX += state->velX * timeDelta;
        obj->anim.localPosY += state->velY * timeDelta;
        obj->anim.localPosZ += state->velZ * timeDelta;

        particleArgs[2] = 3.0f;
        objfx_spawnFlaggedTrailBurst((int*)obj, 0.8f, SB_FIREBALL_SETUP_SIZE,
                                     SB_FIREBALL_SETUP_MODEL_ID, SB_FIREBALL_SETUP_PARAM, NULL);
        (*gPartfxInterface)->spawnObject((void*)obj, SB_FIREBALL_TRAIL_PARTICLE_ID, particleArgs, 1, -1, NULL);

        if (state->age > SB_FIREBALL_HITBOX_ENABLE_DELAY)
        {
            ObjAnim_GetPriorityHitState(&obj->anim)->hitVolumePriority = SB_FIREBALL_HITBOX_TYPE;
            ObjAnim_GetPriorityHitState(&obj->anim)->hitVolumeId = SB_FIREBALL_HITBOX_PRIORITY;
            ObjAnim_GetPriorityHitState(&obj->anim)->objectHitMask = SB_FIREBALL_HITBOX_SIZE;
            ObjAnim_GetPriorityHitState(&obj->anim)->skeletonHitMask = SB_FIREBALL_HITBOX_SIZE;
            ObjAnim_GetPriorityHitState(&obj->anim)->flags |= SB_FIREBALL_SOLID_HITBOX_FLAG;
        }
        else
        {
            ObjAnim_GetPriorityHitState(&obj->anim)->flags &= ~SB_FIREBALL_SOLID_HITBOX_FLAG;
        }

        state->age += framesThisStep;
    }
#undef hits
}

void SB_FireBall_init(GameObject* obj)
{
    SBFireBallState* state = obj->extra;
    obj->unkF4 = SB_FIREBALL_LIFETIME;
    state->launched = 0;
}

void SB_FireBall_release(void)
{
}

void SB_FireBall_initialise(void)
{
}
