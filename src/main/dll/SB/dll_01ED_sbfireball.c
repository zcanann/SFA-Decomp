/*
 * sbfireball (DLL 0x1ED) - the fire projectile used by the ShipBattle
 * (SB) boss set. A fireball is spawned with an owner (taken from the
 * spawning object's slot), drifts along the velocity captured on its
 * first armed frame, spins, trails particles, and arms a solid hitbox
 * after a short delay. It expires when its life timer runs out, and on
 * a hit bursts a cloud of impact particles before being freed.
 */
#include "main/dll_000A_expgfx.h"
#include "main/dll/shipbattlestate_struct.h"
#include "main/dll/sbfireballstate_struct.h"
#include "main/dll/TREX/TREX_levelcontrol.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/TREX/TREX_trex.h"
#include "main/effect_interfaces.h"
#include "main/objhits_types.h"

extern u8 framesThisStep;
extern EffectInterface** gPartfxInterface;

extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E58D8; /* fireball render scale */
extern f32 timeDelta;

STATIC_ASSERT(sizeof(SBFireBallState) == 0x18);

extern f32 lbl_803E58DC; /* particle arg (particleArgs[2]) */
extern f32 lbl_803E58E0; /* trail-burst scale */

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
        objRenderFn_8003b8f4(lbl_803E58D8);
    }
}

void SB_FireBall_hitDetect(int* obj)
{
    ObjHitsPriorityState* hits = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
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

/* unused dispatcher stub kept to align the v1.0 function set */
void FUN_801e55c0(u64 param_1, double param_2, double param_3, u64 param_4, u64 param_5,
                  u64 param_6, u64 param_7, u64 param_8, u16* param_9, int param_10)
{
}

void SB_FireBall_release(void)
{
}

void SB_FireBall_initialise(void)
{
}

void SB_FireBall_init(int p)
{
    SBFireBallState* state = ((GameObject*)p)->extra;
    ((GameObject*)p)->unkF4 = SB_FIREBALL_LIFETIME;
    state->launched = 0;
}

void SB_FireBall_update(int obj)
{
    extern void Obj_FreeObject(int obj);
    extern void objfx_spawnFlaggedTrailBurst(int* obj, f32 f, int a, int b, int c, void* d);
    SBFireBallState* state;
    f32 particleArgs[7];

    state = ((GameObject*)obj)->extra;
    if (state->owner == NULL)
    {
        state->owner = *(void**)&((GameObject*)obj)->unkF8;
    }

    if (state->owner != NULL)
    {
        *(s16*)obj = 0;
        ((GameObject*)obj)->anim.rotZ = (s16)(((GameObject*)obj)->anim.rotZ + framesThisStep * SB_FIREBALL_SPIN_STEP);
        ((GameObject*)obj)->unkF4 -= framesThisStep;
        if (((GameObject*)obj)->unkF4 < 0)
        {
            Obj_FreeObject(obj);
            return;
        }

        if (*(s8*)&state->launched == 0)
        {
            state->velX = ((GameObject*)obj)->anim.velocityX;
            state->velY = ((GameObject*)obj)->anim.velocityY;
            state->velZ = ((GameObject*)obj)->anim.velocityZ;
            state->launched = 1;
        }

        ((GameObject*)obj)->anim.localPosX += state->velX * timeDelta;
        ((GameObject*)obj)->anim.localPosY += state->velY * timeDelta;
        ((GameObject*)obj)->anim.localPosZ += state->velZ * timeDelta;

        particleArgs[2] = lbl_803E58DC;
        objfx_spawnFlaggedTrailBurst((int*)obj, lbl_803E58E0, SB_FIREBALL_SETUP_SIZE,
                                     SB_FIREBALL_SETUP_MODEL_ID, SB_FIREBALL_SETUP_PARAM, NULL);
        (*gPartfxInterface)->spawnObject((void*)obj, SB_FIREBALL_TRAIL_PARTICLE_ID, particleArgs, 1, -1, NULL);

        if (state->age > SB_FIREBALL_HITBOX_ENABLE_DELAY)
        {
            ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumePriority =
                SB_FIREBALL_HITBOX_TYPE;
            ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumeId =
                SB_FIREBALL_HITBOX_PRIORITY;
            ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->objectHitMask =
                SB_FIREBALL_HITBOX_SIZE;
            ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->skeletonHitMask =
                SB_FIREBALL_HITBOX_SIZE;
            ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->flags |=
                SB_FIREBALL_SOLID_HITBOX_FLAG;
        }
        else
        {
            ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->flags &=
                ~SB_FIREBALL_SOLID_HITBOX_FLAG;
        }

        state->age += framesThisStep;
    }
}
