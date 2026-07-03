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
#include "main/dll/shipbattlestate_struct.h"
#include "main/dll/sbkytecagestate_struct.h"
#include "main/dll/sbfireballstate_struct.h"
#include "main/dll/sbcloudballstate_struct.h"

#define MODEL_LIGHT_KIND_POINT 2

extern int getAngle(float y, float x);
extern void objRenderFn_8003b8f4(f32);
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll_000A_expgfx.h"
#include "main/engine_shared.h"

#define SBCLOUDBALL_OBJFLAG_PARENT_SLACK 0x1000

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

extern f32 lbl_803E58E8;
extern f32 lbl_803E58EC;
extern f32 gSbCloudBallFadeTime;
extern void projectileParticleFxFn_80099660(int* obj, f32 scale, int type);
extern f32 gSbCloudBallLightAttenNear;
extern f32 gSbCloudBallLightAttenFar;
extern f32 lbl_803E58F4;
extern f32 lbl_803E58F8;
extern f32 gSbCloudBallVelocityScale;
extern f32 gSbCloudBallTrailVelScale;
extern f32 gSbCloudBallTrailParticleScale;


void SB_CloudBall_release(void)
{
}

void SB_CloudBall_initialise(void)
{
}


int SB_CloudBall_getExtraSize(void) { return 0x24; }
int SB_CloudBall_getObjectTypeId(void) { return 0x0; }
int SB_KyteCage_getExtraSize(void);

void SB_CloudBall_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E58E8);
}


/* Stubs added to align function set with v1.0 asm. Source had Ghidra FUN_xxx
 * splits at wrong addresses; these stubs ensure every asm symbol has a src
 * definition so future hunters can fill bodies one at a time. */

/* EN v1.0 0x801E4F14  size: 60b  Decrement obj->_f4 if > 0, OR in bit 0x8
 * of obj->_af, latch state->_6e = -2 and state->_56 = 0; return 0. */

void SB_CloudBall_free(GameObject* obj)
{
    extern void ModelLightStruct_free(int* p);
    SBCloudBallState* state = obj->extra;
    (*gExpgfxInterface)->freeSource2((u32)obj);
    {
        int* child = (int*)state->light;
        if (child != NULL)
        {
            ModelLightStruct_free(child);
            state->light = 0;
        }
    }
}

void SB_CloudBall_hitDetect(GameObject* obj)
{
    extern void Sfx_PlayFromObject(int* obj, int sfxId);
    SBCloudBallState* state = obj->extra;
    int* target = (int*)ObjAnim_GetPriorityHitState(&obj->anim)->lastHitObject;

    if ((void*)target == NULL) return;
    if (state->fadeTimer != lbl_803E58EC) return;
    if (((GameObject*)target)->anim.seqId == CLOUDBALL_TARGET_TYPE_ID)
    {
        Sfx_PlayFromObject((int*)obj, SFXen_rockshat16);
    }
    {
        ObjHitsPriorityState* hits = ObjAnim_GetPriorityHitState(&obj->anim);
        hits->flags = (s16)(hits->flags & ~1);
    }
    state->fadeTimer = gSbCloudBallFadeTime;
    obj->anim.alpha = 0;
    projectileParticleFxFn_80099660((int*)obj, lbl_803E58E8, 2);
}

void SB_CloudBall_init(GameObject* obj)
{
    extern void modelLightStruct_setDistanceAttenuation(int light, f32 a, f32 b);
    extern void lightSetFieldBC_8001db14(int light, int v);
    extern void modelLightStruct_setDiffuseColor(int light, int p, int r, int g, int p2);
    extern void modelLightStruct_setLightKind(int light, int v);
    extern int objCreateLight(int* obj, int mode);
    SBCloudBallState* state = obj->extra;

    ObjAnim_GetPriorityHitState(&obj->anim)->flags =
        (s16)(ObjAnim_GetPriorityHitState(&obj->anim)->flags & ~1);
    ObjAnim_GetPriorityHitState(&obj->anim)->trackContactMask =
        (u16)(ObjAnim_GetPriorityHitState(&obj->anim)->trackContactMask | 1);
    if ((void*)state->light == NULL)
    {
        state->light = objCreateLight((int*)obj, 1);
        if ((void*)state->light != NULL)
        {
            modelLightStruct_setLightKind(state->light, MODEL_LIGHT_KIND_POINT);
            modelLightStruct_setDiffuseColor(state->light, 0, 90, 150, 0);
            lightSetFieldBC_8001db14(state->light, 1);
            modelLightStruct_setDistanceAttenuation(state->light, gSbCloudBallLightAttenNear, gSbCloudBallLightAttenFar);
        }
    }
}

void SB_CloudBall_update(GameObject* obj)
{
    extern void Obj_FreeObject(int obj);
    extern void objfx_spawnFlaggedTrailBurst(int* obj, f32 f, int a, int b, int c, void* d);

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
            Obj_FreeObject((int)obj);
        }
    }
    else
    {
        f32 particleVelocity[3];
        f32 velocityScale;
        obj->anim.previousLocalPosX = obj->anim.localPosX;
        obj->anim.previousLocalPosY = obj->anim.localPosY;
        obj->anim.previousLocalPosZ = obj->anim.localPosZ;
        obj->anim.rootMotionScale = lbl_803E58F8 * (f32)(int)
        randomGetRange(-0x64, 0x64) + lbl_803E58F4;
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
        velocityScale = gSbCloudBallVelocityScale;
        state->posX = velocityScale * (state->velX * timeDelta) + state->posX;
        state->posY = velocityScale * (state->velY * timeDelta) + state->posY;
        state->posZ = velocityScale * (state->velZ * timeDelta) + state->posZ;
        obj->anim.localPosX = state->posX;
        obj->anim.localPosY = state->posY;
        obj->anim.localPosZ = state->posZ;
        obj->unkF4 = obj->unkF4 - framesThisStep;
        if (obj->unkF4 < 0 || (player != NULL && (((GameObject*)player)->objectFlags & SBCLOUDBALL_OBJFLAG_PARENT_SLACK) != 0))
        {
            if (state->fadeTimer == lbl_803E58EC)
            {
                obj->anim.alpha = 0;
                state->fadeTimer = gSbCloudBallFadeTime;
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
            projectileParticleFxFn_80099660((int*)obj, lbl_803E58E8, 2);
            state->fadeTimer = gSbCloudBallFadeTime;
            obj->anim.alpha = 0;
        }
        particleVelocity[0] = gSbCloudBallTrailVelScale * -state->velX;
        particleVelocity[1] = gSbCloudBallTrailVelScale * -state->velY;
        particleVelocity[2] = gSbCloudBallTrailVelScale * -state->velZ;
        objfx_spawnFlaggedTrailBurst((int*)obj, gSbCloudBallTrailParticleScale, 2, 0x156, 0xf, particleVelocity);
        objfx_spawnFlaggedTrailBurst((int*)obj, gSbCloudBallTrailParticleScale, 2, 0x156, 0xf, particleVelocity);
        objfx_spawnFlaggedTrailBurst((int*)obj, gSbCloudBallTrailParticleScale, 2, 0x156, 0xf, particleVelocity);
        (*gPartfxInterface)->spawnObject((void*)obj, 0xa8, NULL, 2, -1, NULL);
    }
}


/* EN v1.0 0x801E4BA4  size: 48b  When obj->_b8->[0] is non-null,
 * call ObjLink_DetachChild(obj). */

/* EN v1.0 0x801E60A4  size: 28b  shop state reset/seed: zero obj->_b8[2]
 * and obj->_b8[3], stash v in obj->_b8[4]. */

/* EN v1.0 0x801E607C  size: 40b  Increment-and-store: obj->_b8[2] += p3,
 * obj->_b8[3] += p2. */

/* EN v1.0 0x801E6050  size: 44b  Triple s8 fan-out: write obj->_b8[2/3/4]
 * (sign-extended) into *out_b3, *out_b2, *out_b4. */

/* EN v1.0 0x801E6358  size: 104b  Returns 1 unless the item's
 * "available" GameBit gate (lbl_80327FD0[idx*12 + 6]) is present and
 * unset.  (i.e. open by default, gated when slot != -1.) */

/* EN v1.0 0x801E62F0  size: 104b  Returns 1 when shop item's "bought"
 * GameBit (slot at lbl_80327FD0[idx*12 + 8]) is set; else 0. */
