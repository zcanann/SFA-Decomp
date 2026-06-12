/* DLL 0x1ED — SB fireball object [801E4288-801E42F8) */
#include "main/dll_000A_expgfx.h"
#include "main/dll/shipbattlestate_struct.h"
#include "main/dll/sbkytecagestate_struct.h"
#include "main/dll/sbfireballstate_struct.h"
#include "main/dll/sbcloudballstate_struct.h"
#include "main/dll/TREX/TREX_levelcontrol.h"

extern u8 framesThisStep;
extern EffectInterface** gPartfxInterface;

/* Trivial 4b 0-arg blr leaves. */

/* 8b "li r3, N; blr" returners. */

int SB_FireBall_getExtraSize(void) { return SB_FIREBALL_EXTRA_SIZE; }
int SB_FireBall_getObjectTypeId(void) { return 0x0; }

void SB_FireBall_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E58B0;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E58D8;

void SB_FireBall_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E58D8);
}

extern f32 timeDelta;

#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/mapEvent.h"
#include "main/dll/TREX/TREX_trex.h"
#include "main/effect_interfaces.h"
#include "main/dll_000A_expgfx.h"
#include "main/objhits_types.h"
#include "main/objseq.h"
#include "main/resource.h"

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

extern undefined4 ObjLink_DetachChild();

void SB_FireBall_hitDetect(int* obj)
{
    ObjHitsPriorityState* params = *(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState;
    int i;
    if (params->lastHitObject == 0) return;
    params->flags &= ~1;
    for (i = 50; i != 0; i--)
    {
        (*gPartfxInterface)->spawnObject(obj, 167, NULL, 1, -1, NULL);
    }
    for (i = 10; i != 0; i--)
    {
        (*gPartfxInterface)->spawnObject(obj, 171, NULL, 1, -1, NULL);
    }
}

void FUN_801e55c0(undefined8 param_1, double param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  undefined2* param_9, int param_10)
{
}

/* Trivial 4b 0-arg blr leaves. */
void SB_FireBall_release(void)
{
}

void SB_FireBall_initialise(void)
{
}

void SB_CloudBall_release(void);

/* 8b "li r3, N; blr" returners. */

/* 16b chained patterns. */

/* render-with-objRenderFn_8003b8f4 pattern. */

/* Stubs added to align function set with v1.0 asm. Source had Ghidra FUN_xxx
 * splits at wrong addresses; these stubs ensure every asm symbol has a src
 * definition so future hunters can fill bodies one at a time. */

/* EN v1.0 0x801E4F14  size: 60b  Decrement obj->_f4 if > 0, OR in bit 0x8
 * of obj->_af, latch state->_6e = -2 and state->_56 = 0; return 0. */

extern f32 lbl_803E58DC;
extern f32 lbl_803E58E0;

void SB_FireBall_init(int p)
{
    SBFireBallState* state = ((GameObject*)p)->extra;
    ((GameObject*)p)->unkF4 = 0x4b0;
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
            (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->hitVolumePriority =
                SB_FIREBALL_HITBOX_TYPE;
            (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->hitVolumeId =
                SB_FIREBALL_HITBOX_PRIORITY;
            (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->objectHitMask = SB_FIREBALL_HITBOX_SIZE;
            (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->skeletonHitMask =
                SB_FIREBALL_HITBOX_SIZE;
            (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->flags |= SB_FIREBALL_SOLID_HITBOX_FLAG;
        }
        else
        {
            (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->flags &= ~SB_FIREBALL_SOLID_HITBOX_FLAG;
        }

        state->age += framesThisStep;
    }
}

/* EN v1.0 0x801E4BA4  size: 48b  When obj->_b8->[0] is non-null,
 * call ObjLink_DetachChild(obj). */
void SB_KyteCage_free(int* obj);

/* EN v1.0 0x801E60A4  size: 28b  shop state reset/seed: zero obj->_b8[2]
 * and obj->_b8[3], stash (s8)v in obj->_b8[4]. */

/* EN v1.0 0x801E607C  size: 40b  Increment-and-store: obj->_b8[2] += p3,
 * obj->_b8[3] += p2. */

/* EN v1.0 0x801E6050  size: 44b  Triple s8 fan-out: write obj->_b8[2/3/4]
 * (sign-extended) into *out_b3, *out_b2, *out_b4. */

/* shop_getItem* helpers -- table lookup */

/* EN v1.0 0x801E6358  size: 104b  Returns 1 unless the item's
 * "available" GameBit gate (lbl_80327FD0[idx*12 + 6]) is present and
 * unset.  (i.e. open by default, gated when slot != -1.) */

/* EN v1.0 0x801E62F0  size: 104b  Returns 1 when shop item's "bought"
 * GameBit (slot at lbl_80327FD0[idx*12 + 8]) is set; else 0. */
