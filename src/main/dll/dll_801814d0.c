/*
 * dll_801814d0 - Duster hit-response split of the MagicPlant/TrickyWarp/
 * TrickyGuard/StayPoint/Duster/CurveFish multi-object DLL (the shared
 * ObjectDescriptor table lives in dll_0100_trickywarp, its retail home).
 *
 * The one resident function defined here is fn_801814D0, the Duster's
 * hit-response handler: it reads the highest-priority hit on the object,
 * fades the model in on a kill-volume hit (type 0x10), and otherwise
 * spawns the dust light effect, applies area damage to nearby group-0x10
 * objects within range/height, plays the configured sfx, kicks the
 * hit-react timer and launch velocity, then clears its hit volumes and
 * optionally disables itself.
 */
#include "main/dll/dusterstate_types.h"
#include "main/vecmath_distance_api.h"
#include "main/audio/sfx_object_query_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/shader_api.h"
#include "main/game_object.h"
#include "main/obj_group.h"
#include "main/object_api.h"
#include "main/objhits.h"
#include "main/objfx.h"
#include "main/audio/sfx_trigger_ids.h"

int lbl_803DBDA0 = 1;
f32 lbl_803DBDA4 = 15.0f;
f32 lbl_803DBDA8 = 30.0f;

typedef struct DusterHitEffectPos
{
    u8 pad00[0xc];
    f32 x;
    f32 y;
    f32 z;
} DusterHitEffectPos;

STATIC_ASSERT(sizeof(DusterStateFlags) == 1);
STATIC_ASSERT(sizeof(DusterState) == 0x20);
STATIC_ASSERT(offsetof(DusterState, moveStepScale) == 0x00);
STATIC_ASSERT(offsetof(DusterState, floorY) == 0x04);
STATIC_ASSERT(offsetof(DusterState, settleTimer) == 0x08);
STATIC_ASSERT(offsetof(DusterState, hitReactTimer) == 0x0a);
STATIC_ASSERT(offsetof(DusterState, completeGameBit) == 0x0c);
STATIC_ASSERT(offsetof(DusterState, activeGameBit) == 0x0e);
STATIC_ASSERT(offsetof(DusterState, heldObjectId) == 0x10);
STATIC_ASSERT(offsetof(DusterState, driftDir) == 0x18);
STATIC_ASSERT(offsetof(DusterState, hitReactActive) == 0x19);
STATIC_ASSERT(offsetof(DusterState, priorityHit) == 0x1a);
STATIC_ASSERT(offsetof(DusterState, active) == 0x1b);
STATIC_ASSERT(offsetof(DusterState, complete) == 0x1c);
STATIC_ASSERT(offsetof(DusterState, useLaunchVelocity) == 0x1d);
STATIC_ASSERT(offsetof(DusterState, flags) == 0x1e);

/* Group of carryable/blockable objects the duster blast applies area damage to. */
#define DUSTER_AREADAMAGE_OBJGROUP 0x10

extern int lbl_803DBDA0;
extern f32 lbl_803DBDA4;
extern f32 lbl_803DBDA8;
extern f32 lbl_803E3934;
extern f32 lbl_803E3938;

extern void fn_801816F8(int obj, int arg, u8* state);

void fn_801814D0(int obj, int arg, u8* state)
{
    int hitWork[4];
    DusterHitEffectPos effectPos;
    int hitType;
    int* objects;
    int i;
    int* groupObjects;
    f32 dusterY;
    f32 candidateY;
    f32 launchVel;

    hitType = ObjHits_GetPriorityHitWithPosition((GameObject*)(obj), &hitWork[3], &hitWork[2], (u32*)&hitWork[1],
                                                 &effectPos.x, &effectPos.y, &effectPos.z);
    if (hitType != 0)
    {
        if (hitType == 0x10)
        {
            Obj_StartModelFadeIn((GameObject*)obj, 0x12c);
        }
        else
        {
            effectPos.x += playerMapOffsetX;
            effectPos.z += playerMapOffsetZ;
            if (state[0x20] != 0) /* area-damage enable flag (past DusterState) */
            {
                if (hitType != 5)
                {
                    objLightFn_8009a1dc((void*)obj, lbl_803E3934, &effectPos, 4, 0);
                    if (Sfx_IsPlayingFromObjectIntU16Legacy(0, SFXTRIG_staff_rocket_powerup) == 0)
                    {
                        Sfx_PlayFromObject(obj, SFXTRIG_staff_rocket_powerup);
                    }
                    return;
                }
                groupObjects = (int*)ObjGroup_GetObjects(DUSTER_AREADAMAGE_OBJGROUP, &hitWork[0]);
                i = 0;
                objects = groupObjects;
                for (; i < hitWork[0]; i++)
                {
                    if (ObjHits_IsObjectEnabled((ObjAnimComponent*)*objects) != 0)
                    {
                        candidateY = ((GameObject*)*objects)->anim.localPosY;
                        dusterY = ((GameObject*)obj)->anim.localPosY;
                        if (candidateY > dusterY && candidateY < dusterY + lbl_803DBDA8)
                        {
                            if (Vec_xzDistance((f32*)(*objects + 0x18), (f32*)(obj + 0x18)) < lbl_803DBDA4)
                            {
                                ObjHits_RecordObjectHit(*objects, hitWork[3], 5, 1, 0);
                            }
                        }
                    }
                    objects++;
                }
            }
            objLightFn_8009a1dc((void*)obj, lbl_803E3934, &effectPos, 1, 0);
            Obj_SetModelColorFadeRecursive((GameObject*)obj, 0xf, 0xc8, 0, 0, 1);
            if (Sfx_IsPlayingFromObjectIntU16Legacy(0, (u16)((DusterState*)state)->heldObjectId) == 0)
            {
                Sfx_PlayFromObject(obj, (u16)((DusterState*)state)->heldObjectId);
            }
            ((DusterState*)state)->hitReactTimer = 0x32;
            state[9] = 0;
            fn_801816F8(obj, arg, state);
            ((GameObject*)obj)->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            launchVel = lbl_803E3938;
            ((GameObject*)obj)->anim.velocityX = lbl_803E3938;
            ((GameObject*)obj)->anim.velocityZ = launchVel;
            ObjHits_ClearHitVolumes((ObjAnimComponent*)obj);
            if (lbl_803DBDA0 != 0)
            {
                ObjHits_DisableObject(obj);
            }
        }
    }
}
