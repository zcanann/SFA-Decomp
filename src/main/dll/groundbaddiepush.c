/*
 * groundbaddiepush - the ground baddie's player-pushout and frozen-reaction
 * pair. fn_80151DB8 pushes the player out of a cylinder placed in front of the
 * object (offset along the object's facing angle), reprojecting the player's
 * world position back to local space. guardClawUpdateWhileFrozen plays a dirt
 * step sfx and sets a reaction flag. Both are called only from sibling DLLs
 * (seqobj11e, dll_00C4_tricky).
 */
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/sfx.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/dll/baddie_state.h"
#include "main/object_transform.h"
#include "main/object_api.h"

#define GROUND_BADDIE_PI 3.14159274f
#define GROUND_BADDIE_ANGLE_UNIT_SCALE 32768.0f
#define GROUND_BADDIE_PUSH_RADIUS 50.0f
#define GROUND_BADDIE_PUSH_MAX_DEPTH -20.0f


void fn_80151DB8(int obj, u8* state)
{
    GameObject* player;
    ObjPlacement* setup;
    f32 dy;
    f32 px0;
    f32 pz0;
    f32 cosA;
    f32 sinA;
    f32 base;
    f32 f5;
    f32 f2v;
    f32 dx;
    f32 dz;

    player = (GameObject*)Obj_GetPlayerObject();
    setup = ((GameObject*)obj)->anim.placement;
    dy = player->anim.localPosY - ((GameObject*)obj)->anim.localPosY;
    dy = (dy >= 0.0f) ? dy : -dy;
    if (dy > GROUND_BADDIE_PUSH_RADIUS)
    {
        return;
    }
    px0 = setup->posX - GROUND_BADDIE_PUSH_RADIUS * mathSinf(GROUND_BADDIE_PI *
                                                             (f32)((GameObject*)obj)->anim.rotX /
                                                             GROUND_BADDIE_ANGLE_UNIT_SCALE);
    pz0 = setup->posZ - GROUND_BADDIE_PUSH_RADIUS * mathCosf(GROUND_BADDIE_PI *
                                                             (f32)((GameObject*)obj)->anim.rotX /
                                                             GROUND_BADDIE_ANGLE_UNIT_SCALE);
    dx = player->anim.worldPosX - px0;
    dz = player->anim.worldPosZ - pz0;
    if (sqrtf(dx * dx + dz * dz) < ((GroundBaddieState*)state)->baddie.speedScale)
    {
        cosA = mathSinf(GROUND_BADDIE_PI * (f32)((GameObject*)obj)->anim.rotX / GROUND_BADDIE_ANGLE_UNIT_SCALE);
        sinA = mathCosf(GROUND_BADDIE_PI * (f32)((GameObject*)obj)->anim.rotX / GROUND_BADDIE_ANGLE_UNIT_SCALE);
        base = -(cosA * (px0 - cosA) + sinA * (pz0 - sinA));
        f5 = base + (cosA * player->anim.previousWorldPosX + sinA * player->anim.previousWorldPosZ);
        f2v = base + (cosA * player->anim.worldPosX + sinA * player->anim.worldPosZ);
        if (f2v > 0.0f)
        {
            if (!(f5 >= GROUND_BADDIE_PUSH_MAX_DEPTH))
            {
                return;
            }
            player->anim.worldPosX = player->anim.worldPosX - cosA * f5;
            player->anim.worldPosZ = player->anim.worldPosZ - sinA * f5;
            Obj_TransformWorldPointToLocal(player->anim.worldPosX, player->anim.worldPosY, player->anim.worldPosZ,
                                           &player->anim.localPosX, &player->anim.localPosY, &player->anim.localPosZ,
                                           (u32)player->anim.parent);
        }
    }
}

void guardClawUpdateWhileFrozen(int obj, int* state)
{
    Sfx_PlayFromObject((u32)obj, SFXTRIG_wp_pole1_c_23);
    ((GroundBaddieState*)state)->baddie.reactionFlags |= 0x10;
}
