#include "dlls/objects/202.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "game/objects/object.h"
#include "game/objects/object_setup.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/camera.h"
#include "main/camera_shake_api.h"
#include "main/dll/baddie_control_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/mapEventTypes.h"
#include "main/object_render.h"
#include "main/objtype.h"
#include "main/obj_message.h"
#include "main/obj_path.h"
#include "main/objanim.h"
#include "main/objhits.h"
#include "main/objprint_api.h"
#include "main/objseq.h"
#include "main/player_control_interface.h"
#include "main/vecmath.h"
#include "main/voxmaps.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/dll/baddie_state.h"
#include "dlls/objects/201_Baddie.h"
#include "main/dll/wispbaddie_baddie.h"
#include "main/audio/sfx_position_api.h"
#include "main/audio/sfx_ids.h"
#include "main/pad_api.h"
#include "main/dll/seqobj11d_ext.h"
#include "main/dll/wispbaddieseq_ext.h"
#include "main/gameloop_api.h"
#include "main/audio/sfx.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/gamebits.h"
#include "main/dll/objfsa.h"
#include "main/dll/newseqobj_baddie.h"
#include "main/dll/baddie_frozen.h"
#include "main/game_ui_interface.h"
#include "main/dll/tricky_api.h"
#include "main/model.h"
#include "main/object_transform.h"
#include "main/dll/player_target.h"
#include "main/dll/player_api.h"
#include "dlls/objects/225_WispBaddie.h"
#include "main/trig_float_helpers.h"
#include "main/obj_link.h"
#include "main/objfx.h"
#include "main/objtexture.h"
#include "main/dll/seqObj11E.h"
#include "main/dll/groundbaddiepush_ext.h"
#include "main/dll/dll_00C9_enemy_ext.h"
#include "dlls/objects/336_GCRobotLigh.h"
#include "dolphin/mtx.h"
#include "main/dll/mikaladon.h"
#include "main/dll/magicPlant.h"
#include "main/dll/kooshy.h"
#include "main/dll/weevil.h"
#include "main/trig.h"
#include "main/dll/waterfx_interface.h"
#include "main/dll/fall_ladders.h"
#include "main/dll/fireflyLantern.h"
#include "main/dll/duster_api.h"
#include "main/track_bbox_api.h"
#include "main/sky_interface.h"
#include "main/dll/duster.h"
#include "dlls/objects/216_PinPonSpike.h"
#include "main/dll/duster_wb.h"
#include "main/obj_query.h"
#include "main/dll/hoodedzyck.h"
#include "main/camera_interface.h"
#include "main/model_light.h"
#include "main/dll/firecrawler.h"
#include "main/dll/dll_0273_firepipe.h"
#include "main/dll/hagabon_mk2.h"
#include "main/dll/snowworm.h"
#include "main/dll/baddiewhirlpool.h"

/* Baddie-family animation data shared with the sequence-driver TUs. */

#define DUSTER_CHILD_OBJ_POLLEN_SPIT 0x47b
#define DUSTER_HIT_VOLUME_SLOT       10


int gWbCurveInitData[2] = {2, 3};

void wbUpdateWhileFrozen(GameObject* obj, u8* state, GameObject* attacker, int eventKind, int wpad0, int wpad1, Vec* wpad2, int wpad3)
{
    if (eventKind != 0x11)
    {
        if (eventKind == 0x10)
        {
            ((EnemyState*)state)->flags2E8 = ((EnemyState*)state)->flags2E8 | 0x20;
        }
        else
        {
            Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_baddie_mika_wingflap_260);
            ((EnemyState*)state)->current = 0;
            ((EnemyState*)state)->flags2E4 = ((EnemyState*)state)->flags2E4 | 0x20;
            ((EnemyState*)state)->flags2E8 = ((EnemyState*)state)->flags2E8 | 8;
        }
    }
    return;
}

static void wbTickDecoyTimer(GameObject* obj, EnemyState* state)
{
    u32 randVal;

    state->duster.decoyTimer = state->duster.decoyTimer - timeDelta;
    if (state->duster.decoyTimer <= 0.0f)
    {
        if ((state->controlFlags & 0x600) != 0)
        {
            randVal = randomGetRange(0x96, 0xfa);
            state->duster.decoyTimer = (float)(int)randVal;
        }
        else
        {
            randVal = randomGetRange(600, 0x352);
            state->duster.decoyTimer = (float)(int)randVal;
        }
        Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_baddie_eba_pollenspin);
    }
}

void wbUpdateEngaged(GameObject* obj, int state)
{
    GameObject* tracked;
    f32 moveSpeed;
    ObjHitsPriorityState* hitState;

    if (((EnemyState*)state)->duster.decoyTimer > 250.0f)
    {
        ((EnemyState*)state)->duster.decoyTimer = 150.0f;
    }
    hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    hitState->suppressOutgoingHits = 0;
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, DUSTER_HIT_VOLUME_SLOT, 1, 0);
    if ((((EnemyState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
    {
        Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_mn_heart1_c_261);
    }
    wbTickDecoyTimer(obj, (EnemyState*)state);
    if ((((EnemyState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
    {
        ObjAnim_SetCurrentMove(obj, 3, 0.0f, ((EnemyState*)state)->rootMotionFlags);
    }
    if (((EnemyState*)state)->duster.phaseTimer > 0.0f)
    {
        ((EnemyState*)state)->duster.phaseTimer = ((EnemyState*)state)->duster.phaseTimer - timeDelta;
        if (((EnemyState*)state)->duster.phaseTimer <= 0.0f)
        {
            ((EnemyState*)state)->duster.phaseTimer = 600.0f;
            ((EnemyState*)state)->flags2E4 = ((EnemyState*)state)->flags2E4 | 0x10000LL;
        }
    }
    else if ((((EnemyState*)state)->controlFlags & 0x400) != 0)
    {
        ((EnemyState*)state)->duster.phaseTimer = 600.0f;
    }
    if ((((EnemyState*)state)->controlFlags & 0x8000000) != 0)
    {
        moveSpeed = 20.0f;
    }
    else
    {
        tracked = (GameObject*)((EnemyState*)state)->trackedObj;
        moveSpeed = sidekickToy_accelerateTowardTargetXZ(
            (GameObject*)(obj), tracked->anim.worldPosX, 50.0f + tracked->anim.worldPosY,
            tracked->anim.worldPosZ, 30.0f, 0.2f, 5.0f, ((EnemyState*)state)->drag);
    }
    if (((moveSpeed > 0.0f) && (((GameObject*)obj)->anim.velocityY < -0.5f)) ||
        ((((EnemyState*)state)->controlFlags & 0x8000000) != 0))
    {
        ((EnemyState*)state)->userData1 = 1;
    }
    if ((((EnemyState*)state)->userData1 != 0) && (moveSpeed > 0.0f))
    {
        ((EnemyState*)state)->animPlaySpeed = 0.05f;
        if (((EnemyState*)state)->current != 0)
        {
            ((GameObject*)obj)->anim.velocityY += 0.02f;
        }
        if (((GameObject*)obj)->anim.velocityY < -0.7f)
        {
            ((GameObject*)obj)->anim.velocityY = -0.7f;
        }
        else if (((GameObject*)obj)->anim.velocityY > 0.5f)
        {
            ((GameObject*)obj)->anim.velocityY = 0.5f;
        }
    }
    else
    {
        ((EnemyState*)state)->userData1 = 0;
        if (((EnemyState*)state)->animPlaySpeed > 0.025f)
        {
            ((EnemyState*)state)->animPlaySpeed = -(0.005f * timeDelta - ((EnemyState*)state)->animPlaySpeed);
        }
    }
    baddieTurnTowardLookDir((GameObject*)obj, (void*)state, 0x2d, 0.0f, 0.0f, 0);
}

void wbUpdateIdle(GameObject* obj, int state)
{
    RomCurveWalker* route;
    ObjPlacement* placement;
    f32 moveSpeed;
    ObjHitsPriorityState* hitState;

    route = *(RomCurveWalker**)state;
    placement = ((GameObject*)obj)->anim.placement;
    hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    hitState->suppressOutgoingHits = 0;
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, DUSTER_HIT_VOLUME_SLOT, 1, 0);
    if ((((EnemyState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
    {
        Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_mn_heart1_c_261);
    }
    wbTickDecoyTimer(obj, (EnemyState*)state);
    if ((((EnemyState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
    {
        ObjAnim_SetCurrentMove(obj, 0, 0.0f, ((EnemyState*)state)->rootMotionFlags);
    }
    if (((EnemyState*)state)->duster.phaseTimer > 0.0f)
    {
        ((EnemyState*)state)->duster.phaseTimer = ((EnemyState*)state)->duster.phaseTimer - timeDelta;
        if (((EnemyState*)state)->duster.phaseTimer <= 0.0f)
        {
            ((EnemyState*)state)->duster.phaseTimer = 0.0f;
        }
    }
    else
    {
        ((EnemyState*)state)->flags2E4 = ((EnemyState*)state)->flags2E4 & ~0x10000LL;
    }
    if ((((EnemyState*)state)->controlFlags & BADDIE_CONTROL_PATH_FOLLOW) != 0)
    {
        if (((Curve_AdvanceAlongPath(&route->curve, ((EnemyState*)state)->pathStep) != 0 ||
              route->atSegmentEnd != 0) &&
             (*gRomCurveInterface)->goNextPoint(route) != 0) &&
            (*gRomCurveInterface)
                    ->initCurve(*(RomCurveWalker**)state, (void*)obj, 700.0f, (int*)&gWbCurveInitData, -1) != 0)
        {
            ((EnemyState*)state)->controlFlags =
                ((EnemyState*)state)->controlFlags & ~(u64)BADDIE_CONTROL_PATH_FOLLOW;
        }
        if ((((EnemyState*)state)->controlFlags & 0x8000000) != 0)
        {
            moveSpeed = 30.0f;
        }
        else
        {
            moveSpeed = sidekickToy_accelerateTowardTargetXZ((GameObject*)(obj), route->posX, route->posY, route->posZ,
                                                             30.0f, 0.2f, 5.0f,
                                                             ((EnemyState*)state)->drag);
        }
    }
    else if ((((EnemyState*)state)->controlFlags & 0x8000000) != 0)
    {
        moveSpeed = 30.0f;
    }
    else
    {
        moveSpeed = sidekickToy_accelerateTowardTargetXZ((GameObject*)(obj), placement->posX, placement->posY,
                                                         placement->posZ, 30.0f, 0.2f, 5.0f,
                                                         ((EnemyState*)state)->drag);
    }
    if (((moveSpeed > 0.0f) && (((GameObject*)obj)->anim.velocityY < -0.5f)) ||
        ((((EnemyState*)state)->controlFlags & 0x8000000) != 0))
    {
        ((EnemyState*)state)->userData1 = 1;
    }
    if ((((EnemyState*)state)->userData1 != 0) && (moveSpeed > 0.0f))
    {
        ((EnemyState*)state)->animPlaySpeed = 0.05f;
        if (((EnemyState*)state)->current != 0)
        {
            ((GameObject*)obj)->anim.velocityY += 0.02f;
        }
        if (((GameObject*)obj)->anim.velocityY < -0.7f)
        {
            ((GameObject*)obj)->anim.velocityY = -0.7f;
        }
        else if (((GameObject*)obj)->anim.velocityY > 0.5f)
        {
            ((GameObject*)obj)->anim.velocityY = 0.5f;
        }
    }
    else
    {
        ((EnemyState*)state)->userData1 = 0;
        if (((EnemyState*)state)->animPlaySpeed > 0.025f)
        {
            ((EnemyState*)state)->animPlaySpeed = -(0.005f * timeDelta - ((EnemyState*)state)->animPlaySpeed);
        }
    }
    baddieTurnTowardLookDir((GameObject*)obj, (void*)state, 0x2d, 0.0f, 0.0f, 0);
}

void wbInit(u32 unused, int state)
{
    float fa;
    u32 ua;

    ((EnemyState*)state)->sightRange = 60.0f;
    ((EnemyState*)state)->flags2E4 = 0x2002b029;
    ((EnemyState*)state)->animPlaySpeed = 0.05f;
    ((EnemyState*)state)->gravity = 0.006f;
    ((EnemyState*)state)->drag = 0.95f;
    ((EnemyState*)state)->moveId0 = 0;
    fa = 1.0f;
    ((EnemyState*)state)->moveSpeedScale0 = 1.0f;
    ((EnemyState*)state)->moveId1 = 1;
    ((EnemyState*)state)->moveSpeedScale1 = fa;
    ((EnemyState*)state)->moveId2 = 2;
    ((EnemyState*)state)->moveSpeedScale2 = fa;
    ua = randomGetRange(0x78, 0x1e0);
    ((EnemyState*)state)->duster.decoyTimer = (float)(int)ua;
    return;
}
