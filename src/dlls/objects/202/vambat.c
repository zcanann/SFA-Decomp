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
#include "dolphin/mtx/vec.h"

/* Baddie-family animation data shared with the sequence-driver TUs. */

#define MAGICPLANT_PARTFX          0x802
#define MAGICPLANT_HIT_VOLUME_SLOT 0xe


/* The Firebat variant of the shared Vambat/Firebat family (retail
   OBJECTS.bin name "Firebat", DLL 0xC9); it alone runs with userData2 set. */

#define MAGICPLANT_FIREBAT_SEQID 0x7c6


static const f32 gVambatZero[] = {0.0f};

static const f32 gVambatHeartbeatPeriod[] = {60.0f};

int gVambatCurveInitData[2] = {2, 3};

void vambat_updateWhileFrozen(GameObject* obj, u8* state, GameObject* attacker, int msgFlag, int wpad0, int wpad1, Vec* wpad2,
                              int wpad3)
{
    EnemyState* bs = (EnemyState*)state;

    if (bs->userData2 != 0)
    {
        if (msgFlag == 16)
        {
            bs->flags2E8 |= 0x28;
            Sfx_PlayFromObject(obj, SFXTRIG_baddie_mika_wingflap);
            bs->current = 0;
        }
    }
    else if (msgFlag != 17)
    {
        if (msgFlag == 16)
        {
            bs->flags2E8 |= 0x20;
        }
        else
        {
            bs->flags2E8 |= 0x8;
            Sfx_PlayFromObject(obj, SFXTRIG_baddie_mika_wingflap);
            bs->current = 0;
        }
    }
}

void vambat_updateIdle(GameObject* obj, void* state)
{
    ObjHitsPriorityState* hitState;
    RomCurveWalker* curve;
    f32 vec[3];
    EnemyState* bs = (EnemyState*)state;

    curve = *(RomCurveWalker**)state;
    if (obj->anim.hitReactState != NULL)
    {
        hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
        hitState->suppressOutgoingHits = 0;
    }
    if (bs->userData2 != 0)
    {
        bs->flags2E8 |= 0x80;
    }
    if ((bs->controlFlags & BADDIE_CONTROL_PATH_FOLLOW) != 0)
    {
        if (Curve_AdvanceAlongPath(&curve->curve, bs->pathStep) != 0 ||
            curve->atSegmentEnd != 0)
        {
            if ((*gRomCurveInterface)->goNextPoint(curve) != 0)
            {
                if ((*gRomCurveInterface)
                        ->initCurve(*(RomCurveWalker**)state, obj, 7e+02f, gVambatCurveInitData, -1) != 0)
                {
                    bs->controlFlags &= ~BADDIE_CONTROL_PATH_FOLLOW;
                }
            }
        }

        baddieTurnTowardPoint(obj, state, curve->posX, curve->posZ, 0xf, 0);

        vec[0] = curve->posX - obj->anim.localPosX;
        vec[1] = curve->posY - obj->anim.localPosY;
        vec[2] = curve->posZ - obj->anim.localPosZ;
        enemy_steerVelocityToward(obj, state, vec, 1.5f, 0.75f, 0.15f, 1);

        bs->vambat.idleTimer += timeDelta;
        if (bs->vambat.idleTimer > 3.6e+02f)
        {
            bs->flags2E4 &= ~0x10000;
            bs->vambat.idleTimer = gVambatZero[0];
        }
    }

    baddieTurnTowardLookDir(obj, state, 0xf, 1e+01f, 1.0f, 0);

    bs->vambat.heartbeatSfxTimer -= timeDelta;
    if (bs->vambat.heartbeatSfxTimer <= gVambatZero[0])
    {
        bs->vambat.heartbeatSfxTimer = gVambatHeartbeatPeriod[0];
        Sfx_PlayFromObject(obj, SFXTRIG_mn_heart1_c);
    }
    bs->vambat.engagedTimer = gVambatZero[0];
}

void vambat_updateEngaged(GameObject* obj, void* state)
{
    RomCurveWalker* curve;
    f32 vec[3];
    f32 worldPos[3];
    int gridB[2];
    int gridA[2];
    u8 hitOut;
    GameObject* trackedObj;
    EnemyState* bs = (EnemyState*)state;

    curve = *(RomCurveWalker**)state;
    if (bs->userData2 != 0)
    {
        bs->flags2E8 |= 0x80;
    }
    if ((bs->controlFlags & BADDIE_CONTROL_JUST_TRIGGERED) != 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_baddie_mika_bombwhistle);
    }
    if ((bs->controlFlags & BADDIE_CONTROL_PATH_FOLLOW) != 0)
    {
        if (Curve_AdvanceAlongPath(&curve->curve, 2.0f * bs->pathStep) != 0 ||
            curve->atSegmentEnd != 0)
        {
            if ((*gRomCurveInterface)->goNextPoint(curve) != 0)
            {
                if ((*gRomCurveInterface)
                        ->initCurve(*(RomCurveWalker**)state, obj, 7e+02f, gVambatCurveInitData, -1) != 0)
                {
                    bs->controlFlags &= ~BADDIE_CONTROL_PATH_FOLLOW;
                }
            }
        }
    }
    ObjHits_SetHitVolumeSlot(&obj->anim, MAGICPLANT_HIT_VOLUME_SLOT, 1, 0);
    trackedObj = bs->trackedObj;
    vec[0] = trackedObj->anim.localPosX - obj->anim.localPosX;
    vec[1] = (25.0f + trackedObj->anim.localPosY) - obj->anim.localPosY;
    vec[2] = trackedObj->anim.localPosZ - obj->anim.localPosZ;
    PSVECMag((Vec*)vec);
    bs->vambat.engagedTimer += timeDelta;
    if (bs->lastHitObject != NULL || bs->vambat.engagedTimer > 3.6e+02f)
    {
        bs->flags2E4 |= 0x10000;
        bs->vambat.idleTimer = gVambatZero[0];
        bs->vambat.engagedTimer = gVambatZero[0];
    }
    else
    {
        worldPos[0] = obj->anim.localPosX;
        worldPos[1] = obj->anim.localPosY;
        worldPos[2] = obj->anim.localPosZ;
        voxmaps_worldToGrid(worldPos, (s16*)gridA);
        worldPos[0] = curve->posX;
        worldPos[1] = curve->posY;
        worldPos[2] = curve->posZ;
        voxmaps_worldToGrid(worldPos, (s16*)gridB);
        /* BUG: precedence - `!` binds before `&`, so this is (controlFlags == 0) & 0x01000000,
         * which is always false; the line-of-sight abort below can never fire. The author
         * almost certainly meant !(controlFlags & 0x01000000). */
        if (!bs->controlFlags & 0x01000000)
        {
            if (voxmaps_traceLine((VoxPos*)gridB, (VoxPos*)gridA, NULL, &hitOut, 0) == 0)
            {
                bs->flags2E4 |= 0x10000;
                bs->vambat.idleTimer = gVambatZero[0];
                bs->vambat.engagedTimer = gVambatZero[0];
            }
        }
    }
    enemy_steerVelocityToward(obj, state, vec, 1.5f, 0.75f, 0.15f, 1);
    baddieTurnTowardLookDir(obj, state, 0xf, 1e+01f, 1.0f, 0);
}

void vambat_init(GameObject* obj, void* state)
{
    f32 pathStepInit;
    f32 initSpeed;
    EnemyState* bs = (EnemyState*)state;

    bs->sightRange = 4e+01f;
    bs->flags2E4 = 0x1009;
    bs->animPlaySpeed = 0.02f;
    bs->gravity = 0.1f;
    bs->drag = 0.97f;
    bs->moveId0 = 0;
    initSpeed = 1.5f;
    bs->moveSpeedScale0 = initSpeed;
    bs->moveId1 = 1;
    pathStepInit = 1.0f;
    bs->moveSpeedScale1 = pathStepInit;
    bs->moveId2 = 0;
    bs->moveSpeedScale2 = initSpeed;
    bs->vambat.idleTimer = gVambatZero[0];
    bs->vambat.heartbeatSfxTimer = gVambatZero[0];
    bs->vambat.engagedTimer = gVambatZero[0];
    bs->pathStep = pathStepInit;
    switch (obj->anim.romDefNo)
    {
    case MAGICPLANT_FIREBAT_SEQID:
        bs->userData2 = 1;
        break;
    default:
        bs->userData2 = 0;
        break;
    }
}

void magicplantSpawnMovePuffs(GameObject* obj, void* state)
{
    u8 count = 0;
    EnemyState* bs = (EnemyState*)state;
    switch (obj->anim.currentMove)
    {
    case 1:
        count = 1;
        break;
    case 2:
        count = 1;
        break;
    case 3:
        count = 1;
        break;
    case 5:
        if ((bs->controlFlags & BADDIE_CONTROL_JUST_TRIGGERED) != 0)
        {
            count = 0xa;
        }
        break;
    case 7:
        break;
    }
    if (count != 0 && (bs->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) == 0)
    {
        u8 spawn = count;
        while (spawn != 0)
        {
            (*gPartfxInterface)->spawnObject(obj, MAGICPLANT_PARTFX, NULL, 2, -1, NULL);
            spawn--;
        }
    }
}
