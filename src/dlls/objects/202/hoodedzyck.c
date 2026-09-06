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

#define FIRECRAWLER_HIT_VOLUME_SLOT      9
/* group owned by another DLL, queried here */

#define LANTERNFIREFLY_OBJGROUP 0x30 /* DLL 0x10C lanternfirefly */

extern f32 gHoodedZyckFollowUpMoveSpeed;

extern f32 gHoodedZyckLungeMoveSpeed;

extern f32 gHoodedZyckLargeTargetSpeedScale;

extern f32 gHoodedZyckEmergeMoveSpeed;

static void hoodedZyck_tickPhaseTimer(EnemyState* st)
{
    st->duster.phaseTimer = st->duster.phaseTimer - timeDelta;
    if (st->duster.phaseTimer <= 0.0f)
    {
        st->duster.phaseTimer = (f32)(int)randomGetRange(0x3c, 0x78);
    }
}

static int hoodedZyck_getAngleDelta(GameObject* obj, GameObject* target)
{
    f32 d = (f32)(int)((u16)getAngle(obj->anim.localPosX - target->anim.localPosX,
                                     obj->anim.localPosZ - target->anim.localPosZ) -
                       (u16)obj->anim.rotX);
    if (d > 32768.0f)
    {
        d = -65535.0f + d;
    }
    if (d < -32768.0f)
    {
        d = 65535.0f + d;
    }
    return d;
}

void hoodedZyckUpdateWhileFrozen(GameObject* obj, u8* state, GameObject* attacker, int eventKind, int wpad0, int wpad1,
                                 Vec* wpad2, int wpad3)
{
    EnemyState* enemyState = (EnemyState*)state;
    if (eventKind == 0x10)
    {
        enemyState->flags2E8 = enemyState->flags2E8 | 0x20;
    }
    else
    {
        enemyState->flags2E8 = enemyState->flags2E8 | 8;
        Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_dn_boar1_c_244);
        enemyState->current = 0;
    }
    return;
}

void hoodedZyck_updateIdle(GameObject* obj, void* state)
{
    EnemyState* enemyState = (EnemyState*)state;
    bool resetting;
    int groundHit;
    u8 noHit;
    int randBit;
    float toPos[3];
    float fromPos[3];
    float cosYaw;
    float sinYaw;
    float hitOut[22];

    hoodedZyck_tickPhaseTimer(enemyState);
    if (enemyState->duster.decoyTimer != 0.0f)
    {
        ObjHits_DisableObject(obj);
        if ((obj)->anim.currentMove != 5)
        {
            baddieSetMove(obj, state, 5, gHoodedZyckEmergeMoveSpeed, 0, 0);
        }
        else if ((enemyState->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
        {
            ObjHits_EnableObject(obj);
            enemyState->duster.decoyTimer = 0.0f;
        }
        (obj)->anim.alpha = 0xff;
        resetting = true;
    }
    else
    {
        resetting = false;
    }
    if (!resetting)
    {
        (obj)->anim.rotX = (short)((obj)->anim.rotX + enemyState->phaseAngle);
        fromPos[0] = (obj)->anim.localPosX;
        fromPos[1] = (obj)->anim.localPosY;
        fromPos[2] = (obj)->anim.localPosZ;
        angleToVec2Fast((u32)(u16)(obj)->anim.rotX, &sinYaw, &cosYaw);
        toPos[0] = (obj)->anim.localPosX - 10.0f * sinYaw;
        toPos[1] = 5.0f + (obj)->anim.localPosY;
        toPos[2] = (obj)->anim.localPosZ - 10.0f * cosYaw;
        groundHit = trackGetLineIntersect(fromPos, toPos, 0.0f, 3, (TrackLineIntersectResult*)hitOut,
                                       obj,
                                       (u32)enemyState->bboxTraceFlags,
                                       0xffffffff, 0xff, 0);
        noHit = !(groundHit & 0xff);
        if (!noHit || ((enemyState->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0))
        {
            if (noHit && (obj)->anim.currentMove != 0)
            {
                enemyState->phaseAngle = 0;
                baddieSetMove(obj, state, 0, 1.0f, 0, 1);
            }
            else
            {
                float fz;
                baddieSetMove(obj, state, 1, 0.75f, 0, 0);
                fz = 0.0f;
                (obj)->anim.velocityX = fz;
                (obj)->anim.velocityY = fz;
                (obj)->anim.velocityZ = fz;
                randBit = randomGetRange(0, 1);
                enemyState->phaseAngle = (u16)((randBit - 1) * 0x12c);
            }
        }
        (obj)->anim.rotY = enemyState->spawnRotY;
        (obj)->anim.rotZ = enemyState->spawnRotZ;
    }
    return;
}

void hoodedZyck_updateB(GameObject* obj, u8* state)
{
    EnemyState* enemyState = (EnemyState*)state;
    f32 scale;
    int moved;
    int turnRaw;
    u8 noHit;
    u16 mag;
    TrackLineIntersectResult bufA;
    TrackLineIntersectResult bufB;
    f32 tgtA[3];
    f32 posA[3];
    f32 tgtB[3];
    f32 posB[3];
    f32 range;
    f32 cosA;
    f32 sinA;
    f32 cosB;
    f32 sinB;

    {
        u8 n = ((GroundBaddiePlacement*)obj->anim.placementData)->aggression;
        scale = n;
        if (n == 0.0f)
        {
            scale = 10.0f;
        }
        scale = scale / 10.0f;
    }

    hoodedZyck_tickPhaseTimer(enemyState);

    if (enemyState->crawler.emergeTimer != 0.0f)
    {
        ObjHits_DisableObject(obj);
        if (obj->anim.currentMove != 5)
        {
            baddieSetMove(obj, state, 5, gHoodedZyckEmergeMoveSpeed, 0, 0);
        }
        else if ((enemyState->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
        {
            ObjHits_EnableObject(obj);
            enemyState->crawler.emergeTimer = 0.0f;
        }
        obj->anim.alpha = 0xff;
        moved = 1;
    }
    else
    {
        moved = 0;
    }

    if (moved == 0)
    {
        u32 ang;
        f32 diff;
        GameObject* other;

        *(s16*)obj = *(s16*)obj + enemyState->phaseAngle;
        posA[0] = obj->anim.localPosX;
        posA[1] = obj->anim.localPosY;
        posA[2] = obj->anim.localPosZ;
        angleToVec2Fast((u16)obj->anim.rotX, &sinA, &cosA);
        tgtA[0] = -(10.0f * sinA - obj->anim.localPosX);
        tgtA[1] = 5.0f + obj->anim.localPosY;
        tgtA[2] = -(10.0f * cosA - obj->anim.localPosZ);
        noHit = !(u8)trackGetLineIntersect(posA, tgtA, 0.0f, 3, &bufA, obj,
                                        enemyState->bboxTraceFlags, -1, 0xff, 0);
        ang =
            getAngle(
                obj->anim.localPosX - ((GameObject*)enemyState->trackedObj)->anim.localPosX,
                obj->anim.localPosZ - ((GameObject*)enemyState->trackedObj)->anim.localPosZ) &
            0xffff;
        diff = (f32)(int)(ang - ((int)*(s16*)obj & 0xffffu));
        if (diff > 32768.0f)
        {
            diff = -65535.0f + diff;
        }
        if (diff < -32768.0f)
        {
            diff = 65535.0f + diff;
        }
        turnRaw = diff;
        {
            s16 t = turnRaw;
            mag = (u16)(t >= 0 ? t : -t);
        }
        if (playerFindNearestFirefly(Obj_GetPlayerObject()) != 0)
        {
            range = 100.0f;
            other = (GameObject*)objGetNearestTypeTo(LANTERNFIREFLY_OBJGROUP, obj, &range);
            if (other != NULL)
            {
                s16 yaw = Obj_GetYawDeltaToObject(obj, other, &range);
                int t;
                yaw = (yaw < -300) ? -300 : ((yaw > 300) ? 300 : yaw);
                t = yaw;
                enemyState->phaseAngle = t;
                t = yaw >= 0 ? yaw : -yaw;
                if (t < 0x4000)
                {
                    *(s16*)obj = -*(s16*)obj;
                    posB[0] = obj->anim.localPosX;
                    posB[1] = obj->anim.localPosY;
                    posB[2] = obj->anim.localPosZ;
                    angleToVec2Fast((u16)obj->anim.rotX, &sinB, &cosB);
                    tgtB[0] = -(10.0f * sinB - obj->anim.localPosX);
                    tgtB[1] = 5.0f + obj->anim.localPosY;
                    tgtB[2] = -(10.0f * cosB - obj->anim.localPosZ);
                    if ((u8)trackGetLineIntersect(posB, tgtB, 0.0f, 3, &bufB, obj,
                                               enemyState->bboxTraceFlags, -1, 0xff, 0) == 0)
                    {
                        if ((enemyState->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
                        {
                            baddieSetMove(obj, state, 7, 1.0f / (2.0f * scale), 0, 1);
                        }
                        obj->anim.rotY = enemyState->spawnRotY;
                        obj->anim.rotZ = enemyState->spawnRotZ;
                    }
                    *(s16*)obj = -*(s16*)obj;
                }
                return;
            }
        }
        if (enemyState->trackedObj != NULL &&
            ((GameObject*)enemyState->trackedObj)->anim.hitboxScale > 56.0f)
        {
            enemyState->sightRange = gHoodedZyckLargeTargetSpeedScale;
        }
        if ((enemyState->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0 || noHit == 0 ||
            (mag < 3000 && noHit != 0 && obj->anim.currentMove != 0))
        {
            if (noHit != 0 && mag < 3000)
            {
                enemyState->phaseAngle = 0;
                baddieSetMove(obj, state, 0, 1.0f / scale, 0, 1);
            }
            else
            {
                baddieSetMove(obj, state, 1, 0.75f / scale, 0, 0);
                {
                    f32 z = 0.0f;
                    obj->anim.velocityX = z;
                    obj->anim.velocityY = z;
                    obj->anim.velocityZ = z;
                }
                if (mag < 3000)
                {
                    enemyState->phaseAngle = (randomGetRange(0, 1) - 1) * 300;
                }
                else if ((s16)turnRaw < 0)
                {
                    enemyState->phaseAngle = 0xfed4;
                }
                else
                {
                    enemyState->phaseAngle = 300;
                }
            }
        }
        obj->anim.rotY = enemyState->spawnRotY;
        obj->anim.rotZ = enemyState->spawnRotZ;
    }
}

void hoodedZyck_update(GameObject* obj, u8* state)
{
    EnemyState* enemyState = (EnemyState*)state;
    int moved;
    int turnRaw;
    u16 mag;
    u32 grabbed;

    hoodedZyck_tickPhaseTimer(enemyState);

    if (enemyState->crawler.emergeTimer != 0.0f)
    {
        ObjHits_DisableObject(obj);
        if (obj->anim.currentMove != 5)
        {
            baddieSetMove(obj, state, 5, gHoodedZyckEmergeMoveSpeed, 0, 0);
        }
        else if ((enemyState->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
        {
            ObjHits_EnableObject(obj);
            enemyState->crawler.emergeTimer = 0.0f;
        }
        obj->anim.alpha = 0xff;
        moved = 1;
    }
    else
    {
        moved = 0;
    }

    if (moved == 0)
    {
        f32 z;
        *(s16*)obj = (f32)enemyState->phaseAngle * timeDelta + (f32)(int)*(s16*)obj;
        z = 0.0f;
        obj->anim.velocityX = z;
        obj->anim.velocityY = z;
        obj->anim.velocityZ = z;
        ObjHits_SetHitVolumeSlot(&obj->anim, FIRECRAWLER_HIT_VOLUME_SLOT, 1, -1);
        turnRaw = hoodedZyck_getAngleDelta(obj, (GameObject*)enemyState->trackedObj);
        {
            int t = (s16)turnRaw;
            mag = (u16)(t >= 0 ? t : -t);
        }
        ObjHits_EnableObject(obj);
        grabbed = enemyState->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN;
        if (grabbed != 0 && obj->anim.currentMove == 6)
        {
            baddieSetMove(obj, state, 4, gHoodedZyckFollowUpMoveSpeed, 0, 1);
        }
        else
        {
            if (grabbed != 0 ||
                (mag < 1000 && obj->anim.currentMove != 2 && obj->anim.currentMove != 4 &&
                 obj->anim.currentMove != 6))
            {
                if (mag < 1000)
                {
                    if (enemyState->sightRange < 40.0f)
                    {
                        baddieSetMove(obj, state, 2, 0.75f, 0, 0);
                    }
                    else
                    {
                        baddieSetMove(obj, state, 6, gHoodedZyckLungeMoveSpeed, 0, 0);
                    }
                    enemyState->phaseAngle = 0;
                }
                else
                {
                    baddieSetMove(obj, state, 1, 0.75f, 0, 0);
                    if ((s16)turnRaw < 0)
                    {
                        enemyState->phaseAngle = 0xfed4;
                    }
                    else
                    {
                        enemyState->phaseAngle = 300;
                    }
                }
            }
            obj->anim.rotY = enemyState->spawnRotY;
            obj->anim.rotZ = enemyState->spawnRotZ;
        }
    }
}

void hoodedZyck_init(GameObject* obj, EnemyState* st)
{
    f32 ratio;
    f32 base_v;
    u32 flags;
    u32 amt;
    amt = ((GroundBaddiePlacement*)obj->anim.placementData)->aggression;
    ratio = amt;
    if (amt == 0.0f)
    {
        ratio = 10.0f;
    }
    ratio = ratio / 10.0f;
    st->sightRange = 30.0f;
    st->flags2E4 = 0x8b;
    flags = st->flags2E4;
    st->flags2E4 = flags | 0x20;
    st->animPlaySpeed = 0.02f * ratio;
    base_v = 1.0f;
    st->gravity = base_v;
    st->drag = 0.97f;
    *((u8*)st + 0x320) = 0;
    st->moveSpeedScale0 = 1.5f;
    *((u8*)st + 0x321) = 3;
    {
        f32 d2 = 2.0f;
        st->moveSpeedScale1 = d2;
        *((u8*)st + 0x322) = 5;
        st->moveSpeedScale2 = d2;
    }
    st->phaseAngle = 0;
    st->crawler.engineTimer = 60.0f;
    st->crawler.emergeTimer = base_v;
    obj->anim.alpha = 0;
    st->pathStep = 0.5f * ratio;
    st->flags2E8 = 0;
    ObjHits_EnableObject(obj);
}

f32 gHoodedZyckFollowUpMoveSpeed = 0.7f;

f32 gHoodedZyckLungeMoveSpeed = 2.0f;

f32 gHoodedZyckLargeTargetSpeedScale = 110.0f;

f32 gHoodedZyckEmergeMoveSpeed = 2.0f;
