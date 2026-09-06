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
#include "main/audio/sfx_looped_object_api.h"
#include "main/audio/sfx_stop_channel_api.h"

/* Baddie-family animation data shared with the sequence-driver TUs. */

/* gcRobotPatrol_update: main update: child-zap timer, curve follow, heading steps,
 * landing sfx, light-pulse fx, child spark spawn. */

typedef struct
{
    u8 pad[8];
    f32 a;
    f32 b;
    f32 c;
    f32 d;
} SeqFxParams;

void gcRobotPatrol_update(GameObject* obj, u8* state);

void gcRobotPatrol_init(GameObject* obj, void* state);

static inline int hoodedZyck_getAngleDelta(GameObject* obj, GameObject* target)
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

int gGcRobotPatrolCurveInitData[2] = {2, 3};

f32 gGcRobotPatrolRiseAccel = 0.018f;

f32 gGcRobotPatrolCatchCooldown = 240.0f;

GameObject* gcRobotLight_init(GameObject* obj, int childId)
{
    ObjPlacement* sub;
    Seq11EChildSetup* setup;
    u8 canSetupObject;

    sub = (ObjPlacement*)obj->anim.placementData;
    Obj_GetPlayerObject();
    canSetupObject = Obj_CanSetupObject();
    if (canSetupObject == 0)
        return NULL;
    setup = (Seq11EChildSetup*)Obj_AllocObjectSetup(sizeof(*setup), childId);
    setup->head.objectId = childId;
    setup->head.color[0] = sub->color[0];
    setup->head.color[2] = sub->color[2];
    setup->head.color[1] = 1;
    setup->head.color[3] = sub->color[3];
    setup->head.posX = obj->anim.localPosX;
    setup->head.posY = obj->anim.localPosY;
    setup->head.posZ = obj->anim.localPosZ;
    setup->unk19 = 0;
    setup->unk20 = 149;
    return objSetupObject(&setup->head, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
}

void gcRobotPatrol_updateWhileFrozen(GameObject* obj, u8* state, GameObject* attacker, int msg, int wpad0, int wpad1, Vec* wpad2,
                                     int wpad3) {
    EnemyState* enemyState = (EnemyState*)state;
    GroundBaddiePlacement* sub;
    f32 fz;

    sub = (GroundBaddiePlacement*)obj->anim.placementData;
    if (msg == 16 || msg == 17) {
        return;
    }
    Sfx_PlayFromObject(obj, SFXTRIG_wp_pole1_c_23);
    Sfx_PlayFromObject(obj, SFXTRIG_en_lrope_powerdown);
    enemyState->flags2E8 |= 0x8;
    enemyState->gcRobot.cooldownTimer = (f32)(u16)sub->respawnDelay;
    baddieSetMove(obj, state, 1, 2.5f, 0, 0);
    enemyState->flags2E4 &= ~0x20;
    fz = 0.0f;
    obj->anim.velocityZ = 0.0f;
    obj->anim.velocityY = fz;
    obj->anim.velocityX = fz;
}

void gcRobotPatrol_update(GameObject* obj, u8* state)
{
    EnemyState* enemyState = (EnemyState*)state;
    GroundBaddiePlacement* def;
    RomCurveWalker* path;
    int attached;
    s16 spd;
    SeqFxParams fx;

    def = (GroundBaddiePlacement*)obj->anim.placementData;
    path = *(RomCurveWalker**)state;
    if (enemyState->gcRobot.cooldownTimer > 0.0f)
    {
        GameObject* child = obj->childObjs[0];
        if (child != 0)
        {
            Obj_FreeObject(child);
            ObjLink_DetachChild(obj, obj->childObjs[0]);
            obj->childObjs[0] = 0;
        }
        enemyState->gcRobot.cooldownTimer -= timeDelta;
        if (enemyState->gcRobot.cooldownTimer <= 0.0f)
        {
            enemyState->gcRobot.cooldownTimer = 0.0f;
            enemyState->flags2E4 |= 0x20;
            Sfx_StopObjectChannel(obj, 4);
            baddieSetMove(obj, state, 0, 1.0f, 0, 0);
        }
        else if (!(enemyState->flags2E4 & 0x20))
        {
            return;
        }
    }
    if (enemyState->controlFlags & BADDIE_CONTROL_PATH_FOLLOW)
    {
        int step;

        if (Curve_AdvanceAlongPath(&path->curve, enemyState->pathStep) != 0 || path->atSegmentEnd != 0)
        {
            if ((*gRomCurveInterface)->goNextPoint(path) != 0)
            {
                if ((*gRomCurveInterface)
                        ->initCurve(*(RomCurveWalker**)state, obj, 700.0f, gGcRobotPatrolCurveInitData, -1) != 0)
                {
                    enemyState->controlFlags &= ~BADDIE_CONTROL_PATH_FOLLOW;
                }
            }
        }
        obj->anim.velocityX = (path->posX - obj->anim.localPosX) / timeDelta;
        obj->anim.velocityZ = (path->posZ - obj->anim.localPosZ) / timeDelta;
        step = (s8)def->rotX;
        if (step == 0)
        {
            baddieTurnTowardPoint(obj, state, path->posX, path->posZ, 0xf, 0);
        }
        else if (enemyState->controlFlags & BADDIE_CONTROL_PATH_FOLLOW)
        {
            spd = step << 8;
            if ((int)(10.0f * path->tangentY) >= 0)
            {
                step = spd;
            }
            else
            {
                step = -spd;
            }
            obj->anim.rotX -= step;
            baddieTurnTowardPoint(obj, state, path->posX, path->posZ, 0xf, 0);
            if ((int)(10.0f * path->tangentY) >= 0)
            {
                step = spd;
            }
            else
            {
                step = -spd;
            }
            obj->anim.rotX += step;
        }
        else
        {
            step = ((int)(10.0f * path->tangentY) >= 0) ? step : -step;
            obj->anim.rotX += step;
        }
        if (obj->anim.localPosY - path->posY < -1.0f)
        {
            if (Sfx_IsPlayingFromObject(obj, SFXTRIG_dn_boar1_c_18d) == 0)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_18d);
            }
            enemyState->userData1 = 1;
        }
        else
        {
            enemyState->userData1 = 0;
        }
    }
    else
    {
        if (obj->anim.localPosY - def->base.posY < -0.4f)
        {
            if (Sfx_IsPlayingFromObject(obj, SFXTRIG_dn_boar1_c_18d) == 0)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_18d);
            }
            enemyState->userData1 = 1;
        }
        else
        {
            enemyState->userData1 = 0;
        }
        obj->anim.rotX += (s8)def->rotX;
    }
    if (enemyState->userData1 != 0)
    {
        obj->anim.velocityY += gGcRobotPatrolRiseAccel * timeDelta;
    }
    if (obj->objectFlags & OBJECT_OBJFLAG_RENDERED)
    {
        f32 z = 0.0f;
        fx.b = z;
        fx.c = z;
        fx.d = z;
        fx.a = 1.0f;
        objfx_spawnLightPulse(obj, 0.5f, 2, 0, 6, 0.25f, &fx);
        fx.c = 12.0f;
        objfx_spawnMaskedHitEffect(obj, 0.4f, 1, 6, 0x20, &fx);
        fx.b = 0.0f;
        z = -30.0f;
        fx.c = z;
        fx.d = z;
    }
    if (obj->anim.velocityY < -0.5f)
    {
        obj->anim.velocityY = -0.5f;
    }
    else if (obj->anim.velocityY > 0.5f)
    {
        obj->anim.velocityY = 0.5f;
    }
    if (enemyState->gcRobot.cooldownTimer == 0.0f)
    {
        GameObject* child2;

        if (def->sequenceId != -1 && (child2 = obj->childObjs[0]) != 0 &&
            gcRobotLightBeam_isPlayerCaught(child2) != 0)
        {
            ObjHits_RecordObjectHit(Obj_GetPlayerObject(), obj, 0x16, 2, 0);
            gcRobotLight_init(obj, 0x3b2);
            Sfx_PlayFromObject(obj, SFXTRIG_wp_rolovr_6);
            enemyState->gcRobot.cooldownTimer = gGcRobotPatrolCatchCooldown;
        }
        if (randomGetRange(0, (int)(1000.0f * oneOverTimeDelta)) == 0)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_sp_literun114);
        }
        child2 = obj->childObjs[0];
        if (child2 != 0)
        {
            ObjTextureRuntimeSlot* tex = objFindTexture(child2, 0, 0);
            int v;
            if (tex != 0)
            {
                v = tex->offsetS - 0x3c;
                if (v < 0)
                {
                    v += 0x2710;
                }
                tex->offsetS = v;
            }
        }
        else
        {
            GameObject* newObj;
            int flag;

            if ((s8)def->rotX != 0)
            {
                attached = 1;
            }
            else
            {
                attached = 0;
            }
            newObj = gcRobotLight_init(obj, 0x639);
            flag = 0;
            if ((s8)def->rotX != 0 && !(enemyState->controlFlags & BADDIE_CONTROL_PATH_FOLLOW))
            {
                flag = 1;
            }
            newObj->userData1 = flag;
            ObjLink_AttachChild(obj, newObj, attached);
        }
    }
}

void gcRobotPatrol_init(GameObject* obj, void* state)
{
    EnemyState* enemyState = (EnemyState*)state;
    f32 fz;

    enemyState->sightRange = 60.0f;
    enemyState->flags2E4 = 41;
    enemyState->flags2E4 |= 0x7000;
    enemyState->flags2E4 |= 0x20000;
    enemyState->animPlaySpeed = 0.005f;
    enemyState->gravity = 0.006f;
    enemyState->drag = 0.99f;
    enemyState->moveId0 = 0;
    fz = 1.0f;
    enemyState->moveSpeedScale0 = fz;
    enemyState->moveId1 = 0;
    enemyState->moveSpeedScale1 = fz;
    enemyState->moveId2 = 0;
    enemyState->moveSpeedScale2 = fz;
    enemyState->gcRobot.cooldownTimer = 0.0f;
    obj->anim.hitboxScale = 100.0f;
    Sfx_AddLoopedObjectSound(obj, SFXTRIG_tr_bcrek1_c);
}

const f32 gGcRobotPatrolZero = 0.0f;
