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
#include "main/dll/dll_00C9_enemy.h"
#include "main/dll/wispbaddie_baddie.h"
#include "main/audio/sfx_position_api.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/baddie_setmove.h"
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

void gcRobotPatrol_init(GameObject* obj, int state);

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
    u8* setup;

    sub = (ObjPlacement*)(obj->anim.placementData);
    Obj_GetPlayerObject();
    if (Obj_IsLoadingLocked() == 0)
        return NULL;
    setup = (u8*)Obj_AllocObjectSetup(36, childId);
    ((ObjPlacement*)setup)->objectId = childId;
    ((ObjPlacement*)setup)->color[0] = sub->color[0];
    ((ObjPlacement*)setup)->color[2] = sub->color[2];
    ((ObjPlacement*)setup)->color[1] = 1;
    ((ObjPlacement*)setup)->color[3] = sub->color[3];
    ((ObjPlacement*)setup)->posX = obj->anim.localPosX;
    ((ObjPlacement*)setup)->posY = obj->anim.localPosY;
    ((ObjPlacement*)setup)->posZ = obj->anim.localPosZ;
    ((Seq11EChildSetup*)setup)->unk19 = 0;
    ((Seq11EChildSetup*)setup)->unk20 = 149;
    return objSetupObject((ObjPlacement*)setup, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
}

void gcRobotPatrol_updateWhileFrozen(int obj, u8* state, GameObject* attacker, int msg, int wpad0, int wpad1, Vec* wpad2,
                                     int wpad3) {
    GroundBaddiePlacement* sub[1];
    f32 fz;

    sub[0] = (GroundBaddiePlacement*)((GameObject*)obj)->anim.placementData;
    if (msg == 16 || msg == 17) {
        return;
    }
    Sfx_PlayFromObject((GameObject*)(u32)obj, SFXTRIG_wp_pole1_c_23);
    Sfx_PlayFromObject((GameObject*)(u32)obj, SFXTRIG_en_lrope_powerdown);
    ((EnemyState*)state)->flags2E8 |= 0x8;
    ((EnemyState*)state)->gcRobot.cooldownTimer = (f32)(u32)(u16)sub[0]->respawnDelay;
    baddieSetMove((GameObject*)obj, (int)state, 1, 2.5f, 0, 0);
    ((EnemyState*)state)->flags2E4 &= ~0x20LL;
    fz = 0.0f;
    ((GameObject*)obj)->anim.velocityZ = 0.0f;
    ((GameObject*)obj)->anim.velocityY = fz;
    ((GameObject*)obj)->anim.velocityX = fz;
}

void gcRobotPatrol_update(GameObject* obj, u8* state)
{
    GroundBaddiePlacement* def;
    RomCurveWalker* path;
    int attached;
    s16 spd;
    SeqFxParams fx;

    def = (GroundBaddiePlacement*)obj->anim.placementData;
    path = *(RomCurveWalker**)state;
    if (((EnemyState*)state)->gcRobot.cooldownTimer > 0.0f)
    {
        GameObject* child = obj->childObjs[0];
        if (child != 0)
        {
            Obj_FreeObject(child);
            ObjLink_DetachChild(obj, obj->childObjs[0]);
            obj->childObjs[0] = 0;
        }
        ((EnemyState*)state)->gcRobot.cooldownTimer = ((EnemyState*)state)->gcRobot.cooldownTimer - timeDelta;
        if (((EnemyState*)state)->gcRobot.cooldownTimer <= 0.0f)
        {
            ((EnemyState*)state)->gcRobot.cooldownTimer = 0.0f;
            ((EnemyState*)state)->flags2E4 |= 0x20;
            Sfx_StopObjectChannel(obj, 4);
            baddieSetMove(obj, (int)state, 0, 1.0f, 0, 0);
        }
        else if (!(((EnemyState*)state)->flags2E4 & 0x20))
        {
            return;
        }
    }
    if (((EnemyState*)state)->controlFlags & BADDIE_CONTROL_PATH_FOLLOW)
    {
        int step;

        if (Curve_AdvanceAlongPath(&path->curve, ((EnemyState*)state)->pathStep) != 0 || path->atSegmentEnd != 0)
        {
            if ((*gRomCurveInterface)->goNextPoint(path) != 0)
            {
                if ((*gRomCurveInterface)
                        ->initCurve(*(RomCurveWalker**)state, obj, 700.0f, (int*)&gGcRobotPatrolCurveInitData, -1) != 0)
                {
                    ((EnemyState*)state)->controlFlags &= ~(u64)BADDIE_CONTROL_PATH_FOLLOW;
                }
            }
        }
        obj->anim.velocityX = (path->posX - obj->anim.localPosX) / timeDelta;
        obj->anim.velocityZ = (path->posZ - obj->anim.localPosZ) / timeDelta;
        step = (s8)def->rotX;
        if (step == 0)
        {
            baddieTurnTowardPoint(obj, (int)state, path->posX, path->posZ, 0xf, 0);
        }
        else if (((EnemyState*)state)->controlFlags & BADDIE_CONTROL_PATH_FOLLOW)
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
            obj->anim.rotX = obj->anim.rotX - step;
            baddieTurnTowardPoint(obj, (int)state, path->posX, path->posZ, 0xf, 0);
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
            ((EnemyState*)state)->userData1 = 1;
        }
        else
        {
            ((EnemyState*)state)->userData1 = 0;
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
            ((EnemyState*)state)->userData1 = 1;
        }
        else
        {
            ((EnemyState*)state)->userData1 = 0;
        }
        obj->anim.rotX += (s8)def->rotX;
    }
    if (((EnemyState*)state)->userData1 != 0)
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
    if (((EnemyState*)state)->gcRobot.cooldownTimer == 0.0f)
    {
        GameObject* child2;

        if (def->sequenceId != -1 && (child2 = obj->childObjs[0]) != 0 &&
            gcRobotLightBeam_isPlayerCaught(child2) != 0)
        {
            ObjHits_RecordObjectHit(Obj_GetPlayerObject(), obj, 0x16, 2, 0);
            gcRobotLight_init(obj, 0x3b2);
            Sfx_PlayFromObject(obj, SFXTRIG_wp_rolovr_6);
            ((EnemyState*)state)->gcRobot.cooldownTimer = gGcRobotPatrolCatchCooldown;
        }
        if ((int)randomGetRange(0, (int)(1000.0f * oneOverTimeDelta)) == 0)
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
            if ((s8)def->rotX != 0 && !(((EnemyState*)state)->controlFlags & BADDIE_CONTROL_PATH_FOLLOW))
            {
                flag = 1;
            }
            newObj->userData1 = flag;
            ObjLink_AttachChild(obj, newObj, attached);
        }
    }
}

void gcRobotPatrol_init(GameObject* obj, int state)
{
    f32 fz;

    ((EnemyState*)state)->sightRange = 60.0f;
    ((EnemyState*)state)->flags2E4 = 41;
    ((EnemyState*)state)->flags2E4 |= 0x7000;
    ((EnemyState*)state)->flags2E4 |= 0x20000LL;
    ((EnemyState*)state)->animPlaySpeed = 0.005f;
    ((EnemyState*)state)->gravity = 0.006f;
    ((EnemyState*)state)->drag = 0.99f;
    ((EnemyState*)state)->moveId0 = 0;
    fz = 1.0f;
    ((EnemyState*)state)->moveSpeedScale0 = fz;
    ((EnemyState*)state)->moveId1 = 0;
    ((EnemyState*)state)->moveSpeedScale1 = fz;
    ((EnemyState*)state)->moveId2 = 0;
    ((EnemyState*)state)->moveSpeedScale2 = fz;
    ((EnemyState*)state)->gcRobot.cooldownTimer = 0.0f;
    obj->anim.hitboxScale = 100.0f;
    Sfx_AddLoopedObjectSound(obj, SFXTRIG_tr_bcrek1_c);
}

const f32 gGcRobotPatrolZero = 0.0f;
