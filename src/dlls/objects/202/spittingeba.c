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

/* Baddie-family animation data shared with the sequence-driver TUs. */

#define DUSTER_CHILD_OBJ_POLLEN_SPIT 0x47b
#define DUSTER_HIT_VOLUME_SLOT       10


void spittingEbaSpawnPollen(GameObject* obj, int state)
{
    u32 loadLocked;
    int ref;
    ObjPlacement* setup;
    f32 spd;
    f32 t;
    f32 dx;
    f32 dz;
    f32 a[3];
    f32 b[3];
    float velXZ;
    float cosVal;
    float velY;
    float cosPitch;

    loadLocked = Obj_CanSetupObject();
    if ((loadLocked & 0xff) != 0)
    {
        a[0] = obj->anim.localPosX;
        a[1] = 15.0f + obj->anim.localPosY;
        a[2] = obj->anim.localPosZ;
        ref = (int)((EnemyState*)state)->trackedObj;
        b[0] = ((GameObject*)ref)->anim.localPosX;
        b[1] = 30.0f + ((GameObject*)ref)->anim.localPosY;
        b[2] = ((GameObject*)ref)->anim.localPosZ;
        spd = (3.25f) * ((0.02f) * (f32)(int)randomGetRange(-10, 10) + (1.0f));
        ref = pinponspike_calculateLaunchAngle(a, b, spd, 1, (0.045f));
        angleToVec2Precise(ref, &cosVal, &velXZ);
        velXZ = velXZ * spd;
        cosVal = cosVal * spd;
        dx = b[0] - obj->anim.localPosX;
        dz = b[2] - obj->anim.localPosZ;
        if (dz != 0.0f)
        {
            ref = getAngle(dx, dz);
            angleToVec2Precise(ref, &cosPitch, &velY);
            t = velXZ;
            velY = velY * t;
            velXZ = t * cosPitch;
        }
        else
        {
            velY = 0.0f;
        }
        setup = Obj_AllocObjectSetup(0x24, DUSTER_CHILD_OBJ_POLLEN_SPIT);
        setup->posX = a[0];
        setup->posY = a[1];
        setup->posZ = a[2];
        setup->color[0] = 1;
        setup->color[1] = 1;
        setup->color[2] = 0xff;
        setup->color[3] = 0xff;
        ref = (int)objSetupObject((ObjPlacement*)setup, 5, -1, -1, 0);
        if ((void*)ref != NULL)
        {
            ((GameObject*)ref)->anim.velocityX = velXZ;
            ((GameObject*)ref)->anim.velocityY = cosVal;
            ((GameObject*)ref)->anim.velocityZ = velY;
            ((GameObject*)ref)->ownerObj = obj;
            Sfx_PlayFromObject(obj, SFXTRIG_baddie_mika_cackle);
        }
    }
    return;
}

void spittingEbaUpdateTimeOfDay(int obj, int state)
{
    u8 isDaytime;
    float timeInfo[4];

    (*gSkyInterface)->getTimeOfDay(timeInfo);
    if ((timeInfo[0] >= 21600.0f) && (timeInfo[0] <= 64800.0f))
    {
        isDaytime = 1;
    }
    else
    {
        isDaytime = 0;
    }
    if ((isDaytime != 0) && (((EnemyState*)state)->userData1 == 0))
    {
        ((EnemyState*)state)->userData1 = 1;
        ((EnemyState*)state)->flags2E4 = ((EnemyState*)state)->flags2E4 | 0x10000LL;
        Baddie_SetMove(obj, state, 1, 2.0f, 0, 0);
    }
    else if ((isDaytime == 0) && (((EnemyState*)state)->userData1 == 2))
    {
        ((EnemyState*)state)->userData1 = 1;
        ((EnemyState*)state)->flags2E4 = ((EnemyState*)state)->flags2E4 | 0x10000LL;
        Baddie_SetMove(obj, state, 3, 2.0f, 0, 0);
    }
    return;
}

void spittingEbaUpdateWhileFrozen(GameObject* obj, u8* state, GameObject* attacker, int eventKind, int unused2, int damage,
                                  Vec* wpad0, int wpad1)
{
    if (eventKind == 0x10)
    {
        ((EnemyState*)state)->flags2E8 = ((EnemyState*)state)->flags2E8 | 0x20;
    }
    else if (eventKind == 0x11)
    {
        if ((((EnemyState*)state)->userData1 == 2) && (((GameObject*)obj)->anim.currentMove != 5))
        {
            Baddie_SetMove(obj, state, 5, 3.0f, 0, 0);
        }
    }
    else if ((((GameObject*)obj)->anim.currentMove == 5) || (((GameObject*)obj)->anim.currentMove == 4))
    {
        if (damage > (int)(u32)((EnemyState*)state)->current)
        {
            ((EnemyState*)state)->current = 0;
            Sfx_PlayFromObject((GameObject*)(u32)obj, SFXTRIG_baddie_zyck_strike);
            Sfx_PlayFromObject((GameObject*)(u32)obj, SFXTRIG_stftest);
        }
        else
        {
            ((EnemyState*)state)->current = ((EnemyState*)state)->current - damage;
            Sfx_PlayFromObject((GameObject*)(u32)obj, SFXTRIG_baddie_kooshy_call);
            Sfx_PlayFromObject((GameObject*)(u32)obj, SFXTRIG_stftest);
        }
        ((EnemyState*)state)->flags2E8 = ((EnemyState*)state)->flags2E8 | 8;
    }
    else
    {
        ((EnemyState*)state)->flags2E8 = ((EnemyState*)state)->flags2E8 | 0x10;
        Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_mv_ladderslide16_250);
    }
    return;
}

void spittingEbaUpdateIdle(GameObject* obj, int state)
{
    ((EnemyState*)state)->duster.phaseTimer = 0.0f;
    if ((((EnemyState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
    {
        if (((EnemyState*)state)->userData1 == 1)
        {
            if ((obj)->anim.currentMove == 1)
            {
                ((EnemyState*)state)->userData1 = 2;
                ((EnemyState*)state)->flags2E4 = ((EnemyState*)state)->flags2E4 & ~0x10000LL;
            }
            else if ((obj)->anim.currentMove == 3)
            {
                ((EnemyState*)state)->userData1 = 0;
                ((EnemyState*)state)->flags2E4 = ((EnemyState*)state)->flags2E4 | 0x10000LL;
                Baddie_SetMove(obj, state, 0, (1.0f), 0, 0);
            }
        }
        else if ((((EnemyState*)state)->userData1 == 2) && ((obj)->anim.currentMove != 2))
        {
            Baddie_SetMove(obj, state, 2, (1.0f), 0, 0);
        }
    }
    spittingEbaUpdateTimeOfDay((int)obj, state);
    return;
}

void spittingEbaUpdateEngaged(GameObject* obj, int state)
{
    u8 timerExpired;

    timerExpired = 0;
    ((EnemyState*)state)->duster.phaseTimer = ((EnemyState*)state)->duster.phaseTimer - timeDelta;
    if (((EnemyState*)state)->duster.phaseTimer <= 0.0f)
    {
        timerExpired = 1;
        ((EnemyState*)state)->duster.phaseTimer = 0.0f;
    }
    if ((((EnemyState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
    {
        if (obj->anim.currentMove == 4)
        {
            spittingEbaSpawnPollen(obj, state);
            ((EnemyState*)state)->duster.phaseTimer = 180.0f;
            Baddie_SetMove(obj, state, 5, (1.0f), 0, 0);
        }
        else if ((obj->anim.currentMove == 5) && (timerExpired))
        {
            Baddie_SetMove(obj, state, 6, (1.0f), 0, 0);
            Sfx_PlayFromObject(obj, SFXTRIG_baddie_kooshy_death);
        }
        else if (obj->anim.currentMove == 6)
        {
            Baddie_SetMove(obj, state, 2, (1.0f), 0, 0);
            ((EnemyState*)state)->duster.phaseTimer = 180.0f;
        }
        else if ((obj->anim.currentMove == 2) && (timerExpired) &&
                 ((((EnemyState*)state)->controlFlags & 0x4000000) != 0))
        {
            Baddie_SetMove(obj, state, 4, (1.0f), 0, 0);
            Sfx_PlayFromObject(obj, SFXTRIG_baddie_kooshy_hit);
        }
    }
    spittingEbaUpdateTimeOfDay((int)obj, state);
    return;
}

void spittingEbaInit(u32 unused, int state)
{
    float fa;
    float fb;

    ((EnemyState*)state)->sightRange = 40.0f;
    ((EnemyState*)state)->flags2E4 = 1;
    ((EnemyState*)state)->animPlaySpeed = (0.02f);
    ((EnemyState*)state)->gravity = 0.1f;
    ((EnemyState*)state)->drag = 0.97f;
    ((EnemyState*)state)->moveId0 = 0;
    fb = 1.5f;
    ((EnemyState*)state)->moveSpeedScale0 = 1.5f;
    ((EnemyState*)state)->moveId1 = 7;
    fa = (1.0f);
    ((EnemyState*)state)->moveSpeedScale1 = (1.0f);
    ((EnemyState*)state)->moveId2 = 0;
    ((EnemyState*)state)->moveSpeedScale2 = fb;
    ((EnemyState*)state)->userData1 = 0;
    ((EnemyState*)state)->duster.phaseTimer = 0.0f;
    ((EnemyState*)state)->pathStep = fa;
    return;
}
