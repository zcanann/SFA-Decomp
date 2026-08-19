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

#define FIREFLYLANTERN_HIT_VOLUME_SLOT 0xe

int gPinPonCurveInitData[2] = {2, 3};

void baddieSpawnWaterRipple(GameObject* obj, EnemyState* state)
{
    f32 mtx[17];
    MatrixTransform stk;
    f32 tx;
    f32 ox;
    f32 tz;

    state->fireflyLantern.rippleTimer -= timeDelta;
    if (state->fireflyLantern.rippleTimer <= 0.0f)
    {
        state->fireflyLantern.rippleTimer = (f32)(s32)randomGetRange(30, 60);
        stk.x = obj->anim.localPosX;
        stk.y = 0.0f;
        stk.z = obj->anim.localPosZ;
        stk.rotX = obj->anim.rotX;
        stk.rotY = 0;
        stk.rotZ = 0;
        stk.scale = 1.0f;
        setMatrixFromObjectPos(mtx, &stk);
        tx = 5.0f + (f32)(s32)randomGetRange(-20, 20) / 10.0f;
        tz = 2.0f + (f32)(s32)randomGetRange(-20, 20) / 10.0f;
        Matrix_TransformPoint(mtx, tx, 0.0f, tz, &tx, &ox, &tz);
        (*gWaterfxInterface)->spawnRipple(tx, state->fireflyLantern.anchorY, tz, 0, 0.0f, 3);
        if (sqrtf(obj->anim.velocityX * obj->anim.velocityX + obj->anim.velocityZ * obj->anim.velocityZ) > 0.5f)
        {
            Sfx_PlayAtPositionFromObject(obj, stk.x, stk.y, stk.z, SFXstaff_proj_putaway);
        }
    }
}

void pinPon_updateWhileFrozen(GameObject* obj, EnemyState* state, GameObject* attacker, int cmd, int wpad0, int wpad1,
                              Vec* wpad2, int wpad3)
{
    if (cmd == 17 || cmd == 16)
        return;
    if (((GameObject*)obj)->anim.currentMoveProgress > 0.5f)
    {
        state->flags2E8 |= 8;
        Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_en_rfall5_c);
        Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_wp_iceywindlp16_233);
        state->current = 0;
        state->flags2E4 |= 32;
    }
    else
    {
        state->flags2E8 |= 16;
    }
}

void pinPon_updateIdle(GameObject* obj, void* state)
{
    ObjHitsPriorityState* hitState;
    RomCurveWalker* curve;
    u8 rnd;
    f32 vec[3];

    curve = *(RomCurveWalker**)state;
    ((EnemyState*)state)->userData2 = 0;
    hitState = (ObjHitsPriorityState*)(obj)->anim.hitReactState;
    hitState->suppressOutgoingHits = 0;
    if ((((EnemyState*)state)->controlFlags & BADDIE_CONTROL_PATH_FOLLOW) != 0)
    {
        if ((Curve_AdvanceAlongPath(&curve->curve, ((EnemyState*)state)->pathStep) != 0 ||
             curve->atSegmentEnd != 0) &&
            (*gRomCurveInterface)->goNextPoint((void*)curve) != 0 &&
            (*gRomCurveInterface)
                    ->initCurve(*(RomCurveWalker**)state, (void*)obj, 700.0f, gPinPonCurveInitData, -1) != 0)
        {
            ((EnemyState*)state)->controlFlags &= ~(u64)BADDIE_CONTROL_PATH_FOLLOW;
        }
        vec[0] = curve->posX - (obj)->anim.localPosX;
        vec[1] = 0.0f;
        vec[2] = curve->posZ - (obj)->anim.localPosZ;
        enemy_steerVelocityToward(obj, (void*)state, vec, 2.0f, 0.1f, 0.1f, 1);
        ((EnemyState*)state)->pinPon.idleTimer += timeDelta;
        if (((EnemyState*)state)->pinPon.idleTimer > 360.0f)
        {
            ((EnemyState*)state)->flags2E4 &= ~(u64)0x10000;
            ((EnemyState*)state)->pinPon.idleTimer = 0.0f;
        }
    }
    (obj)->anim.rotY =
        -(1024.0f * mathSinfFast(0.19634955f * (f32)(u32)((EnemyState*)state)->userData1) - (f32)(obj)->anim.rotY);
    baddieTurnTowardLookDir(obj, (void*)state, 0xf, 7.5f, 1.0f, 0);
    if ((((EnemyState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
    {
        if ((obj)->anim.currentMoveProgress < 0.5)
        {
            rnd = randomGetRange(0, 200);
        }
        else
        {
            rnd = randomGetRange(0, 0x3c);
        }
        if (rnd == 0)
        {
            if ((obj)->anim.currentMoveProgress > 0.5)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_baddie_kooshy_hit);
                ((EnemyState*)state)->animPlaySpeed = -0.02f;
            }
            else
            {
                Sfx_PlayFromObject(obj, SFXTRIG_baddie_kooshy_death);
                ((EnemyState*)state)->animPlaySpeed = 0.02f;
            }
        }
    }
    ((EnemyState*)state)->userData1 += 1;
    (obj)->anim.rotY =
        1024.0f * mathSinfFast(0.19634955f * (f32)(u32)((EnemyState*)state)->userData1) + (f32)(obj)->anim.rotY;
    baddieSpawnWaterRipple(obj, (EnemyState*)state);
}

void pinPon_updateEngaged(GameObject* obj, int* state)
{
    RomCurveWalker* curve;
    u8 flag;
    f32 dvec[3];
    f32 fval;

    curve = *(RomCurveWalker**)state;
    if (((EnemyState*)state)->controlFlags & 0x80000000U)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_windlift_loop);
    }
    if (((((EnemyState*)state)->controlFlags & 0x2000U) != 0) &&
        ((Curve_AdvanceAlongPath(&curve->curve, 0.0f) != 0 || curve->atSegmentEnd != 0) &&
         ((*gRomCurveInterface)->goNextPoint(curve) != 0)) &&
        ((*gRomCurveInterface)->initCurve(*(RomCurveWalker**)state, (void*)obj, 700.0f, (int*)&gPinPonCurveInitData, -1) !=
         0))
    {
        ((EnemyState*)state)->controlFlags &= ~0x2000LL;
    }
    ObjHits_SetHitVolumeSlot(&obj->anim, FIREFLYLANTERN_HIT_VOLUME_SLOT, 1, 0);
    flag = playerGetFlags3F0Bit5((GameObject*)(Obj_GetPlayerObject()));
    dvec[0] = ((GameObject*)((EnemyState*)state)->trackedObj)->anim.localPosX - (obj)->anim.localPosX;
    dvec[1] = 0.0f;
    dvec[2] = ((GameObject*)((EnemyState*)state)->trackedObj)->anim.localPosZ - (obj)->anim.localPosZ;
    if ((((EnemyState*)state)->lastHitObject != NULL) &&
        (((EnemyState*)state)->lastHitObject == Obj_GetPlayerObject()))
    {
        ((EnemyState*)state)->flags2E4 |= 0x10000LL;
        ((EnemyState*)state)->fireflyLantern.trackTimer = 0.0f;
    }
    (obj)->anim.rotY = -(1024.0f * mathSinfFast(0.19634955f * (f32)(u32)((EnemyState*)state)->userData1) -
                         (f32)(obj)->anim.rotY);
    if (flag == 0)
    {
        fval = 0.0f;
        (obj)->anim.velocityX = fval;
        (obj)->anim.velocityZ = fval;
        baddieTurnTowardPoint(obj, state, ((GameObject*)((EnemyState*)state)->trackedObj)->anim.localPosX,
                              ((GameObject*)((EnemyState*)state)->trackedObj)->anim.localPosZ, 10, 0);
    }
    else
    {
        enemy_steerVelocityToward(obj, state, dvec, 2.0f, 0.1f, 0.1f, 1);
        baddieTurnTowardLookDir(obj, state, 0xf, 7.5f, 1.0f, 0);
    }
    if (((EnemyState*)state)->controlFlags & 0x40000000U)
    {
        fval = 0.0f;
        if (fval == ((EnemyState*)state)->fireflyLantern.breathTimer)
        {
            if (flag == 0)
            {
                if ((obj)->anim.currentMoveProgress > 0.5f)
                {
                    ((EnemyState*)state)->fireflyLantern.breathTimer = 300.0f;
                    ((EnemyState*)state)->userData2 += 1;
                }
                else
                {
                    ((EnemyState*)state)->fireflyLantern.breathTimer = 120.0f;
                }
            }
            else if ((obj)->anim.currentMoveProgress > 0.5)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_baddie_kooshy_hit);
                ((EnemyState*)state)->animPlaySpeed = -0.02f;
            }
            else
            {
                Sfx_PlayFromObject(obj, SFXTRIG_baddie_kooshy_death);
                ((EnemyState*)state)->animPlaySpeed = 0.02f;
            }
        }
        else
        {
            ((EnemyState*)state)->fireflyLantern.breathTimer -= timeDelta;
            if (((EnemyState*)state)->fireflyLantern.breathTimer <= fval)
            {
                ((EnemyState*)state)->fireflyLantern.breathTimer = fval;
                if ((obj)->anim.currentMoveProgress > 0.5)
                {
                    Sfx_PlayFromObject(obj, SFXTRIG_baddie_kooshy_hit);
                    ((EnemyState*)state)->animPlaySpeed = -0.02f;
                }
                else
                {
                    Sfx_PlayFromObject(obj, SFXTRIG_baddie_kooshy_death);
                    ((EnemyState*)state)->animPlaySpeed = 0.1f;
                }
            }
        }
    }
    ((EnemyState*)state)->userData1 += 1;
    (obj)->anim.rotY = (1024.0f * mathSinfFast(0.19634955f * (f32)(u32)((EnemyState*)state)->userData1) +
                        (f32)(obj)->anim.rotY);
    baddieSpawnWaterRipple(obj, (EnemyState*)state);
}

void pinPon_init(GameObject* obj, void* state)
{
    float fval;
    u32 randVal;

    ((EnemyState*)state)->sightRange = 40.0f;
    ((EnemyState*)state)->flags2E4 = 0x8000009;
    ((EnemyState*)state)->animPlaySpeed = -0.02f;
    ((EnemyState*)state)->gravity = 0.1f;
    ((EnemyState*)state)->drag = 0.97f;
    ((EnemyState*)state)->moveId0 = 0;
    fval = 1.5f;
    ((EnemyState*)state)->moveSpeedScale0 = 1.5f;
    ((EnemyState*)state)->moveId1 = 1;
    ((EnemyState*)state)->moveSpeedScale1 = 1.0f;
    ((EnemyState*)state)->moveId2 = 0;
    ((EnemyState*)state)->moveSpeedScale2 = fval;
    fval = 0.0f;
    ((EnemyState*)state)->fireflyLantern.trackTimer = fval;
    ((EnemyState*)state)->fireflyLantern.breathTimer = fval;
    ((EnemyState*)state)->fireflyLantern.anchorY = obj->anim.localPosY;
    randVal = randomGetRange(0, 0xff);
    ((EnemyState*)state)->userData1 = randVal;
    ((EnemyState*)state)->userData2 = 0;
    ((EnemyState*)state)->fireflyLantern.rippleTimer = 30.0f;
    randVal = randomGetRange(0x32, 0x4b);
    fval = (f32)(s32)randVal;
    fval = 0.01f * fval;
    ((EnemyState*)state)->pathStep = fval;
}
