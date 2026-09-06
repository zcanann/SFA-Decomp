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

#define FALL_LADDERS_HIT_VOLUME_SLOT 0x18

int gWeevilCurveInitData[2] = {2, 3};

void weevil_updateWhileFrozen(GameObject* obj, u8* state, GameObject* attacker, int msgFlag, int wpad0, int wpad1,
                              Vec* wpad2, int wpad3) {
    EnemyState* enemy = (EnemyState*)state;
    u8 cond = 0;
    int kind = obj->anim.currentMove;
    do {
        if (kind == 5) {
        } else if (kind == 4) {
        } else if (kind == 6) {
            if ((double)obj->anim.currentMoveProgress < 0.5) {
            } else {
                break;
            }
        } else {
            break;
        }

        if (msgFlag != 0xe) {
            cond = 1;
        }
    } while (0);

    {
        u32 condV = cond;
        if (msgFlag == 0x10) {
            if (condV != 0) {
                enemy->flags2E8 |= 0x20;
            }
        } else if (condV != 0) {
            if (enemy->userData2 == 0) {
                enemy->flags2E8 |= 0x8;
                enemy->current = 0;
                Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_25f);
            }
        } else if (msgFlag == 0x11) {
            enemy->weevil.recoverTimer = 120.0f;
            enemy->weevil.approachTimer = 180.0f;
            baddieSetMove(obj, state, 4, 2.0f, 0, 3);
            enemy->flags2E4 |= 0x10000;
            enemy->userData2 = 0x3c;
        } else {
            enemy->flags2E8 |= 0x10;
        }
    }
}

void weevil_updateIdle(GameObject* obj, void* state) {
    EnemyState* enemy = (EnemyState*)state;
    RomCurveWalker* curve;
    u32 rnd;
    u8 ctr;

    curve = *(RomCurveWalker**)state;
    enemy->userData1 = 0;
    enemy->weevil.retreatTimer = 0.0f;
    if ((enemy->controlFlags & BADDIE_CONTROL_PATH_FOLLOW) != 0) {
        if (Curve_AdvanceAlongPath(&curve->curve, enemy->pathStep) != 0 || curve->atSegmentEnd != 0) {
            if ((*gRomCurveInterface)->goNextPoint(curve) != 0) {
                if ((*gRomCurveInterface)
                        ->initCurve(*(RomCurveWalker**)state, (void*)obj, 700.0f, gWeevilCurveInitData, -1) != 0) {
                    enemy->controlFlags &= ~BADDIE_CONTROL_PATH_FOLLOW;
                }
            }
        }
        if (enemy->weevil.recoverTimer == 0.0f) {
            if (obj->anim.currentMove == 0) {
                baddieTurnTowardPoint(obj, state, curve->posX, curve->posZ, 0x3c, 0);
            }
            if (enemy->weevil.approachTimer > 0.0f) {
                f32 zero = 0.0f;
                enemy->weevil.approachTimer -= timeDelta;
                if (enemy->weevil.approachTimer <= zero) {
                    enemy->flags2E4 &= ~0x10000;
                    enemy->weevil.approachTimer = zero;
                }
            }
        }
    }
    if (enemy->weevil.recoverTimer > 0.0f) {
        f32 zero = 0.0f;
        enemy->weevil.recoverTimer -= timeDelta;
        if (enemy->weevil.recoverTimer <= zero) {
            baddieSetMove(obj, state, 6, 2.0f, 0, 3);
            enemy->weevil.recoverTimer = 0.0f;
        } else if ((enemy->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0) {
            baddieSetMove(obj, state, 5, 1.0f, 0, 3);
        }
    } else if ((enemy->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0) {
        baddieSetMove(obj, state, 0, 0.5f, 0, 3);
    }
    obj->anim.rotY = enemy->spawnRotY;
    obj->anim.rotZ = enemy->spawnRotZ;
    enemy->weevil.gruntTimer -= timeDelta;
    if (enemy->weevil.gruntTimer <= 0.0f) {
        rnd = randomGetRange(0x3c, 0x78);
        enemy->weevil.gruntTimer = (f32)(s32)rnd;
        Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_25e);
    }
    ctr = enemy->userData2;
    if (ctr != 0) {
        enemy->userData2--;
    }
}

void weevil_updateEngaged(GameObject* obj, void* state) {
    EnemyState* enemy = (EnemyState*)state;
    u8 done;

    enemy->weevil.recoverTimer = 0.0f;
    done = 0;
    ObjHits_SetHitVolumeSlot(&obj->anim, FALL_LADDERS_HIT_VOLUME_SLOT, 1, -1);
    if (enemy->lastHitObject != NULL) {
        done = 1;
        enemy->weevil.approachTimer = 360.0f;
        enemy->weevil.recoverTimer = 0.0f;
        if (obj->anim.currentMove != 0) {
            baddieSetMove(obj, state, 2, 0.5f, 0, 3);
        }
    }
    if (obj->anim.currentMove != 3) {
        baddieTurnTowardPoint(obj, state, enemy->trackedObj->anim.localPosX, enemy->trackedObj->anim.localPosZ, 0x3c,
                              0);
    } else {
        enemy->weevil.retreatTimer -= timeDelta;
        if (enemy->weevil.retreatTimer <= 0.0f) {
            done = 1;
            enemy->weevil.recoverTimer = 120.0f;
            enemy->weevil.approachTimer = 180.0f;
            baddieSetMove(obj, state, 4, 2.0f, 0, 3);
        }
    }
    if (done != 0) {
        enemy->flags2E4 |= 0x10000;
    } else if (enemy->userData1 == 0) {
        enemy->userData1 = 1;
        baddieSetMove(obj, state, 1, 0.35f, 0, 3);
    } else if ((enemy->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0 &&
               (baddieSetMove(obj, state, 3, 0.375f, 0, 3), 0.0f == enemy->weevil.retreatTimer)) {
        enemy->weevil.retreatTimer = 50.0f;
        baddieTurnTowardPoint(obj, state, enemy->trackedObj->anim.localPosX, enemy->trackedObj->anim.localPosZ, 1, 0);
        Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_25d);
    }
    obj->anim.rotY = enemy->spawnRotY;
    obj->anim.rotZ = enemy->spawnRotZ;
    if (enemy->userData2 != 0) {
        enemy->userData2 -= 1;
    }
}

void weevil_init(GameObject* unused, u8* state) {
    EnemyState* enemy = (EnemyState*)state;
    f32 fz;
    f32 fc;
    enemy->sightRange = 40.0f;
    enemy->flags2E4 = 173;
    enemy->animPlaySpeed = 0.02f;
    enemy->gravity = 1.0f;
    enemy->drag = 0.97f;
    enemy->moveId0 = 0;
    fz = 1.5f;
    enemy->moveSpeedScale0 = fz;
    enemy->moveId1 = 7;
    enemy->moveSpeedScale1 = 4.0f;
    enemy->moveId2 = 0;
    enemy->moveSpeedScale2 = fz;
    fc = 0.0f;
    enemy->weevil.approachTimer = fc;
    enemy->weevil.retreatTimer = fc;
    enemy->weevil.recoverTimer = fc;
    enemy->userData1 = 0;
    enemy->userData2 = 0;
    enemy->weevil.gruntTimer = 60.0f;
    enemy->pathStep = 0.5f;
}
