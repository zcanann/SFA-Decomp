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
#include "main/audio/sfx_limited_object_api.h"

/* Baddie-family animation data shared with the sequence-driver TUs. */

#define MAGICPLANT_OBJFLAG_PARENT_SLACK 0x1000

/* Spit projectile spawned by kooshy_spawnProjectile; retail OBJECTS.bin name
   "KaldachomSp" (DLL 0xD7 kaldachomspit), shared with the snowworm spitter. */

#define KALDACHOM_SPIT_OBJ 0x51b

/* The magic-plant's one particle-fx effect (spawned per hit-count in the
   attack handler). */

void kooshy_spawnProjectile(GameObject* obj, void* state);

u8 gMagicPlantSeqEntryTable[8] = {1, 1, 3, 2, 0, 0, 0, 0};

void kooshy_spawnProjectile(GameObject* obj, void* state) {
    EnemyState* enemyState = (EnemyState*)state;
    ObjPlacement* fx;
    GameObject* newObj;

    if ((u8)Obj_CanSetupObject() != 0) {
        fx = (ObjPlacement*)Obj_AllocObjectSetup(0x24, KALDACHOM_SPIT_OBJ);
        fx->posX = (obj)->anim.localPosX;
        fx->posY = 14.0f + (obj)->anim.localPosY;
        fx->posZ = (obj)->anim.localPosZ;
        fx->color[0] = 1;
        fx->color[1] = 1;
        fx->color[2] = 0xff;
        fx->color[3] = 0xff;
        newObj = objSetupObject(fx, 5, -1, -1, 0);
        if ((void*)newObj != NULL) {
            newObj->anim.velocityX = 0.02f * (((GameObject*)enemyState->trackedObj)->anim.localPosX - fx->posX);
            {
                newObj->anim.velocityY = 0.02f * ((14.0f + ((GameObject*)enemyState->trackedObj)->anim.localPosY +
                                                   (f32)(s32)randomGetRange(-10, 10)) -
                                                  fx->posY);
                newObj->anim.velocityZ = 0.02f * (((GameObject*)enemyState->trackedObj)->anim.localPosZ - fx->posZ);
            }
            newObj->ownerObj = (void*)obj;
        }
        Sfx_PlayFromObject(obj, SFXTRIG_baddie_blooplaugh2);
    }
}

void kooshy_updateWhileFrozen(GameObject* obj, u8* state, GameObject* attacker, int msgFlag, int hitId, int damage,
                              Vec* wpad0, int wpad1) {
    EnemyState* enemyState = (EnemyState*)state;
    if ((obj)->anim.currentMove == 1) {
        if ((enemyState->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0) {
            return;
        }
    }
    if (msgFlag == 0x10) {
        enemyState->flags2E8 = enemyState->flags2E8 | 0x20;
    } else {
        enemyState->flags2E8 = enemyState->flags2E8 | 0x8;
        if (damage > (s32)enemyState->current) {
            Sfx_PlayFromObject(obj, SFXTRIG_sc_walkstep);
            enemyState->current = 0;
        } else {
            Sfx_PlayFromObject(obj, SFXTRIG_sc_runstep);
            enemyState->current = (u16)(enemyState->current - damage);
        }
    }
}

void kooshy_updateIdle(GameObject* obj, void* state) {
    EnemyState* enemyState = (EnemyState*)state;
    u32 hit;
    u8 losDetected;
    f32 worldPos[3];
    f32 vec[3];
    int gridB[2];
    int gridA[2];
    u8 hitOut;
    u8 flagByte;
    u32 rnd;
    s16 angle;

    enemyState->userData2 = enemyState->userData2 & 0x7f;
    losDetected = 0;
    vec[0] = (obj)->anim.localPosX - ((GameObject*)enemyState->trackedObj)->anim.localPosX;
    vec[1] = (obj)->anim.localPosY - ((GameObject*)enemyState->trackedObj)->anim.localPosY;
    vec[2] = (obj)->anim.localPosZ - ((GameObject*)enemyState->trackedObj)->anim.localPosZ;
    if (PSVECMag((Vec*)vec) < 400.0f &&
        (((GameObject*)enemyState->trackedObj)->objectFlags & MAGICPLANT_OBJFLAG_PARENT_SLACK) == 0) {
        worldPos[0] = (obj)->anim.localPosX;
        worldPos[1] = 10.0f + (obj)->anim.localPosY;
        worldPos[2] = (obj)->anim.localPosZ;
        voxmaps_worldToGrid(worldPos, (s16*)gridA);
        {
            GameObject* trackedObj = enemyState->trackedObj;
            worldPos[0] = trackedObj->anim.localPosX;
            worldPos[1] = 20.0f + trackedObj->anim.localPosY;
            worldPos[2] = trackedObj->anim.localPosZ;
        }
        voxmaps_worldToGrid(worldPos, (s16*)gridB);
        hit = voxmaps_traceLine((VoxPos*)gridB, (VoxPos*)gridA, NULL, &hitOut, 0) & 0xff;
        if (hit != 0) {
            GameObject* trackedObj = enemyState->trackedObj;
            baddieTurnTowardPoint(obj, state, trackedObj->anim.localPosX, trackedObj->anim.localPosZ, 0x14, 0);
            angle = (s16)(getAngle(vec[0], vec[2]) - (u16)(obj)->anim.rotX);
            if (angle > 0x8000) {
                angle = (angle - 0x10000) + 1;
            }
            if (angle < -0x8000) {
                angle = (angle + 0x10000) - 1;
            }
            if (angle < 0) {
                angle = -angle;
            }
            if (angle < 1000) {
                losDetected = 1;
            }
        }
    } else {
        hit = 0;
    }
    flagByte = enemyState->userData2;
    if ((flagByte & 0x40) == 0) {
        Sfx_PlayFromObjectLimited(obj, SFXTRIG_baddie_blooplaugh3, 2);
        baddieSetMove(obj, state, 2, 1.0f, 0, 0);
        enemyState->userData2 = (u8)((enemyState->userData2) | 0x40);
        enemyState->userData1 = 0;
    } else if ((enemyState->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0) {
        u8 mode;
        if ((u8)hit != 0) {
            if (enemyState->userData1 != 0) {
                enemyState->userData1 -= 1;
                mode = (u8)(obj)->anim.currentMove;
            } else if ((obj)->anim.currentMove != 5 && losDetected) {
                mode = 5;
                enemyState->userData1 = gMagicPlantSeqEntryTable[enemyState->userData2 & 3];
                enemyState->userData2 = (u8)((*(s8*)&enemyState->userData2 + 1) & 0xc3);
            } else {
                mode = 4;
                rnd = randomGetRange(1, 2);
                enemyState->userData1 = rnd;
            }
        } else {
            rnd = randomGetRange(2, 4);
            mode = rnd;
            if (mode == 2) {
                mode = 0;
            } else if (mode == 4) {
                Sfx_PlayFromObject(obj, SFXTRIG_newtricky_01j);
            }
        }
        baddieSetMove(obj, state, mode, 1.5f, 0, 0);
    }
    if ((obj)->anim.currentMove == 5 && (double)(obj)->anim.currentMoveProgress >= 0.7647 &&
        (double)(obj)->anim.currentMoveProgress < 0.7647 + enemyState->animPlaySpeed * timeDelta) {
        kooshy_spawnProjectile(obj, state);
    } else {
        enemyState->kooshy.sfxTimer = enemyState->kooshy.sfxTimer - timeDelta;
        if (enemyState->kooshy.sfxTimer <= 0.0f) {
            rnd = randomGetRange(0x96, 0x12c);
            enemyState->kooshy.sfxTimer = (f32)(s32)rnd;
            Sfx_PlayFromObject(obj, SFXTRIG_sc_clubswipe);
        }
    }
    magicplantSpawnMovePuffs(obj, state);
}

void kooshy_updateEngaged(GameObject* obj, void* state) {
    EnemyState* enemyState = (EnemyState*)state;
    enemyState->userData2 = enemyState->userData2 & 0xbf;
    if ((enemyState->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0 && (obj)->anim.currentMove != 1) {
        Sfx_PlayFromObjectLimited(obj, SFXTRIG_baddie_eggsnatch_movelp, 2);
        baddieSetMove(obj, state, 1, 1.0f, 0, 0);
    }
    magicplantSpawnMovePuffs(obj, state);
}

void kooshy_init(GameObject* unused, void* state) {
    EnemyState* enemyState = (EnemyState*)state;
    f32 eventFlagsVal;
    f32 pathStepInit;
    enemyState->sightRange = 40.0f;
    enemyState->flags2E4 = 1;
    enemyState->animPlaySpeed = 0.02f;
    enemyState->gravity = 0.1f;
    enemyState->drag = 0.97f;
    enemyState->moveId0 = 0;
    eventFlagsVal = 1.5f;
    enemyState->moveSpeedScale0 = eventFlagsVal;
    enemyState->moveId1 = 7;
    pathStepInit = 1.0f;
    enemyState->moveSpeedScale1 = pathStepInit;
    enemyState->moveId2 = 0;
    enemyState->moveSpeedScale2 = eventFlagsVal;
    enemyState->userData1 = 0;
    enemyState->userData2 = 0;
    enemyState->kooshy.sfxTimer = 150.0f;
    enemyState->pathStep = pathStepInit;
}
