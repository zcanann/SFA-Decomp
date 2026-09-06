/*
 * DLL 0xC9 (Baddie) - the generic enemy/baddie controller. It runs several romlist
 * enemy types, including GCRobotPatrol ("GCRobotPatr[ol]"), the floating
 * patrol robot of CloudRunner Fortress (placed in fortress.romlist).
 * GCRobotPatrol carries the GCRobotLightBeam searchlight (DLL 0x150) as
 * childObjs[0] and reads that child's "player caught" flag to react; the
 * SharpClaw disguise fools the beam.
 */
#include "dlls/objects/201_Baddie.h"
#include "dlls/objects/237.h"
#include "main/camera_interface.h"
#include "main/dll/dll_0049_cameramodecombat.h"
#include "main/dll/objfx_api.h"
#include "main/objfx.h"
#include "main/newshadows_audio_api.h"
#include "main/dll/dll_005A_staffcollision.h"
#include "main/object_render.h"
#include "main/track_bbox_api.h"
#include "main/track_dolphin_api.h"
#include "main/dll/boneparticleeffect_interface.h"
#include "main/objtype.h"
#include "main/obj_link.h"
#include "main/objprint_character_api.h"
#include "sys/objects/lifecycle.h"
#include "sys/objects.h"
#include "main/model.h"
#include "main/mm.h"
#include "main/objseq.h"
#include "main/dll/rom_curve_interface.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "game/objects/object_setup.h"
#include "main/objhits.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/path_control_interface.h"
#include "main/mapEventTypes.h"
#include "main/resource.h"
#include "main/vecmath.h"
#include "main/dll/duster.h"
#include "main/dll/tricky_api.h"
#include "main/lightmap_api.h"
#include "main/shader_api.h"
#include "main/frame_timing.h"
#include "main/model_engine.h"
#include "main/model_light.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/mtx.h"
#include "main/dll/hagabon_mk2.h"
#include "main/dll/duster_wb.h"
#include "main/dll/weevil.h"
#include "main/dll/hoodedzyck.h"
#include "main/dll/snowworm.h"
#include "main/dll/kooshy.h"
#include "main/dll/mikaladon.h"
#include "main/dll/baddiewhirlpool.h"
#include "main/dll/newseqobj_baddie.h"
#include "main/dll/fireflyLantern.h"
#include "main/dll/firecrawler_baddie.h"
#include "main/dll/seqobj11e_baddie.h"
#include "main/dll/wispbaddie_baddie.h"
#include "main/dll/seqobj11d_baddie.h"
#include "main/dll/magicPlant.h"
#include "main/dll/seqObj11D.h"
#include "dlls/objects/196_Tricky.h"
#include "main/dll/fall_ladders.h"
#include "main/gameloop_gamebit_api.h"
#include "main/obj_path.h"
#include "main/dll/player_api.h"
#include "dolphin/mtx/vec.h"
#include "main/audio/sfx_limited_object_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/voxmaps.h"

u8 lbl_8031DBD8[12] = {0};
u8 lbl_8031DBE4[12] = {0};

int lbl_803DBC58[2] = {2, 3};
f32 lbl_803DBC60 = 20.0f;
f32 lbl_803DBC64 = 20.0f;
f32 lbl_803DBC68 = 2.3509887e-38f;

const struct BaddieSightQuadrantBits gBaddieSightQuadrantBitsInit = {{0x10000, 0x20000, 0x40000, 0x80000}};
const StaffCollisionColorArgs gBaddieFrozenFxColors = {0x08, 0xFF, 0xFF, 0x78};

GameObject* gBaddieRewardObject;
StaffCollisionInterface** gBaddieStaffCollisionInterface;

/* object groups: the enemy's own group / secondary group left on a message */
#define ENEMY_OBJGROUP           3
#define ENEMY_OBJGROUP_SECONDARY 0x50

/* enemy defNos (anim.romDefNo) - names read from retail OBJECTS.bin at def+0x91;
   every id below gates to this file's own DLL 0xC9 */
#define ENEMY_SHARPCLAW_GR_OBJ  0x11
#define ENEMY_GUARDCLAW_OBJ     0xd8
#define ENEMY_SHARPCLAW_SN_OBJ  0x13a
#define ENEMY_PINPON_OBJ        0x251
#define ENEMY_RACHNOP_OBJ       0x25d
#define ENEMY_WEEVIL_OBJ        0x369
#define ENEMY_VAMBAT_OBJ        0x3fe
#define ENEMY_BATTLEDROID_OBJ   0x427
#define ENEMY_SPITTINGEBA_OBJ   0x457
#define ENEMY_MUTATEDEBA_OBJ    0x458
#define ENEMY_HOODEDZYCK_OBJ    0x4ac
#define ENEMY_WB_OBJ            0x4d7
#define ENEMY_KOOSHY_OBJ        0x58b
#define ENEMY_SHARPCLAW_CO_OBJ  0x5b7
#define ENEMY_SHARPCLAW_AS_OBJ  0x5b8
#define ENEMY_SHARPCLAW_SH_OBJ  0x5b9
#define ENEMY_SHARPCLAW_SO_OBJ  0x5e1
#define ENEMY_GCROBOTPATROL_OBJ 0x613
#define ENEMY_MIKALADON_OBJ     0x642
#define ENEMY_FIRECRAWLER_OBJ   0x6a2
#define ENEMY_REDEYE_OBJ        0x6a3
#define ENEMY_SHADOWHUNTER_OBJ  0x6a4
#define ENEMY_SWAMPSTRIDER_OBJ  0x6a5
#define ENEMY_BOSSGENERAL_OBJ   0x7a6
#define ENEMY_FIREBAT_OBJ       0x7c6
#define ENEMY_HAGABONMK2_OBJ    0x7c8
#define ENEMY_SNOWWORM_OBJ      0x842
#define ENEMY_SNOWWORM_BABY_OBJ 0x84b
#define ENEMY_WHIRLPOOL_OBJ     0x851

#define TRICKY_CHILD_OBJ_MAGIC_DUST 0x2cd /* "MagicDustMi..." (DLL 0xFF magicgem) */
#define TRICKY_CHILD_OBJ_ENERGY_EGG 0xb   /* "EnergyEgg" (DLL 0xED) */
#define TRICKY_OBJ_APPLE            0x3cd /* "Apple" (DLL 0xED) */

#define ENEMY_FLAG2E4_BBOX_BLOCKS_SIGHT   0x00000008
#define ENEMY_FLAG2E4_USE_SPECIAL_FLOOR_Y 0x08000000
#define ENEMY_FLAG2E4_OFFSET_FLOOR_Y      0x20000000
#define ENEMY_FLAG2E4_FLOOR_RESPONSE_MASK 0x28000002

#define ENEMY_SURFACE_FLAG_HAS_NEARBY_FLOOR 0x10

/* controlFlags status bits set by the floor-response pass to record what floor
 * correction ran this frame. */
#define ENEMY_CONTROL_FLOOR_OFFSET_APPLIED 0x08000000 /* offset-floor-Y push applied */
#define ENEMY_CONTROL_FLOOR_SNAP_APPLIED   0x00100000 /* snap-to-floor velocity applied */
#define ENEMY_CONTROL_SPECIAL_FLOOR_FOUND  0x10000000 /* a nearby type-0xe special floor was found */

/* ObjPlacement offsets read by the defeat handler to fire the baddie's
 * death gamebits. */

static const u16 lbl_803E2558[4] = {0x2C4, 0x2CD, 0x2CE, 0x2CF};
static const u16 lbl_803E2560[2] = {0x3CD, 0xB};
static const u16 lbl_803E2564[2] = {0x3CD, 0x2C4};
static const u16 lbl_803E2568[1] = {0xB};

void Tricky_resumeAfterCommand(GameObject* obj, EnemyState* state) {
    ObjHitsPriorityState* hitState;
    u8 moveId;

    state->actionId = 1;
    if (((state->controlFlags & 0x1000) != 0) && ((state->prevControlFlags & 0x1000) == 0)) {
        obj->anim.flags = obj->anim.flags & ~OBJANIM_FLAG_HIDDEN;
        moveId = state->moveId0;
        state->animPlaySpeed = 1.0f / (60.0f * state->moveSpeedScale0);
        state->rootMotionFlags = 1;
        ObjAnim_SetCurrentMove(obj, moveId, 0.0f, OBJANIM_MOVE_CONTROL_SKIP_EVENT_COUNTDOWN);
        if (obj->anim.hitReactState != NULL) {
            hitState = (ObjHitsPriorityState*)(obj)->anim.hitReactState;
            hitState->suppressOutgoingHits = 0;
        }
        state->flags2E8 |= 4;
        Sfx_PlayFromObjectLimited(obj, SFXTRIG_holorays16, 2);
        ObjHits_EnableObject(obj);
    }
    if ((state->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0) {
        state->animPlaySpeed = 0.0055555557f;
        state->rootMotionFlags = 0;
        ObjAnim_SetCurrentMove(obj, 0, 0.0f, 0);
        if (obj->anim.hitReactState != NULL) {
            hitState = (ObjHitsPriorityState*)(obj)->anim.hitReactState;
            hitState->suppressOutgoingHits = 0;
        }
        state->controlFlags &= 0xffffef7f;
        state->flags2E8 &= ~0x4;
        state->particleScale = 0.0f;
        obj->anim.alpha = 0xff;
    } else {
        obj->anim.alpha = (int)(255.0f * obj->anim.currentMoveProgress);
        state->particleScale = obj->anim.currentMoveProgress;
    }
}

void tricky_handleDefeat(GameObject* obj, EnemyState* state) {
    ObjHitsPriorityState* hitState;
    EnemyPlacement* setup;
    int alpha;
    void* tricky;
    int spawnBits;
    u8 moveId;

    setup = (EnemyPlacement*)obj->anim.placementData;
    state->actionId = 0;
    if (((state->controlFlags & 0x800) != 0) && ((state->prevControlFlags & 0x800) == 0)) {
        tricky = (void*)getTrickyObject();
        if (tricky != NULL) {
            trickyImpress((GameObject*)tricky);
        }
        if ((state->flags2E4 & 0x40000000) == 0) {
            if (((EnemyPlacement*)setup)->gameBit != -1) {
                gameBitIncrement(((EnemyPlacement*)setup)->gameBit);
            }
            if (((EnemyPlacement*)setup)->gameBit2 != -1) {
                mainSetBits(((EnemyPlacement*)setup)->gameBit2, 0);
            }
        }
        state->trackedObj = NULL;
        ObjHits_DisableObject(obj);
        obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED;
        moveId = state->moveId1;
        state->animPlaySpeed = 1.0f / (60.0f * state->moveSpeedScale1);
        state->rootMotionFlags = 1;
        ObjAnim_SetCurrentMove(obj, moveId, 0.0f, 0);
        if ((void*)(obj)->anim.hitReactState != NULL) {
            hitState = (ObjHitsPriorityState*)(obj)->anim.hitReactState;
            hitState->suppressOutgoingHits = 0;
        }
        state->flags2E8 |= 1;
        Sfx_PlayFromObject(obj, SFXTRIG_wp_iceywindlp16_233);
        if (randomGetRange(0, 100) > 50) {
            if ((state->flags2E4 & 0x100000) != 0) {
                baddie_spawnRewardDrops(obj, (int)state, state->spawnBits, 0, 4);
            } else {
                spawnBits = ((EnemyPlacement*)setup)->droppedItemId & 0xf00;
                if (spawnBits != 0) {
                    baddie_spawnRewardDrops(obj, (int)state, spawnBits, 0, 1);
                }
                spawnBits = ((EnemyPlacement*)setup)->droppedItemId & 0xf000;
                if (spawnBits != 0) {
                    baddie_spawnRewardDrops(obj, (int)state, spawnBits, 0, 2);
                }
                spawnBits = ((EnemyPlacement*)setup)->droppedItemId & 0xff;
                if (spawnBits != 0) {
                    baddie_spawnRewardDrops(obj, (int)state, spawnBits, 0, 3);
                }
            }
        }
    }
    alpha = 0xff - (int)(255.0f * obj->anim.currentMoveProgress);
    alpha = (alpha < 0) ? 0 : ((alpha > 0xff) ? 0xff : alpha);
    obj->anim.alpha = alpha;
    state->particleScale = 1.0f + (f32)(0xff - obj->anim.alpha) / 255.0f;
    if (obj->anim.alpha < 5) {
        if ((state->flags2E4 & 0x40000000) != 0) {
            if (((EnemyPlacement*)setup)->gameBit != -1) {
                gameBitIncrement(((EnemyPlacement*)setup)->gameBit);
            }
            if (((EnemyPlacement*)setup)->gameBit2 != -1) {
                mainSetBits(((EnemyPlacement*)setup)->gameBit2, 0);
            }
        }
        state->particleScale = 0.0f;
        state->controlFlags = 0;
        obj->anim.flags = obj->anim.flags | OBJANIM_FLAG_HIDDEN;
        obj->anim.alpha = 0;
        obj->userData1 = 1;
        if ((u32)((ObjPlacement*)setup)->ident == 0xFFFFFFFF) {
            Obj_FreeObject(obj);
        } else {
            if (((EnemyPlacement*)setup)->respawnDelay != 0) {
                (*gMapEventInterface)
                    ->addTime(((ObjPlacement*)setup)->ident, 60.0f * (f32)((EnemyPlacement*)setup)->respawnDelay);
            }
            state->controlFlags &= ~0x800;
            state->flags2E8 &= ~3;
        }
    }
}

/* Shared frozen-state update + per-baddie reaction dispatch. */
void baddie_updateWhileFrozen(GameObject* obj, u8* state, u8 fromHit) {
    EnemyState* enemyState = (EnemyState*)state;
    GameObject* player;
    int hit;
    int result;
    u16 sector;
    int diff;
    f32 hDist;
    f32 vDist;
    GameObject* proj;
    f32* dp;
    f32 zero;
    FrozenFxParams params;
    Vec hitPos;
    f32 delta[3];
    StaffCollisionColorArgs colors;
    GameObject* attacker;
    f32 fxA;
    f32 fxB;
    f32 fxC;
    int hitArg;
    u32 hitCount;
    u32 hitEffects;
    u16 hitStun;

    player = Obj_GetPlayerObject();
    colors = gBaddieFrozenFxColors;
    result = 2;
    if ((enemyState->controlFlags & 0x1800) == 0) {
        if ((enemyState->flags2E4 & 1) != 0) {
            ObjHits_EnableObject(obj);
        } else {
            ObjHits_DisableObject(obj);
        }
        hit = ObjHits_GetPriorityHitWithPosition(obj, &attacker, &hitArg, &hitCount, &hitPos.x, &hitPos.y, &hitPos.z);
        hitPos.x += playerMapOffsetX;
        hitPos.z += playerMapOffsetZ;
        enemyState->repeatHitCooldown -= timeDelta;
        if (hit == 0x1a) {
            if (enemyState->repeatHitCooldown >= 0.0f) {
                hit = 0;
            } else {
                enemyState->repeatHitCooldown = 5.0f;
            }
        }
        enemyState->controlFlags &= ~0x30;
        enemyState->freezeRecoverTimer -= timeDelta;
        if (enemyState->freezeRecoverTimer < 0.0f) {
            enemyState->freezeRecoverTimer = 0.0f;
        }
        playerGetAttackHitProperties(player, &hitEffects, &fxA, &fxB, &fxC, &hitStun);
        baddie_decodePlayerAttackFlags((EnemyState*)state, hitEffects, fxA, hitStun);
        if (hit != 0) {
            if (fromHit) {
                if (hit != 0x10) {
                    params.scale = 2.0f;
                    (*gBoneParticleEffectInterface)->spawnEffect((void*)obj, 0x7fb, NULL, 0x64, &params);
                    (*gBoneParticleEffectInterface)->spawnEffect((void*)obj, 0x7fc, NULL, 0x32, NULL);
                    Obj_Shatter(obj);
                    enemyState->current = 0;
                    enemyState->flags2E8 &= ~0x20;
                    enemyState->flags2E8 |= 0x200;
                    Sfx_PlayFromObject(obj, SFXTRIG_barrel_bounce1);
                } else {
                    enemyState->flags2E8 |= 0x10;
                }
            } else {
                if (hitEffects != 0) {
                    if (attacker->anim.classId == 1 || attacker->anim.classId == 0x2d) {
                        if ((enemyState->flags2E4 & 0x200) != 0) {
                            if (fxC >= 0.1f && fxC <= 1.0f) {
                                enemyState->drag = fxC;
                            }
                            zero = 0.0f;
                            obj->anim.velocityX = zero;
                            obj->anim.velocityY = zero;
                            if ((enemyState->controlFlags & 0x40) != 0) {
                                obj->anim.velocityZ = 0.3f * fxB;
                            } else {
                                obj->anim.velocityZ = fxB;
                            }
                            vecRotateZXY(&obj->anim.rotX, &obj->anim.velocityX);
                        }
                    }
                }
                enemyState->freezeRecoverTimer += 30.0f * (f32)(int)hitCount;
                if ((enemyState->controlFlags & 0x4000) != 0) {
                    enemyState->controlFlags |= 0x10;
                }
                if ((enemyState->controlFlags & 0x40) == 0) {
                    enemyState->controlFlags |= 0x4000;
                }
                enemyState->controlFlags |= 0x20;
                dp = delta;
                dp[0] = obj->anim.worldPosX - hitPos.x;
                dp[1] = obj->anim.worldPosY - hitPos.y;
                dp[2] = obj->anim.worldPosZ - hitPos.z;
                diff = (u16)getAngle(-dp[0], -dp[2]) - (u16)(obj)->anim.rotX;
                if (diff > 0x8000) {
                    diff -= 0xffff;
                }
                if (diff < -0x8000) {
                    diff += 0xffff;
                }
                sector = (u32)(u16)diff >> 13;
                hDist = sqrtf(dp[0] * dp[0] + dp[2] * dp[2]);
                vDist = sqrtf(dp[1] * dp[1]);
                switch (obj->anim.romDefNo) {
                case 0x11:
                case 0x13a:
                case 0x5b7:
                case 0x5b8:
                case 0x5b9:
                case 0x5e1:
                case 0x7a6:
                    result = sharpClawHandleHitMessage(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector,
                                                       hDist, vDist);
                    break;
                case 0xd8:
                case 0x281:
                    guardClawUpdateWhileFrozen((GameObject*)(obj), state, attacker, hit, hitArg, hitCount, &hitPos,
                                               sector);
                    break;
                case 0x613:
                    gcRobotPatrol_updateWhileFrozen(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x642:
                    mikaladon_updateWhileFrozen(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x3fe:
                case 0x7c6:
                    vambat_updateWhileFrozen(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x58b:
                    kooshy_updateWhileFrozen(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x369:
                    weevil_updateWhileFrozen(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x251:
                    pinPon_updateWhileFrozen(obj, (EnemyState*)state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x25d:
                    rachnopUpdateWhileFrozen(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x4d7:
                    wbUpdateWhileFrozen(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x457:
                    spittingEbaUpdateWhileFrozen(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x458:
                    mutatedEbaUpdateWhileFrozen(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x851:
                    whirlpool_updateWhileFrozen(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x842:
                case 0x84b:
                    snowworm_updateWhileFrozen(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x4ac:
                    hoodedZyckUpdateWhileFrozen(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x427:
                    battleDroidUpdateWhileFrozen(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x6a2:
                case 0x6a3:
                case 0x6a4:
                case 0x6a5:
                    crawler_onHit(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x7c8:
                    hagabonMK2_updateWhileFrozen(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                default:
                    battleDroidUpdateWhileFrozen(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                }
            }
        } else {
            if ((enemyState->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0) {
                enemyState->controlFlags &= ~0x4000;
            }
        }
        if ((enemyState->flags2E8 & 0x208) != 0) {
            params.pos.x = hitPos.x;
            params.pos.y = hitPos.y;
            params.pos.z = hitPos.z;
            if (enemyState->modelLight == NULL) {
                enemyState->modelLight = objCreateLight(NULL, 1);
            }
            if ((enemyState->flags2E8 & 0x200) != 0) {
                objDoHitParticleFx((void*)obj, 0.014f, &params, 1, (void*)enemyState->modelLight);
            } else if ((enemyState->flags2F1 & 0x10) != 0) {
                objDoHitParticleFx((void*)obj, 0.014f, &params, 3, (void*)enemyState->modelLight);
            } else if ((enemyState->flags2F1 & 8) != 0) {
                objDoHitParticleFx((void*)obj, 0.014f, &params, 2, (void*)enemyState->modelLight);
            } else {
                objDoHitParticleFx((void*)obj, 0.014f, &params, 1, (void*)enemyState->modelLight);
            }
            Obj_SetModelColorFadeRecursive(obj, 0xf, 0xc8, 0, 0, 1);
        }
        enemyState->freezeEffectTimer -= timeDelta;
        if (enemyState->freezeEffectTimer < 0.0f) {
            enemyState->freezeEffectTimer = 0.0f;
        }
        if ((enemyState->flags2E8 & 0x10) != 0) {
            if (enemyState->freezeEffectTimer <= 0.0f) {
                params.pos.x = hitPos.x;
                params.pos.y = hitPos.y;
                params.pos.z = hitPos.z;
                params.scale = 1.0f;
                params.rot[2] = 0;
                params.rot[1] = 0;
                params.rot[0] = 0;
                if (gBaddieStaffCollisionInterface != NULL) {
                    (*gBaddieStaffCollisionInterface)->spawn(NULL, 1, (PartFxSpawnParams*)&params, 0x401, -1, &colors);
                }
                enemyState->freezeEffectTimer = 20.0f;
                if (enemyState->modelLight == NULL) {
                    enemyState->modelLight = objCreateLight(NULL, 1);
                }
                objDoHitParticleFx((void*)obj, 0.014f, &params, 4, (void*)enemyState->modelLight);
            }
            proj = enemyState->trackedObj;
            if (proj != NULL && proj->anim.classId == 1) {
                playerSetHitReactionVariant(proj, result);
            }
        } else if ((enemyState->flags2E8 & 0x20) != 0) {
            if (enemyState->frozenFadeCounter == 0) {
                Sfx_PlayFromObject(obj, SFXTRIG_fox_kick2);
                enemyState->frozenFadeCounter = 0x1f;
            }
            Obj_StartModelFadeIn(obj, 0x12c);
        } else {
            if (enemyState->frozenFadeCounter != 0) {
                enemyState->frozenFadeCounter--;
            }
        }
        enemyState->flags2E8 &= 0xfffffdc7;
    }
}

void baddie_decodePlayerAttackFlags(EnemyState* state, u32 flags, f32 f, u16 hitStunFrames) {
    state->flags2F1 = 0;
    if ((flags & 0x2) != 0) {
        state->flags2F1 = (u8)(state->flags2F1 | 0x20);
    }
    if ((flags & 0x1) != 0) {
        state->flags2F1 = (u8)(state->flags2F1 | 0x40);
    }
    if ((flags & 0x4) != 0) {
        state->flags2F1 = (u8)(state->flags2F1 | 0x1);
    }
    if ((flags & 0x8) != 0) {
        state->flags2F1 = (u8)(state->flags2F1 | 0x2);
    }
    if ((flags & 0x10) != 0) {
        state->flags2F1 = (u8)(state->flags2F1 | 0x4);
    }
    if (f == 0.2f) {
        state->flags2F1 = (u8)(state->flags2F1 | 0x8);
    } else if (f == 0.3f) {
        state->flags2F1 = (u8)(state->flags2F1 | 0x10);
    }
    if ((flags & 0x80) != 0) {
        state->flags2F1 = (u8)(state->flags2F1 | 0x80);
    }
    if ((flags & 0x100) != 0) {
        state->spawnBits = 1;
    } else if ((flags & 0x200) != 0) {
        state->spawnBits = 2;
    } else if ((flags & 0x400) != 0) {
        state->spawnBits = 3;
    }
    state->hitStunFrames = hitStunFrames;
}

int baddie_spawnRewardDrops(GameObject* obj, int state, int spawnBits, u32 useAltMode, u32 mode) {
    u32 commandSpawnIds[2];
    struct TrickyRewardSpawnTail {
        u32 pair;
        u16 single;
    } rewardTail;
    f32 nearestDistance;
    u32 rewardSpawnIds0;
    GameObject* nearest;
    ObjPlacement* parentSetup;
    ObjPlacement* setup;
    int index;
    f32 savedX;
    f32 savedY;
    f32 savedZ;
    f32 v;
    u8 canSetupObject;

    (void)state;
    parentSetup = (ObjPlacement*)obj->anim.placementData;
    *(struct TrickyCommandSpawnPair*)commandSpawnIds = *(struct TrickyCommandSpawnPair*)lbl_803E2558;
    rewardSpawnIds0 = *(u32*)lbl_803E2560;
    rewardTail.pair = *(u32*)lbl_803E2564;
    rewardTail.single = lbl_803E2568[0];
    if (spawnBits == 0) {
        return 0;
    }
    canSetupObject = Obj_CanSetupObject();
    if (canSetupObject == 0) {
        return 0;
    }
    mode = (u8)mode;
    if (mode == 1) {
        index = ((spawnBits & 0xf00) >> 8) - 1;
        if (index > 3) {
            index = 3;
        }
        setup = Obj_AllocObjectSetup(0x30, *(u16*)((int)commandSpawnIds + index * 2));
    } else if (mode == 2) {
        index = ((spawnBits & 0xf000) >> 0xc) - 1;
        if (index > 1) {
            index = 1;
        }
        setup = Obj_AllocObjectSetup(0x30, *(u16*)((int)&rewardSpawnIds0 + index * 2));
    } else if (mode == 3) {
        switch (spawnBits) {
        case 1:
            setup = Obj_AllocObjectSetup(0x30, TRICKY_CHILD_OBJ_MAGIC_DUST);
            break;
        case 3:
            setup = Obj_AllocObjectSetup(0x30, TRICKY_CHILD_OBJ_ENERGY_EGG);
            break;
        case 4:
            setup = Obj_AllocObjectSetup(0x30, TRICKY_CHILD_OBJ_MAGIC_DUST);
            break;
        case 5:
            savedX = obj->anim.worldPosX;
            savedY = obj->anim.worldPosY;
            savedZ = obj->anim.worldPosZ;
            parentSetup = (ObjPlacement*)obj->anim.placementData;
            if ((void*)parentSetup != NULL) {
                obj->anim.worldPosX = parentSetup->posX;
                obj->anim.worldPosY = parentSetup->posY;
                obj->anim.worldPosZ = parentSetup->posZ;
            }
            nearestDistance = 750.0f;
            gBaddieRewardObject = objGetNearestTypeTo(COLLECTIBLE_OBJECT_GROUP, obj, &nearestDistance);
            obj->anim.worldPosX = savedX;
            obj->anim.worldPosY = savedY;
            obj->anim.worldPosZ = savedZ;
            if (gBaddieRewardObject != NULL) {
                v = obj->anim.localPosX;
                gBaddieRewardObject->anim.worldPosX = v;
                gBaddieRewardObject->anim.localPosX = v;
                v = 15.0f + obj->anim.localPosY;
                gBaddieRewardObject->anim.worldPosY = v;
                gBaddieRewardObject->anim.localPosY = v;
                v = obj->anim.localPosZ;
                gBaddieRewardObject->anim.worldPosZ = v;
                gBaddieRewardObject->anim.localPosZ = v;
            }
            return (int)gBaddieRewardObject;
        default:
            return 0;
        }
    } else if (mode == 4) {
        index = spawnBits;
        if (index > 3) {
            index = 3;
        }
        if (index <= 0) {
            return 0;
        }
        setup = Obj_AllocObjectSetup(0x30, ((u16*)((u8*)&rewardTail.pair - 2))[index]);
    }
    ((CollectibleSetup*)setup)->unk1A = 0x14;
    ((CollectibleSetup*)setup)->counterGameBit = -1;
    ((CollectibleSetup*)setup)->hideGameBit = -1;
    ((CollectibleSetup*)setup)->visibilityGameBit = -1;
    setup->posX = obj->anim.localPosX;
    setup->posY = 30.0f + obj->anim.localPosY;
    setup->posZ = obj->anim.localPosZ;
    if ((useAltMode & 0xff) != 0) {
        ((CollectibleSetup*)setup)->spawnMode = 2;
    } else {
        ((CollectibleSetup*)setup)->spawnMode = 1;
    }
    setup->color[0] = parentSetup->color[0];
    setup->color[2] = parentSetup->color[2];
    setup->color[1] = parentSetup->color[1];
    setup->color[3] = parentSetup->color[3];
    nearest = objSetupObject(setup, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
    gBaddieRewardObject = (GameObject*)nearest;
    if ((nearest->anim.romDefNo == TRICKY_OBJ_APPLE) || (nearest->anim.romDefNo == TRICKY_CHILD_OBJ_ENERGY_EGG)) {
        ((void (*)(GameObject*, f32, f32, f32))nearest->anim.dll[0][11])(nearest, 0.0f, 1.0f, 0.0f);
    }
    return (int)gBaddieRewardObject;
}

void baddieInstantiateWeapon(GameObject* obj, EnemyState* state) {
    BaddieInstantiateWeaponPlacement* parentSetup;
    void* child;
    ObjPlacement* setup;
    u8 canSetupObject;

    parentSetup = (BaddieInstantiateWeaponPlacement*)obj->anim.placementData;
    if ((state->spawnedWeaponRomDefNo != state->weaponRomDefNo) && (obj->anim.alpha != 0)) {
        if (obj->childObjs[0] != NULL) {
            child = obj->childObjs[0];
            ObjLink_DetachChild(obj, child);
            Obj_FreeObject((GameObject*)child);
        }
        canSetupObject = Obj_CanSetupObject();
        if (canSetupObject > 0) {
            if (state->weaponRomDefNo > 0) {
                setup = Obj_AllocObjectSetup(0x20, state->weaponRomDefNo);
                setup->color[1] |= parentSetup->unk5 & 0x18;
                child = objSetupObject((ObjPlacement*)setup, 4, obj->anim.mapEventSlot, -1, obj->anim.parent);
                ObjLink_AttachChild(obj, child, 0);
                state->spawnedWeaponRomDefNo = state->weaponRomDefNo;
            }
        } else {
            state->spawnedWeaponRomDefNo = 0;
        }
    }
}

u8 baddie_canSeeTarget(GameObject* obj, EnemyState* state, void* from, void* to) {
    u8 traceHit[4];
    s16 toGrid[4];
    s16 fromGrid[4];
    Vec probe;
    Vec delta;
    TrackLineIntersectResult bboxHit;
    s16 setupId;
    u8 visible;
    int keepGroundOffset;

    traceHit[0] = 0;
    visible = 0;
    if (state->trackedObj != NULL) {
        probe.x = ((Vec*)from)->x;
        probe.y = ((Vec*)from)->y;
        probe.z = ((Vec*)from)->z;
        keepGroundOffset = 1;
        setupId = obj->anim.romDefNo;
        if (((((setupId != 0x613) && (setupId != 0x642)) && (setupId != 0x3fe)) &&
             ((setupId != 0x7c6) && (setupId != 0x7c8))) &&
            ((setupId != 0x251) && (setupId != 0x851))) {
            probe.y += 20.0f;
            keepGroundOffset = 0;
        }
        voxmaps_worldToGrid((f32*)&probe, fromGrid);
        probe.x = ((Vec*)to)->x;
        probe.y = 20.0f + ((Vec*)to)->y;
        probe.z = ((Vec*)to)->z;
        voxmaps_worldToGrid((f32*)&probe, toGrid);
        PSVECSubtract((Vec*)from, &probe, &delta);
        if (PSVECMag(&delta) < 1905.0f) {
            if (obj->anim.parent == NULL) {
                visible = voxmaps_traceLine((VoxPos*)toGrid, (VoxPos*)fromGrid, NULL, traceHit, 0);
            }
            if ((keepGroundOffset == 0) && (traceHit[0] == 1)) {
                visible = 1;
            }
        }
    }
    if ((visible != 0) && ((state->flags2E4 & ENEMY_FLAG2E4_BBOX_BLOCKS_SIGHT) != 0)) {
        if (trackGetLineIntersect((f32*)from, (f32*)&probe, 1.0f, 0, &bboxHit, obj, state->bboxTraceFlags, -1, 0, 0) !=
            0) {
            visible = 0;
        }
    }
    return visible;
}

void baddie_updateSightQuadrants(GameObject* obj, EnemyState* state, f32 radius) {
    u8 traceHit[4];
    s16 probeGrid[4];
    s16 baseGrid[4];
    Vec probe;
    struct BaddieSightQuadrantBits visibilityBits;
    Vec delta;
    TrackLineIntersectResult bboxHit;
    s16 baseAngle;
    u16 i;
    u8 visible;
    s16 setupId;
    f32 angle;

    visibilityBits = gBaddieSightQuadrantBitsInit;
    probe.x = obj->anim.localPosX;
    probe.y = 20.0f + obj->anim.localPosY;
    probe.z = obj->anim.localPosZ;
    voxmaps_worldToGrid((f32*)&probe, baseGrid);
    if (obj->anim.parent != NULL) {
        baseAngle = obj->anim.rotX + *(s16*)obj->anim.parent;
    } else {
        baseAngle = obj->anim.rotX;
    }
    i = 0;
    for (; i < 4; i++) {
        angle = (3.1415927f * (f32)(s32)((s32)baseAngle + ((u32)(u16)i << 0xe))) / 32768.0f;
        probe.x = obj->anim.worldPosX - (radius * mathSinf(angle));
        probe.y = obj->anim.worldPosY;
        probe.z = obj->anim.worldPosZ - (radius * mathCosf(angle));
        setupId = obj->anim.romDefNo;
        if (((((setupId != 0x613) && (setupId != 0x642)) && (setupId != 0x3fe)) &&
             ((setupId != 0x7c6) && (setupId != 0x7c8))) &&
            ((setupId != 0x251) && (setupId != 0x851))) {
            probe.y += 20.0f;
        }
        voxmaps_worldToGrid((f32*)&probe, probeGrid);
        PSVECSubtract(&obj->anim.worldPos, &probe, &delta);
        if (PSVECMag(&delta) < 1905.0f) {
            if (obj->anim.parent != NULL) {
                visible = 1;
            } else {
                visible = voxmaps_traceLine((VoxPos*)probeGrid, (VoxPos*)baseGrid, NULL, traceHit, 0);
                if (traceHit[0] == 1) {
                    visible = 1;
                }
            }
        } else {
            visible = 0;
        }
        if ((visible != 0) && ((state->flags2E4 & ENEMY_FLAG2E4_BBOX_BLOCKS_SIGHT) != 0)) {
            if (trackGetLineIntersect(&obj->anim.worldPosX, (f32*)&probe, 1.0f, 0, &bboxHit, obj, state->bboxTraceFlags,
                                      -1, 0, 0) != 0) {
                visible = 0;
            }
        }
        if (visible != 0) {
            state->controlFlags |= visibilityBits.w[i];
        } else {
            state->controlFlags &= ~visibilityBits.w[i];
        }
    }
}

void enemy_applyFloorResponse(GameObject* obj, EnemyState* state) {
    f32 nearestFloorY;
    f32 nearestSpecialY;
    f32 points[6];
    u32 flags;

    state->controlFlags &= 0xf7efffff;
    flags = state->flags2E4;
    if ((flags & ENEMY_FLAG2E4_FLOOR_RESPONSE_MASK) != 0) {
        enemy_findNearbyFloorHeights(obj, state, &nearestFloorY, &nearestSpecialY);
        flags = state->flags2E4;
        if ((flags & ENEMY_FLAG2E4_USE_SPECIAL_FLOOR_Y) != 0) {
            f32 sd = nearestSpecialY - obj->anim.localPosY;
            obj->anim.velocityY = sd * oneOverTimeDelta;
        } else if ((flags & ENEMY_FLAG2E4_OFFSET_FLOOR_Y) != 0) {
            f32 dy = nearestFloorY - obj->anim.localPosY;
            if ((dy > -20.0f) && (dy < 20.0f)) {
                f32 od = 25.0f + dy;
                obj->anim.velocityY = od * oneOverTimeDelta;
                state->controlFlags |= ENEMY_CONTROL_FLOOR_OFFSET_APPLIED;
            }
        } else {
            f32 dy = nearestFloorY - obj->anim.localPosY;
            if ((dy > -20.0f) && (dy < 20.0f)) {
                obj->anim.velocityY = dy * oneOverTimeDelta;
                state->controlFlags |= ENEMY_CONTROL_FLOOR_SNAP_APPLIED;
            }
        }
        if ((state->flags2E4 & ENEMY_FLAG2E4_BBOX_BLOCKS_SIGHT) == 0) {
            state->physicsActive = 0;
        }
    } else {
        if ((flags & 0xc) != 0) {
            state->physicsActive = 1;
        } else {
            state->physicsActive = 0;
        }
    }

    (*gPathControlInterface)->update((void*)obj, &state->flags, timeDelta);
    if ((state->flags2E4 & 4) != 0) {
        (*gPathControlInterface)->apply((void*)obj, &state->flags);
    }
    (*gPathControlInterface)->advance((void*)obj, &state->flags, timeDelta);

    if (((state->physicsActive != 0) && ((state->flags2E4 & ENEMY_FLAG2E4_FLOOR_RESPONSE_MASK) == 0)) &&
        ((state->surfaceFlags & ENEMY_SURFACE_FLAG_HAS_NEARBY_FLOOR) != 0)) {
        obj->anim.velocityY = 0.0f;
        state->controlFlags |= ENEMY_CONTROL_FLOOR_SNAP_APPLIED;
    }
    if ((state->flags2E4 & 0x00200000) != 0) {
        ObjPath_GetPointWorldPositionArray(obj, 2, 2, points);
        objAudioDispatchEventMask(obj, state->animEventMask, 7, points, &state->curvesCollision, state->pathSpeed, 1.0f);
    }
}

void enemy_findNearbyFloorHeights(GameObject* obj, EnemyState* state, f32* nearestFloorY, f32* nearestSpecialY) {
    TrackGroundHit** hitList[2];
    u16 hitCount;
    u16 i;
    TrackGroundHit* hit;
    f32 hitY;
    f32 zero;
    f32 nearestSpecialDelta;
    f32 nearestFloorDelta;
    f32 dy;
    f32 absDy;
    f32 defaultY;

    defaultY = -1.0f;
    *nearestFloorY = defaultY;
    *nearestSpecialY = defaultY;
    hitCount = (u16)trackGetHeight(obj, obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, hitList, 0, 0);
    *nearestFloorY = obj->anim.localPosY;
    *nearestSpecialY = obj->anim.localPosY;
    nearestSpecialDelta = nearestFloorDelta = 99999.0f;
    i = 0;
    state->controlFlags &= ~ENEMY_CONTROL_SPECIAL_FLOOR_FOUND;
    zero = 0.0f;
    state->nearestSpecialDeltaY = zero;
    state->surfaceFlags &= ~ENEMY_SURFACE_FLAG_HAS_NEARBY_FLOOR;
    for (; i < hitCount; i++) {
        hit = hitList[0][i];
        hitY = hit->height;
        dy = hitY - obj->anim.localPosY;
        absDy = dy;
        if (dy < zero) {
            absDy = -dy;
        }
        if ((s8)hit->surfaceType == 0xe) {
            if (absDy < nearestSpecialDelta) {
                state->nearestSpecialDeltaY = dy;
                state->surfaceFlags |= ENEMY_SURFACE_FLAG_HAS_NEARBY_FLOOR;
                nearestSpecialDelta = absDy;
                *nearestSpecialY = hitList[0][i]->height;
                if (state->nearestSpecialDeltaY > 20.0f) {
                    state->controlFlags |= (ENEMY_CONTROL_SPECIAL_FLOOR_FOUND | ENEMY_CONTROL_FLOOR_SNAP_APPLIED);
                }
            }
        } else if (absDy < nearestFloorDelta) {
            *nearestFloorY = hitY;
            state->surfaceFlags |= ENEMY_SURFACE_FLAG_HAS_NEARBY_FLOOR;
            nearestFloorDelta = absDy;
        }
    }
}

void enemyObjAnimUpdate(short* obj, EnemyState* state) {
    f32 vy;
    f32 dz;
    f32 dx;
    f32 dy;
    u32 flags;
    int mode;
    int i;
    f32 vel;
    f32 phase;
    f32 outY;
    EnemyMoveResult res;
    MatrixTransform rec;
    f32 mtx[16];

    memcpy(&state->prevLookDirX, &state->lookDirX, 0xc);
    memcpy(&state->lookDirX, obj + 0x12, 0xc);
    if ((state->flags2E4 & 0x400) != 0) {
        characterDoEyeAnims((GameObject*)obj, &state->eyeAnimState);
    }
    if ((state->trackedObj != NULL) && ((state->flags2E4 & 0x800) != 0)) {
        characterSetHeadYawToTarget((GameObject*)obj, state->trackedObj, &state->eyeAnimState, 0x19);
    }
    state->prevActionId = state->actionId;
    flags = state->controlFlags;
    if ((flags & 0x800) != 0) {
        tricky_handleDefeat((GameObject*)(obj), state);
    } else if ((flags & 0x1000) != 0) {
        Tricky_resumeAfterCommand((GameObject*)(obj), state);
    } else if ((flags & 0x20000000) != 0) {
        if ((flags & 0x400) != 0) {
            state->actionId = 3;
            switch (((GameObject*)obj)->anim.romDefNo) {
            case ENEMY_SHARPCLAW_GR_OBJ:
            case ENEMY_SHARPCLAW_SN_OBJ:
            case ENEMY_SHARPCLAW_CO_OBJ:
            case ENEMY_SHARPCLAW_AS_OBJ:
            case ENEMY_SHARPCLAW_SH_OBJ:
            case ENEMY_SHARPCLAW_SO_OBJ:
            case ENEMY_BOSSGENERAL_OBJ:
                sharpClawUpdateAttack((GameObject*)(obj), (u8*)state);
                break;
            case ENEMY_GUARDCLAW_OBJ:
            case 0x281:
                guardClaw_update((GameObject*)obj, (u8*)state);
                break;
            case ENEMY_GCROBOTPATROL_OBJ:
                gcRobotPatrol_update((GameObject*)obj, (u8*)state);
                break;
            case ENEMY_MIKALADON_OBJ:
                mikaladon_update((GameObject*)obj, state);
                break;
            case ENEMY_VAMBAT_OBJ:
            case ENEMY_FIREBAT_OBJ:
                vambat_updateEngaged((GameObject*)(obj), state);
                break;
            case ENEMY_KOOSHY_OBJ:
                kooshy_updateEngaged((GameObject*)(obj), state);
                break;
            case ENEMY_WEEVIL_OBJ:
                weevil_updateEngaged((GameObject*)(obj), state);
                break;
            case ENEMY_PINPON_OBJ:
                pinPon_updateEngaged((GameObject*)(obj), (int*)state);
                break;
            case ENEMY_RACHNOP_OBJ:
                rachnopUpdateAttack((GameObject*)obj, state);
                break;
            case ENEMY_SPITTINGEBA_OBJ:
                spittingEbaUpdateEngaged((GameObject*)(obj), (int)state);
                break;
            case ENEMY_WB_OBJ:
                wbUpdateEngaged((GameObject*)obj, (int)state);
                break;
            case ENEMY_MUTATEDEBA_OBJ:
                mutatedEbaUpdateEngaged((GameObject*)obj, state);
                break;
            case ENEMY_WHIRLPOOL_OBJ:
                iceBaddie_enterWhirlpoolGroup((GameObject*)obj, state);
                break;
            case ENEMY_SNOWWORM_OBJ:
            case ENEMY_SNOWWORM_BABY_OBJ:
                snowworm_update((GameObject*)obj, (u8*)state);
                break;
            case ENEMY_HOODEDZYCK_OBJ:
                hoodedZyck_update((GameObject*)obj, (u8*)state);
                break;
            case ENEMY_BATTLEDROID_OBJ:
                battleDroidUpdateAttack((GameObject*)obj, state);
                break;
            case ENEMY_FIRECRAWLER_OBJ:
            case ENEMY_REDEYE_OBJ:
            case ENEMY_SHADOWHUNTER_OBJ:
            case ENEMY_SWAMPSTRIDER_OBJ:
                crawler_update((GameObject*)obj, (u8*)state);
                break;
            case ENEMY_HAGABONMK2_OBJ:
                hagabonMK2_updateB((GameObject*)obj, (u8*)state);
                break;
            case 0x7c7:
            default:
                battleDroidUpdateAttack((GameObject*)obj, state);
                break;
            }
        } else {
            state->actionId = 4;
            switch (((GameObject*)obj)->anim.romDefNo) {
            case ENEMY_SHARPCLAW_GR_OBJ:
            case ENEMY_SHARPCLAW_SN_OBJ:
            case ENEMY_SHARPCLAW_CO_OBJ:
            case ENEMY_SHARPCLAW_AS_OBJ:
            case ENEMY_SHARPCLAW_SH_OBJ:
            case ENEMY_SHARPCLAW_SO_OBJ:
            case ENEMY_BOSSGENERAL_OBJ:
                sharpClawUpdateApproach((GameObject*)(obj), (void*)state);
                break;
            case ENEMY_GUARDCLAW_OBJ:
            case 0x281:
                guardClaw_update((GameObject*)obj, (u8*)state);
                break;
            case ENEMY_GCROBOTPATROL_OBJ:
                gcRobotPatrol_update((GameObject*)obj, (u8*)state);
                break;
            case ENEMY_MIKALADON_OBJ:
                mikaladon_update((GameObject*)obj, state);
                break;
            case ENEMY_VAMBAT_OBJ:
            case ENEMY_FIREBAT_OBJ:
                vambat_updateEngaged((GameObject*)(obj), state);
                break;
            case ENEMY_KOOSHY_OBJ:
                kooshy_updateEngaged((GameObject*)(obj), state);
                break;
            case ENEMY_WEEVIL_OBJ:
                weevil_updateEngaged((GameObject*)(obj), state);
                break;
            case ENEMY_PINPON_OBJ:
                pinPon_updateEngaged((GameObject*)(obj), (int*)state);
                break;
            case ENEMY_RACHNOP_OBJ:
                rachnopUpdateApproach((GameObject*)obj, state);
                break;
            case ENEMY_SPITTINGEBA_OBJ:
                spittingEbaUpdateEngaged((GameObject*)(obj), (int)state);
                break;
            case ENEMY_WB_OBJ:
                wbUpdateEngaged((GameObject*)obj, (int)state);
                break;
            case ENEMY_MUTATEDEBA_OBJ:
                mutatedEbaUpdateEngaged((GameObject*)obj, state);
                break;
            case ENEMY_WHIRLPOOL_OBJ:
                iceBaddie_enterWhirlpoolGroup((GameObject*)obj, state);
                break;
            case ENEMY_SNOWWORM_OBJ:
            case ENEMY_SNOWWORM_BABY_OBJ:
                snowworm_update((GameObject*)obj, (u8*)state);
                break;
            case ENEMY_HOODEDZYCK_OBJ:
                hoodedZyck_updateB((GameObject*)obj, (u8*)state);
                break;
            case ENEMY_BATTLEDROID_OBJ:
                battleDroidUpdate((GameObject*)obj, state);
                break;
            case ENEMY_FIRECRAWLER_OBJ:
            case ENEMY_REDEYE_OBJ:
            case ENEMY_SHADOWHUNTER_OBJ:
            case ENEMY_SWAMPSTRIDER_OBJ:
                crawler_updateB((GameObject*)obj, (u8*)state);
                break;
            case ENEMY_HAGABONMK2_OBJ:
                hagabonMK2_update((GameObject*)obj, (u8*)state);
                break;
            case 0x7c7:
            default:
                battleDroidUpdate((GameObject*)obj, state);
                break;
            }
        }
    } else if ((flags & 0x100) != 0) {
        state->actionId = 2;
        if (((state->controlFlags & 0x100) != 0) && ((state->prevControlFlags & 0x100) == 0)) {
            int moveId = state->moveId2;
            state->animPlaySpeed = 1.0f / (60.0f * state->moveSpeedScale2);
            state->rootMotionFlags = 1;
            ObjAnim_SetCurrentMove(obj, moveId, 0.0f, OBJANIM_MOVE_CONTROL_SKIP_EVENT_COUNTDOWN);
            if (*(void**)(obj + 0x2a) != 0) {
                ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->suppressOutgoingHits = 0;
            }
        }
        if ((state->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0) {
            state->animPlaySpeed = 0.0055555557f;
            state->rootMotionFlags = 0;
            ObjAnim_SetCurrentMove(obj, 0, 0.0f, 0);
            if (*(void**)(obj + 0x2a) != 0) {
                ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->suppressOutgoingHits = 0;
            }
            state->controlFlags &= ~0x100;
            ((GameObject*)obj)->anim.alpha = 0xff;
        } else {
            ((GameObject*)obj)->anim.alpha = (u8)(int)(255.0f * ((GameObject*)obj)->anim.currentMoveProgress);
            ((GameObject*)obj)->anim.flags = ((GameObject*)obj)->anim.flags & ~OBJANIM_FLAG_HIDDEN;
        }
    } else {
        state->actionId = 5;
        switch (((GameObject*)obj)->anim.romDefNo) {
        case ENEMY_SHARPCLAW_GR_OBJ:
        case ENEMY_SHARPCLAW_SN_OBJ:
        case ENEMY_SHARPCLAW_CO_OBJ:
        case ENEMY_SHARPCLAW_AS_OBJ:
        case ENEMY_SHARPCLAW_SH_OBJ:
        case ENEMY_SHARPCLAW_SO_OBJ:
        case ENEMY_BOSSGENERAL_OBJ:
            sharpClawUpdateIdle((GameObject*)obj, (u8*)state);
            break;
        case ENEMY_GUARDCLAW_OBJ:
        case 0x281:
            guardClaw_update((GameObject*)obj, (u8*)state);
            break;
        case ENEMY_GCROBOTPATROL_OBJ:
            gcRobotPatrol_update((GameObject*)obj, (u8*)state);
            break;
        case ENEMY_MIKALADON_OBJ:
            mikaladon_update((GameObject*)obj, state);
            break;
        case ENEMY_VAMBAT_OBJ:
        case ENEMY_FIREBAT_OBJ:
            vambat_updateIdle((GameObject*)(obj), state);
            break;
        case ENEMY_KOOSHY_OBJ:
            kooshy_updateIdle((GameObject*)(obj), state);
            break;
        case ENEMY_WEEVIL_OBJ:
            weevil_updateIdle((GameObject*)(obj), state);
            break;
        case ENEMY_PINPON_OBJ:
            pinPon_updateIdle((GameObject*)(obj), state);
            break;
        case ENEMY_RACHNOP_OBJ:
            rachnopUpdateIdle((GameObject*)obj, state);
            break;
        case ENEMY_SPITTINGEBA_OBJ:
            spittingEbaUpdateIdle((GameObject*)(obj), (int)state);
            break;
        case ENEMY_WB_OBJ:
            wbUpdateIdle((GameObject*)obj, (int)state);
            break;
        case ENEMY_MUTATEDEBA_OBJ:
            mutatedEbaUpdateIdle((GameObject*)obj, state);
            break;
        case ENEMY_WHIRLPOOL_OBJ:
            iceBaddie_leaveWhirlpoolGroup((GameObject*)obj, state);
            break;
        case ENEMY_SNOWWORM_OBJ:
        case ENEMY_SNOWWORM_BABY_OBJ:
            snowworm_applyReactionState((GameObject*)obj, (int*)state);
            break;
        case ENEMY_HOODEDZYCK_OBJ:
            hoodedZyck_updateIdle((GameObject*)(obj), state);
            break;
        case ENEMY_BATTLEDROID_OBJ:
            battleDroidUpdate((GameObject*)obj, state);
            break;
        case ENEMY_FIRECRAWLER_OBJ:
        case ENEMY_REDEYE_OBJ:
        case ENEMY_SHADOWHUNTER_OBJ:
        case ENEMY_SWAMPSTRIDER_OBJ:
            crawler_updateC((GameObject*)obj, (u8*)state);
            break;
        case ENEMY_HAGABONMK2_OBJ:
            hagabonMK2_updateB((GameObject*)obj, (u8*)state);
            break;
        case 0x7c7:
        default:
            battleDroidUpdate((GameObject*)obj, state);
            break;
        }
    }
    if (state->actionId != state->prevActionId) {
        state->controlFlags = state->controlFlags | BADDIE_CONTROL_JUST_TRIGGERED;
    } else {
        state->controlFlags = state->controlFlags & 0x7fffffff;
    }
    res.eventCount = 0;
    if (ObjAnim_AdvanceCurrentMove(obj, state->animPlaySpeed, timeDelta, (ObjAnimEventList*)&res) != 0) {
        state->controlFlags |= BADDIE_CONTROL_SEQUENCE_DRIVEN;
    } else {
        state->controlFlags &= ~BADDIE_CONTROL_SEQUENCE_DRIVEN;
    }
    state->animEventMask = 0;
    for (i = 0; i < res.eventCount; i++) {
        state->animEventMask |= 1 << res.events[i];
    }
    vy = 0.0f;
    if ((((state->flags2E4 & 0x20) != 0) && ((state->flags2E4 & 0x400000) == 0)) &&
        (((state->controlFlags & 0x1800) == 0) && ((state->rootMotionFlags & 4) == 0))) {
        vy = -(state->gravity * timeDelta - ((GameObject*)obj)->anim.velocityY);
    }
    vel = ((GameObject*)obj)->anim.velocityX;
    ((GameObject*)obj)->anim.velocityX = (vel < -10.0f) ? -10.0f : ((vel > 10.0f) ? 10.0f : vel);
    vel = ((GameObject*)obj)->anim.velocityY;
    ((GameObject*)obj)->anim.velocityY = (vel < -10.0f) ? -10.0f : ((vel > 10.0f) ? 10.0f : vel);
    vel = ((GameObject*)obj)->anim.velocityZ;
    ((GameObject*)obj)->anim.velocityZ = (vel < -10.0f) ? -10.0f : ((vel > 10.0f) ? 10.0f : vel);
    mode = 0;
    if (((state->flags2E4 & 0x80) != 0) && (state->rootMotionFlags != 0)) {
        mode = 1;
    } else if ((state->flags2E4 & 0x100) != 0) {
        mode = 2;
    } else if ((state->flags2E4 & 0x10) != 0) {
        mode = 3;
    }
    if (((state->flags2E4 & 0x200) != 0) && ((state->controlFlags & 0x4010) != 0)) {
        mode = 3;
    }
    if (mode == 1) {
        f32 zero;
        dx = (dz = 0.0f);
        dy = dz;
        if ((state->rootMotionFlags & 2) != 0) {
            dx = res.dx * oneOverTimeDelta;
        }
        if ((state->rootMotionFlags & 4) != 0) {
            dy = res.dy * oneOverTimeDelta;
        }
        if ((state->rootMotionFlags & 1) != 0) {
            dz = -res.dz * oneOverTimeDelta;
        }
        if ((state->rootMotionFlags & 8) != 0) {
            ((GameObject*)obj)->anim.rotX += res.dAngle;
        }
        rec.rotX = ((GameObject*)obj)->anim.rotX;
        rec.rotY = ((GameObject*)obj)->anim.rotY;
        rec.rotZ = ((GameObject*)obj)->anim.rotZ;
        rec.scale = 1.0f;
        zero = 0.0f;
        rec.x = zero;
        rec.y = zero;
        rec.z = zero;
        setMatrixFromObjectPos(mtx, &rec);
        if ((state->rootMotionFlags & 4) != 0) {
            Matrix_TransformPoint(mtx, dx, dy, -dz, (f32*)(obj + 0x12), (f32*)(obj + 0x14), (f32*)(obj + 0x16));
        } else {
            Matrix_TransformPoint(mtx, dx, 0.0f, -dz, (f32*)(obj + 0x12), &outY, (f32*)(obj + 0x16));
        }
    } else if (mode == 2) {
        if (ObjAnim_SampleRootCurvePhase((ObjAnimComponent*)obj,
                                         sqrtf(((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX +
                                               ((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ),
                                         &phase) != 0) {
            state->animPlaySpeed = phase;
        }
    } else if (mode == 3) {
        if ((state->flags2F1 & 0x80) == 0) {
            ((GameObject*)obj)->anim.velocityX =
                ((GameObject*)obj)->anim.velocityX * powfBitEstimate(state->drag, timeDelta);
            ((GameObject*)obj)->anim.velocityY =
                ((GameObject*)obj)->anim.velocityY * powfBitEstimate(state->drag, timeDelta);
            ((GameObject*)obj)->anim.velocityZ =
                ((GameObject*)obj)->anim.velocityZ * powfBitEstimate(state->drag, timeDelta);
        }
    }
    enemy_applyFloorResponse((GameObject*)(obj), state);
    if (((state->flags2E4 & 0x400000) != 0) || ((state->controlFlags & 0x8100000) != 0)) {
        if ((state->flags2F1 & 0x80) == 0) {
            objMove((GameObject*)obj, ((GameObject*)obj)->anim.velocityX * timeDelta,
                    ((GameObject*)obj)->anim.velocityY * timeDelta, ((GameObject*)obj)->anim.velocityZ * timeDelta);
        }
    } else if ((state->flags2E4 & 0x20) != 0) {
        f32 newY = (((GameObject*)obj)->anim.velocityY * timeDelta + ((GameObject*)obj)->anim.localPosY) -
                   0.5f * (state->gravity * (timeDelta * timeDelta));
        if ((state->flags2F1 & 0x80) == 0) {
            objMove((GameObject*)obj, ((GameObject*)obj)->anim.velocityX * timeDelta,
                    newY - ((GameObject*)obj)->anim.localPosY, ((GameObject*)obj)->anim.velocityZ * timeDelta);
            ((GameObject*)obj)->anim.velocityY = vy;
        }
    } else if ((state->flags2F1 & 0x80) == 0) {
        objMove((GameObject*)obj, ((GameObject*)obj)->anim.velocityX * timeDelta,
                ((GameObject*)obj)->anim.velocityY * timeDelta, ((GameObject*)obj)->anim.velocityZ * timeDelta);
    }
}

void baddie_updateEngagementState(GameObject* obj, EnemyState* sub) {
    GameObject* player;
    int* tricky;
    GameObject* target;
    GameObject* camTarget;

    player = Obj_GetPlayerObject();
    tricky = (int*)getTrickyObject();
    target = sub->trackedObj;
    if (target != NULL && (sub->flags2E4 & 0x10000) == 0 &&
        (target != player || (player->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0)) {
        sub->controlFlags &= ~0x800000;
        camTarget = (GameObject*)(*gCameraInterface)->getOverrideTarget();
        if (camTarget == obj) {
            sub->controlFlags |= 0x800200;
        }
        {
            u16 dist = sub->targetDist;
            u16 near = (u16)(int)sub->sightRange;
            if (dist < near) {
                sub->controlFlags |= 0x400;
                sub->controlFlags &= ~0x200;
            } else {
                f32 midf = sub->aggroRange;
                u16 mid = (u16)(int)midf;
                if (dist < mid) {
                    sub->controlFlags |= 0x200;
                    sub->controlFlags &= ~0x400;
                } else {
                    u16 far = (u16)(int)(1.39f * midf);
                    if (dist > far) {
                        sub->controlFlags &= ~0x20000600;
                    }
                }
            }
        }
    } else {
        sub->controlFlags &= ~0x800600;
        if ((sub->flags2E4 & 0x10000) != 0 ||
            (sub->trackedObj == player && (player->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) != 0)) {
            sub->controlFlags &= ~0x20000000;
        }
    }
    sub->controlFlags &= ~0x76f0008;
    if (tricky != NULL) {
        u8 r = TRICKY_INTERFACE(tricky)->isPlayingBall((GameObject*)tricky);
        if (r != 0) {
            sub->controlFlags |= 0x200000;
        }
    }
    if (sub->trackedObj == player) {
        if (playerIsDisguised(player) != 0) {
            sub->controlFlags |= 8;
            if ((sub->flags2E4 & BADDIE_CONTROL_PATH_FOLLOW) != 0) {
                sub->controlFlags &= ~0x800600;
            }
        }
    }
    if ((sub->controlFlags & 0x20000600) != 0) {
        if ((sub->flags2E4 & 0x1000) != 0) {
            u8 r = baddie_canSeeTarget(obj, sub, &obj->anim.worldPosX, (u8*)sub->trackedObj + 0x18);
            if (r != 0) {
                sub->controlFlags |= 0x1000000;
            }
            if ((sub->controlFlags & 0x1000000) == 0) {
                sub->controlFlags &= ~0x20000000;
            }
        } else {
            sub->controlFlags |= 0x1000000;
        }
        {
            u16 mode = sub->turnOctant;
            if (mode < 2 || mode > 5) {
                sub->controlFlags |= 0x400000;
            } else if ((sub->controlFlags & 0x1000000) != 0) {
                sub->controlFlags |= 0x2000000;
            }
        }
        if ((sub->flags2E4 & 0x4000) == 0) {
            f32* t = (f32*)sub->trackedObj;
            f32 mag = sqrtf(t[11] * t[11] + (t[9] * t[9] + t[10] * t[10]));
            if (mag > 0.5f) {
                sub->controlFlags |= 0x4000000;
            }
        }
        if ((sub->controlFlags & 0x600) != 0 && (sub->controlFlags & 0x6800000) != 0 &&
            (sub->controlFlags & 0x1000000) != 0) {
            sub->controlFlags |= 0x20000000;
        }
        if ((sub->controlFlags & 0x20000000) != 0) {
            if ((sub->flags2E4 & 0x40) != 0) {
                baddie_updateSightQuadrants(obj, sub, sub->sightRange);
            } else {
                sub->controlFlags |= 0xf0000;
            }
        }
    }
    if (sub->current == 0) {
        sub->controlFlags |= 0x800;
    }
}
void baddieTurnTowardTarget(GameObject* node, EnemyState* sub) {
    GameObject* target = sub->trackedObj;
    if (target != NULL) {
        f32 d[3];
        f32* dp = d;
        int raw;
        s32 delta;
        f32 dist;
        u16 ua;

        if ((sub->flags2E4 & 0x8000) != 0) {
            dp[0] = node->anim.worldPosX - target->anim.worldPosX;
            dp[1] = 0.0f;
            dp[2] = node->anim.worldPosZ - target->anim.worldPosZ;
        } else {
            dp[0] = node->anim.worldPosX - target->anim.worldPosX;
            dp[1] = node->anim.worldPosY - target->anim.worldPosY;
            dp[2] = node->anim.worldPosZ - target->anim.worldPosZ;
        }
        ua = getAngle(-dp[0], -dp[2]);
        if ((int*)node->anim.parent != NULL) {
            raw = (s16)(node->anim.rotX + *(s16*)node->anim.parent);
        } else {
            raw = node->anim.rotX;
        }
        delta = ua - (u16)(s16)raw;
        if (delta > 0x8000) {
            delta -= 0xFFFF;
        }
        if (delta < -0x8000) {
            delta += 0xFFFF;
        }
        sub->turnAngleDelta = delta;
        sub->turnOctant = (u32)(u16)delta >> 13;

        {
            f32 sqX;
            f32 sqZ;
            f32 sqY;
            f32 t;
            t = dp[2];
            sqZ = t * t;
            t = dp[0];
            sqX = t * t;
            t = dp[1];
            sqY = t * t;
            dist = sqrtf(sqZ + (sqX + sqY));
        }
        *(s16*)&sub->targetDist = (s16)dist;

        {
            GameObject* targetObj = sub->trackedObj;
            *(s16*)&sub->targetHeightDelta = (s16)(targetObj->anim.worldPosY - node->anim.worldPosY);
        }
    }
}

u32 gEnemySelfAngleFlagClearMask[] = {
    0x40000, 0x80000, 0x80000, 0x10000, 0x10000, 0x20000, 0x20000, 0x40000,
};

u32 gEnemyTargetAngleFlagClearMask[] = {
    0x10000, 0x20000, 0x20000, 0x40000, 0x40000, 0x80000, 0x80000, 0x10000,
};

ObjectDescriptor gBaddieObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)enemy_initialise,
    (ObjectDescriptorCallback)enemy_release,
    0,
    (ObjectDescriptorCallback)enemy_init,
    (ObjectDescriptorCallback)enemy_update,
    (ObjectDescriptorCallback)enemy_hitDetect,
    (ObjectDescriptorCallback)enemy_render,
    (ObjectDescriptorCallback)enemy_free,
    (ObjectDescriptorCallback)enemy_getObjectTypeId,
    enemy_getExtraSize,
};

int enemy_SeqFn(GameObject* node, int unused, ObjSeqState* animUpdate) {
    char* sub = (char*)node->extra;
    EnemyState* enemyState = (EnemyState*)sub;
    EnemyPlacement* placement = (EnemyPlacement*)node->anim.placementData;
    int i;
    GameObject* obj;

    if (node->userData1 != 0) {
        return 0;
    }
    enemyState->controlFlags |= 0x8000;
    memcpy(&enemyState->prevLookDirX, &enemyState->lookDirX, sizeof(Vec));
    memcpy(&enemyState->lookDirX, &node->anim.velocityX, sizeof(Vec));
    for (i = 0; i < animUpdate->eventCount; i++) {
        switch (animUpdate->eventIds[i]) {
        case 1:
            obj = getTrickyObject();
            if (obj != NULL) {
                ((void (*)(GameObject*, int, GameObject*))obj->anim.dll[0][13])(obj, 1, node);
                enemyState->controlFlags |= 0x200000;
                enemyState->trackedObj = obj;
            }
            break;
        case 4:
            obj = Obj_GetPlayerObject();
            if (obj != NULL) {
                enemyState->controlFlags &= ~0x200000;
                enemyState->trackedObj = obj;
            }
            break;
        case 2:
            if (node->anim.romDefNo == ENEMY_BOSSGENERAL_OBJ) {
                enemyState->weaponRomDefNo = 0x7a5;
            } else {
                enemyState->weaponRomDefNo = 0x33;
            }
            break;
        case 3:
            (*gObjectTriggerInterface)->setCamVars(CAMERA_MODE_COMBAT_RESOURCE_ID, 4, (int)node, 0x3c);
            break;
        case 6:
            if (enemyState->tailSimHandle != NULL) {
                ObjModelChain_SetEnabled(enemyState->tailSimHandle, 1);
            }
            break;
        case 7:
            if (enemyState->tailSimHandle != NULL) {
                ObjModelChain_SetEnabled(enemyState->tailSimHandle, 0);
            }
            break;
        }
    }
    baddieInstantiateWeapon(node, (EnemyState*)sub);
    if (node->seqIndex == -1) {
        enemyState->flags2E8 &= ~3;
        ObjHits_DisableObject(node);
        return 0;
    }
    if ((enemyState->controlFlags & 0x1800) == 0) {
        baddieTurnTowardTarget(node, (EnemyState*)sub);
        baddie_updateEngagementState(node, (EnemyState*)sub);
    }
    if (placement->triggerSequenceId != -1) {
        if ((enemyState->controlFlags & 0x600) != 0) {
            if (animUpdate->slot == node->seqIndex) {
                return 4;
            }
        }
    }
    return 0;
}

/* sidekickToy_updateCurveTargetLatch: pre-curve probe + state-bit gate. If controlFlags'
 * BADDIE_CONTROL_PATH_FOLLOW bit is set, ask baddie_canSeeTarget whether the target is
 * locked on; on hit, leave controlFlags alone. Otherwise initialise the rom-curve walker with
 * (data, obj, 700.0f, &lbl_803DBC58, -1) and toggle
 * the 0x2000 bit based on the u8 result. */
void sidekickToy_updateCurveTargetLatch(GameObject* obj) {
    EnemyState* state = obj->extra;
    u8* data = *(u8**)state;
    if ((state->controlFlags & BADDIE_CONTROL_PATH_FOLLOW) != 0) {
        if (baddie_canSeeTarget(obj, (EnemyState*)state, &obj->anim.worldPosX, data + 0x68) != 0) {
            return;
        }
    }
    if ((*gRomCurveInterface)->initCurve(*(u8**)state, (void*)obj, 700.0f, (int*)&lbl_803DBC58, -1) != 0) {
        state->controlFlags &= ~BADDIE_CONTROL_PATH_FOLLOW;
    } else {
        state->controlFlags |= BADDIE_CONTROL_PATH_FOLLOW;
    }
}

int enemy_findNearbyEnemies(GameObject* obj, f32 radius, u8 flags, int max, EnemyTargetSearchResult* out) {
    EnemyState* state;
    int resultCount;
    GameObject** arr;
    short ang;
    GameObject* tgt;
    u32 diff;
    int i;
    f32 distSquared;
    int count;
    Vec d;
    void* dp = &d;

    state = obj->extra;
    count = 0;
    resultCount = 0;
    if ((flags & 1) != 0) {
        tgt = objGetNearestTypeTo(ENEMY_OBJGROUP, obj, &radius);
        out->obj = tgt;
        if (tgt != 0) {
            out->dist = radius;
            resultCount = 1;
            if ((flags & 2) != 0) {
                if ((state->flags2E4 & 0x8000) != 0) {
                    d.x = obj->anim.worldPosX - out->obj->anim.worldPosX;
                    d.y = 0.0f;
                    d.z = obj->anim.worldPosZ - out->obj->anim.worldPosZ;
                } else {
                    d.x = obj->anim.worldPosX - out->obj->anim.worldPosX;
                    d.y = obj->anim.worldPosY - out->obj->anim.worldPosY;
                    d.z = obj->anim.worldPosZ - out->obj->anim.worldPosZ;
                }
                diff = getAngle(-d.x, -d.z) & 0xffff;
                if (obj->anim.parent != 0) {
                    ang = (s16)(obj->anim.rotX + *(s16*)obj->anim.parent);
                } else {
                    ang = obj->anim.rotX;
                }
                diff = diff - ((int)ang & 0xffffU);
                if ((int)diff > 0x8000) {
                    diff = diff - 0xffff;
                }
                if ((int)diff < -0x8000) {
                    diff = diff + 0xffff;
                }
                ang = (short)((diff & 0xffff) >> 0xd);
                state->controlFlags &= ~gEnemySelfAngleFlagClearMask[ang];
                if ((flags & 4) != 0) {
                    ((EnemyState*)out->obj->extra)->controlFlags &= ~gEnemyTargetAngleFlagClearMask[ang];
                }
            }
        }
    } else {
        radius = radius * radius;
        arr = (GameObject**)objGetAllOfType(ENEMY_OBJGROUP, &count);
        if (count != 0) {
            i = 0;
            for (; i < count; i++) {
                distSquared = vec3f_distanceSquared(&obj->anim.worldPosX, &arr[i]->anim.worldPosX);
                if ((distSquared < radius) && (arr[i] != obj)) {
                    out[resultCount].obj = arr[i];
                    out[resultCount].dist = sqrtf(distSquared);
                    if ((flags & 2) != 0) {
                        if ((state->flags2E4 & 0x8000) != 0) {
                            d.x = obj->anim.worldPosX - out[resultCount].obj->anim.worldPosX;
                            d.y = 0.0f;
                            d.z = obj->anim.worldPosZ - out[resultCount].obj->anim.worldPosZ;
                        } else {
                            d.x = obj->anim.worldPosX - out[resultCount].obj->anim.worldPosX;
                            d.y = obj->anim.worldPosY - out[resultCount].obj->anim.worldPosY;
                            d.z = obj->anim.worldPosZ - out[resultCount].obj->anim.worldPosZ;
                        }
                        diff = getAngle(-d.x, -d.z) & 0xffff;
                        if (obj->anim.parent != 0) {
                            ang = (s16)(obj->anim.rotX + *(s16*)obj->anim.parent);
                        } else {
                            ang = obj->anim.rotX;
                        }
                        diff = diff - ((int)ang & 0xffffU);
                        if ((int)diff > 0x8000) {
                            diff = diff - 0xffff;
                        }
                        if ((int)diff < -0x8000) {
                            diff = diff + 0xffff;
                        }
                        ang = (short)((diff & 0xffff) >> 0xd);
                        state->controlFlags &= ~gEnemySelfAngleFlagClearMask[ang];
                        if ((flags & 4) != 0) {
                            ((EnemyState*)out[resultCount].obj->extra)->controlFlags &=
                                ~gEnemyTargetAngleFlagClearMask[ang];
                        }
                    }
                    resultCount++;
                    if (resultCount >= max) {
                        i = count;
                    }
                }
            }
        }
    }
    return resultCount;
}

u8 enemy_getFreezeRecoverSeconds(GameObject* obj) {
    EnemyState* state;
    f32 freezeRecoverTimer;
    f32 zero;
    if (obj != NULL) {
        state = obj->extra;
    } else {
        return 0;
    }
    if (state != NULL) {
        freezeRecoverTimer = state->freezeRecoverTimer;
        zero = 0.0f;
        if (freezeRecoverTimer != zero) {
            return (u8)((s32)(freezeRecoverTimer / 30.0f) + 1);
        } else {
            return 0;
        }
    }
    return 0;
}

void enemy_getCurveParams(GameObject* obj, int* outIdx, f32* outA, f32* outB) {
    EnemyState* state;
    f32 fz;
    if (obj != NULL) {
        state = obj->extra;
        if (state != NULL) {
            *outA = (f32)(u32)(state)->curveParamA / 255.0f;
            *outB = (f32)(u32)(state)->curveParamB;
            *outIdx = state->curveIndex;
            return;
        }
    }
    fz = 0.0f;
    *outA = fz;
    *outB = fz;
    *outIdx = 0;
}
void enemy_setHealthZero(GameObject* obj) {
    EnemyState* state = obj->extra;
    state->current = 0;
}

f32 enemy_getHealthFraction(register GameObject* obj) {
    register u16 maxHealth;
    register EnemyState* state;
    u16 curHealth;
    state = obj->extra;
    if (state == NULL) {
        return 0.0f;
    }
    maxHealth = state->max;
    if (maxHealth != 0) {
        curHealth = state->current;
        if (curHealth != 0) {
            return (f32)(u32)curHealth / (f32)(u32)maxHealth;
        }
    }
    return 0.0f;
}

void enemy_trackPlayer(GameObject* obj) {
    EnemyState* state = obj->extra;
    state->trackedObj = Obj_GetPlayerObject();
}

void enemy_setTrackedObj(GameObject* obj, GameObject* target) {
    ((EnemyState*)obj->extra)->trackedObj = target;
}

void enemy_steerVelocityToward(GameObject* obj, void* state, f32* desiredVec, f32 maxSpeed, f32 speedBand,
                               f32 maxTurnRad, u8 clampToGround) {
    EnemyState* enemyState = (EnemyState*)state;
    f32 curMag, targetMag, axisMag, speed, speedScale;
    Vec curDir;
    Vec targetDir;
    Vec turnAxis;
    Mtx rotMtx;

    curMag = PSVECMag((Vec*)&enemyState->lookDirX);
    if (curMag > 0.0f) {
        f32 inv = 1.0f / curMag;
        curDir.x = enemyState->lookDirX * inv;
        curDir.y = enemyState->lookDirY * inv;
        curDir.z = enemyState->lookDirZ * inv;
        PSVECNormalize(&curDir, &curDir);
    } else {
        curDir.x = 0.0f;
        curDir.y = 0.0f;
        curDir.z = 0.0f;
    }

    targetMag = PSVECMag((Vec*)desiredVec);
    if (targetMag > 0.0f) {
        f32 inv = 1.0f / targetMag;
        targetDir.x = desiredVec[0] * inv;
        targetDir.y = desiredVec[1] * inv;
        targetDir.z = desiredVec[2] * inv;
    } else {
        targetDir.x = 0.0f;
        targetDir.y = 0.0f;
        targetDir.z = 0.0f;
    }

    PSVECCrossProduct(&curDir, &targetDir, &turnAxis);
    axisMag = PSVECMag(&turnAxis);
    if (axisMag > 0.0f) {
        f32 angle;
        int gt;
        f64 gtf;
        f32 zero;
        angle = acosf_fast(PSVECDotProduct(&curDir, &targetDir));
        gt = (angle > maxTurnRad);
        zero = 0.0f;
        gtf = __fabs((f32)gt);
        if (gtf != zero) {
            f32 rot = maxTurnRad * ((angle > 0.0f) ? 1.0f : -1.0f);
            PSMTXRotAxisRad(rotMtx, &turnAxis, rot);
            PSMTXMultVecSR(rotMtx, &curDir, &targetDir);
        }
    }

    speedScale = 0.075f;
    speed = targetMag * speedScale;
    {
        f32 cap_high = curMag + speedBand;
        if (speed > cap_high) {
            speed = cap_high;
        } else {
            f32 cap_low = curMag - speedBand;
            if (speed < cap_low) {
                speed = cap_low;
            }
        }
        if (speed > maxSpeed) {
            speed = maxSpeed;
        }
    }

    obj->anim.velocityX = targetDir.x * speed;
    obj->anim.velocityY = targetDir.y * speed;
    obj->anim.velocityZ = targetDir.z * speed;

    if (clampToGround != 0) {
        f32 y = obj->anim.velocityY;
        if (y < 0.0f) {
            f32 floor_height = obj->anim.localPosY;
            GameObject* target = enemyState->trackedObj;
            f32 ground = 10.0f + target->anim.localPosY;
            if (floor_height < ground) {
                f32 t = (ground - floor_height) / 10.0f;
                obj->anim.velocityY = y * (1.0f - t);
            }
        }
    }
}

/* sidekickToy_accelerateTowardTarget3D: 3D physics step toward a target. Variant of sidekickToy_accelerateTowardTargetXZ that
 * uses the full 3D distance (xyz) instead of planar (xz), and also nudges
 * the y-axis velocity at obj+0x28. Returns the y-delta. */

f32 sidekickToy_accelerateTowardTarget3D(GameObject* obj, f32 tx, f32 ty, f32 tz, f32 accel, f32 speedScale, f32 maxVel,
                                         f32 drag) {
    f32 dx = tx - obj->anim.worldPosX;
    f32 dy = ty - obj->anim.worldPosY;
    f32 dz = tz - obj->anim.worldPosZ;
    f32 dist = sqrtf(dx * dx + dy * dy + dz * dz);
    if (dist > accel) {
        obj->anim.velocityX = obj->anim.velocityX + timeDelta * (speedScale * (dx / dist));
        obj->anim.velocityY = obj->anim.velocityY + timeDelta * (speedScale * (dy / dist));
        obj->anim.velocityZ = obj->anim.velocityZ + timeDelta * (speedScale * (dz / dist));
    } else if (dist > 0.0f) {
        obj->anim.velocityX = obj->anim.velocityX + timeDelta * (speedScale * (dx / accel));
        obj->anim.velocityY = obj->anim.velocityY + timeDelta * (speedScale * (dy / accel));
        obj->anim.velocityZ = obj->anim.velocityZ + timeDelta * (speedScale * (dz / accel));
    }
    if (obj->anim.velocityX < -maxVel) {
        obj->anim.velocityX = -maxVel;
    } else if (obj->anim.velocityX > maxVel) {
        obj->anim.velocityX = maxVel;
    }
    if (obj->anim.velocityY < -maxVel) {
        obj->anim.velocityY = -maxVel;
    } else if (obj->anim.velocityY > maxVel) {
        obj->anim.velocityY = maxVel;
    }
    if (obj->anim.velocityZ < -maxVel) {
        obj->anim.velocityZ = -maxVel;
    } else if (obj->anim.velocityZ > maxVel) {
        obj->anim.velocityZ = maxVel;
    }
    if (drag != 0.0f) {
        obj->anim.velocityX = obj->anim.velocityX * powfBitEstimate(drag, timeDelta);
        obj->anim.velocityY = obj->anim.velocityY * powfBitEstimate(drag, timeDelta);
        obj->anim.velocityZ = obj->anim.velocityZ * powfBitEstimate(drag, timeDelta);
    }
    return dy;
}

/* sidekickToy_accelerateTowardTargetXZ: xz-plane physics step toward a target. Computes the planar
 * distance to (tx,ty,tz), then nudges the obj's xz velocity (offsets 0x24,
 * 0x2c) by timeDelta * speedScale * unitDir, clamped at +/-maxVel, with an
 * optional drag pass. Returns the y-delta. */
f32 sidekickToy_accelerateTowardTargetXZ(GameObject* obj, f32 tx, f32 ty, f32 tz, f32 accel, f32 speedScale, f32 maxVel,
                                         f32 drag) {
    f32 dx = tx - obj->anim.worldPosX;
    f32 dy = ty - obj->anim.worldPosY;
    f32 dz = tz - obj->anim.worldPosZ;
    f32 dist = sqrtf(dx * dx + dz * dz);
    if (dist > accel) {
        obj->anim.velocityX = obj->anim.velocityX + timeDelta * (speedScale * (dx / dist));
        obj->anim.velocityZ = obj->anim.velocityZ + timeDelta * (speedScale * (dz / dist));
    } else if (dist > 0.0f) {
        obj->anim.velocityX = obj->anim.velocityX + timeDelta * (speedScale * (dx / accel));
        obj->anim.velocityZ = obj->anim.velocityZ + timeDelta * (speedScale * (dz / accel));
    }
    if (obj->anim.velocityX < -maxVel) {
        obj->anim.velocityX = -maxVel;
    } else if (obj->anim.velocityX > maxVel) {
        obj->anim.velocityX = maxVel;
    }
    if (obj->anim.velocityZ < -maxVel) {
        obj->anim.velocityZ = -maxVel;
    } else if (obj->anim.velocityZ > maxVel) {
        obj->anim.velocityZ = maxVel;
    }
    if (drag != 0.0f) {
        obj->anim.velocityX = obj->anim.velocityX * powfBitEstimate(drag, timeDelta);
        obj->anim.velocityZ = obj->anim.velocityZ * powfBitEstimate(drag, timeDelta);
    }
    return dy;
}

void baddieTurnTowardLookDir(GameObject* node, void* sub, int divisor, f32 fa, f32 fb, u8 useScaledRoll) {
    EnemyState* enemyState = (EnemyState*)sub;
    f32 dt;
    int angle;
    s32 delta;
    f32 delta_f;
    s16 newVal;
    f32 zero;

    dt = timeDelta / (f32)(u32)(u16)divisor;
    if (dt > 1.0f) {
        dt = 1.0f;
    }

    angle = (u16)getAngle(-enemyState->lookDirX, -enemyState->lookDirZ);
    delta = angle - (u16)node->anim.rotX;
    delta_f = delta;
    if (delta_f > 32768.0f) {
        delta_f = -65535.0f + delta_f;
    }
    if (delta_f < -32768.0f) {
        delta_f = 65535.0f + delta_f;
    }
    delta_f *= dt;
    newVal = (s16)(*(s16*)(int)node + (s32)delta_f);
    node->anim.rotX = newVal;

    zero = 0.0f;
    if (fa != zero) {
        if (useScaledRoll != 0) {
            node->anim.rotZ = (s16)(node->anim.rotZ + (s32)(fa * (delta_f * dt)));
        } else {
            node->anim.rotZ = (s16)(oneOverTimeDelta * (delta_f * fa));
            {
                s16 v = node->anim.rotZ;
                if (v > 0x2000) {
                    node->anim.rotZ = 0x2000;
                } else if (v < -0x2000) {
                    node->anim.rotZ = -0x2000;
                }
            }
        }
    }

    if (fb != 0.0f) {
        f32 dz2 = enemyState->lookDirZ * enemyState->lookDirZ;
        f32 dx2 = enemyState->lookDirX * enemyState->lookDirX;
        f32 hyp = sqrtf(dz2 + dx2);
        int angle2 = (u16)getAngle(enemyState->lookDirY * fb, hyp);
        s32 d2 = angle2 - (u16)node->anim.rotY;
        f32 d2f = d2;
        s16 newVal2;
        if (d2f > 32768.0f) {
            d2f = -65535.0f + d2f;
        }
        if (d2f < -32768.0f) {
            d2f = 65535.0f + d2f;
        }
        newVal2 = (s16)(*(s16*)((int)node + 2) + (s32)(d2f * dt));
        node->anim.rotY = newVal2;
    }
}

void baddieTurnTowardPoint(GameObject* node, void* state, f32 targetX, f32 targetZ, int divisor, int angleBias) {
    s32 delta;
    f32 dt;
    s16 newVal;
    f32 t0 = node->anim.localPosX - targetX;
    f32 t1 = node->anim.localPosZ - targetZ;
    delta = getAngle(t0, t1);
    delta = (s16)(delta - (u16)node->anim.rotX);
    if (delta > 0x8000) {
        delta = (s16)(delta - 0xFFFF);
    }
    if ((s16)delta < -0x8000) {
        delta = (s16)(delta + 0xFFFF);
    }
    delta += angleBias;
    dt = timeDelta / (f32)(u32)(u16)divisor;
    if (dt > 1.0f) {
        dt = 1.0f;
    }
    newVal = (s16)(*(s16*)node + (s32)((f32)(s16)delta * dt));
    node->anim.rotX = newVal;
}

void baddieSetMove(GameObject* obj, void* state, u8 moveId, f32 rateScale, u8 moveControlFlags, u8 stateByte) {
    EnemyState* enemyState = (EnemyState*)state;
    ObjHitsPriorityState* hitState;

    enemyState->animPlaySpeed = 1.0f / (60.0f * rateScale);
    enemyState->rootMotionFlags = stateByte;
    ObjAnim_SetCurrentMove(obj, moveId, 0.0f, moveControlFlags);
    hitState = (ObjHitsPriorityState*)(obj)->anim.hitReactState;
    if (hitState != NULL) {
        hitState->suppressOutgoingHits = 0;
    }
}

void baddieAfterUpdateBonesCb(GameObject* obj, ObjModel* model) {
    EnemyState* state = obj->extra;
    ModelFileHeader* v = model->file;
    switch (obj->anim.romDefNo) {
    case ENEMY_HAGABONMK2_OBJ:
        ObjModelChain_Update(model, v, state->tailSimHandle, crawler_rotateVectorYaw);
        break;
    default:
        ObjModelChain_Update(model, v, state->tailSimHandle, NULL);
        break;
    }
}

int enemy_getExtraSize(void) {
    return sizeof(EnemyState);
}
int enemy_getObjectTypeId(void) {
    return 0x14b;
}

void enemy_free(GameObject* obj, int flag) {
    GameObject* child;
    int i;
    int n;
    EnemyState* state;

    state = obj->extra;

    if (state->tailSimHandle != NULL) {
        ObjModelChain_Free(state->tailSimHandle);
    }
    if (state->modelLight != NULL) {
        ModelLightStruct_free(state->modelLight);
        state->modelLight = NULL;
    }
    if (*(void**)state != NULL) {
        mm_free((void*)*(int*)state);
        *(int*)state = 0;
    }
    switch (obj->anim.romDefNo) {
    case ENEMY_HAGABONMK2_OBJ:
        hagabonMK2_stopLoopSfx(obj, (u8*)state);
        break;
    case ENEMY_WHIRLPOOL_OBJ:
        if (objIsObjectType(obj, ENEMY_OBJGROUP_SECONDARY) != 0) {
            objFreeObjectType(obj, ENEMY_OBJGROUP_SECONDARY);
        }
        break;
    }
    n = obj->childCount;
    for (i = 0; i < n; i++) {
        child = obj->childObjs[0];
        if (child != NULL) {
            ObjLink_DetachChild(obj, (GameObject*)child);
            if (flag == 0 || (child->objectFlags & 0x10) == 0) {
                Obj_FreeObject((GameObject*)child);
            }
        }
    }
    (*gExpgfxInterface)->freeSource((int)obj);
    objFreeObjectType(obj, ENEMY_OBJGROUP);
}

void enemy_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible) {
    EnemyState* state = obj->extra;
    if (visible != 0) {
        switch (obj->userData1) {
        case 0:
            objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
            {
                u32 flags = state->flags2E8;
                if ((flags & 3) != 0) {
                    if ((flags & 1) != 0) {
                        state->flags2E8 &= ~1;
                        state->flags2E8 |= 2;
                    }
                    if (state->modelLight == NULL) {
                        state->modelLight = objCreateLight(0, 1);
                    }
                    objDoParticleFx(obj, 1.0f, 3, state->particleScale, state->modelLight);
                }
            }
            if ((state->flags2E8 & 4) != 0) {
                if (state->modelLight == NULL) {
                    state->modelLight = objCreateLight(0, 1);
                }
                objDoParticleFx(obj, 1.0f, 4, state->particleScale, state->modelLight);
            }
            if ((state->flags2E8 & 0x40) != 0) {
                Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_forcecryslp11);
                objDoParticleFx(obj, 1.0f, 5, state->particleScale, 0);
            }
            if ((state->flags2E8 & 0x80) != 0) {
                Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_forcecryslp11);
                objDoParticleFx(obj, 1.5f, 6, state->particleScale, 0);
            }
            if ((state->flags2E8 & 0x100) != 0) {
                objDoParticleFx(obj, 0.75f, 7, state->particleScale, 0);
            }
            break;
        }
    }
}

void enemy_hitDetect(GameObject* obj) {
    EnemyState* state = obj->extra;
    ObjHitsPriorityState* childHitState;

    if (state->modelLight != NULL && modelLightStruct_getActiveState(state->modelLight) == 0) {
        ModelLightStruct_free(state->modelLight);
        state->modelLight = NULL;
    }
    state->lastHitObject = (GameObject*)((ObjHitsPriorityState*)obj->anim.hitReactState)->lastHitObject;
    if (((ObjHitsPriorityState*)obj->anim.hitReactState)->lastHitObject != 0) {
        ((ObjHitsPriorityState*)obj->anim.hitReactState)->suppressOutgoingHits = 1;
    }
    if (obj->childObjs[0] != NULL && ((GameObject*)obj->childObjs[0])->anim.hitReactState != NULL &&
        (childHitState = (ObjHitsPriorityState*)((GameObject*)obj->childObjs[0])->anim.hitReactState)->lastHitObject !=
            0) {
        ((ObjHitsPriorityState*)obj->anim.hitReactState)->suppressOutgoingHits = 1;
    }
    if (state->tailSimHandle != NULL) {
        ObjModelChain_AdvancePhase((ObjModelChain*)state->tailSimHandle);
    }
}

void enemy_update(GameObject* obj) {
    GameObject* player;
    EnemyState* state;
    u8* setup;
    GameObject* tricky;
    u32 flags;
    EnemyPlacement* s2;
    f32 fz;

    state = obj->extra;
    setup = (u8*)obj->anim.placementData;
    tricky = getTrickyObject();
    if (getCurUiDll() == 4) {
        return;
    }
    if ((state->flags2E4 & 0x8000006) != 0) {
        if (objPosToMapBlockIdx(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ) == -1) {
            return;
        }
    } else {
        if (isInBounds(obj->anim.localPosX, obj->anim.localPosZ) == 0) {
            return;
        }
    }
    if (objIsFrozen(obj) != 0) {
        baddie_updateWhileFrozen(obj, (u8*)state, 1);
        return;
    }
    if (state->trackedObj == NULL) {
        state->trackedObj = Obj_GetPlayerObject();
    } else if ((((GameObject*)state->trackedObj)->objectFlags & OBJECT_OBJFLAG_FREED) != 0) {
        state->trackedObj = Obj_GetPlayerObject();
    }
    state->prevControlFlags = state->controlFlags;
    baddieInstantiateWeapon(obj, (EnemyState*)state);
    flags = state->controlFlags;
    if ((flags & 1) != 0 && (flags & 2) == 0) {
        if (((EnemyPlacement*)setup)->triggerSequenceId == -1) {
            return;
        }
        if (setup != NULL && (((EnemyPlacement*)setup)->flags & 8) != 0) {
            obj->anim.localPosX = ((ObjPlacement*)setup)->posX;
            obj->anim.localPosY = ((ObjPlacement*)setup)->posY;
            obj->anim.localPosZ = ((ObjPlacement*)setup)->posZ;
        }
        (*gObjectTriggerInterface)->runSequence(((EnemyPlacement*)setup)->triggerSequenceId, obj, -1);
        state->controlFlags |= 2;
        state->controlFlags &= ~1;
        return;
    }
    if (obj->userData1 != 0) {
        if (((EnemyPlacement*)setup)->gameBit2 != -1) {
            if (mainGetBit(((EnemyPlacement*)setup)->gameBit2) == 0) {
                return;
            }
            if ((state->controlFlags & 0x800) != 0) {
                return;
            }
            if ((state->controlFlags & 0x1000) == 0) {
                return;
            }
            player = Obj_GetPlayerObject();
            if (((EnemyPlacement*)setup)->gameBit != -1) {
                if (mainGetBit(((EnemyPlacement*)setup)->gameBit) != 0) {
                    return;
                }
            }
            if (player != NULL) {
                if (vec3f_distanceSquared(&player->anim.worldPosX, &((EnemyPlacement*)setup)->base.posX) > 1600.0f) {
                    enemy_init(obj, setup, 0);
                    state->controlFlags |= 0x1000;
                    state->prevControlFlags &= ~0x1000;
                } else {
                    return;
                }
            } else {
                return;
            }
        } else if (((EnemyPlacement*)setup)->gameBit != -1) {
            if (mainGetBit(((EnemyPlacement*)setup)->gameBit) != 0) {
                return;
            }
            if ((state->controlFlags & 0x800) != 0) {
                return;
            }
            player = Obj_GetPlayerObject();
            if (player != NULL) {
                if (vec3f_distanceSquared(&player->anim.worldPosX, &((EnemyPlacement*)setup)->base.posX) > 1600.0f) {
                    enemy_init(obj, setup, 0);
                    state->controlFlags |= 0x1000;
                    state->prevControlFlags &= ~0x1000;
                } else {
                    return;
                }
            } else {
                return;
            }
        } else {
            if (*(u32*)&((ObjPlacement*)setup)->ident == 0xFFFFFFFF) {
                return;
            }
            if (((EnemyPlacement*)setup)->respawnDelay == 0) {
                return;
            }
            if ((*gMapEventInterface)->shouldNotSaveTime(((ObjPlacement*)setup)->ident) != 0) {
                if ((state->controlFlags & 0x800) == 0) {
                    player = Obj_GetPlayerObject();
                    if (player != NULL) {
                        if (vec3f_distanceSquared(&player->anim.worldPosX, &((EnemyPlacement*)setup)->base.posX) >
                            1600.0f) {
                            enemy_init(obj, setup, 0);
                            state->controlFlags |= 0x1000;
                            state->prevControlFlags &= ~0x1000;
                        } else {
                            return;
                        }
                    } else {
                        return;
                    }
                } else {
                    return;
                }
            } else {
                return;
            }
        }
    }
    if ((state->controlFlags & 0x8000) != 0) {
        setHudForceShowMask(0);
        (*gPathControlInterface)->attachObject(obj, &((EnemyState*)state)->flags);
        state->controlFlags &= ~0x8003;
        if ((state->flags2E4 & 0x20000) != 0) {
            s2 = (EnemyPlacement*)obj->anim.placementData;
            obj->anim.localPosX = s2->base.posX;
            obj->anim.localPosY = s2->base.posY;
            obj->anim.localPosZ = s2->base.posZ;
            obj->anim.rotZ = 0;
            obj->anim.rotY = 0;
            obj->anim.rotX = s2->initialYaw << 8;
            fz = 0.0f;
            obj->anim.velocityX = fz;
            obj->anim.velocityY = fz;
            obj->anim.velocityZ = fz;
        }
    }
    if ((state->flags2E4 & 0x80000) != 0) {
        if (tricky != NULL && mainGetBit(GAMEBIT_Tricky_Learned_Distract) != 0) {
            obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
        } else {
            obj->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
        }
        if (tricky != NULL && (obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0) {
            TRICKY_INTERFACE(tricky)->sideCommandEnable(tricky, obj, TRICKY_COMMAND_KIND_PRIORITY,
                                                        TRICKY_COMMAND_TYPE_DISTRACT);
        }
    }
    baddie_updateWhileFrozen(obj, (u8*)state, 0);
    if ((state->controlFlags & 0x1800) == 0) {
        baddieTurnTowardTarget(obj, (EnemyState*)state);
        baddie_updateEngagementState(obj, (EnemyState*)state);
    }
    enemyObjAnimUpdate((short*)obj, (EnemyState*)state);
}

void enemy_init(GameObject* obj, u8* setup, int flag) {
    u8* state = obj->extra;
    EnemyState* enemyState = (EnemyState*)state;
    f32 fz;

    obj->userData1 = 0;
    if (flag == 0) {
        if (((EnemyPlacement*)setup)->gameBit2 != -1) {
            if (((EnemyPlacement*)setup)->gameBit != -1) {
                if (mainGetBit(((EnemyPlacement*)setup)->gameBit) == 0) {
                    obj->userData1 = mainGetBit(((EnemyPlacement*)setup)->gameBit2) == 0;
                }
            } else {
                obj->userData1 = mainGetBit(((EnemyPlacement*)setup)->gameBit2) == 0;
            }
        }
        if (*(u32*)&((ObjPlacement*)setup)->ident != 0xFFFFFFFF) {
            if (obj->userData1 == 0) {
                if (((EnemyPlacement*)setup)->gameBit != -1) {
                    obj->userData1 = mainGetBit(((EnemyPlacement*)setup)->gameBit);
                }
                if (obj->userData1 == 0) {
                    if (((EnemyPlacement*)setup)->respawnDelay != 0) {
                        int snst = (*gMapEventInterface)->shouldNotSaveTime(((ObjPlacement*)setup)->ident);
                        if (snst == 0) {
                            obj->userData1 = 1;
                        }
                    }
                }
            }
        }
    }
    if (obj->userData1 != 0) {
        obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
        obj->anim.alpha = 0;
    } else {
        obj->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        obj->anim.alpha = 255;
    }
    enemyState->pathStep = ((EnemyPlacement*)setup)->pathStepByte / 255.0f;
    enemyState->aggroRange = (f32)(u32)(((EnemyPlacement*)setup)->aggroRangeByte << 3);
    enemyState->controlFlags = 0;
    enemyState->prevControlFlags = enemyState->controlFlags;
    obj->anim.rotX = ((EnemyPlacement*)setup)->initialYaw << 8;
    obj->anim.localPosX = ((ObjPlacement*)setup)->posX;
    obj->anim.localPosY = ((ObjPlacement*)setup)->posY;
    obj->anim.localPosZ = ((ObjPlacement*)setup)->posZ;
    obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
    if (flag == 0) {
        enemyState->flags2E4 = 0;
        enemyState->flags2E8 = 0;
        enemyState->flags2F1 = 0;
        enemyState->curveIndex = 0;
        enemyState->hitStunFrames = 0;
        enemyState->spawnBits = 0;
        fz = 0.0f;
        enemyState->gravity = fz;
        enemyState->drag = fz;
        enemyState->animPlaySpeed = fz;
        enemyState->particleScale = fz;
        enemyState->rootMotionFlags = 0;
        enemyState->pathSpeed = fz;
        enemyState->animEventMask = 0;
        enemyState->userData1 = 0;
        enemyState->userData2 = 0;
        enemyState->phaseAngle = 0;
        enemyState->familyData.unk33C[0] = 0;
        enemyState->familyData.unk33C[1] = 0;
        enemyState->unk324 = fz;
        enemyState->unk328 = fz;
        enemyState->unk32C = fz;
        enemyState->unk330 = fz;
        enemyState->intervalTimer = fz;
        enemyState->spawnedWeaponRomDefNo = -1;
        enemyState->weaponRomDefNo = enemyState->spawnedWeaponRomDefNo;
        obj->objectFlags |= ((EnemyPlacement*)setup)->objectFlagBits & 7;
        enemyState->current = ((EnemyPlacement*)setup)->hitPoints;
        obj->animEventCallback = enemy_SeqFn;
        switch (obj->anim.romDefNo) {
        case ENEMY_SHARPCLAW_GR_OBJ:
        case ENEMY_SHARPCLAW_SN_OBJ:
        case ENEMY_SHARPCLAW_CO_OBJ:
        case ENEMY_SHARPCLAW_AS_OBJ:
        case ENEMY_SHARPCLAW_SH_OBJ:
        case ENEMY_SHARPCLAW_SO_OBJ:
        case ENEMY_BOSSGENERAL_OBJ:
            sharpClawInit(obj, state);
            break;
        case ENEMY_GUARDCLAW_OBJ:
        case 641:
            guardClaw_init(obj, state);
            break;
        case ENEMY_GCROBOTPATROL_OBJ:
            gcRobotPatrol_init(obj, state);
            break;
        case ENEMY_MIKALADON_OBJ:
            mikaladon_init(obj, (EnemyState*)state);
            break;
        case ENEMY_VAMBAT_OBJ:
        case ENEMY_FIREBAT_OBJ:
            vambat_init(obj, state);
            break;
        case ENEMY_KOOSHY_OBJ:
            kooshy_init(obj, state);
            break;
        case ENEMY_WEEVIL_OBJ:
            weevil_init(obj, state);
            break;
        case ENEMY_PINPON_OBJ:
            pinPon_init(obj, state);
            break;
        case ENEMY_RACHNOP_OBJ:
            rachnopInit((GameObject*)obj, state);
            break;
        case ENEMY_SPITTINGEBA_OBJ:
            spittingEbaInit((int)obj, (int)state);
            break;
        case ENEMY_WB_OBJ:
            wbInit((int)obj, (int)state);
            break;
        case ENEMY_MUTATEDEBA_OBJ:
            mutatedEbaInit((u32)obj, (int)state);
            break;
        case ENEMY_WHIRLPOOL_OBJ:
            baddie_initWhirlpoolState((int*)obj, (EnemyState*)state);
            break;
        case ENEMY_SNOWWORM_OBJ:
        case ENEMY_SNOWWORM_BABY_OBJ:
            snowworm_init(obj, (int*)state);
            break;
        case ENEMY_HOODEDZYCK_OBJ:
            hoodedZyck_init(obj, (struct EnemyState*)state);
            break;
        case ENEMY_BATTLEDROID_OBJ:
            battleDroidInit(obj, (char*)state);
            break;
        case ENEMY_FIRECRAWLER_OBJ:
        case ENEMY_REDEYE_OBJ:
        case ENEMY_SHADOWHUNTER_OBJ:
        case ENEMY_SWAMPSTRIDER_OBJ:
            crawler_initModelVariant(obj, state);
            break;
        case ENEMY_HAGABONMK2_OBJ:
            hagabonMK2_init(obj, (struct EnemyState*)state);
            break;
        default:
            battleDroidInit(obj, (char*)state);
            break;
        }
        enemyState->max = enemyState->current;
        if (((EnemyPlacement*)setup)->unk34 != 0) {
            enemyState->flags2E4 &= -39;
        }
        objAddObjectType(obj, ENEMY_OBJGROUP);
        enemyState->prevActionId = 7;
        enemyState->actionId = 2;
        if (*(void**)state == NULL) {
            *(void**)state = mmAlloc(sizeof(RomCurveWalker), 26, 0);
        }
        if (*(void**)state != NULL) {
            memset(*(void**)state, 0, sizeof(RomCurveWalker));
        }
        if ((*gRomCurveInterface)
                ->initCurve(*(void**)state, (void*)obj, enemyState->sightRange, (int*)&lbl_803DBC58, -1) ==
            0) {
            enemyState->controlFlags |= BADDIE_CONTROL_PATH_FOLLOW;
        }
        (*gPathControlInterface)->init(state + 4, 0, 422, 1);
        if ((enemyState->flags2E4 & 8) != 0) {
            (*gPathControlInterface)->setLocalPointCollision(state + 4, 1, lbl_8031DBE4, &lbl_803DBC64, 4);
        }
        if ((enemyState->flags2E4 & 4) != 0) {
            (*gPathControlInterface)->setup(state + 4, 1, lbl_8031DBD8, &lbl_803DBC60, &lbl_803DBC68);
        }
        (*gPathControlInterface)->attachObject(obj, state + 4);
        if ((enemyState->flags2E4 & 0xc) != 0) {
            enemyState->physicsActive = 1;
        }
        if ((enemyState->flags2E4 & 0x8000022) != 0 || ((EnemyPlacement*)setup)->unk34 != 0 ||
            obj->anim.romDefNo == ENEMY_VAMBAT_OBJ || obj->anim.romDefNo == ENEMY_FIREBAT_OBJ) {
            enemyState->flags |= 0x40000u;
        } else {
            enemyState->flags &= ~0x40000u;
        }
        if ((enemyState->flags2E4 & 4) == 0 && (enemyState->flags2E4 & 8) != 0) {
            enemyState->flags &= ~0x3800u;
        }
        if (obj->userData1 != 0) {
            enemyState->controlFlags |= 0x1000;
            enemyState->prevControlFlags &= ~0x1000;
            ObjHits_DisableObject(obj);
        } else if ((enemyState->flags2E4 & 1) != 0) {
            ObjHits_EnableObject(obj);
        }
    }
    enemyState->freezeRecoverTimer = 0.0f;
    if (enemyState->aggroRange > 1905.0f) {
        enemyState->aggroRange = 1905.0f;
    }
    if (enemyState->sightRange > 1905.0f) {
        enemyState->sightRange = 1905.0f;
    }
}

void enemy_release(void) {
    if (gBaddieStaffCollisionInterface != NULL) {
        Resource_Release(gBaddieStaffCollisionInterface);
        gBaddieStaffCollisionInterface = NULL;
    }
}

void enemy_initialise(void) {
    if (gBaddieStaffCollisionInterface == NULL) {
        gBaddieStaffCollisionInterface = Resource_Acquire(0x5a, 1);
    }
}

const f32 lbl_803E2604 = 0.0f;
