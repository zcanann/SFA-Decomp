/*
 * WCPushBlock (DLL 656) - the sliding push-block puzzle object in the
 * Walled City (WC). Two block variants (anim.bankIndex: VARIANT_A vs B)
 * ride a shared tile grid owned by a separate level-controller object,
 * found via objGetNearestTypeTo on controller group
 * WCPUSHBLOCK_CONTROLLER_GROUP; the controller's WCLevelContInterface
 * (vtable at controller+0x68) does all tile<->world mapping, move tracing
 * and tile-occupancy writes (A/B method pairs).
 *
 * Per-frame phase machine: INIT_MOVE places the block at its initial tile;
 * IDLE fades in, polls the player push and traces a move; SLIDING eases
 * toward the target tile with a looped sliding sfx and clamps; FADE_OUT/
 * FADE_IN reset to the initial cell when a move is rejected; LOCKED/SOLVED
 * swap to the locked texture. A vertical bob is applied each frame. Per-
 * variant solved/fade/count game bits drive the puzzle; reaching
 * WCPUSHBLOCK_REQUIRED_LOCK_COUNT latches the solved bit.
 *
 * The WC level controller's own act-1/act-2 mode machines (timers, save
 * points, map gating, music) live in WCLevelCont (DLL 653)
 * (wclevelcont_updateAct1State / wclevelcont_updateAct2State), not here.
 * Offsets/bit values inferred from code.
 */
#include "main/dll/WC/dll_0290_wcpushblock.h"

#include "MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/frame_timing.h"
#include "main/gamebit_ids.h"
#include "main/gamebits.h"
#include "main/gameloop_gamebit_api.h"
#include "main/mapEventTypes.h"
#include "main/objhits.h"
#include "main/objtexture.h"
#include "main/objtype.h"
#include "sys/objects.h"
#include "main/dll/WC/dll_028D_wclevelcont.h"
#include "main/dll/player_api.h"
#include "game/objects/object.h"
#include "main/objfx.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/sfx.h"
#include "main/object_render.h"
#include "dlls/object_descriptor.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_play_api.h"

#define WCPUSHBLOCK_CONTROLLER_GROUP 9

#define WCPUSHBLOCK_PHASE_INIT_MOVE 0
#define WCPUSHBLOCK_PHASE_IDLE      1
#define WCPUSHBLOCK_PHASE_SLIDING   2
#define WCPUSHBLOCK_PHASE_FADE_OUT  3
#define WCPUSHBLOCK_PHASE_LOCKED    4
#define WCPUSHBLOCK_PHASE_FADE_IN   5
#define WCPUSHBLOCK_PHASE_SOLVED    6

#define WCPUSHBLOCK_VARIANT_A 1

#define WCPUSHBLOCK_DIR_POS_X 0
#define WCPUSHBLOCK_DIR_NEG_X 1
#define WCPUSHBLOCK_DIR_POS_Z 2
#define WCPUSHBLOCK_DIR_NEG_Z 3

#define WCPUSHBLOCK_MOVE_RESULT_CONTINUE 1
#define WCPUSHBLOCK_MOVE_RESULT_LOCKED   2

#define WCPUSHBLOCK_REQUIRED_LOCK_COUNT 4

#define CLAMP_EXPR(value, low, high) ((value) < (low) ? (low) : ((value) > (high) ? (high) : (value)))

void wcpushblock_initialise(void) {
}

void wcpushblock_release(void) {
}

void wcpushblock_init(GameObject* obj, WCPushBlockSetup* setup) {
    WCPushBlockRuntimeState* state = obj->extra;

    obj->anim.alpha = 0;
    obj->anim.bankIndex = setup->modelIndex;
    if (obj->anim.bankIndex >= obj->anim.modelInstance->modelCount) {
        obj->anim.bankIndex = 0;
    }
    ObjHitbox_SetStateIndex(obj, obj->anim.hitReactState, obj->anim.bankIndex);
    state->block.tileIndex = setup->initialTile;
    state->block.baseY = 5.0f + setup->base.posY;
}

void wcpushblock_update(GameObject* obj) {
    WCPushBlockRuntimeState* state;
    GameObject* player;
    f32 range;
    ObjTextureRuntimeSlot* tex;
    f32 speed;
    f32 volume;
    int alpha;
    BOOL reachedTarget;

    state = obj->extra;
    player = Obj_GetPlayerObject();

    range = 100000.0f;
    if (state->block.controller == NULL) {
        state->block.controller = objGetNearestTypeTo(WCPUSHBLOCK_CONTROLLER_GROUP, obj, &range);
        obj->anim.alpha = 0;
        return;
    }

    tex = objFindTexture(obj, 0, 0);
    if (tex != NULL) {
        tex->textureId = 0;
    }

    obj->objectFlags &= ~0x100;

    if (state->flags.phase != WCPUSHBLOCK_PHASE_SOLVED) {
        if (obj->anim.bankIndex == WCPUSHBLOCK_VARIANT_A) {
            if (mainGetBit(GAMEBIT_WC_PushBlockASolved)) {
                state->flags.phase = WCPUSHBLOCK_PHASE_SOLVED;
                WC_LEVEL_CONT_INTERFACE(state->block.controller)
                    ->getSolvedTileXYA(state->block.tileIndex, &state->block.cellX, &state->block.cellZ);
                WC_LEVEL_CONT_INTERFACE(state->block.controller)
                    ->tileAToWorldPos(obj, state->block.cellX, state->block.cellZ, &obj->anim.localPosX,
                                      &obj->anim.localPosZ);
            } else if (mainGetBit(GAMEBIT_WC_PushBlockAFade)) {
                state->flags.phase = WCPUSHBLOCK_PHASE_FADE_OUT;
            }
        } else {
            if (mainGetBit(GAMEBIT_WC_PushBlockBSolved)) {
                state->flags.phase = WCPUSHBLOCK_PHASE_SOLVED;
                WC_LEVEL_CONT_INTERFACE(state->block.controller)
                    ->getSolvedTileXYB(state->block.tileIndex, &state->block.cellX, &state->block.cellZ);
                WC_LEVEL_CONT_INTERFACE(state->block.controller)
                    ->tileBToWorldPos(obj, state->block.cellX, state->block.cellZ, &obj->anim.localPosX,
                                      &obj->anim.localPosZ);
            } else if (mainGetBit(GAMEBIT_WC_PushBlockBFade)) {
                state->flags.phase = WCPUSHBLOCK_PHASE_FADE_OUT;
            }
        }
    }

    if (state->flags.phase != WCPUSHBLOCK_PHASE_FADE_OUT && state->flags.phase != WCPUSHBLOCK_PHASE_FADE_IN) {
        if (obj->anim.bankIndex == WCPUSHBLOCK_VARIANT_A) {
            objfx_spawnBoxBurst(obj, 1, 2.0f, 3, 1, 50, 65.0f, 2.0f, 65.0f, NULL, 0);
        } else {
            objfx_spawnBoxBurst(obj, 1, 2.0f, 1, 1, 50, 65.0f, 2.0f, 65.0f, NULL, 0);
        }
    }

    switch (state->flags.phase) {
    case WCPUSHBLOCK_PHASE_INIT_MOVE:
        if (obj->anim.bankIndex == WCPUSHBLOCK_VARIANT_A) {
            WC_LEVEL_CONT_INTERFACE(state->block.controller)
                ->getInitialTileXYA(state->block.tileIndex, &state->block.cellX, &state->block.cellZ);
            WC_LEVEL_CONT_INTERFACE(state->block.controller)
                ->tileAToWorldPos(obj, state->block.cellX, state->block.cellZ, &obj->anim.localPosX,
                                  &obj->anim.localPosZ);
        } else {
            WC_LEVEL_CONT_INTERFACE(state->block.controller)
                ->getInitialTileXYB(state->block.tileIndex, &state->block.cellX, &state->block.cellZ);
            WC_LEVEL_CONT_INTERFACE(state->block.controller)
                ->tileBToWorldPos(obj, state->block.cellX, state->block.cellZ, &obj->anim.localPosX,
                                  &obj->anim.localPosZ);
        }
        state->flags.phase = WCPUSHBLOCK_PHASE_IDLE;
        break;
    case WCPUSHBLOCK_PHASE_IDLE:
        alpha = obj->anim.alpha + framesThisStep * 8;
        obj->anim.alpha = CLAMP_EXPR(alpha, alpha, 255);
        obj->anim.velocityX = 0.0f;
        obj->anim.velocityZ = 0.0f;
        if (playerIsPushingObject(player, obj, &state->block.pushDir)) {
            if (obj->anim.bankIndex == WCPUSHBLOCK_VARIANT_A) {
                if (state->block.pushDir == WCPUSHBLOCK_DIR_POS_X) {
                    state->moveResult = WC_LEVEL_CONT_INTERFACE(state->block.controller)
                                            ->traceMoveA(obj, state->block.cellX, state->block.cellZ,
                                                         &state->block.targetX, &state->block.targetZ, -1, 0);
                } else if (state->block.pushDir == WCPUSHBLOCK_DIR_NEG_X) {
                    state->moveResult = WC_LEVEL_CONT_INTERFACE(state->block.controller)
                                            ->traceMoveA(obj, state->block.cellX, state->block.cellZ,
                                                         &state->block.targetX, &state->block.targetZ, 1, 0);
                } else if (state->block.pushDir == WCPUSHBLOCK_DIR_POS_Z) {
                    state->moveResult = WC_LEVEL_CONT_INTERFACE(state->block.controller)
                                            ->traceMoveA(obj, state->block.cellX, state->block.cellZ,
                                                         &state->block.targetX, &state->block.targetZ, 0, -1);
                } else if (state->block.pushDir == WCPUSHBLOCK_DIR_NEG_Z) {
                    state->moveResult = WC_LEVEL_CONT_INTERFACE(state->block.controller)
                                            ->traceMoveA(obj, state->block.cellX, state->block.cellZ,
                                                         &state->block.targetX, &state->block.targetZ, 0, 1);
                }
            } else {
                if (state->block.pushDir == WCPUSHBLOCK_DIR_POS_X) {
                    state->moveResult = WC_LEVEL_CONT_INTERFACE(state->block.controller)
                                            ->traceMoveB(obj, state->block.cellX, state->block.cellZ,
                                                         &state->block.targetX, &state->block.targetZ, -1, 0);
                } else if (state->block.pushDir == WCPUSHBLOCK_DIR_NEG_X) {
                    state->moveResult = WC_LEVEL_CONT_INTERFACE(state->block.controller)
                                            ->traceMoveB(obj, state->block.cellX, state->block.cellZ,
                                                         &state->block.targetX, &state->block.targetZ, 1, 0);
                } else if (state->block.pushDir == WCPUSHBLOCK_DIR_POS_Z) {
                    state->moveResult = WC_LEVEL_CONT_INTERFACE(state->block.controller)
                                            ->traceMoveB(obj, state->block.cellX, state->block.cellZ,
                                                         &state->block.targetX, &state->block.targetZ, 0, -1);
                } else if (state->block.pushDir == WCPUSHBLOCK_DIR_NEG_Z) {
                    state->moveResult = WC_LEVEL_CONT_INTERFACE(state->block.controller)
                                            ->traceMoveB(obj, state->block.cellX, state->block.cellZ,
                                                         &state->block.targetX, &state->block.targetZ, 0, 1);
                }
            }
            if (state->block.targetX != obj->anim.localPosX || state->block.targetZ != obj->anim.localPosY) {
                state->flags.phase = WCPUSHBLOCK_PHASE_SLIDING;
            }
        }
        break;
    case WCPUSHBLOCK_PHASE_SLIDING:
        if (obj->anim.velocityX != 0.0f || obj->anim.velocityZ != 0.0f) {
            speed =
                sqrtf(obj->anim.velocityX * obj->anim.velocityX + obj->anim.velocityZ * obj->anim.velocityZ) - 0.25f;
            if (speed < 0.0f) {
                speed = 0.0f;
            }

            volume = 1.0f + 126.0f * speed / 1.25f;
            if (volume > 127.0f) {
                volume = 127.0f;
            }

            Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_en_treedrum16_c8);
            Sfx_SetObjectSfxVolume(obj, SFXTRIG_en_treedrum16_c8, volume, 0.5f);
            state->flags.sfxActive = 1;
        }

        objMove(obj, obj->anim.velocityX * timeDelta, 0.0f, obj->anim.velocityZ * timeDelta);
        reachedTarget = FALSE;
        if (state->block.pushDir == WCPUSHBLOCK_DIR_POS_X) {
            if (obj->anim.velocityX < 1.5f) {
                obj->anim.velocityX += 0.05f * timeDelta;
            }
            if (obj->anim.localPosX >= state->block.targetX) {
                obj->anim.localPosX = state->block.targetX;
                reachedTarget = TRUE;
            }
        } else if (state->block.pushDir == WCPUSHBLOCK_DIR_NEG_X) {
            if (obj->anim.velocityX > -1.5f) {
                obj->anim.velocityX -= 0.05f * timeDelta;
            }
            if (obj->anim.localPosX <= state->block.targetX) {
                obj->anim.localPosX = state->block.targetX;
                reachedTarget = TRUE;
            }
        } else if (state->block.pushDir == WCPUSHBLOCK_DIR_POS_Z) {
            if (obj->anim.velocityZ < 1.5f) {
                obj->anim.velocityZ += 0.05f * timeDelta;
            }
            if (obj->anim.localPosZ >= state->block.targetZ) {
                obj->anim.localPosZ = state->block.targetZ;
                reachedTarget = TRUE;
            }
        } else if (state->block.pushDir == WCPUSHBLOCK_DIR_NEG_Z) {
            if (obj->anim.velocityZ > -1.5f) {
                obj->anim.velocityZ -= 0.05f * timeDelta;
            }
            if (obj->anim.localPosZ <= state->block.targetZ) {
                obj->anim.localPosZ = state->block.targetZ;
                reachedTarget = TRUE;
            }
        }

        if (obj->anim.velocityX > 1.5f) {
            obj->anim.velocityX = 1.5f;
        }
        if (obj->anim.velocityX < -1.5f) {
            obj->anim.velocityX = -1.5f;
        }
        if (obj->anim.velocityZ > 1.5f) {
            obj->anim.velocityZ = 1.5f;
        }
        if (obj->anim.velocityZ < -1.5f) {
            obj->anim.velocityZ = -1.5f;
        }

        if (reachedTarget) {
            obj->anim.velocityX = 0.0f;
            obj->anim.velocityZ = 0.0f;

            if (state->moveResult == WCPUSHBLOCK_MOVE_RESULT_LOCKED) {
                state->flags.phase = WCPUSHBLOCK_PHASE_LOCKED;
                if (obj->anim.bankIndex == WCPUSHBLOCK_VARIANT_A) {
                    if (gameBitIncrement(GAMEBIT_WC_PushBlockACount) != WCPUSHBLOCK_REQUIRED_LOCK_COUNT) {
                        Sfx_PlayFromObject(NULL, SFXTRIG_sc_menuups16k_ca);
                    }
                } else {
                    if (gameBitIncrement(GAMEBIT_WC_PushBlockBCount) != WCPUSHBLOCK_REQUIRED_LOCK_COUNT) {
                        Sfx_PlayFromObject(NULL, SFXTRIG_sc_menuups16k_ca);
                    }
                }
            } else if (state->moveResult == WCPUSHBLOCK_MOVE_RESULT_CONTINUE) {
                state->flags.phase = WCPUSHBLOCK_PHASE_IDLE;
                if (state->flags.sfxActive) {
                    state->flags.sfxActive = 0;
                    Sfx_PlayFromObject(obj, SFXTRIG_mv_bflconc1);
                }
            } else {
                if (obj->anim.bankIndex == WCPUSHBLOCK_VARIANT_A) {
                    mainSetBits(GAMEBIT_WC_PushBlockAFade, 1);
                } else {
                    mainSetBits(GAMEBIT_WC_PushBlockBFade, 1);
                }
            }
            if (state->flags.phase != WCPUSHBLOCK_PHASE_FADE_OUT) {
                if (obj->anim.bankIndex == WCPUSHBLOCK_VARIANT_A) {
                    WC_LEVEL_CONT_INTERFACE(state->block.controller)
                        ->setTileA(0, state->block.cellX, state->block.cellZ);
                    WC_LEVEL_CONT_INTERFACE(state->block.controller)
                        ->worldPosToTileA(obj, obj->anim.localPosX, obj->anim.localPosZ, &state->block.cellX,
                                          &state->block.cellZ);
                    WC_LEVEL_CONT_INTERFACE(state->block.controller)
                        ->setTileA(state->block.tileIndex, state->block.cellX, state->block.cellZ);
                } else {
                    WC_LEVEL_CONT_INTERFACE(state->block.controller)
                        ->setTileB(0, state->block.cellX, state->block.cellZ);
                    WC_LEVEL_CONT_INTERFACE(state->block.controller)
                        ->worldPosToTileB(obj, obj->anim.localPosX, obj->anim.localPosZ, &state->block.cellX,
                                          &state->block.cellZ);
                    WC_LEVEL_CONT_INTERFACE(state->block.controller)
                        ->setTileB(state->block.tileIndex, state->block.cellX, state->block.cellZ);
                }
            }
        }
        break;
    case WCPUSHBLOCK_PHASE_FADE_OUT:
        ObjHits_DisableObject(obj);
        if (obj->anim.alpha == 255) {
            Sfx_PlayFromObject(obj, SFXTRIG_wp_iceywindlp16_cb);
        }

        alpha = obj->anim.alpha - framesThisStep * 8;
        obj->anim.alpha = CLAMP_EXPR(alpha, 0, alpha);

        if (obj->anim.alpha == 0 && wcblock_isPlayerAwayFromStoredCell(obj, &state->block, Obj_GetPlayerObject())) {
            if (obj->anim.bankIndex == WCPUSHBLOCK_VARIANT_A) {
                WC_LEVEL_CONT_INTERFACE(state->block.controller)
                    ->getInitialTileXYA(state->block.tileIndex, &state->block.cellX, &state->block.cellZ);
                WC_LEVEL_CONT_INTERFACE(state->block.controller)
                    ->tileAToWorldPos(obj, state->block.cellX, state->block.cellZ, &obj->anim.localPosX,
                                      &obj->anim.localPosZ);
            } else {
                WC_LEVEL_CONT_INTERFACE(state->block.controller)
                    ->getInitialTileXYB(state->block.tileIndex, &state->block.cellX, &state->block.cellZ);
                WC_LEVEL_CONT_INTERFACE(state->block.controller)
                    ->tileBToWorldPos(obj, state->block.cellX, state->block.cellZ, &obj->anim.localPosX,
                                      &obj->anim.localPosZ);
            }
            state->flags.phase = WCPUSHBLOCK_PHASE_FADE_IN;
        }
        break;
    case WCPUSHBLOCK_PHASE_FADE_IN:
        if (obj->anim.alpha == 0) {
            ObjHits_EnableObject(obj);
            Sfx_PlayFromObject(NULL, SFXTRIG_en_cvdrip1c_cc);
        }
        alpha = obj->anim.alpha + framesThisStep * 8;
        obj->anim.alpha = CLAMP_EXPR(alpha, alpha, 255);
        if (obj->anim.alpha >= 255) {
            state->flags.phase = WCPUSHBLOCK_PHASE_IDLE;
        }
        break;
    case WCPUSHBLOCK_PHASE_SOLVED:
        obj->anim.alpha = 255;
    case WCPUSHBLOCK_PHASE_LOCKED:
        tex = objFindTexture(obj, 0, 0);
        if (tex != NULL) {
            tex->textureId = 0x100;
        }
        obj->objectFlags |= 0x100;
        break;
    }

    state->block.bobAngle += 250.0f * timeDelta;
    state->block.bobY = 3.0f * mathSinf(3.1415927f * state->block.bobAngle / 32768.0f);
    obj->anim.localPosY = state->block.baseY + state->block.bobY;
}

void wcpushblock_hitDetect(void) {
}

void wcpushblock_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible) {
    if (!visible) {
        return;
    }

    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void wcpushblock_free(void) {
}

int wcpushblock_getObjectTypeId(GameObject* obj) {
    int modelIndex = ((WCPushBlockSetup*)obj->anim.placement)->modelIndex;
    if (modelIndex >= obj->anim.modelInstance->modelCount) {
        modelIndex = 0;
    }

    return (modelIndex << 11) | 0x400;
}

int wcpushblock_getExtraSize(void) {
    return sizeof(WCPushBlockRuntimeState);
}

int wcblock_isPlayerAwayFromStoredCell(GameObject* obj, WCBlockState* state, GameObject* player) {
    f32 x;
    f32 z;
    f32 minX;
    f32 maxX;
    f32 minZ;
    f32 maxZ;

    if (obj->anim.bankIndex == WCPUSHBLOCK_VARIANT_A) {
        WC_LEVEL_CONT_INTERFACE(state->controller)->getInitialTileXYA(state->tileIndex, &state->cellX, &state->cellZ);
        WC_LEVEL_CONT_INTERFACE(state->controller)->tileAToWorldPos(obj, state->cellX, state->cellZ, &x, &z);
    } else {
        WC_LEVEL_CONT_INTERFACE(state->controller)->getInitialTileXYB(state->tileIndex, &state->cellX, &state->cellZ);
        WC_LEVEL_CONT_INTERFACE(state->controller)->tileBToWorldPos(obj, state->cellX, state->cellZ, &x, &z);
    }

    minX = x - 56.0f;
    maxX = x + 56.0f;
    if (player->anim.localPosX > maxX || player->anim.localPosX < minX) {
        return 1;
    }

    minZ = z - 56.0f;
    maxZ = z + 56.0f;
    if (player->anim.localPosZ > maxZ || player->anim.localPosZ < minZ) {
        return 1;
    }

    return 0;
}

ObjectDescriptor gWCPushBlockObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)wcpushblock_initialise,
    (ObjectDescriptorCallback)wcpushblock_release,
    0,
    (ObjectDescriptorCallback)wcpushblock_init,
    (ObjectDescriptorCallback)wcpushblock_update,
    (ObjectDescriptorCallback)wcpushblock_hitDetect,
    (ObjectDescriptorCallback)wcpushblock_render,
    (ObjectDescriptorCallback)wcpushblock_free,
    (ObjectDescriptorCallback)wcpushblock_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)wcpushblock_getExtraSize,
};
