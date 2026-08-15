/*
 * Fuel-cell collectible (DLL slot 291 / 0x123).
 *
 * Activates between per-placement game-bit gates, offers itself to the player,
 * and renders a pool of short-lived lightning effects. Normal cells can link
 * their lightning to another member of the shared fuel-cell object group.
 */
#include "dlls/objects/291_fuelCell.h"
#include "dolphin/gx/GXTev.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/model.h"
#include "main/newclouds.h"
#include "main/obj_message.h"
#include "main/object_render.h"
#include "main/objfx.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "track/intersect_depth_state_api.h"
#include "dolphin/gx/GXPixel.h"
#include "main/audio/sfx_looped_object_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/gameloop_gamebit_api.h"
#include "main/hud_visibility_api.h"
#include "main/objtype.h"

#define FUEL_CELL_MESSAGE_IN_RANGE 0x7000A /* Sent to the player when pickup is offered. */
#define FUEL_CELL_MESSAGE_RELEASE  0x7000B /* Sent after the player completes the pickup. */

#define FUEL_CELL_BURST_CHANCE              0x14
#define FUEL_CELL_LIGHTNING_LIFETIME_FRAMES 0x14
#define FUEL_CELL_LIGHTNING_WIDTH_LOCAL     0x40
#define FUEL_CELL_LIGHTNING_WIDTH_LINKED    0xFF
#define FUEL_CELL_LINK_CANDIDATE_COUNT      9
#define FUEL_CELL_LINK_ROLL_MAX             9

int FuelCell_SeqFn(GameObject* obj) {
    FuelCellState* state = obj->extra;
    state->flags.alternateEffects = 1;
    state->flags.resetPosition = 1;
    return 0;
}

void FuelCell_setupModelRenderState(GameObject* obj) {
    if (obj->anim.renderAlpha == 0xFF) {
        GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
    } else {
        GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_ONE, GX_LO_NOOP);
    }
    gxSetZMode_(1, GX_LEQUAL, 0);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
}

int FuelCell_getExtraSize(void) {
    return sizeof(FuelCellState);
}

void FuelCell_free(GameObject* obj) {
    FuelCellState* state = obj->extra;
    u8 i;

    for (i = 0; i < FUEL_CELL_LIGHTNING_EFFECT_COUNT; i++) {
        if (state->lightningEffects[i] != NULL) {
            mm_free_(state->lightningEffects[i]);
        }
    }

    if (state->flags.active) {
        objFreeObjectType(obj, FUEL_CELL_OBJECT_GROUP);
    }
}

void FuelCell_render(GameObject* obj, int p2, int p3, int p4, int p5) {
    GameObject** fuelCells;
    FuelCellState* state;
    u8 lightningWidth;
    u8 i;
    u8 j;
    u8 candidateSlot;
    u8 spawnedLightning;
    f32 lightningRadiusX;
    f32 jitterScale;
    GameObject* candidates[FUEL_CELL_LINK_CANDIDATE_COUNT];
    Vec3f endPosition;
    f32 linkDistance;
    int fuelCellCount;

    state = obj->extra;
    lightningRadiusX = 4.0f;
    fuelCellCount = 0;
    lightningWidth = FUEL_CELL_LIGHTNING_WIDTH_LOCAL;
    candidateSlot = 0;
    spawnedLightning = 0;
    if (state->flags.active) {
        if (state->flags.alternateEffects) {
            objfx_spawnDirectionalBurst(obj, 5, 1.0f, 1, 1, FUEL_CELL_BURST_CHANCE, 3.5f, NULL, 0);
        } else {
            objfx_spawnDirectionalBurst(obj, 5, 1.0f, 1, 1, FUEL_CELL_BURST_CHANCE, 4.5f, NULL, 0);
        }
        {
            Shader* op = ObjModel_GetRenderOp(Obj_GetActiveModel(obj)->file, 0);
            op->alphaOverride = 0x7F;
        }
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);

        for (i = 0; i < FUEL_CELL_LIGHTNING_EFFECT_COUNT; i++) {
            if (state->lightningEffects[i] != NULL) {
                lightningRender(state->lightningEffects[i]);
                if (getHudHiddenFrameCount() == 0) {
                    state->lightningAges[i] += timeDelta;
                    state->lightningEffects[i]->timer = (int)(0.5f + state->lightningAges[i]);
                    if (state->lightningEffects[i]->timer > FUEL_CELL_LIGHTNING_LIFETIME_FRAMES) {
                        mm_free_(state->lightningEffects[i]);
                        state->lightningEffects[i] = NULL;
                    }
                }
            } else if (!spawnedLightning && getHudHiddenFrameCount() == 0) {
                GameObject* target;
                if (randomGetRange(0, FUEL_CELL_LINK_ROLL_MAX) == 0 && !state->flags.alternateEffects) {
                    fuelCells = (GameObject**)objGetAllOfType(FUEL_CELL_OBJECT_GROUP, &fuelCellCount);
                    for (j = 0; j < fuelCellCount; j++) {
                        GameObject* other = fuelCells[j];
                        u8 canLink;
                        if (other != obj) {
                            if (other->extra != NULL && ((FuelCellState*)other->extra)->flags.alternateEffects) {
                                canLink = 0;
                            } else {
                                canLink = 1;
                            }
                            if (canLink &&
                                vec3f_distanceSquared(&other->anim.worldPosX, &obj->anim.worldPosX) < 10000.0f) {
                                candidates[candidateSlot++] = fuelCells[j];
                            }
                        }
                    }
                }
                if (candidateSlot != 0) {
                    candidateSlot--;
                    candidateSlot = randomGetRange(0, candidateSlot);
                    linkDistance =
                        Vec_distance(&candidates[candidateSlot]->anim.worldPosX, &obj->anim.worldPosX) / 100.0f;
                    lightningRadiusX = 0.1f - 0.07f * linkDistance;
                    lightningWidth = FUEL_CELL_LIGHTNING_WIDTH_LINKED;
                } else {
                    candidates[0] = obj;
                }
                target = candidates[candidateSlot];
                endPosition.x = target->anim.localPosX;
                endPosition.y = target->anim.localPosY;
                endPosition.z = target->anim.localPosZ;
                if (target == obj) {
                    if (state->flags.alternateEffects) {
                        jitterScale = 0.0017f;
                    } else {
                        jitterScale = 0.003f;
                    }
                    endPosition.x = jitterScale * (f32)(randomGetRange(0, 2000) - 1000) + endPosition.x;
                    endPosition.y = jitterScale * (f32)(randomGetRange(0, 2000) - 1000) + endPosition.y;
                    endPosition.z = jitterScale * (f32)(randomGetRange(0, 2000) - 1000) + endPosition.z;
                }
                state->lightningEffects[i] =
                    lightningCreate(&obj->anim.localPos, &endPosition, lightningRadiusX, 0.2f,
                                    FUEL_CELL_LIGHTNING_LIFETIME_FRAMES, (u8)lightningWidth, 0);
                state->lightningAges[i] = 0.0f;
                spawnedLightning = 1;
            }
        }
    }
}

void FuelCell_update(GameObject* obj) {
    FuelCellPlacement* placement = (FuelCellPlacement*)obj->anim.placementData;
    FuelCellState* state = obj->extra;
    GameObject* player;
    int msgId;
    int msgParam;

    player = Obj_GetPlayerObject();
    if (state->flags.pickupPending) {
        while (ObjMsg_Pop(obj, (u32*)&msgId, (u32*)&msgParam, 0) != 0) {
            if (msgId == FUEL_CELL_MESSAGE_RELEASE) {
                state->flags.pickupPending = 0;
                mainSetBits(placement->offBit, 1);
                gameBitIncrement(GAMEBIT_ITEM_FuelCell_Count);
                mainSetBits(GAMEBIT_ITEM_FuelCell_CantGet, 0);
            }
        }
    } else {
        int gameBit = placement->offBit;
        if (gameBit != -1 && mainGetBit(gameBit) == 0) {
            gameBit = placement->onBit;
            if (gameBit == -1 || mainGetBit(gameBit) != 0) {
                f32 dy;
                if (!state->flags.active) {
                    Sfx_AddLoopedObjectSound(obj, SFXTRIG_pk_fuelcell_fizz);
                    state->flags.active = 1;
                    objAddObjectType(obj, FUEL_CELL_OBJECT_GROUP);
                } else if (state->flags.resetPosition) {
                    obj->anim.localPosX = placement->base.posX;
                    obj->anim.localPosY = placement->base.posY;
                    obj->anim.localPosZ = placement->base.posZ;
                    obj->anim.alpha = 0xFF;
                    state->flags.resetPosition = 0;
                }
                dy = obj->anim.localPosY - player->anim.localPosY;
                if (dy > -5.0f && dy < 40.0f && mainGetBit(GAMEBIT_ITEM_FuelCell_CantGet) == 0 &&
                    getXZDistanceSquared(&obj->anim.worldPosX, &player->anim.worldPosX) < 81.0f) {
                    state->triggerGameBit = GAMEBIT_SawFuelCell;
                    ObjMsg_SendToObject(player, FUEL_CELL_MESSAGE_IN_RANGE, obj, (u32)&state->triggerGameBit);
                    state->flags.pickupPending = 1;
                    mainSetBits(GAMEBIT_ITEM_FuelCell_CantGet, 1);
                    Sfx_PlayFromObject(obj, SFXTRIG_lockoff22);
                }
            }
        } else if (state->flags.active) {
            state->flags.active = 0;
            Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_pk_fuelcell_fizz);
            objFreeObjectType(obj, FUEL_CELL_OBJECT_GROUP);
        }
    }
}

void FuelCell_init(GameObject* obj) {
    obj->animEventCallback = FuelCell_SeqFn;
    ObjModel_SetPostRenderCallback(Obj_GetActiveModel(obj), FuelCell_setupModelRenderState);
    ObjMsg_AllocQueue(obj, 2);
}

ObjectDescriptor gFuelCellObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)FuelCell_init,
    (ObjectDescriptorCallback)FuelCell_update,
    0,
    (ObjectDescriptorCallback)FuelCell_render,
    (ObjectDescriptorCallback)FuelCell_free,
    0,
    FuelCell_getExtraSize,
};
