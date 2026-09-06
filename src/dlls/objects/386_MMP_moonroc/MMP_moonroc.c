#include "dlls/objects/386_MMP_moonroc.h"
#include "dlls/objects/387_MMP_gyserve.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "main/audio/sfx_channel_volume_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/carryable_interface.h"
#include "main/dll/objfx_api.h"
#include "main/dll/player_api.h"
#include "main/dll/player_state.h"
#include "main/dll/savegame_object_api.h"
#include "main/dll/tricky_api.h"
#include "main/frame_timing.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/lightmap_api.h"
#include "main/mapEventTypes.h"
#include "main/objtype.h"
#include "main/obj_list.h"
#include "main/objfx.h"
#include "main/objhits.h"
#include "main/objanim_internal.h"
#include "main/object_render.h"
#include "main/track_bbox_api.h"
#include "main/track_dolphin_api.h"
#include "main/vecmath.h"
#include "main/vecmath_distance_api.h"
#include "sys/objects.h"
#include "main/dll/partfx_interface.h"

PartFxSpawnParams gMMPMoonRockSpawnParams;

#define MMP_MOON_ROCK_OBJECT_GROUP            4
#define MMP_GEYSER_VENT_SEQUENCE_ID           0x518
#define MMP_MOON_ROCK_HIT_VOLUME_SLOT         14
#define CARRYABLE_OBJECT_GROUP                0x10
#define MMP_MOON_ROCK_PARTICLE_AMBIENT        0x723
#define MMP_MOON_ROCK_PARTICLE_SPAWN_MODE     0x200001
#define MMP_MOON_ROCK_PARTICLE_MODEL_NONE     -1
#define MMP_MOON_ROCK_MAP_EVENT_GROUP         0x12
#define MMP_MOON_ROCK_MAP_EVENT_STATUS        6
#define MMP_MOON_ROCK_PEDESTAL_COUNT_GAMEBIT  0x88C
#define MMP_MOON_ROCK_INVENTORY_COUNT_GAMEBIT 0x894
#define MMP_MOON_ROCK_PLACEMENT_EVENT_GAMEBIT 0x9AE
#define MMP_MOON_ROCK_WATER_SURFACE_TYPE      0x0E
#define MMP_MOON_ROCK_RESET_DURATION          120.0f
#define MMP_MOON_ROCK_SFX_CHANNEL             0x40
#define MMP_MOON_ROCK_VEL_CLAMP_MIN           -5.0f
#define MMP_MOON_ROCK_VEL_CLAMP_MAX           5.0f

#define MMP_MOON_ROCK_FLAG_ACTION_PENDING   0x001
#define MMP_MOON_ROCK_FLAG_DETACH_ARMED     0x002
#define MMP_MOON_ROCK_FLAG_FROZEN           0x004
#define MMP_MOON_ROCK_FLAG_HELD_LAST_UPDATE 0x008
#define MMP_MOON_ROCK_FLAG_ICON_PLACE       0x010
#define MMP_MOON_ROCK_FLAG_ICON_THROW       0x020
#define MMP_MOON_ROCK_FLAG_THROWN           0x040
#define MMP_MOON_ROCK_FLAG_LANDED_FLAT      0x080
#define MMP_MOON_ROCK_FLAG_FLOOR_HIT        0x100
#define MMP_MOON_ROCK_FLAG_RESETTING        0x200
#define MMP_MOON_ROCK_FLAG_PLACED           0x400

static int mmpMoonRock_probeFloor(GameObject* obj, f32 x, f32 y, f32 z, f32 maxY, f32* floorYOut,
                                  GameObject** floorObjectOut) {
    TrackGroundHit** results;
    int i;
    int count;

    count = trackGetHeight(obj, x, y, z, &results, 0, 1);
    *floorYOut = y;
    *floorObjectOut = NULL;
    for (i = 0; i < count; i++) {
        if ((s8)results[i]->surfaceType != MMP_MOON_ROCK_WATER_SURFACE_TYPE && y < results[i]->height &&
            (maxY > results[i]->height || i == count - 1)) {
            *floorObjectOut = results[i]->object;
            *floorYOut = results[i]->height;
            return (results[i]->normalY < 0.707f) + 1;
        }
    }
    return 0;
}

void mmpMoonRock_handleImpact(GameObject* obj) {
    TrackLineIntersectResult hitScratch;
    GameObject* priorityObjectOut;
    MMPMoonRockState* state;
    int hit;

    state = obj->extra;
    hit = ObjHits_GetPriorityHit(obj, &priorityObjectOut, 0, 0);
    if (hit == 0) {
        hit = trackGetLineIntersect(&obj->anim.previousLocalPosX, &obj->anim.localPosX, 8.0f, 1, &hitScratch, obj, 1,
                                    -1, 0xff, 0);
    }
    if ((hit != 0) || ((ObjAnim_GetPriorityHitState(&obj->anim)->contactFlags != 0 &&
                        (state->flags & MMP_MOON_ROCK_FLAG_THROWN) != 0) ||
                       (state->flags & MMP_MOON_ROCK_FLAG_FLOOR_HIT) != 0)) {
        obj->anim.localPosY += 10.0f;
        spawnExplosion(obj, 0.0f, 1, 1, 0, 0, 0, 1, 0);
        state->flags |= MMP_MOON_ROCK_FLAG_RESETTING;
        state->resetTimer = MMP_MOON_ROCK_RESET_DURATION;
        obj->anim.alpha = 0;
        obj->anim.localPosX = state->homeX;
        obj->anim.localPosY = state->homeY;
        obj->anim.localPosZ = state->homeZ;
        saveGame_saveObjectPos(obj);
    }
}

static inline f32 mmpMoonRock_clampVelocity(f32 vel) {
    if (vel < MMP_MOON_ROCK_VEL_CLAMP_MIN) {
        return MMP_MOON_ROCK_VEL_CLAMP_MIN;
    }
    if (vel > MMP_MOON_ROCK_VEL_CLAMP_MAX) {
        return MMP_MOON_ROCK_VEL_CLAMP_MAX;
    }
    return vel;
}

void mmpMoonRock_updateThrow(GameObject* obj) {
    MMPMoonRockState* state = obj->extra;
    GameObject* floorObject;
    f32 floorY;
    int mapBlockIndex;
    f32 posY;
    int floorType;

    mapBlockIndex = objPosToMapBlockIdx(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ);
    if (mapBlockIndex == -1) {
        return;
    }
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, MMP_MOON_ROCK_HIT_VOLUME_SLOT, 1, 0);
    ObjHits_EnableObject(obj);
    obj->anim.velocityY = obj->anim.velocityY - 0.12f * timeDelta;
    obj->anim.velocityX = mmpMoonRock_clampVelocity(obj->anim.velocityX);
    obj->anim.velocityY = mmpMoonRock_clampVelocity(obj->anim.velocityY);
    obj->anim.velocityX = mmpMoonRock_clampVelocity(obj->anim.velocityX);
    objMove(obj, obj->anim.velocityX * timeDelta, obj->anim.velocityY * timeDelta, obj->anim.velocityZ * timeDelta);
    state->flags &= ~MMP_MOON_ROCK_FLAG_LANDED_FLAT;
    posY = obj->anim.localPosY;
    floorType = mmpMoonRock_probeFloor(obj, obj->anim.localPosX, posY, obj->anim.localPosZ, 20.0f + posY, &floorY,
                                       &floorObject);
    if (floorType == 0) {
        return;
    }
    if (floorType == 2) {
        state->flags |= MMP_MOON_ROCK_FLAG_FLOOR_HIT;
        obj->anim.velocityX = 0.0f;
        obj->anim.velocityY = 0.0f;
        obj->anim.velocityZ = 0.0f;
    } else {
        state->flags |= MMP_MOON_ROCK_FLAG_LANDED_FLAT | MMP_MOON_ROCK_FLAG_FLOOR_HIT;
        obj->anim.localPosY = floorY;
        obj->anim.velocityX = 0.0f;
        obj->anim.velocityY = 0.0f;
        obj->anim.velocityZ = 0.0f;
    }
}

void mmpMoonRock_throwFromPlayer(GameObject* obj) {
    MMPMoonRockState* state = obj->extra;
    MatrixTransform rotation;
    GameObject* player = Obj_GetPlayerObject();
    PlayerState* playerState = player->extra;
    obj->anim.velocityX = 0.0f;
    obj->anim.velocityY = 0.75f * playerState->baddie.inputMagnitude + 2.2f;
    obj->anim.velocityZ = -0.75f * playerState->baddie.inputMagnitude + -2.2f;
    rotation.x = 0.0f;
    rotation.y = 0.0f;
    rotation.z = 0.0f;
    rotation.scale = 1.0f;
    rotation.rotZ = 0;
    rotation.rotY = 0;
    rotation.rotX = player->anim.rotX;
    vecRotateZXY(&rotation.rotX, &obj->anim.velocityX);
    state->flags |= MMP_MOON_ROCK_FLAG_THROWN;
}

void mmpMoonRock_reconcilePlacement(GameObject* obj, u8 place, u8 mode) {
    int i;
    int count;
    GameObject** list;
    MMPMoonRockState* state;
    MMPGeyserVentPlacement* ventPlacement;
    MMPMoonRockPlacement* rockPlacement;
    s8 pedestalCount;
    s8 inventoryCount;

    state = obj->extra;
    list = ObjList_GetObjects(&i, &count);
    for (; i < count; i++) {
        GameObject* otherObj = list[i];
        if (otherObj != obj && otherObj->anim.romDefNo == MMP_GEYSER_VENT_SEQUENCE_ID &&
            Vec_distance(&obj->anim.worldPosX, &otherObj->anim.worldPosX) < 40.0f) {
            ventPlacement = (MMPGeyserVentPlacement*)(list[i])->anim.placementData;
            rockPlacement = (MMPMoonRockPlacement*)obj->anim.placementData;
            pedestalCount = mainGetBit(MMP_MOON_ROCK_PEDESTAL_COUNT_GAMEBIT);
            inventoryCount = mainGetBit(MMP_MOON_ROCK_INVENTORY_COUNT_GAMEBIT);
            if (place == 0) {
                (*gCarryableInterface)->setGravityEnabled(&state->carryable, 1);
                if (ventPlacement->disableGameBit != -1) {
                    mainSetBits(ventPlacement->disableGameBit, 0);
                }
                if (state->kind == 3 || state->kind == 4 || state->kind == 6) {
                    pedestalCount -= 1;
                } else {
                    inventoryCount -= 1;
                }
                if (rockPlacement->kindGameBit != -1) {
                    mainSetBits(rockPlacement->kindGameBit, 0);
                    state->kind = 0;
                }
                state->savedBaseY = state->baseY = obj->anim.localPosY;
                state->flags &= ~MMP_MOON_ROCK_FLAG_PLACED;
                obj->anim.localPosX = state->homeX;
                obj->anim.localPosY = state->homeY;
                obj->anim.localPosZ = state->homeZ;
                saveGame_saveObjectPos(obj);
            } else {
                (*gCarryableInterface)->setGravityEnabled(&state->carryable, 0);
                if (ventPlacement->disableGameBit != -1) {
                    mainSetBits(ventPlacement->disableGameBit, 1);
                }
                if (mode == 0) {
                    obj->anim.localPosX = (list[i])->anim.localPosX;
                    obj->anim.localPosY = (list[i])->anim.localPosY;
                    obj->anim.localPosZ = (list[i])->anim.localPosZ;
                    saveGame_saveObjectPos(obj);
                }
                state->savedBaseY = state->baseY = obj->anim.localPosY;
                if (rockPlacement->kindGameBit != -1) {
                    mainSetBits(rockPlacement->kindGameBit, ventPlacement->moonRockKind);
                    state->kind = ventPlacement->moonRockKind;
                }
                if (state->kind == 3 || state->kind == 4 || state->kind == 6) {
                    if (mode != 2) {
                        pedestalCount += 1;
                    }
                    if (mode == 0) {
                        Sfx_PlayFromObject(0, pedestalCount < 3 ? SFXTRIG_menuups16k : SFXTRIG_mpick1_b);
                        mainSetBits(MMP_MOON_ROCK_PLACEMENT_EVENT_GAMEBIT, 1);
                    }
                    state->flags |= MMP_MOON_ROCK_FLAG_PLACED;
                    setAButtonIcon(0);
                } else if (mode != 2) {
                    inventoryCount += 1;
                }
            }
            if (pedestalCount >= 3) {
                mainSetBits(GAMEBIT_MMP_MovedMeteor, 1);
            } else {
                mainSetBits(GAMEBIT_MMP_MovedMeteor, 0);
            }
            if (pedestalCount > 3) {
                pedestalCount = 3;
            } else if (pedestalCount < 0) {
                pedestalCount = 0;
            }
            if (inventoryCount > 3) {
                inventoryCount = 3;
            } else if (inventoryCount < 0) {
                inventoryCount = 0;
            }
            mainSetBits(MMP_MOON_ROCK_PEDESTAL_COUNT_GAMEBIT, pedestalCount);
            mainSetBits(MMP_MOON_ROCK_INVENTORY_COUNT_GAMEBIT, inventoryCount);
        }
    }
}

void mmpMoonRock_setPosition(GameObject* obj, f32 x, f32 y, f32 z) {
    obj->anim.localPosX = x;
    obj->anim.localPosY = y;
    obj->anim.localPosZ = z;
    saveGame_saveObjectPos(obj);
}

void mmpMoonRock_setFrozen(GameObject* obj, u8 frozen) {
    MMPMoonRockState* state = obj->extra;
    if (frozen != 0) {
        state->flags |= MMP_MOON_ROCK_FLAG_FROZEN;
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    } else {
        state->flags &= ~MMP_MOON_ROCK_FLAG_FROZEN;
        obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
    }
}

int mmpMoonRock_getExtraSize(void) {
    return sizeof(MMPMoonRockState);
}

int mmpMoonRock_getObjectTypeId(void) {
    return 0;
}

void mmpMoonRock_free(GameObject* obj) {
    objFreeObjectType(obj, MMP_MOON_ROCK_OBJECT_GROUP);
    (*gCarryableInterface)->free(obj);
}

void mmpMoonRock_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    if ((*gCarryableInterface)->updateRenderState(obj, visible) != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void mmpMoonRock_hitDetect(void) {
}

static inline u8 mmpMoonRock_checkDropSpacing(GameObject* obj) {
    CarryableState* carryable;
    GameObject** objects;
    int count;
    int i;

    carryable = obj->extra;
    (*gCarryableInterface)->setDropDisabled(carryable, 0);
    objects = objGetAllOfType(CARRYABLE_OBJECT_GROUP, &count);
    for (i = 0; i < count; i++) {
        if (objects[i] != obj && objects[i]->anim.romDefNo == MMP_MOON_ROCK_SEQUENCE_ID &&
            Vec_xzDistance(&obj->anim.worldPosX, &objects[i]->anim.worldPosX) < 40.0f) {
            (*gCarryableInterface)->setDropDisabled(carryable, 1);
            return 0;
        }
    }
    return 1;
}

void mmpMoonRock_update(GameObject* obj) {
    MMPMoonRockState* state = obj->extra;
    u8 isHeld;
    int particleHeight;
    MMPMoonRockPlacement* placement = (MMPMoonRockPlacement*)obj->anim.placementData;
    if (objPosToMapBlockIdx(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ) == -1) {
        return;
    }
    if ((state->flags & MMP_MOON_ROCK_FLAG_FROZEN) != 0) {
        return;
    }
    if ((state->flags & MMP_MOON_ROCK_FLAG_RESETTING) != 0) {
        if (state->resetTimer > 0.0f) {
            state->resetTimer -= timeDelta;
            if (state->resetTimer <= 0.0f) {
                state->flags = 0;
                obj->anim.alpha = 0xFF;
                ObjHits_DisableObject(obj);
                mmpMoonRock_reconcilePlacement(obj, 1, 1);
            } else {
                obj->anim.alpha = (int)(255.0f * (1.0f - state->resetTimer / MMP_MOON_ROCK_RESET_DURATION));
                objDoParticleFx(obj, 0.5f, 2, 1.0f - state->resetTimer / MMP_MOON_ROCK_RESET_DURATION, 0);
                objDoParticleFx(obj, 0.5f, 2, 1.0f - state->resetTimer / MMP_MOON_ROCK_RESET_DURATION, 0);
            }
        }
        return;
    }
    objfx_spawnDirectionalBurst(obj, 1, 1.0f, 5, 1, 0xA, 8.0f, NULL, 0);
    objfx_spawnDirectionalBurst(obj, 5, 1.0f, 5, 1, 0x14, 8.0f, NULL, 0);
    if ((state->flags & MMP_MOON_ROCK_FLAG_THROWN) != 0) {
        mmpMoonRock_updateThrow(obj);
        mmpMoonRock_handleImpact(obj);
        return;
    }
    isHeld = 0;
    if ((state->flags & MMP_MOON_ROCK_FLAG_HELD_LAST_UPDATE) != 0 &&
        (*gMapEventInterface)->getObjGroupStatus(MMP_MOON_ROCK_MAP_EVENT_GROUP, MMP_MOON_ROCK_MAP_EVENT_STATUS) ==
            0) {
        state->flags |= MMP_MOON_ROCK_FLAG_ACTION_PENDING;
    } else if ((state->flags & MMP_MOON_ROCK_FLAG_PLACED) == 0) {
        if (placement->pickupGateGameBit != -1 && mainGetBit(placement->pickupGateGameBit) == 0) {
            obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        } else if ((*gCarryableInterface)->updateHeld(obj, (CarryableState*)obj->extra) != 0) {
            isHeld = 1;
        }
    } else {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    }
    state->flags &= ~MMP_MOON_ROCK_FLAG_HELD_LAST_UPDATE;
    if (isHeld != 0) {
        u8 spacingClear;
        if ((playerGetStateFlag310(Obj_GetPlayerObject()) & PLAYER_STATE_FLAG_CAN_PLACE_CARRYABLE) != 0) {
            setAButtonIcon(A_BUTTON_ICON_PLACE_CARRYABLE);
            state->flags |= MMP_MOON_ROCK_FLAG_HELD_LAST_UPDATE | MMP_MOON_ROCK_FLAG_ICON_PLACE;
            state->flags &= ~MMP_MOON_ROCK_FLAG_ICON_THROW;
        } else {
            setAButtonIcon(A_BUTTON_ICON_THROW_CARRYABLE);
            state->flags |= MMP_MOON_ROCK_FLAG_HELD_LAST_UPDATE | MMP_MOON_ROCK_FLAG_ICON_THROW;
            state->flags &= ~MMP_MOON_ROCK_FLAG_ICON_PLACE;
        }
        spacingClear = mmpMoonRock_checkDropSpacing(obj);
        if (spacingClear != 0) {
            state->flags |= MMP_MOON_ROCK_FLAG_ACTION_PENDING;
        }
        if ((state->flags & MMP_MOON_ROCK_FLAG_DETACH_ARMED) != 0) {
            mmpMoonRock_reconcilePlacement(obj, 0, 0);
            state->flags &= ~MMP_MOON_ROCK_FLAG_DETACH_ARMED;
        }
        return;
    }
    if ((state->flags & MMP_MOON_ROCK_FLAG_PLACED) == 0 && (state->flags & MMP_MOON_ROCK_FLAG_ACTION_PENDING) != 0) {
        if ((state->flags & MMP_MOON_ROCK_FLAG_ICON_THROW) != 0) {
            mmpMoonRock_throwFromPlayer(obj);
        } else {
            mmpMoonRock_reconcilePlacement(obj, 1, 0);
        }
        state->flags &= ~MMP_MOON_ROCK_FLAG_ACTION_PENDING;
    }
    state->flags |= MMP_MOON_ROCK_FLAG_DETACH_ARMED;
    if (state->kind == 0) {
        return;
    }
    if ((state->flags & MMP_MOON_ROCK_FLAG_PLACED) != 0) {
        state->heightLevel = mainGetBit(MMP_MOON_ROCK_INVENTORY_COUNT_GAMEBIT);
    } else {
        state->heightLevel = 0;
    }
    Sfx_PlayFromObject(obj, SFXTRIG_en_diallp_c);
    Sfx_SetObjectChannelVolume(obj, MMP_MOON_ROCK_SFX_CHANNEL, state->heightLevel * 0x20 + 0x20, 0.5f);
    {
        f32 speed = obj->anim.velocityY;
        if (speed < 0.1f * ((20.0f * state->heightLevel + state->baseY) - obj->anim.localPosY)) {
            f32 velocityStep = 0.03f;
            obj->anim.velocityY = speed + velocityStep;
        } else {
            obj->anim.velocityY = speed - 0.051f;
        }
    }
    state->bobPhase += 0x1000;
    state->rollPhase += 0xDAC;
    state->pitchPhase += 0x800;
    objMove(obj, 0.0f, obj->anim.velocityY * timeDelta, 0.0f);
    obj->anim.localPosY = obj->anim.localPosY + mathSinf((3.1415927f * state->bobPhase) / 32768.0f);
    if (obj->anim.localPosY < state->baseY) {
        obj->anim.localPosY = state->baseY;
    }
    obj->anim.rotZ += (int)(182.0f * mathSinf((3.1415927f * state->rollPhase) / 32768.0f));
    obj->anim.rotY += (int)(182.0f * mathSinf((3.1415927f * state->pitchPhase) / 32768.0f));
    gMMPMoonRockSpawnParams.scale = 1.0f;
    gMMPMoonRockSpawnParams.posX = obj->anim.localPosX;
    gMMPMoonRockSpawnParams.posY = state->baseY;
    gMMPMoonRockSpawnParams.posZ = obj->anim.localPosZ;
    particleHeight = obj->anim.localPosY - state->baseY;
    (*gPartfxInterface)
        ->spawnObject(obj, MMP_MOON_ROCK_PARTICLE_AMBIENT, &gMMPMoonRockSpawnParams,
                      MMP_MOON_ROCK_PARTICLE_SPAWN_MODE, MMP_MOON_ROCK_PARTICLE_MODEL_NONE, &particleHeight);
}

void mmpMoonRock_init(GameObject* obj, const MMPMoonRockPlacement* placement) {
    MMPMoonRockState* state = obj->extra;
    u8 kind;

    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
    state->flags = 0;
    state->kind = mainGetBit(placement->kindGameBit);
    kind = state->kind;
    if (kind != 0) {
        if ((u8)(kind - 3) <= 1 || kind == 6) {
            state->flags |= MMP_MOON_ROCK_FLAG_PLACED;
        }
        (*gCarryableInterface)->setGravityEnabled(&state->carryable, 0);
    } else {
        (*gCarryableInterface)->setGravityEnabled(&state->carryable, 1);
    }
    state->savedBaseY = state->baseY = obj->anim.localPosY;
    (*gCarryableInterface)->init(obj, (CarryableState*)obj->extra, 0x32);
    (*gCarryableInterface)->setSuppressPositionSave(&state->carryable, 1);
    objAddObjectType(obj, MMP_MOON_ROCK_OBJECT_GROUP);
    state->homeX = obj->anim.localPosX;
    state->homeY = obj->anim.localPosY;
    state->homeZ = obj->anim.localPosZ;
    ObjHits_DisableObject(obj);
    mmpMoonRock_reconcilePlacement(obj, 1, 2);
}

void mmpMoonRock_release(void) {
}

void mmpMoonRock_initialise(void) {
}

ObjectDescriptor gMMPMoonRockObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)mmpMoonRock_initialise,
    (ObjectDescriptorCallback)mmpMoonRock_release,
    0,
    (ObjectDescriptorCallback)mmpMoonRock_init,
    (ObjectDescriptorCallback)mmpMoonRock_update,
    (ObjectDescriptorCallback)mmpMoonRock_hitDetect,
    (ObjectDescriptorCallback)mmpMoonRock_render,
    (ObjectDescriptorCallback)mmpMoonRock_free,
    (ObjectDescriptorCallback)mmpMoonRock_getObjectTypeId,
    mmpMoonRock_getExtraSize,
};
