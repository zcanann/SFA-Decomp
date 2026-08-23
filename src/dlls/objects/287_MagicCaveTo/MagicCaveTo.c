/*
 * Top-area Magic Cave warp object (DLL slot 287 / 0x11F).
 *
 * The object stages the destination map as the player approaches, runs the
 * cave-entry sequence, and restores the exterior sequence when the bottom
 * object returns through the shared Magic Cave gamebits.
 */
#include "dlls/objects/287_MagicCaveTo.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/camera_interface.h"
#include "main/dll/CAM/dll_0001_camcontrol.h"
#include "main/dll/dll_00E2_staff_api.h"
#include "main/dll/objfx.h"
#include "main/dll/player_objects.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/mapEventTypes.h"
#include "main/map_load.h"
#include "main/model.h"
#include "main/objfx.h"
#include "main/objseq.h"
#include "main/pad.h"
#include "main/pi_dolphin_api.h"
#include "main/rcp_dolphin_api.h"
#include "main/vecmath_distance_api.h"
#include "sys/objects.h"

#define MAGIC_CAVE_TOP_MAP_UNLOAD_FLAGS 0x20000000

#define MAGIC_CAVE_TOP_ENTER_SEQUENCE    0
#define MAGIC_CAVE_TOP_EXIT_SEQUENCE     1
#define MAGIC_CAVE_TOP_SEQUENCE_ARG_NONE -1

#define MAGIC_CAVE_TOP_RANGE_SCALE 2

#define MAGIC_CAVE_TOP_STAFF_GLOW_MODE     5
#define MAGIC_CAVE_TOP_STAFF_GLOW_DISABLED 0
#define MAGIC_CAVE_TOP_STAFF_GLOW_ACTIVE   2
#define MAGIC_CAVE_TOP_ALPHA_OPAQUE        0xFF

#define MAGIC_CAVE_TOP_BURST_MODE             2
#define MAGIC_CAVE_TOP_BURST_FLAGS            0
#define MAGIC_CAVE_TOP_BURST_PRIMARY_EFFECT   1
#define MAGIC_CAVE_TOP_BURST_SECONDARY_EFFECT 5
#define MAGIC_CAVE_TOP_BURST_DEFAULT_KIND     2
#define MAGIC_CAVE_TOP_BURST_ALTERNATE_KIND   5
#define MAGIC_CAVE_TOP_BURST_PRIMARY_CHANCE   0x32
#define MAGIC_CAVE_TOP_BURST_SECONDARY_CHANCE 0x14
#define MAGIC_CAVE_TOP_TEXTURE_SWAP_DEFAULT   22
#define MAGIC_CAVE_TOP_TEXTURE_SWAP_ALT       23

#define MAGIC_CAVE_TOP_WALLED_CITY_MAP_SLOT 0xD
#define MAGIC_CAVE_TOP_WARP_TRANSITION_TYPE 0

#define MAGIC_CAVE_TOP_CAMERA_ARG1         0
#define MAGIC_CAVE_TOP_CAMERA_ARG2         1
#define MAGIC_CAVE_TOP_CAMERA_FLAGS        0
#define MAGIC_CAVE_TOP_CAMERA_BLEND_FRAMES 0x1E
#define MAGIC_CAVE_TOP_CAMERA_PRIORITY     0xFF

const f32 gMagicCaveTopWarpDistSq[1] = {225.0f};
const f32 gMagicCaveTopRumbleStartDistSq[1] = {14400.0f};
const f32 lbl_803E3C38[1] = {0.0f};
const f32 gMagicCaveTopRumbleStopDistSq[1] = {3600.0f};
const f32 gMagicCaveTopRumblePulseDistSq[1] = {8100.0f};
const f32 gMagicCaveTopRumbleStrength[1] = {3.0f};
const f32 gMagicCaveTopRumbleDuration[1] = {300.0f};
const f32 gMagicCaveTopFadeMax[1] = {100.0f};
const f32 gMagicCaveTopAlphaMax[1] = {255.0f};
const f32 gMagicCaveTopBurstHeight1[1] = {40.0f};
const f32 gMagicCaveTopBurstRadius[1] = {0.5f};
const f32 gMagicCaveTopBurstSpreadX[1] = {18.0f};
const f32 gMagicCaveTopBurstSpreadY[1] = {8.0f};
const f32 gMagicCaveTopBurstSpreadZ[1] = {80.0f};
const f32 gMagicCaveTopBurstHeight2[1] = {5.0f};

#define MAGIC_CAVE_TOP_WARP_DISTANCE_SQ         (gMagicCaveTopWarpDistSq[0])
#define MAGIC_CAVE_TOP_RUMBLE_START_DISTANCE_SQ (gMagicCaveTopRumbleStartDistSq[0])
#define MAGIC_CAVE_TOP_ZERO                     (lbl_803E3C38[0])
#define MAGIC_CAVE_TOP_RUMBLE_STOP_DISTANCE_SQ  (gMagicCaveTopRumbleStopDistSq[0])
#define MAGIC_CAVE_TOP_RUMBLE_PULSE_DISTANCE_SQ (gMagicCaveTopRumblePulseDistSq[0])
#define MAGIC_CAVE_TOP_RUMBLE_STRENGTH          (gMagicCaveTopRumbleStrength[0])
#define MAGIC_CAVE_TOP_RUMBLE_DURATION          (gMagicCaveTopRumbleDuration[0])
#define MAGIC_CAVE_TOP_FADE_MAX                 (gMagicCaveTopFadeMax[0])
#define MAGIC_CAVE_TOP_ALPHA_MAX                (gMagicCaveTopAlphaMax[0])
#define MAGIC_CAVE_TOP_BURST_PRIMARY_HEIGHT     (gMagicCaveTopBurstHeight1[0])
#define MAGIC_CAVE_TOP_BURST_SCALE              (gMagicCaveTopBurstRadius[0])
#define MAGIC_CAVE_TOP_BURST_PRIMARY_ANGLE      (gMagicCaveTopBurstSpreadX[0])
#define MAGIC_CAVE_TOP_BURST_PRIMARY_ANGLE_LOW  (gMagicCaveTopBurstSpreadY[0])
#define MAGIC_CAVE_TOP_BURST_PRIMARY_ANGLE_HIGH (gMagicCaveTopBurstSpreadZ[0])
#define MAGIC_CAVE_TOP_BURST_SECONDARY_HEIGHT   (gMagicCaveTopBurstHeight2[0])
#define MAGIC_CAVE_TOP_BURST_SECONDARY_ANGLE    10.0f

int MagicCaveTop_getExtraSize(void) {
    return sizeof(MagicCaveTopState);
}

void MagicCaveTop_free(GameObject* obj) {
    MagicCaveTopState* state = obj->extra;
    MagicCaveTopPlacement* placement = (MagicCaveTopPlacement*)obj->anim.placementData;
    GameObject* player;
    GameObject* staff;

    stopRumble2();
    player = Obj_GetPlayerObject();
    if (player != NULL) {
        staff = Player_GetStaffObject(player);
        if (staff != NULL) {
            staffSetGlow(staff, MAGIC_CAVE_TOP_STAFF_GLOW_MODE, MAGIC_CAVE_TOP_STAFF_GLOW_DISABLED);
        }
    }
    if (state->phase == MAGIC_CAVE_TOP_PHASE_LOADED) {
        if (placement->skipMapLoad == 0) {
            mapUnload(mapGetDirIdx(placement->mapId), MAGIC_CAVE_TOP_MAP_UNLOAD_FLAGS);
        }
    }
}

void MagicCaveTop_update(GameObject* obj) {
    ObjFxParticleParams effectParams;
    GameObject* player;
    MagicCaveTopState* state;
    MagicCaveTopPlacement* placement;
    int isVisible;
    u8 mapDirIndex;
    int range;
    GameObject* staff;
    f32 distanceSquared;
    f32 effectOriginXZ;

    player = Obj_GetPlayerObject();
    state = obj->extra;
    placement = (MagicCaveTopPlacement*)obj->anim.placementData;
    isVisible = 0;
    if (player != NULL) {
        if (mainGetBit(GAMEBIT_MC_IsExiting) != 0) {
            mainSetBits(GAMEBIT_MC_IsExiting, 0);
            (*gMapEventInterface)->setObjGroupStatus(placement->mapId, placement->objectGroup, 0);
            (*gObjectTriggerInterface)
                ->runSequence(MAGIC_CAVE_TOP_EXIT_SEQUENCE, obj, MAGIC_CAVE_TOP_SEQUENCE_ARG_NONE);
            unlockLevel(0, 0, 1);
            state->phase = MAGIC_CAVE_TOP_PHASE_WARP_DONE;
            return;
        }
        mapDirIndex = mapGetDirIdx(placement->mapId);
        distanceSquared = vec3f_distanceSquared(&player->anim.worldPosX, &obj->anim.worldPosX);
        isVisible = mainGetBit(placement->visibleGameBit);
        switch (state->phase) {
        case MAGIC_CAVE_TOP_PHASE_IDLE:
            range = placement->innerRange * MAGIC_CAVE_TOP_RANGE_SCALE;
            if (distanceSquared < (f32)(range * range)) {
                if (placement->skipMapLoad == 0) {
                    loadMapAndParent(placement->mapId);
                }
                state->phase = MAGIC_CAVE_TOP_PHASE_LOADED;
            }
            break;
        case MAGIC_CAVE_TOP_PHASE_LOADED:
            range = placement->outerRange * MAGIC_CAVE_TOP_RANGE_SCALE;
            if (distanceSquared > (f32)(range * range)) {
                if (placement->skipMapLoad == 0) {
                    mapUnload(mapDirIndex, MAGIC_CAVE_TOP_MAP_UNLOAD_FLAGS);
                }
                state->phase = MAGIC_CAVE_TOP_PHASE_IDLE;
            } else if (distanceSquared < MAGIC_CAVE_TOP_WARP_DISTANCE_SQ && isVisible != 0) {
                state->phase = MAGIC_CAVE_TOP_PHASE_WARPING;
                (*gMapEventInterface)->setObjGroupStatus(placement->mapId, placement->objectGroup, 1);
                (*gMapEventInterface)->setMapAct(placement->mapId, placement->mapAct);
                (*gObjectTriggerInterface)
                    ->runSequence(MAGIC_CAVE_TOP_ENTER_SEQUENCE, obj, MAGIC_CAVE_TOP_SEQUENCE_ARG_NONE);
                (*gCameraInterface)
                    ->setMode(CAMCONTROL_ACTION_DEFAULT, MAGIC_CAVE_TOP_CAMERA_ARG1, MAGIC_CAVE_TOP_CAMERA_ARG2,
                              MAGIC_CAVE_TOP_CAMERA_FLAGS, NULL, MAGIC_CAVE_TOP_CAMERA_BLEND_FRAMES,
                              MAGIC_CAVE_TOP_CAMERA_PRIORITY);
            }
            break;
        case MAGIC_CAVE_TOP_PHASE_WARPING:
            mainSetBits(GAMEBIT_MagicCaveExitWarp, placement->exitWarpId);
            if (placement->skipMapLoad != 0) {
                unlockLevel(0, 0, 1);
                lockLevel(placement->lockDirId, 0);
                lockLevel(placement->lockDirId, 1);
            } else {
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(obj->anim.mapEventSlot), 0);
                lockLevel(mapDirIndex, 1);
            }
            if (obj->anim.mapEventSlot == MAGIC_CAVE_TOP_WALLED_CITY_MAP_SLOT) {
                mainSetBits(GAMEBIT_WC_MagicCaveRelated0E05, 0);
            }
            warpToMap(placement->warpMapId, MAGIC_CAVE_TOP_WARP_TRANSITION_TYPE);
            break;
        case MAGIC_CAVE_TOP_PHASE_WARP_DONE:
            if (distanceSquared > MAGIC_CAVE_TOP_WARP_DISTANCE_SQ) {
                state->phase = MAGIC_CAVE_TOP_PHASE_LOADED;
            }
            break;
        }
        if ((state->flags & MAGIC_CAVE_TOP_FLAG_RUMBLE_DISABLED) == 0) {
            if (distanceSquared >= MAGIC_CAVE_TOP_RUMBLE_START_DISTANCE_SQ) {
                state->rumbleTimer = MAGIC_CAVE_TOP_ZERO;
                state->flags &= ~MAGIC_CAVE_TOP_FLAG_RUMBLE_COMPLETE;
            } else if ((state->flags & MAGIC_CAVE_TOP_FLAG_RUMBLE_COMPLETE) == 0) {
                if ((state->flags & MAGIC_CAVE_TOP_FLAG_RUMBLE_ACTIVE) != 0) {
                    if (distanceSquared < MAGIC_CAVE_TOP_RUMBLE_STOP_DISTANCE_SQ) {
                        stopRumble();
                        if (player != NULL) {
                            staff = Player_GetStaffObject(player);
                            if (staff != NULL) {
                                staffSetGlow(staff, MAGIC_CAVE_TOP_STAFF_GLOW_MODE, MAGIC_CAVE_TOP_STAFF_GLOW_DISABLED);
                            }
                        }
                        state->rumbleState = MAGIC_CAVE_TOP_RUMBLE_STATE_STOPPED;
                    } else if (distanceSquared < MAGIC_CAVE_TOP_RUMBLE_PULSE_DISTANCE_SQ) {
                        if (state->rumbleState == MAGIC_CAVE_TOP_RUMBLE_STATE_PULSING) {
                            stopRumble();
                            if (player != NULL) {
                                staff = Player_GetStaffObject(player);
                                if (staff != NULL) {
                                    staffSetGlow(staff, MAGIC_CAVE_TOP_STAFF_GLOW_MODE,
                                                 MAGIC_CAVE_TOP_STAFF_GLOW_DISABLED);
                                }
                            }
                            state->rumbleState = MAGIC_CAVE_TOP_RUMBLE_STATE_STOPPED;
                        } else {
                            stopRumble2();
                            if (player != NULL) {
                                staff = Player_GetStaffObject(player);
                                if (staff != NULL) {
                                    staffSetGlow(staff, MAGIC_CAVE_TOP_STAFF_GLOW_MODE,
                                                 MAGIC_CAVE_TOP_STAFF_GLOW_DISABLED);
                                }
                            }
                            state->rumbleState = MAGIC_CAVE_TOP_RUMBLE_STATE_PULSING;
                        }
                    } else {
                        stopRumble2();
                        if (player != NULL) {
                            staff = Player_GetStaffObject(player);
                            if (staff != NULL) {
                                staffSetGlow(staff, MAGIC_CAVE_TOP_STAFF_GLOW_MODE, MAGIC_CAVE_TOP_STAFF_GLOW_DISABLED);
                            }
                        }
                        state->rumbleState = MAGIC_CAVE_TOP_RUMBLE_STATE_PULSING;
                    }
                    state->flags &= ~MAGIC_CAVE_TOP_FLAG_RUMBLE_ACTIVE;
                    state->rumbleTimer += timeDelta;
                } else if (distanceSquared < MAGIC_CAVE_TOP_RUMBLE_START_DISTANCE_SQ) {
                    doRumble(MAGIC_CAVE_TOP_RUMBLE_STRENGTH);
                    if (player != NULL) {
                        staff = Player_GetStaffObject(player);
                        if (staff != NULL) {
                            staffSetGlow(staff, MAGIC_CAVE_TOP_STAFF_GLOW_MODE, MAGIC_CAVE_TOP_STAFF_GLOW_ACTIVE);
                        }
                    }
                    state->flags |= MAGIC_CAVE_TOP_FLAG_RUMBLE_ACTIVE;
                    state->rumbleTimer += timeDelta;
                }
                if (state->rumbleTimer > MAGIC_CAVE_TOP_RUMBLE_DURATION) {
                    state->flags |= MAGIC_CAVE_TOP_FLAG_RUMBLE_COMPLETE;
                }
            }
        }
    }
    if (isVisible != 0) {
        if (MAGIC_CAVE_TOP_ZERO == state->fadeTimer) {
            Sfx_PlayFromObject(obj, SFXTRIG_door_creak);
        }
        state->fadeTimer += timeDelta;
        if (state->fadeTimer > MAGIC_CAVE_TOP_FADE_MAX) {
            state->fadeTimer = MAGIC_CAVE_TOP_FADE_MAX;
            obj->anim.alpha = MAGIC_CAVE_TOP_ALPHA_OPAQUE;
        } else {
            obj->anim.alpha = (u8)(int)(MAGIC_CAVE_TOP_ALPHA_MAX * (state->fadeTimer / MAGIC_CAVE_TOP_FADE_MAX));
        }
    } else {
        obj->anim.alpha = 0;
    }
    if (obj->anim.alpha != 0) {
        effectOriginXZ = MAGIC_CAVE_TOP_ZERO;
        effectParams.position[0] = effectOriginXZ;
        effectParams.position[1] = MAGIC_CAVE_TOP_BURST_PRIMARY_HEIGHT;
        effectParams.position[2] = effectOriginXZ;
        if ((state->flags & MAGIC_CAVE_TOP_FLAG_ALT_EFFECT) != 0) {
            objfx_spawnArcedBurst(obj, MAGIC_CAVE_TOP_BURST_PRIMARY_EFFECT, MAGIC_CAVE_TOP_BURST_SCALE,
                                  MAGIC_CAVE_TOP_BURST_ALTERNATE_KIND, MAGIC_CAVE_TOP_BURST_MODE,
                                  MAGIC_CAVE_TOP_BURST_PRIMARY_CHANCE, MAGIC_CAVE_TOP_BURST_PRIMARY_ANGLE,
                                  MAGIC_CAVE_TOP_BURST_PRIMARY_ANGLE_LOW, MAGIC_CAVE_TOP_BURST_PRIMARY_ANGLE_HIGH,
                                  &effectParams, MAGIC_CAVE_TOP_BURST_FLAGS);
            effectParams.position[1] = MAGIC_CAVE_TOP_BURST_SECONDARY_HEIGHT;
            objfx_spawnArcedBurst(obj, MAGIC_CAVE_TOP_BURST_SECONDARY_EFFECT, MAGIC_CAVE_TOP_BURST_SCALE,
                                  MAGIC_CAVE_TOP_BURST_ALTERNATE_KIND, MAGIC_CAVE_TOP_BURST_MODE,
                                  MAGIC_CAVE_TOP_BURST_SECONDARY_CHANCE, MAGIC_CAVE_TOP_BURST_SECONDARY_ANGLE,
                                  MAGIC_CAVE_TOP_BURST_SECONDARY_ANGLE, MAGIC_CAVE_TOP_BURST_SECONDARY_ANGLE,
                                  &effectParams, MAGIC_CAVE_TOP_BURST_FLAGS);
        } else {
            objfx_spawnArcedBurst(obj, MAGIC_CAVE_TOP_BURST_PRIMARY_EFFECT, MAGIC_CAVE_TOP_BURST_SCALE,
                                  MAGIC_CAVE_TOP_BURST_DEFAULT_KIND, MAGIC_CAVE_TOP_BURST_MODE,
                                  MAGIC_CAVE_TOP_BURST_PRIMARY_CHANCE, MAGIC_CAVE_TOP_BURST_PRIMARY_ANGLE,
                                  MAGIC_CAVE_TOP_BURST_PRIMARY_ANGLE_LOW, MAGIC_CAVE_TOP_BURST_PRIMARY_ANGLE_HIGH,
                                  &effectParams, MAGIC_CAVE_TOP_BURST_FLAGS);
            effectParams.position[1] = MAGIC_CAVE_TOP_BURST_SECONDARY_HEIGHT;
            objfx_spawnArcedBurst(obj, MAGIC_CAVE_TOP_BURST_SECONDARY_EFFECT, MAGIC_CAVE_TOP_BURST_SCALE,
                                  MAGIC_CAVE_TOP_BURST_DEFAULT_KIND, MAGIC_CAVE_TOP_BURST_MODE,
                                  MAGIC_CAVE_TOP_BURST_SECONDARY_CHANCE, MAGIC_CAVE_TOP_BURST_SECONDARY_ANGLE,
                                  MAGIC_CAVE_TOP_BURST_SECONDARY_ANGLE, MAGIC_CAVE_TOP_BURST_SECONDARY_ANGLE,
                                  &effectParams, MAGIC_CAVE_TOP_BURST_FLAGS);
        }
    }
}

void MagicCaveTop_init(GameObject* obj, MagicCaveTopPlacement* placement) {
    MagicCaveTopState* state = obj->extra;
    ModelRenderOpTextureRefs* textureRefs;

    obj->objectFlags = (u16)((u32)obj->objectFlags | (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED));
    if (mainGetBit(placement->visibleGameBit) != 0) {
        state->fadeTimer = MAGIC_CAVE_TOP_FADE_MAX;
    }
    obj->anim.rotX = (s16)((s32)placement->rotationX << 8);
    textureRefs = ObjModel_GetRenderOpTextureRefs(Obj_GetActiveModel(obj), 0);
    if (placement->textureSwapGameBit > 0) {
        if (mainGetBit(placement->textureSwapGameBit) != 0) {
            state->flags = (u8)(state->flags | (MAGIC_CAVE_TOP_FLAG_RUMBLE_DISABLED | MAGIC_CAVE_TOP_FLAG_ALT_EFFECT));
            textureRefs->swapSelector = MAGIC_CAVE_TOP_TEXTURE_SWAP_ALT;
        } else {
            textureRefs->swapSelector = MAGIC_CAVE_TOP_TEXTURE_SWAP_DEFAULT;
        }
    }
}

ObjectDescriptor gMagicCaveTopObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)MagicCaveTop_init,
    (ObjectDescriptorCallback)MagicCaveTop_update,
    0,
    0,
    (ObjectDescriptorCallback)MagicCaveTop_free,
    0,
    MagicCaveTop_getExtraSize,
};
