/*
 * CCgasventCo - Crystal Caves gas-vent controller (DLL 0x186). One
 * controller supervises the individual vents registered in the shared vent
 * object group.
 *
 * Once all four vents exist and the room trigger fires, the controller runs
 * an intro sequence and starts the air meter. Unblocked vents raise the gas
 * and drain the player's air while submerged. Exhausting the meter starts the
 * restart sequence; blocking every vent completes the puzzle. The fog clears
 * after the shared gas-active gamebit resets.
 */
#include "dlls/objects/390_CCgasventCo.h"
#include "dlls/objects/389_CCgasvent.h"

#include "main/audio/sfx_looped_object_api.h"
#include "main/audio/sfx_object_volume_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/camera_interface.h"
#include "main/frame_timing.h"
#include "main/game_ui_interface.h"
#include "main/gamebits_api.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/object_render.h"
#include "main/objtype.h"
#include "main/pi_dolphin_api.h"
#include "main/vecmath.h"
#include "sys/objects.h"

#define CC_GAS_VENT_CONTROL_VENT_COUNT 4

#define CC_GAS_VENT_CONTROL_BLOCKER_CLEAR_DISTANCE 100.0f
#define CC_GAS_VENT_CONTROL_GAS_RISE_DIVISOR       100.0f

#define CC_GAS_VENT_CONTROL_LOOPED_SFX_VOLUME_BASE 0x28
#define CC_GAS_VENT_CONTROL_LOOPED_SFX_VOLUME_STEP 0x0F
#define CC_GAS_VENT_CONTROL_SFX_VOLUME_MAX         127.0f

#define CC_GAS_VENT_CONTROL_RENDER_SCALE 1.0f

#define CC_GAS_VENT_CONTROL_AIR_METER_CAPACITY   6000
#define CC_GAS_VENT_CONTROL_AIR_METER_TEXTURE_ID 0x603
#define CC_GAS_VENT_CONTROL_AIR_MAX              6000.0f
#define CC_GAS_VENT_CONTROL_AIR_MIN              0.0f
#define CC_GAS_VENT_CONTROL_AIR_RECOVERY_RATE    16.0f

#define CC_GAS_VENT_CONTROL_GAS_HEIGHT_MAX    50.0f
#define CC_GAS_VENT_CONTROL_FOG_BOTTOM_OFFSET 15.0f
#define CC_GAS_VENT_CONTROL_FOG_DEPTH_SCALE   800.0f
#define CC_GAS_VENT_CONTROL_FOG_DEPTH_OFFSET  0.1f
#define CC_GAS_VENT_CONTROL_FOG_WORLD_SCALE   0.0005f

#define CC_GAS_VENT_CONTROL_INTRO_SEQUENCE   0
#define CC_GAS_VENT_CONTROL_RESTART_SEQUENCE 1

#define CC_GAS_VENT_CONTROL_DEFAULT_CAMERA_MODE 0x42
#define CC_GAS_VENT_CONTROL_CAMERA_BLEND_FRAMES 0x1E
#define CC_GAS_VENT_CONTROL_CAMERA_PRIORITY     0xFF

#define CC_GAS_VENT_CONTROL_INTRO_TRIGGER_GAMEBIT 0x3EC
#define CC_GAS_VENT_CONTROL_PUZZLE_STATE_GAMEBIT  0x620

#define CC_GAS_VENT_CONTROL_PHASE_WAIT_FOR_VENTS 0
#define CC_GAS_VENT_CONTROL_PHASE_WAIT_FOR_INTRO 1
#define CC_GAS_VENT_CONTROL_PHASE_INIT_METER     2
#define CC_GAS_VENT_CONTROL_PHASE_ACTIVE         3
#define CC_GAS_VENT_CONTROL_PHASE_RESTART        4
#define CC_GAS_VENT_CONTROL_PHASE_SAVE_POINT     5
#define CC_GAS_VENT_CONTROL_PHASE_WAIT_FOR_CLEAR 6
#define CC_GAS_VENT_CONTROL_PHASE_COMPLETE       7

int ccGasVentControl_sequenceCallback(GameObject* obj) {
    ccGasVentControl_countUnblockedVents(obj, obj->extra);
    return 0;
}

u8 ccGasVentControl_countUnblockedVents(GameObject* obj, CCGasVentControlState* state) {
    u8 i;
    u8 unblockedVentCount = 0;

    if (mainGetBit(CC_GAS_VENT_ACTIVE_GAMEBIT) != 0) {
        int ventCount;
        GameObject** vents = (GameObject**)objGetAllOfType(CC_GAS_VENT_OBJECT_GROUP, &ventCount);
        f32 blockerClearDistance;

        i = 0;
        blockerClearDistance = CC_GAS_VENT_CONTROL_BLOCKER_CLEAR_DISTANCE;
        for (; i < CC_GAS_VENT_CONTROL_VENT_COUNT; i++) {
            GameObject* nearestBlocker =
                objGetNearestTypeTo(CC_GAS_VENT_BLOCKER_OBJECT_GROUP, vents[i], 0);
            if (getXZDistanceSquared(&vents[i]->anim.worldPosX, &nearestBlocker->anim.worldPosX) > blockerClearDistance) {
                unblockedVentCount = unblockedVentCount + 1u;
            }
        }
    }
    if (unblockedVentCount != 0) {
        if (state->loopedSoundActive == 0) {
            Sfx_AddLoopedObjectSound(obj, SFXTRIG_en_diallp_c_223);
            state->loopedSoundActive = 1;
        }
        Sfx_SetObjectSfxVolume(obj, SFXTRIG_en_diallp_c_223,
                               (unblockedVentCount * CC_GAS_VENT_CONTROL_LOOPED_SFX_VOLUME_STEP +
                                    CC_GAS_VENT_CONTROL_LOOPED_SFX_VOLUME_BASE),
                               CC_GAS_VENT_CONTROL_SFX_VOLUME_MAX);
    } else {
        if (state->loopedSoundActive != 0) {
            Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_en_diallp_c_223);
            state->loopedSoundActive = 0;
        }
    }
    return unblockedVentCount;
}

int ccGasVentControl_getExtraSize(void) {
    return sizeof(CCGasVentControlState);
}

void ccGasVentControl_free(GameObject* obj) {
    CCGasVentControlState* state = obj->extra;
    u8 phase = state->phase;

    if (phase == CC_GAS_VENT_CONTROL_PHASE_ACTIVE || phase == CC_GAS_VENT_CONTROL_PHASE_RESTART) {
        disableHeavyFog();
    }
    (*gGameUIInterface)->airMeterShutdown();
}

void ccGasVentControl_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                             s8 visible) {
    s32 isVisible = visible;

    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5,
                                    CC_GAS_VENT_CONTROL_RENDER_SCALE);
    }
}

ObjectDescriptor gCCGasVentControlObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)ccGasVentControl_init,
    (ObjectDescriptorCallback)ccGasVentControl_update,
    0,
    (ObjectDescriptorCallback)ccGasVentControl_render,
    (ObjectDescriptorCallback)ccGasVentControl_free,
    0,
    ccGasVentControl_getExtraSize,
};

void ccGasVentControl_update(GameObject* obj) {
    CCGasVentControlState* state = obj->extra;
    u8 unblockedVentCount = ccGasVentControl_countUnblockedVents(obj, state);

    switch (state->phase) {
    case CC_GAS_VENT_CONTROL_PHASE_WAIT_FOR_VENTS: {
        int ventCount;

        objGetAllOfType(CC_GAS_VENT_OBJECT_GROUP, &ventCount);
        if (ventCount == CC_GAS_VENT_CONTROL_VENT_COUNT) {
            state->phase = CC_GAS_VENT_CONTROL_PHASE_WAIT_FOR_INTRO;
        }
        break;
    }
    case CC_GAS_VENT_CONTROL_PHASE_WAIT_FOR_INTRO:
        if (mainGetBit(CC_GAS_VENT_CONTROL_INTRO_TRIGGER_GAMEBIT) != 0) {
            (*gObjectTriggerInterface)->runSequence(CC_GAS_VENT_CONTROL_INTRO_SEQUENCE, obj, -1);
            state->phase = CC_GAS_VENT_CONTROL_PHASE_INIT_METER;
        }
        break;
    case CC_GAS_VENT_CONTROL_PHASE_INIT_METER:
        (*gGameUIInterface)
            ->initAirMeter(CC_GAS_VENT_CONTROL_AIR_METER_CAPACITY, CC_GAS_VENT_CONTROL_AIR_METER_TEXTURE_ID);
        state->airRemaining = CC_GAS_VENT_CONTROL_AIR_MAX;
        state->phase = CC_GAS_VENT_CONTROL_PHASE_ACTIVE;
        state->previousUnblockedVentCount = unblockedVentCount;
        break;
    case CC_GAS_VENT_CONTROL_PHASE_ACTIVE:
        if (unblockedVentCount != 0) {
            GameObject* player = Obj_GetPlayerObject();

            state->gasHeightOffset = state->gasHeightOffset + timeDelta / CC_GAS_VENT_CONTROL_GAS_RISE_DIVISOR;
            if (state->gasHeightOffset > CC_GAS_VENT_CONTROL_GAS_HEIGHT_MAX) {
                state->gasHeightOffset = CC_GAS_VENT_CONTROL_GAS_HEIGHT_MAX;
            }
            if (player->anim.localPosY <= obj->anim.localPosY + state->gasHeightOffset) {
                state->airRemaining = -(timeDelta * unblockedVentCount - state->airRemaining);
            } else {
                state->airRemaining = CC_GAS_VENT_CONTROL_AIR_RECOVERY_RATE * timeDelta + state->airRemaining;
                if (state->airRemaining > CC_GAS_VENT_CONTROL_AIR_MAX) {
                    state->airRemaining = CC_GAS_VENT_CONTROL_AIR_MAX;
                }
            }
            enableHeavyFog(obj->anim.localPosY + state->gasHeightOffset,
                           obj->anim.localPosY - CC_GAS_VENT_CONTROL_FOG_BOTTOM_OFFSET,
                           CC_GAS_VENT_CONTROL_FOG_DEPTH_SCALE, CC_GAS_VENT_CONTROL_FOG_DEPTH_OFFSET,
                           CC_GAS_VENT_CONTROL_FOG_WORLD_SCALE, 0);
            if (state->airRemaining >= CC_GAS_VENT_CONTROL_AIR_MIN) {
                (*gGameUIInterface)->runAirMeter((int)state->airRemaining);
            } else {
                (*gGameUIInterface)->airMeterShutdown();
                obj->anim.localPosX = player->anim.localPosX;
                obj->anim.localPosY = player->anim.localPosY;
                obj->anim.localPosZ = player->anim.localPosZ;
                (*gObjectTriggerInterface)->runSequence(CC_GAS_VENT_CONTROL_RESTART_SEQUENCE, obj, -1);
                (*gCameraInterface)
                    ->setMode(CC_GAS_VENT_CONTROL_DEFAULT_CAMERA_MODE, 0, 1, 0, NULL,
                              CC_GAS_VENT_CONTROL_CAMERA_BLEND_FRAMES, CC_GAS_VENT_CONTROL_CAMERA_PRIORITY);
                state->phase = CC_GAS_VENT_CONTROL_PHASE_RESTART;
            }
            if (unblockedVentCount != state->previousUnblockedVentCount) {
                Sfx_PlayFromObject(0, SFXTRIG_sc_menuups16k_409);
                state->previousUnblockedVentCount = unblockedVentCount;
            }
        } else {
            Sfx_PlayFromObject(0, SFXTRIG_mpick1_b);
            (*gGameUIInterface)->airMeterShutdown();
            mainSetBits(CC_GAS_VENT_CONTROL_PUZZLE_COMPLETE_GAMEBIT, 1);
            mainSetBits(CC_GAS_VENT_CONTROL_PUZZLE_STATE_GAMEBIT, 0);
            state->phase = CC_GAS_VENT_CONTROL_PHASE_SAVE_POINT;
        }
        break;
    case CC_GAS_VENT_CONTROL_PHASE_RESTART:
        (*gMapEventInterface)->gotoRestartPoint();
        break;
    case CC_GAS_VENT_CONTROL_PHASE_SAVE_POINT: {
        GameObject* player = Obj_GetPlayerObject();

        (*gMapEventInterface)->savePoint(&player->anim.localPosX, player->anim.rotX, 1, 0);
        state->phase = CC_GAS_VENT_CONTROL_PHASE_WAIT_FOR_CLEAR;
        break;
    }
    case CC_GAS_VENT_CONTROL_PHASE_WAIT_FOR_CLEAR:
        if (mainGetBit(CC_GAS_VENT_ACTIVE_GAMEBIT) == 0) {
            disableHeavyFog();
            state->phase = CC_GAS_VENT_CONTROL_PHASE_COMPLETE;
        }
        break;
    }
}

void ccGasVentControl_init(GameObject* obj, const CCGasVentControlPlacement* placement) {
    CCGasVentControlState* state = obj->extra;

    obj->animEventCallback = ccGasVentControl_sequenceCallback;
    obj->anim.rotX = (s16)((u32)placement->rotXByte << 8);
    if (mainGetBit(CC_GAS_VENT_CONTROL_PUZZLE_COMPLETE_GAMEBIT) != 0) {
        state->phase = CC_GAS_VENT_CONTROL_PHASE_COMPLETE;
    }
}
