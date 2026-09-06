/* CloudRunner Fortress main-crystal controller and position source. */

#include "dlls/objects/331_CFMainCryst.h"
#include "dolphin/mtx/vec.h"

#include "dlls/objects/330_CFPowerBase.h"
#include "main/audio/sfx_channel_query_api.h"
#include "main/audio/sfx_channel_volume_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/camera_shake_api.h"
#include "main/dll/expgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/obj_message.h"
#include "main/object_render.h"
#include "main/render_envfx_api.h"
#include "main/vecmath.h"
#include "sys/objects.h"

#define CFMAINCRYSTAL_PYLON_ACTIVE_FRAMES  0x78
#define CFMAINCRYSTAL_FORCED_CHARGE_FRAMES 0x5A
#define CFMAINCRYSTAL_CHARGE_FIRE_FRAMES   0x3C
#define CFMAINCRYSTAL_PARTIAL_CHARGE_TOTAL 0x12C
#define CFMAINCRYSTAL_PYLON_TIMER_LIMIT    0x80
#define CFMAINCRYSTAL_PYLON_CHIME_PERIOD   0x64
#define CFMAINCRYSTAL_BEAM_CHIME_PERIOD    0x14
#define CFMAINCRYSTAL_PYLON_CHIME_DELAY    0x1E
#define CFMAINCRYSTAL_PARTFX_CHARGE_SPARK  0x81
#define CFMAINCRYSTAL_PARTFX_BEAM          0x7F4
#define CFMAINCRYSTAL_ENVFX                0x7F

#define CFMAINCRYSTAL_POSITION_REQUEST_FLAGS 5
#define CFMAINCRYSTAL_PYLON_REQUEST_FLAGS    4
#define CFMAINCRYSTAL_MESSAGE_QUEUE_CAPACITY 2
#define CFMAINCRYSTAL_OBJECT_TYPE_ID         1
#define CFMAINCRYSTAL_RENDER_BANK_INDEX      1
#define CFMAINCRYSTAL_BEAM_CHIME_INDEX       CFMAINCRYSTAL_PYLON_COUNT
#define CFMAINCRYSTAL_INITIAL_RED_CHIME      0x28
#define CFMAINCRYSTAL_INITIAL_BEAM_CHIME     0x46

#define CFMAINCRYSTAL_PYLON_BEAM_Y              1945.0f
#define CFMAINCRYSTAL_CRYSTAL_BEAM_Y_OFFSET     20.0f
#define CFMAINCRYSTAL_PYLON_BEAM_Y_OFFSET       55.0f
#define CFMAINCRYSTAL_DOWNWARD_BEAM_Y           -80.0f
#define CFMAINCRYSTAL_CHARGE_BEAM_FRAME_DIVISOR 30.0f
#define CFMAINCRYSTAL_CHARGE_BEAM_Y_OFFSET      15.0f
#define CFMAINCRYSTAL_CHARGE_BEAM_SPEED         250.0f
#define CFMAINCRYSTAL_HUM_INITIAL_VOLUME        0.66f
#define CFMAINCRYSTAL_HUM_BASE_VOLUME           0.33f
#define CFMAINCRYSTAL_HUM_PYLON_DIVISOR         3.0f
#define CFMAINCRYSTAL_HUM_APPROACH_RATE         0.0625f

#define CFMAINCRYSTAL_HUM_CHANNEL           0x40
#define CFMAINCRYSTAL_HUM_VOLUME            0x64
#define CFMAINCRYSTAL_PYLON_ROTATION_SPEED  0x7E
#define CFMAINCRYSTAL_IDLE_ROTATION_SPEED   0x2A
#define CFMAINCRYSTAL_SOURCE_ROTATION_SPEED 0xB6

typedef enum CfMainCrystalMessage {
    CFMAINCRYSTAL_MESSAGE_POSITION = 0x110004,
} CfMainCrystalMessage;

typedef enum CfMainCrystalPylonIndex {
    CFMAINCRYSTAL_PYLON_RED = 0,
    CFMAINCRYSTAL_PYLON_GREEN = 1,
    CFMAINCRYSTAL_PYLON_BLUE = 2,
} CfMainCrystalPylonIndex;


GameObject* gCfMainCrystalPositionObject;

void cfMainCrystal_updateBeams(GameObject* obj) {
    int pylonIndex;
    CfMainCrystalState* state = obj->extra;
    int index;
    int activePylonCount;
    PartFxSpawnParams effectParams;
    f32 beamDirection[3];
    GameObject* messageSender;
    u32 message;
    u32 unusedMessageArgument = 0;
    Obj_GetPlayerObject();
    CameraShake_Enable();
    while (ObjMsg_Pop(obj, &message, (u32*)&messageSender, &unusedMessageArgument) != 0) {
        switch (message) {
        case CFPOWERBASE_PYLON_MESSAGE_1:
            state->pylonX[CFMAINCRYSTAL_PYLON_RED] = messageSender->anim.localPosX;
            state->pylonY[CFMAINCRYSTAL_PYLON_RED] = CFMAINCRYSTAL_PYLON_BEAM_Y;
            state->pylonZ[CFMAINCRYSTAL_PYLON_RED] = messageSender->anim.localPosZ;
            state->pylonTimers[CFMAINCRYSTAL_PYLON_RED] = 1;
            break;
        case CFPOWERBASE_PYLON_MESSAGE_2:
            state->pylonX[CFMAINCRYSTAL_PYLON_GREEN] = messageSender->anim.localPosX;
            state->pylonY[CFMAINCRYSTAL_PYLON_GREEN] = CFMAINCRYSTAL_PYLON_BEAM_Y;
            state->pylonZ[CFMAINCRYSTAL_PYLON_GREEN] = messageSender->anim.localPosZ;
            state->pylonTimers[CFMAINCRYSTAL_PYLON_GREEN] = 1;
            break;
        case CFPOWERBASE_PYLON_MESSAGE_3:
            state->pylonX[CFMAINCRYSTAL_PYLON_BLUE] = messageSender->anim.localPosX;
            state->pylonY[CFMAINCRYSTAL_PYLON_BLUE] = CFMAINCRYSTAL_PYLON_BEAM_Y;
            state->pylonZ[CFMAINCRYSTAL_PYLON_BLUE] = messageSender->anim.localPosZ;
            state->pylonTimers[CFMAINCRYSTAL_PYLON_BLUE] = 1;
            break;
        case CFMAINCRYSTAL_MESSAGE_POSITION:
            state->crystalX = messageSender->anim.localPosX;
            state->crystalY = messageSender->anim.localPosY;
            state->crystalZ = messageSender->anim.localPosZ;
            state->hasCrystalPosition = 1;
            break;
        }
    }
    if (state->hasCrystalPosition == 0) {
        ObjMsg_SendToObjects(CFMAINCRYSTAL_OBJECT_ID, CFMAINCRYSTAL_POSITION_REQUEST_FLAGS, obj,
                             CFMAINCRYSTAL_MESSAGE_POSITION, 0);
    }
    if (mainGetBit(GAMEBIT_CF_RedPowerBasePowered) != 0 && state->pylonTimers[CFMAINCRYSTAL_PYLON_RED] == 0) {
        ObjMsg_SendToObjects(CFPOWERBASE_OBJECT_ID, CFMAINCRYSTAL_PYLON_REQUEST_FLAGS, obj, CFPOWERBASE_PYLON_MESSAGE_1,
                             0);
    }
    if (mainGetBit(GAMEBIT_CF_GreenPowerBasePowered) != 0 && state->pylonTimers[CFMAINCRYSTAL_PYLON_GREEN] == 0) {
        ObjMsg_SendToObjects(CFPOWERBASE_OBJECT_ID, CFMAINCRYSTAL_PYLON_REQUEST_FLAGS, obj, CFPOWERBASE_PYLON_MESSAGE_2,
                             0);
    }
    if (mainGetBit(GAMEBIT_CF_BluePowerBasePowered) != 0 && state->pylonTimers[CFMAINCRYSTAL_PYLON_BLUE] == 0) {
        ObjMsg_SendToObjects(CFPOWERBASE_OBJECT_ID, CFMAINCRYSTAL_PYLON_REQUEST_FLAGS, obj, CFPOWERBASE_PYLON_MESSAGE_3,
                             0);
    }
    state->beams[0].active = 0;
    state->beams[1].active = 0;
    state->beams[2].active = 0;
    state->beams[3].active = 0;
    state->beams[4].active = 0;
    state->beams[5].active = 0;
    state->beams[6].active = 0;
    state->beams[7].active = 0;
    state->beams[8].active = 0;
    state->beams[9].active = 0;
    activePylonCount = 0;
    index = 0;
    if (state->hasCrystalPosition != 0) {
        if (mainGetBit(GAMEBIT_CF_PowerOn) != 0) {
            if (state->pylonTimers[CFMAINCRYSTAL_PYLON_RED] != 0) {
                state->pylonTimers[CFMAINCRYSTAL_PYLON_RED] = CFMAINCRYSTAL_PYLON_ACTIVE_FRAMES;
            }
            if (state->pylonTimers[CFMAINCRYSTAL_PYLON_GREEN] != 0) {
                state->pylonTimers[CFMAINCRYSTAL_PYLON_GREEN] = CFMAINCRYSTAL_PYLON_ACTIVE_FRAMES;
            }
            if (state->pylonTimers[CFMAINCRYSTAL_PYLON_BLUE] != 0) {
                state->pylonTimers[CFMAINCRYSTAL_PYLON_BLUE] = CFMAINCRYSTAL_PYLON_ACTIVE_FRAMES;
            }
            state->chargeTimer = CFMAINCRYSTAL_FORCED_CHARGE_FRAMES;
        }
        pylonIndex = 0;
        do {
            if (pylonIndex <= CFMAINCRYSTAL_PYLON_BLUE && state->pylonTimers[pylonIndex] != 0) {
                CfMainCrystalBeam* beam = &state->beams[index++];
                beam->active = 1;
                beam->colorR = 0x7F;
                beam->colorG = 0x7F;
                beam->colorB = 0xFF;
                beam->startX = state->crystalX;
                beam->startY = CFMAINCRYSTAL_CRYSTAL_BEAM_Y_OFFSET + state->crystalY;
                beam->startZ = state->crystalZ;
                beamDirection[0] = state->pylonX[pylonIndex] - beam->startX;
                beamDirection[1] = (CFMAINCRYSTAL_PYLON_BEAM_Y_OFFSET + state->pylonY[pylonIndex]) - beam->startY;
                beamDirection[2] = state->pylonZ[pylonIndex] - beam->startZ;
                PSVECNormalize((Vec*)beamDirection, (Vec*)beamDirection);
                effectParams.posX = state->pylonX[pylonIndex] - state->crystalX;
                effectParams.posY = (CFMAINCRYSTAL_PYLON_BEAM_Y_OFFSET + state->pylonY[pylonIndex]) - state->crystalY;
                effectParams.posZ = state->pylonZ[pylonIndex] - state->crystalZ;
                beamDirection[0] = -beamDirection[0];
                beamDirection[1] = -beamDirection[1];
                beamDirection[2] = -beamDirection[2];
                effectParams.arg3 = pylonIndex;
                (*gPartfxInterface)->spawnObject(obj, CFMAINCRYSTAL_PARTFX_BEAM, &effectParams, 2, -1, beamDirection);
                beamDirection[0] = state->pylonX[pylonIndex] - gCfMainCrystalPositionObject->anim.localPosX;
                beamDirection[1] = CFMAINCRYSTAL_DOWNWARD_BEAM_Y;
                beamDirection[2] = state->pylonZ[pylonIndex] - gCfMainCrystalPositionObject->anim.localPosZ;
                PSVECNormalize((Vec*)beamDirection, (Vec*)beamDirection);
                effectParams.posX = 0.0f;
                effectParams.posY = CFMAINCRYSTAL_CRYSTAL_BEAM_Y_OFFSET;
                effectParams.posZ = 0.0f;
                effectParams.arg3 = pylonIndex + CFMAINCRYSTAL_PYLON_COUNT;
                (*gPartfxInterface)
                    ->spawnObject(gCfMainCrystalPositionObject, CFMAINCRYSTAL_PARTFX_BEAM, &effectParams, 2, -1,
                                  beamDirection);
                effectParams.posX = state->pylonX[pylonIndex];
                effectParams.posY = state->pylonY[pylonIndex];
                effectParams.posZ = state->pylonZ[pylonIndex];
                if (state->chimeTimers[CFMAINCRYSTAL_BEAM_CHIME_INDEX] > CFMAINCRYSTAL_BEAM_CHIME_PERIOD) {
                    effectParams.posX = state->pylonX[pylonIndex];
                    effectParams.posY = state->pylonY[pylonIndex];
                    effectParams.posZ = state->pylonZ[pylonIndex];
                    effectParams.arg2 = pylonIndex;
                }
                effectParams.posX = state->pylonX[pylonIndex];
                effectParams.posY = state->pylonY[pylonIndex];
                effectParams.posZ = state->pylonZ[pylonIndex];
                effectParams.arg2 = pylonIndex;
                beam = &state->beams[index++];
                beam->active = 1;
                activePylonCount++;
            }
            pylonIndex++;
        } while (pylonIndex < CFMAINCRYSTAL_PYLON_COUNT);
        if (state->pylonTimers[CFMAINCRYSTAL_PYLON_RED] + state->pylonTimers[CFMAINCRYSTAL_PYLON_GREEN] +
                    state->pylonTimers[CFMAINCRYSTAL_PYLON_BLUE] <
                CFMAINCRYSTAL_PARTIAL_CHARGE_TOTAL &&
            randomGetRange(0, CFMAINCRYSTAL_PYLON_COUNT) == 0) {
            (*gPartfxInterface)->spawnObject(obj, CFMAINCRYSTAL_PARTFX_CHARGE_SPARK, NULL, 0, -1, NULL);
        }
        if (state->pylonTimers[CFMAINCRYSTAL_PYLON_RED] != 0 || state->pylonTimers[CFMAINCRYSTAL_PYLON_GREEN] != 0 ||
            state->pylonTimers[CFMAINCRYSTAL_PYLON_BLUE] != 0) {
            if (state->chimeTimers[CFMAINCRYSTAL_PYLON_RED] > CFMAINCRYSTAL_PYLON_CHIME_PERIOD) {
                state->chimeTimers[CFMAINCRYSTAL_PYLON_RED] = 0;
            }
            if (state->chimeTimers[CFMAINCRYSTAL_PYLON_GREEN] > CFMAINCRYSTAL_PYLON_CHIME_PERIOD) {
                state->chimeTimers[CFMAINCRYSTAL_PYLON_GREEN] = 0;
            }
            if (state->chimeTimers[CFMAINCRYSTAL_PYLON_BLUE] > CFMAINCRYSTAL_PYLON_CHIME_PERIOD) {
                state->chimeTimers[CFMAINCRYSTAL_PYLON_BLUE] = 0;
            }
            if (state->chimeTimers[CFMAINCRYSTAL_BEAM_CHIME_INDEX] > CFMAINCRYSTAL_BEAM_CHIME_PERIOD) {
                state->chimeTimers[CFMAINCRYSTAL_BEAM_CHIME_INDEX] = 0;
            }
            state->chimeTimers[CFMAINCRYSTAL_PYLON_RED] += framesThisStep;
            state->chimeTimers[CFMAINCRYSTAL_PYLON_GREEN] += framesThisStep;
            state->chimeTimers[CFMAINCRYSTAL_PYLON_BLUE] += framesThisStep;
            state->chimeTimers[CFMAINCRYSTAL_BEAM_CHIME_INDEX] += framesThisStep;
        }
        if (activePylonCount == CFMAINCRYSTAL_PYLON_COUNT) {
            if (state->chargeTimer == 0) {
                Sfx_PlayFromObject(0, SFXTRIG_mpick1_b);
                getEnvfxAct(0, 0, CFMAINCRYSTAL_ENVFX, 0);
            }
            state->chargeTimer += framesThisStep;
        }
        if (state->chargeTimer >= CFMAINCRYSTAL_CHARGE_FIRE_FRAMES) {
            f32 chargeProgress = (f32)(state->chargeTimer - CFMAINCRYSTAL_CHARGE_FIRE_FRAMES);
            CfMainCrystalBeam* beam;
            chargeProgress /= CFMAINCRYSTAL_CHARGE_BEAM_FRAME_DIVISOR;
            beam = &state->beams[index];
            beam->active = 1;
            beam->colorR = 0;
            beam->colorG = 0;
            beam->colorB = 0;
            beam->startX = obj->anim.localPosX;
            beam->startY = CFMAINCRYSTAL_CHARGE_BEAM_Y_OFFSET + obj->anim.localPosY;
            beam->startZ = obj->anim.localPosZ;
            beam->endX = beam->startX;
            beam->endY = -(CFMAINCRYSTAL_CHARGE_BEAM_SPEED * chargeProgress - beam->startY);
            beam->endZ = beam->startZ;
        }
        obj->anim.rotX += framesThisStep * (activePylonCount * CFMAINCRYSTAL_PYLON_ROTATION_SPEED);
    }
    if (activePylonCount != 0) {
        if (Sfx_IsPlayingFromObjectChannel(obj, CFMAINCRYSTAL_HUM_CHANNEL) == 0) {
            Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_d5);
            state->humVolume = CFMAINCRYSTAL_HUM_INITIAL_VOLUME;
        } else {
            f32 targetVolume = CFMAINCRYSTAL_HUM_BASE_VOLUME + activePylonCount / CFMAINCRYSTAL_HUM_PYLON_DIVISOR;
            {
                f32 volumeDelta = targetVolume - state->humVolume;
                f32 approachRate = CFMAINCRYSTAL_HUM_APPROACH_RATE;
                state->humVolume = volumeDelta * approachRate + state->humVolume;
            }
            if (state->chargeTimer >= CFMAINCRYSTAL_CHARGE_FIRE_FRAMES) {
                state->humVolume = targetVolume;
            }
            Sfx_SetObjectChannelVolume(obj, CFMAINCRYSTAL_HUM_CHANNEL, CFMAINCRYSTAL_HUM_VOLUME, state->humVolume);
        }
    }
    pylonIndex = 0;
    do {
        index = state->pylonTimers[pylonIndex];
        if (index != 0 && index < CFMAINCRYSTAL_PYLON_TIMER_LIMIT) {
            state->pylonTimers[pylonIndex] += framesThisStep;
            if (index == 1 && state->pylonTimers[pylonIndex] > 1) {
                Sfx_PlayFromObject(obj, SFXTRIG_en_icecrk16_d6);
            }
            if (index < CFMAINCRYSTAL_PYLON_CHIME_DELAY &&
                state->pylonTimers[pylonIndex] >= CFMAINCRYSTAL_PYLON_CHIME_DELAY) {
                Sfx_PlayFromObject(obj, SFXTRIG_en_lflsh1_c);
            }
        }
        pylonIndex++;
    } while (pylonIndex < CFMAINCRYSTAL_PYLON_COUNT);
    obj->anim.rotX += framesThisStep * CFMAINCRYSTAL_IDLE_ROTATION_SPEED;
}

int cfMainCrystal_getExtraSize(void) {
    return sizeof(CfMainCrystalState);
}

int cfMainCrystal_getObjectTypeId(void) {
    return CFMAINCRYSTAL_OBJECT_TYPE_ID;
}

void cfMainCrystal_free(GameObject* obj) {
    (*gExpgfxInterface)->freeSource((u32)obj);
}

void cfMainCrystal_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    s32 isVisible = visible;
    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void cfMainCrystal_hitDetect(void) {
}

void cfMainCrystal_update(GameObject* obj) {
    u32 unusedMessageArgument;
    u32 message;
    u32 messageSender;
    s8 variant;
    variant = ((CfMainCrystalPlacement*)obj->anim.placement)->variant;
    switch (variant) {
    case CFMAINCRYSTAL_VARIANT_BEAM_CONTROLLER:
        cfMainCrystal_updateBeams(obj);
        break;
    case CFMAINCRYSTAL_VARIANT_POSITION_SOURCE:
        unusedMessageArgument = 0;
        while (ObjMsg_Pop(obj, &message, &messageSender, &unusedMessageArgument) != 0) {
            switch (message) {
            case CFMAINCRYSTAL_MESSAGE_POSITION:
                ObjMsg_SendToObject((GameObject*)messageSender, CFMAINCRYSTAL_MESSAGE_POSITION, obj, 0);
                break;
            }
        }
        gCfMainCrystalPositionObject = obj;
        obj->anim.rotX = (s16)(obj->anim.rotX + framesThisStep * CFMAINCRYSTAL_SOURCE_ROTATION_SPEED);
        break;
    }
}

void cfMainCrystal_init(GameObject* obj, CfMainCrystalPlacement* placement) {
    CfMainCrystalState* state = obj->extra;
    obj->anim.rotX = (s16)((s32)placement->initialYaw << 8);
    if (placement->variant == CFMAINCRYSTAL_VARIANT_BEAM_CONTROLLER) {
        state->chimeTimers[CFMAINCRYSTAL_PYLON_RED] = CFMAINCRYSTAL_INITIAL_RED_CHIME;
        state->chimeTimers[CFMAINCRYSTAL_PYLON_GREEN] = 0;
        state->chimeTimers[CFMAINCRYSTAL_PYLON_BLUE] = 0;
        state->chimeTimers[CFMAINCRYSTAL_BEAM_CHIME_INDEX] = CFMAINCRYSTAL_INITIAL_BEAM_CHIME;
        obj->anim.bankIndex = CFMAINCRYSTAL_RENDER_BANK_INDEX;
        state->unknown158 = 0;
    }
    ObjMsg_AllocQueue(obj, CFMAINCRYSTAL_MESSAGE_QUEUE_CAPACITY);
}

void cfMainCrystal_release(void) {
}

void cfMainCrystal_initialise(void) {
}

ObjectDescriptor gCFMainCrystalObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)cfMainCrystal_initialise,
    (ObjectDescriptorCallback)cfMainCrystal_release,
    0,
    (ObjectDescriptorCallback)cfMainCrystal_init,
    (ObjectDescriptorCallback)cfMainCrystal_update,
    (ObjectDescriptorCallback)cfMainCrystal_hitDetect,
    (ObjectDescriptorCallback)cfMainCrystal_render,
    (ObjectDescriptorCallback)cfMainCrystal_free,
    (ObjectDescriptorCallback)cfMainCrystal_getObjectTypeId,
    cfMainCrystal_getExtraSize,
};
