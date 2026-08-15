/*
 * DIM2Conveyo (DLL 0x1D5) - DIM 2 conveyor belt object.
 * Supplies a placement-oriented scroll vector to objects standing on its
 * conveyor surface. One map variant can periodically reverse that vector.
 */
#include "dlls/objects/469_DIM2Conveyo.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "main/audio/music_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/object_render.h"
#include "main/objtype.h"

#define DIM2CONVEYOR_OBJECT_GROUP                   0x16
#define DIM2CONVEYOR_GAMEBIT_NEGATIVE_DIRECTION     3163
#define DIM2CONVEYOR_GAMEBIT_POSITIVE_DIRECTION     3164
#define DIM2CONVEYOR_GAMEBIT_DIRECTION_SWAP_ENABLED 3169
#define DIM2CONVEYOR_SINGLE_DIRECTION_MAP_ID        7849
#define DIM2CONVEYOR_DUAL_DIRECTION_MAP_ID          0x49B23
#define DIM2CONVEYOR_MUSIC_TRACK_ID                 0xDF

void dim2conveyor_getScrollVector(GameObject* obj, GameObject* caller, f32 unused, f32* outX, f32* outZ) {
    Dim2ConveyorState* state = obj->extra;
    s32 ident;

    if (state->musicHoldTimer == 0) {
        Music_Trigger(DIM2CONVEYOR_MUSIC_TRACK_ID, 1);
    }
    state->musicHoldTimer = 20;
    ident = ((const Dim2ConveyorPlacement*)obj->anim.placementData)->base.ident;
    switch (ident) {
    case DIM2CONVEYOR_SINGLE_DIRECTION_MAP_ID:
        *outX = state->scrollX;
        *outZ = state->scrollZ;
        break;
    case DIM2CONVEYOR_DUAL_DIRECTION_MAP_ID:
        if (mainGetBit(DIM2CONVEYOR_GAMEBIT_POSITIVE_DIRECTION) != 0 &&
            mainGetBit(DIM2CONVEYOR_GAMEBIT_NEGATIVE_DIRECTION) == 0) {
            *outX = state->scrollX;
            *outZ = state->scrollZ;
        }
        if (mainGetBit(DIM2CONVEYOR_GAMEBIT_NEGATIVE_DIRECTION) != 0 &&
            mainGetBit(DIM2CONVEYOR_GAMEBIT_POSITIVE_DIRECTION) == 0) {
            *outX = -state->scrollX;
            *outZ = -state->scrollZ;
        }
        if (mainGetBit(DIM2CONVEYOR_GAMEBIT_NEGATIVE_DIRECTION) != 0) {
            mainSetBits(DIM2CONVEYOR_GAMEBIT_POSITIVE_DIRECTION, 0);
        }
        if (mainGetBit(DIM2CONVEYOR_GAMEBIT_NEGATIVE_DIRECTION) == 0) {
            mainSetBits(DIM2CONVEYOR_GAMEBIT_POSITIVE_DIRECTION, 1);
        }
        break;
    default:
        *outX = state->scrollX;
        *outZ = state->scrollZ;
        break;
    }
}

int dim2conveyor_getExtraSize(void) {
    return sizeof(Dim2ConveyorState);
}

int dim2conveyor_getObjectTypeId(void) {
    return 0;
}

void dim2conveyor_free(GameObject* obj) {
    objFreeObjectType(obj, DIM2CONVEYOR_OBJECT_GROUP);
}

void dim2conveyor_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    s32 isVisible = visible;

    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void dim2conveyor_hitDetect(void) {
}

void dim2conveyor_update(GameObject* obj) {
    Dim2ConveyorState* state = obj->extra;

    Sfx_PlayFromObject(obj, SFXTRIG_mv_liftloop);
    if (state->musicHoldTimer != 0) {
        state->musicHoldTimer = state->musicHoldTimer - 1;
        if (state->musicHoldTimer == 0) {
            Music_Trigger(DIM2CONVEYOR_MUSIC_TRACK_ID, 0);
        }
    }
    switch (((const Dim2ConveyorPlacement*)obj->anim.placementData)->base.ident) {
    case DIM2CONVEYOR_DUAL_DIRECTION_MAP_ID:
        if (mainGetBit(DIM2CONVEYOR_GAMEBIT_DIRECTION_SWAP_ENABLED) != 0) {
            state->directionSwapTimer = state->directionSwapTimer + timeDelta;
            if (state->directionSwapTimer > 100.0f) {
                if (mainGetBit(DIM2CONVEYOR_GAMEBIT_NEGATIVE_DIRECTION) != 0) {
                    mainSetBits(DIM2CONVEYOR_GAMEBIT_POSITIVE_DIRECTION, 1);
                    mainSetBits(DIM2CONVEYOR_GAMEBIT_NEGATIVE_DIRECTION, 0);
                } else if (mainGetBit(DIM2CONVEYOR_GAMEBIT_POSITIVE_DIRECTION) != 0) {
                    mainSetBits(DIM2CONVEYOR_GAMEBIT_POSITIVE_DIRECTION, 0);
                    mainSetBits(DIM2CONVEYOR_GAMEBIT_NEGATIVE_DIRECTION, 1);
                }
                state->directionSwapTimer = 0.0f;
            }
        }
        if (mainGetBit(DIM2CONVEYOR_GAMEBIT_NEGATIVE_DIRECTION) != 0) {
            mainSetBits(DIM2CONVEYOR_GAMEBIT_POSITIVE_DIRECTION, 0);
        }
        if (mainGetBit(DIM2CONVEYOR_GAMEBIT_NEGATIVE_DIRECTION) == 0) {
            mainSetBits(DIM2CONVEYOR_GAMEBIT_POSITIVE_DIRECTION, 1);
        }
        break;
    case DIM2CONVEYOR_SINGLE_DIRECTION_MAP_ID:
        break;
    }
}

void dim2conveyor_init(GameObject* obj, const Dim2ConveyorPlacement* placement) {
    f32 scale = (f32)placement->scrollSpeed / 5.0f;
    Dim2ConveyorState* state;

    obj->anim.rotX = (s16)(placement->rotationXByte << 8);
    state = obj->extra;
    state->scrollX = scale * mathSinf(3.1415927f * (f32)obj->anim.rotX / 32768.0f);
    state->scrollZ = scale * mathCosf(3.1415927f * (f32)obj->anim.rotX / 32768.0f);
    state->directionSwapTimer = 0.0f;
    state->musicHoldTimer = 0;
    objAddObjectType(obj, DIM2CONVEYOR_OBJECT_GROUP);
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
    if (placement->base.ident == DIM2CONVEYOR_DUAL_DIRECTION_MAP_ID) {
        mainSetBits(DIM2CONVEYOR_GAMEBIT_POSITIVE_DIRECTION, 1);
    }
}

void dim2conveyor_release(void) {
}

void dim2conveyor_initialise(void) {
}

ObjectDescriptor11WithPadding gDIM2ConveyorObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
        (ObjectDescriptorCallback)dim2conveyor_initialise,
        (ObjectDescriptorCallback)dim2conveyor_release,
        0,
        (ObjectDescriptorCallback)dim2conveyor_init,
        (ObjectDescriptorCallback)dim2conveyor_update,
        (ObjectDescriptorCallback)dim2conveyor_hitDetect,
        (ObjectDescriptorCallback)dim2conveyor_render,
        (ObjectDescriptorCallback)dim2conveyor_free,
        (ObjectDescriptorCallback)dim2conveyor_getObjectTypeId,
        dim2conveyor_getExtraSize,
        (ObjectDescriptorCallback)dim2conveyor_getScrollVector,
    },
    0,
};
