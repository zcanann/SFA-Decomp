/*
 * Proximity particle emitter family with placement-controlled volume,
 * effect type, emission cadence, rotation, and game-bit gates.
 */
#include "dlls/objects/304_AreaFXEmit.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/dll/partfx_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/resource.h"
#include "sys/objects.h"
#include "main/vecmath.h"
#include "main/objseq.h"

#define AREAFXEMIT_GAME_BIT_NONE -1

#define AREAFXEMIT_EXTENT_SHIFT   2
#define AREAFXEMIT_ROTATION_SHIFT 8

#define AREAFXEMIT_EFFECT_SCALE      1.0f
#define AREAFXEMIT_ROOT_MOTION_SCALE 0.1f

#define AREAFXEMIT_RESOURCE_OFFSET     0x58
#define AREAFXEMIT_ALT_RESOURCE_OFFSET 0xAB
#define AREAFXEMIT_RESOURCE_GROUP      1

#define AREAFXEMIT_WORLD_SPAWN_MODE 0x200001
#define AREAFXEMIT_LOCAL_SPAWN_MODE 2
#define AREAFXEMIT_MODEL_NONE       -1

#define AREAFXEMIT_APPROACH_BURST_COUNT 0x23

typedef enum AreaFXEmitSpawnType {
    AREAFXEMIT_SPAWN_LOCAL_WORLD = 0,
    AREAFXEMIT_SPAWN_OBJECT_RESOURCE = 1,
    AREAFXEMIT_SPAWN_OBJECT_RESOURCE_ALT = 2,
    AREAFXEMIT_SPAWN_LOCAL_OBJECT = 3,
} AreaFXEmitSpawnType;

typedef enum AreaFXEmitSequenceEvent {
    AREAFXEMIT_SEQUENCE_EVENT_EMIT = 1,
} AreaFXEmitSequenceEvent;

#define AREAFXEMIT_RANDOMIZE_OFFSET(state, position)                                                                   \
    do {                                                                                                               \
        u16 range;                                                                                                     \
        range = (state)->extentX;                                                                                      \
        (position)[0] = (f32)(s32)randomGetRange(-range, range);                                                       \
        range = (state)->extentY;                                                                                      \
        (position)[1] = (f32)(s32)randomGetRange(-range, range);                                                       \
        range = (state)->extentZ;                                                                                      \
        (position)[2] = (f32)(s32)randomGetRange(-range, range);                                                       \
    } while (0)

#define AREAFXEMIT_ROTATE_FROM_LOCAL(obj, state, position, rotation)                                                   \
    do {                                                                                                               \
        (rotation)[0] = (state)->emitAngles[0];                                                                        \
        (rotation)[1] = (state)->emitAngles[1];                                                                        \
        (rotation)[2] = (state)->emitAngles[2];                                                                        \
        if ((obj)->anim.parent != NULL) {                                                                              \
            (rotation)[2] += ((ObjAnimComponent*)(obj)->anim.parent)->rotZ;                                            \
        }                                                                                                              \
        vecRotateZXY((rotation), (position));                                                                          \
    } while (0)

#define AREAFXEMIT_ADD_OBJECT_POSITION(obj, position)                                                                  \
    do {                                                                                                               \
        (position)[0] += (obj)->anim.localPosX;                                                                        \
        (position)[1] += (obj)->anim.localPosY;                                                                        \
        (position)[2] += (obj)->anim.localPosZ;                                                                        \
    } while (0)

void AreaFXEmit_emitBurst(GameObject* obj, int count) {
    AreaFXEmitState* state;
    s16 i;
    PartFxSpawnParams args;

    state = obj->extra;
    if (count > 0) {
        for (i = 0; i < count; i++) {
            {
                u16 sx = state->extentX;
                args.posX = (f32)(s32)randomGetRange(-sx, sx);
            }
            {
                u16 sy = state->extentY;
                args.posY = (f32)(s32)randomGetRange(-sy, sy);
            }
            {
                u16 sz = state->extentZ;
                args.posZ = (f32)(s32)randomGetRange(-sz, sz);
            }
            vecRotateZXY(state->emitAngles, &args.posX);
            {
                u8 type = state->emitType;
                if (type == 4 || type == 6) {
                    args.posX += obj->anim.localPosX;
                    args.posY += obj->anim.localPosY;
                    args.posZ += obj->anim.localPosZ;
                    (*gPartfxInterface)
                        ->spawnObject(obj, state->effectId, &args, AREAFXEMIT_WORLD_SPAWN_MODE, AREAFXEMIT_MODEL_NONE,
                                      NULL);
                } else {
                    (*gPartfxInterface)
                        ->spawnObject(obj, state->effectId, &args, AREAFXEMIT_LOCAL_SPAWN_MODE, AREAFXEMIT_MODEL_NONE,
                                      NULL);
                }
            }
        }
    }
}

void AreaFXEmit_emitEffect(GameObject* obj) {
    AreaFXEmitState* state;
    s16 i;
    s16 rotation[3];
    u8 type;
    ObjectInterfaceHandle resource;
    PartFxSpawnParams args;

    state = obj->extra;
    args.scale = AREAFXEMIT_EFFECT_SCALE;
    type = state->emitType;

    if (type == AREAFXEMIT_SPAWN_LOCAL_WORLD) {
        if (state->emitCount > 0) {
            for (i = 0; i < state->emitCount; i++) {
                AREAFXEMIT_RANDOMIZE_OFFSET(state, &args.posX);
                AREAFXEMIT_ROTATE_FROM_LOCAL(obj, state, &args.posX, rotation);
                AREAFXEMIT_ADD_OBJECT_POSITION(obj, &args.posX);
                (*gPartfxInterface)
                    ->spawnObject(obj, state->effectId, &args, AREAFXEMIT_WORLD_SPAWN_MODE, AREAFXEMIT_MODEL_NONE,
                                  NULL);
            }
        } else {
            AREAFXEMIT_RANDOMIZE_OFFSET(state, &args.posX);
            AREAFXEMIT_ROTATE_FROM_LOCAL(obj, state, &args.posX, rotation);
            AREAFXEMIT_ADD_OBJECT_POSITION(obj, &args.posX);
            (*gPartfxInterface)
                ->spawnObject(obj, state->effectId, &args, AREAFXEMIT_WORLD_SPAWN_MODE, AREAFXEMIT_MODEL_NONE, NULL);
        }
    } else if (type == AREAFXEMIT_SPAWN_OBJECT_RESOURCE) {
        resource = Resource_Acquire((state->effectId + AREAFXEMIT_RESOURCE_OFFSET), AREAFXEMIT_RESOURCE_GROUP);
        if (state->emitCount > 0) {
            for (i = 0; i < state->emitCount; i++) {
                (*(void (**)(GameObject*, int, int, int, int, int))(*(int*)resource + 4))(obj, 0, 0, 1, -1, 0);
            }
        } else {
            (*(void (**)(GameObject*, int, int, int, int, int))(*(int*)resource + 4))(obj, 0, 0, 1, -1, 0);
        }
        Resource_Release(resource);
    } else if (type == AREAFXEMIT_SPAWN_OBJECT_RESOURCE_ALT) {
        resource = Resource_Acquire((state->effectId + AREAFXEMIT_ALT_RESOURCE_OFFSET), AREAFXEMIT_RESOURCE_GROUP);
        if (state->emitCount > 0) {
            for (i = 0; i < state->emitCount; i++) {
                (*(void (**)(GameObject*, int, int, int, int, int, int))(*(int*)resource + 4))(
                    obj, 0, 0, 1, -1, state->effectId & 0xFF, 0);
            }
        } else {
            (*(void (**)(GameObject*, int, int, int, int, int, int))(*(int*)resource + 4))(obj, 0, 0, 1, -1,
                                                                                           state->effectId & 0xFF, 0);
        }
        Resource_Release(resource);
    } else if (type == AREAFXEMIT_SPAWN_LOCAL_OBJECT) {
        if (state->emitCount > 0) {
            for (i = 0; i < state->emitCount; i++) {
                AREAFXEMIT_RANDOMIZE_OFFSET(state, &args.posX);
                AREAFXEMIT_ROTATE_FROM_LOCAL(obj, state, &args.posX, rotation);
                (*gPartfxInterface)
                    ->spawnObject(obj, state->effectId, &args, AREAFXEMIT_LOCAL_SPAWN_MODE, AREAFXEMIT_MODEL_NONE,
                                  NULL);
            }
        } else {
            AREAFXEMIT_RANDOMIZE_OFFSET(state, &args.posX);
            AREAFXEMIT_ROTATE_FROM_LOCAL(obj, state, &args.posX, rotation);
            (*gPartfxInterface)
                ->spawnObject(obj, state->effectId, &args, AREAFXEMIT_LOCAL_SPAWN_MODE, AREAFXEMIT_MODEL_NONE, NULL);
        }
    } else if (type >= 6) {
        if (state->emitCount > 0) {
            for (i = 0; i < state->emitCount; i++) {
                AREAFXEMIT_RANDOMIZE_OFFSET(state, &args.posX);
                vecRotateZXY(state->emitAngles, &args.posX);
                if (state->emitType == 6) {
                    AREAFXEMIT_ADD_OBJECT_POSITION(obj, &args.posX);
                    (*gPartfxInterface)
                        ->spawnObject(obj, state->effectId, &args, AREAFXEMIT_WORLD_SPAWN_MODE, AREAFXEMIT_MODEL_NONE,
                                      NULL);
                } else {
                    (*gPartfxInterface)
                        ->spawnObject(obj, state->effectId, &args, AREAFXEMIT_LOCAL_SPAWN_MODE, AREAFXEMIT_MODEL_NONE,
                                      NULL);
                }
            }
        } else {
            AREAFXEMIT_RANDOMIZE_OFFSET(state, &args.posX);
            vecRotateZXY(state->emitAngles, &args.posX);
            if (state->emitType == 6) {
                AREAFXEMIT_ADD_OBJECT_POSITION(obj, &args.posX);
                (*gPartfxInterface)
                    ->spawnObject(obj, state->effectId, &args, AREAFXEMIT_WORLD_SPAWN_MODE, AREAFXEMIT_MODEL_NONE,
                                  NULL);
            } else {
                (*gPartfxInterface)
                    ->spawnObject(obj, state->effectId, &args, AREAFXEMIT_LOCAL_SPAWN_MODE, AREAFXEMIT_MODEL_NONE,
                                  NULL);
            }
        }
    }
}

int AreaFXEmit_sequenceCallback(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    u8 i;
    for (i = 0; i < animUpdate->eventCount; i++) {
        switch ((s32)animUpdate->eventIds[i]) {
        case AREAFXEMIT_SEQUENCE_EVENT_EMIT:
            AreaFXEmit_emitEffect(obj);
            break;
        }
    }
    return 0;
}

int AreaFXEmit_getExtraSize(void) {
    return sizeof(AreaFXEmitState);
}

int AreaFXEmit_getObjectTypeId(void) {
    return 0;
}

void AreaFXEmit_free(GameObject* obj) {
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void AreaFXEmit_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    if (visible == 0) {
        return;
    }
}

void AreaFXEmit_hitDetect(void) {
}

void AreaFXEmit_update(GameObject* obj) {
    AreaFXEmitState* state;
    ObjAnimComponent* player;
    f32 xDelta;
    f32 yDelta;
    f32 zDelta;
    f32 ySquared;
    f32 distance;
    f32 radius;

    state = obj->extra;
    player = (ObjAnimComponent*)Obj_GetPlayerObject();
    if ((player != NULL) &&
        ((state->enableGameBit == AREAFXEMIT_GAME_BIT_NONE) || (mainGetBit(state->enableGameBit) != 0))) {
        switch (state->suppressed) {
        case 0:
            if (mainGetBit(state->stopGameBit) != 0) {
                state->suppressed = 1;
            }
            if ((state->emitCount >= 0) || ((state->emitCount < 0) && (obj->userData1 <= 0))) {
                xDelta = obj->anim.worldPosX - player->worldPosX;
                yDelta = obj->anim.worldPosY - player->worldPosY;
                zDelta = obj->anim.worldPosZ - player->worldPosZ;
                if (state->emitCount == 0) {
                    state->suppressed = 1;
                }
                ySquared = yDelta * yDelta;
                distance = sqrtf(ySquared + xDelta * xDelta + zDelta * zDelta);
                radius = state->triggerRadius;
                if (distance <= radius || radius == 0.0f) {
                    if ((state->emitType >= 4) && ((state->lastDistance > radius && (radius != 0.0f)))) {
                        AreaFXEmit_emitBurst(obj, AREAFXEMIT_APPROACH_BURST_COUNT);
                    }
                    AreaFXEmit_emitEffect(obj);
                }
                obj->userData1 = -state->emitCount;
                state->lastDistance = distance;
            } else if ((state->emitCount < 0) && (obj->userData1 > 0)) {
                obj->userData1 = obj->userData1 - framesThisStep;
            }
            break;
        }
    }
}

void AreaFXEmit_init(GameObject* obj, AreaFXEmitPlacement* placement) {
    AreaFXEmitState* state;
    s16 angle;

    obj->animEventCallback = AreaFXEmit_sequenceCallback;
    state = obj->extra;

    state->triggerRadius = (f32)((s32)placement->triggerRadius << AREAFXEMIT_EXTENT_SHIFT);
    state->emitType = placement->emitType;
    state->effectId = placement->effectId;
    state->emitCount = placement->emitCount;
    state->enableGameBit = placement->enableGameBit;
    state->stopGameBit = placement->stopGameBit;
    state->suppressed = 0;
    state->extentX = (u16)(placement->extentX << AREAFXEMIT_EXTENT_SHIFT);
    state->extentZ = (u16)(placement->extentZ << AREAFXEMIT_EXTENT_SHIFT);
    state->extentY = (u16)(placement->extentY << AREAFXEMIT_EXTENT_SHIFT);

    angle = (s16)(placement->initialRotZ << AREAFXEMIT_ROTATION_SHIFT);
    state->emitAngles[2] = angle;
    obj->anim.rotZ = angle;
    angle = (s16)(placement->initialRotY << AREAFXEMIT_ROTATION_SHIFT);
    state->emitAngles[1] = angle;
    obj->anim.rotY = angle;
    angle = (s16)(placement->initialRotX << AREAFXEMIT_ROTATION_SHIFT);
    state->emitAngles[0] = angle;
    obj->anim.rotX = angle;
    obj->anim.rootMotionScale = AREAFXEMIT_ROOT_MOTION_SCALE;

    if (state->emitCount < 1) {
        obj->userData1 = state->emitCount;
    } else {
        obj->userData1 = 0;
    }

    if (state->stopGameBit != AREAFXEMIT_GAME_BIT_NONE && mainGetBit(state->stopGameBit) != 0) {
        state->suppressed = 1;
    }
}

void AreaFXEmit_release(void) {
}

void AreaFXEmit_initialise(void) {
}

ObjectDescriptor gAreaFXEmitObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)AreaFXEmit_initialise,
    (ObjectDescriptorCallback)AreaFXEmit_release,
    0,
    (ObjectDescriptorCallback)AreaFXEmit_init,
    (ObjectDescriptorCallback)AreaFXEmit_update,
    (ObjectDescriptorCallback)AreaFXEmit_hitDetect,
    (ObjectDescriptorCallback)AreaFXEmit_render,
    (ObjectDescriptorCallback)AreaFXEmit_free,
    (ObjectDescriptorCallback)AreaFXEmit_getObjectTypeId,
    AreaFXEmit_getExtraSize,
};
