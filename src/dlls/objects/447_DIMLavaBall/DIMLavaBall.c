/*
 * DIMLavaBall (DLL 0x1BF) - DIM lava-ball cannon proxy; manages the spawned
 * 0x18D lava-ball sub-object, controls its fire period and game-bit gate,
 * and relaunches it on each fire cycle.
 */

#include "dlls/objects/447_DIMLavaBall.h"

#include "dlls/objects/446.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/object_render.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"

#define DIM_LAVA_BALL_RENDER_SCALE 1.0f

#define DIM_LAVA_BALL_PROJECTILE_SETUP_WORDS 9
#define DIM_LAVA_BALL_PROJECTILE_COLOR_RED   2
#define DIM_LAVA_BALL_PROJECTILE_COLOR_GREEN 4
#define DIM_LAVA_BALL_PROJECTILE_COLOR_BLUE  0xff
#define DIM_LAVA_BALL_PROJECTILE_COLOR_ALPHA 0x50
#define DIM_LAVA_BALL_PROJECTILE_SETUP_FLAGS 5

#define DIM_LAVA_BALL_FIRE_JITTER_MIN 0
#define DIM_LAVA_BALL_FIRE_JITTER_MAX 0x3c

void lavaball1bf_clearPending(GameObject* obj) {
    DimLavaBallState* state = obj->extra;

    if (state->pendingEnabled == 0) {
        return;
    }
    if (state->pending == 0) {
        return;
    }
    state->pending = 0;
}

int lavaball1bf_trySetPending(GameObject* obj) {
    DimLavaBallState* state;

    state = obj->extra;
    if (state->pendingEnabled == 0) {
        return 0;
    }
    if (state->pending == 0) {
        state->pending = 1;
        return 1;
    }
    return 0;
}

int lavaball1bf_getExtraSize(void) {
    return sizeof(DimLavaBallState);
}

int lavaball1bf_getObjectTypeId(void) {
    return 0x0;
}

void lavaball1bf_free(GameObject* obj, int mode) {
    DimLavaBallState* state = obj->extra;

    if (mode == 0 && state->projectile != NULL) {
        Obj_FreeObject(state->projectile);
    }
}

void lavaball1bf_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    s32 visibleValue = visible;

    if (visibleValue != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, DIM_LAVA_BALL_RENDER_SCALE);
    }
}

void lavaball1bf_hitDetect(void) {
}

void lavaball1bf_update(GameObject* obj) {
    const DimLavaBallPlacement* placement;
    DimLavaBallState* state;
    GameObject* projectile;
    f32 timer;

    state = obj->extra;
    placement = (const DimLavaBallPlacement*)obj->anim.placementData;
    state->fireEnabled = mainGetBit(placement->stateGameBit);
    if (state->awaitingTrigger != 0) {
        if (mainGetBit(placement->triggerGameBit) != 0) {
            state->fireEnabled = 1;
            state->awaitingTrigger = 0;
            state->fireTimer = 0.0f;
        } else {
            state->fireEnabled = 0;
        }
    }
    if (state->projectile == NULL && Obj_IsLoadingLocked() != 0) {
        DimLavaProjectilePlacement* projectilePlacement =
            (DimLavaProjectilePlacement*)Obj_AllocObjectSetup(sizeof(DimLavaProjectilePlacement),
                                                               DIM_LAVA_PROJECTILE_SEQUENCE_ID);

        projectilePlacement->base.size = DIM_LAVA_BALL_PROJECTILE_SETUP_WORDS;
        projectilePlacement->base.color[0] = DIM_LAVA_BALL_PROJECTILE_COLOR_RED;
        projectilePlacement->base.color[2] = DIM_LAVA_BALL_PROJECTILE_COLOR_BLUE;
        projectilePlacement->base.color[1] = DIM_LAVA_BALL_PROJECTILE_COLOR_GREEN;
        projectilePlacement->base.color[3] = DIM_LAVA_BALL_PROJECTILE_COLOR_ALPHA;
        projectilePlacement->base.posX = obj->anim.localPosX;
        projectilePlacement->base.posY = obj->anim.localPosY;
        projectilePlacement->base.posZ = obj->anim.localPosZ;
        projectilePlacement->launchYaw = placement->rotXByte;
        projectilePlacement->verticalSpeed = placement->verticalSpeed;
        projectilePlacement->horizontalSpeed = placement->horizontalSpeed;
        projectilePlacement->targetObjectId = placement->projectileTargetObjectId;
        state->projectile = objSetupObject(&projectilePlacement->base, DIM_LAVA_BALL_PROJECTILE_SETUP_FLAGS,
                                            obj->anim.mapEventSlot, -1, NULL);
    }
    projectile = state->projectile;
    timer = state->fireTimer - timeDelta;
    state->fireTimer = timer;
    if (timer <= 0.0f &&
        (s32)(*(DimLavaProjectileInterfaceVTable**)projectile->anim.dll)->isInactive(projectile) != 0) {
        if (state->fireEnabled != 0) {
            int verticalSpeed;

            if (mainGetBit(placement->triggerGameBit) != 0 && state->triggeredLaunchUsed == 0) {
                verticalSpeed = placement->triggeredVerticalSpeed;
                state->triggeredLaunchUsed = 1;
            } else {
                verticalSpeed = placement->verticalSpeed;
            }
            (*(DimLavaProjectileInterfaceVTable**)projectile->anim.dll)
                ->relaunch(projectile, verticalSpeed, placement->horizontalSpeed);
        }
        state->fireTimer =
            state->firePeriod + (f32)(int)randomGetRange(DIM_LAVA_BALL_FIRE_JITTER_MIN, DIM_LAVA_BALL_FIRE_JITTER_MAX);
    }
}

void lavaball1bf_init(GameObject* obj, const DimLavaBallPlacement* placement) {
    DimLavaBallState* state;

    obj->anim.rotX = (s16)((s32)placement->rotXByte << 8);
    state = obj->extra;
    state->firePeriod = placement->firePeriod;
    state->fireTimer = 0.0f;
    state->pendingEnabled = placement->pendingEnabled;
    state->triggeredLaunchUsed = mainGetBit(placement->triggeredLaunchGameBit);
    if (placement->stateGameBit == -1 && state->triggeredLaunchUsed == 0) {
        state->awaitingTrigger = 1;
    }
    obj->objectFlags |= (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED);
}

void lavaball1bf_release(void) {
}

void lavaball1bf_initialise(void) {
}

ObjectDescriptor12 gLavaBall1BFObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_12_SLOTS,
    (ObjectDescriptorCallback)lavaball1bf_initialise,
    (ObjectDescriptorCallback)lavaball1bf_release,
    0,
    (ObjectDescriptorCallback)lavaball1bf_init,
    (ObjectDescriptorCallback)lavaball1bf_update,
    (ObjectDescriptorCallback)lavaball1bf_hitDetect,
    (ObjectDescriptorCallback)lavaball1bf_render,
    (ObjectDescriptorCallback)lavaball1bf_free,
    (ObjectDescriptorCallback)lavaball1bf_getObjectTypeId,
    lavaball1bf_getExtraSize,
    (ObjectDescriptorCallback)lavaball1bf_trySetPending,
    (ObjectDescriptorCallback)lavaball1bf_clearPending,
};
