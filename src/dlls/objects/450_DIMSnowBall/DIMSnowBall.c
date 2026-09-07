/*
 * DIMSnowBall (DLL 0x1C2) - timed snowball spawner for Dinosaur Island
 * Mission.  On each timer expiry, if loading is not locked and the player
 * is clear, allocates a 36-byte setup for rolling-snowball sequence 0x196,
 * seeds it from the placement params, and resets the spawn countdown.
 */

#include "dlls/objects/450_DIMSnowBall.h"

#include "dlls/objects/449_DIMSnowBall.h"
#include "main/dll/player_api.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"

#define DIM_SNOWBALL_SPAWNER_SETUP_FLAGS 5

#define DIM_SNOWBALL_SPAWNER_RENDER_SCALE 1.0f

#define DIM_SNOWBALL_SPAWNER_RANDOM_MIN     0
#define DIM_SNOWBALL_SPAWNER_RANDOM_MAX     100
#define DIM_SNOWBALL_SPAWNER_RANDOM_DIVISOR 100.0f

int dimsnowball1c2_getExtraSize(void) {
    return sizeof(DimSnowBallSpawnerState);
}

int dimsnowball1c2_getObjectTypeId(void) {
    return 0x0;
}

void dimsnowball1c2_free(void) {
}

void dimsnowball1c2_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                           s8 visible) {
    s32 visibleValue = visible;

    if (visibleValue != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5,
                                    DIM_SNOWBALL_SPAWNER_RENDER_SCALE);
    }
}

void dimsnowball1c2_hitDetect(void) {
}

void dimsnowball1c2_update(GameObject* obj) {
    if ((u8)Obj_CanSetupObject()) {
        DimSnowBallSpawnerState* state = obj->extra;

        if ((state->spawnCountdown -= framesThisStep) <= 0) {
            if (playerGetFocusObject(Obj_GetPlayerObject()) == NULL) {
                DimSnowBallPlacement* setup;
                const DimSnowBallSpawnerPlacement* placement;

                placement = (const DimSnowBallSpawnerPlacement*)obj->anim.placementData;
                setup =
                    (DimSnowBallPlacement*)Obj_AllocObjectSetup(sizeof(DimSnowBallPlacement), DIM_SNOWBALL_SEQUENCE_ID);
                setup->base.color[0] = placement->base.color[0];
                setup->base.color[2] = placement->base.color[2];
                setup->base.color[1] = placement->base.color[1];
                setup->base.color[3] = placement->base.color[3];
                setup->base.posX = obj->anim.localPosX;
                setup->base.posY = obj->anim.localPosY;
                setup->base.posZ = obj->anim.localPosZ;
                setup->targetObjectId = placement->base.ident;
                {
                    int childRotationX = placement->childRotationXByte;

                    setup->rotationXByte = childRotationX;
                }
                setup->rotationParam1A = placement->childRotationParam1A;
                setup->rotationParam1C =
                    (f32)(u32)placement->childRotationParam1CBase +
                    randomGetRange(DIM_SNOWBALL_SPAWNER_RANDOM_MIN, DIM_SNOWBALL_SPAWNER_RANDOM_MAX) /
                        DIM_SNOWBALL_SPAWNER_RANDOM_DIVISOR;
                objSetupObject(&setup->base, DIM_SNOWBALL_SPAWNER_SETUP_FLAGS, obj->anim.mapEventSlot, -1, 0);
                state->spawnCountdown = state->spawnPeriod;
            }
        }
    }
}

void dimsnowball1c2_init(GameObject* obj, DimSnowBallSpawnerPlacement* placement) {
    DimSnowBallSpawnerState* state;

    obj->anim.rotX = (s16)((u32)placement->parentRotationXByte << 8);
    state = obj->extra;
    state->spawnPeriod = placement->spawnPeriod;
    state->spawnCountdown = placement->spawnPeriod;
    obj->objectFlags |= (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED);
}

void dimsnowball1c2_release(void) {
}

void dimsnowball1c2_initialise(void) {
}

ObjectDescriptor gDIMSnowBall1C2ObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dimsnowball1c2_initialise,
    (ObjectDescriptorCallback)dimsnowball1c2_release,
    0,
    (ObjectDescriptorCallback)dimsnowball1c2_init,
    (ObjectDescriptorCallback)dimsnowball1c2_update,
    (ObjectDescriptorCallback)dimsnowball1c2_hitDetect,
    (ObjectDescriptorCallback)dimsnowball1c2_render,
    (ObjectDescriptorCallback)dimsnowball1c2_free,
    (ObjectDescriptorCallback)dimsnowball1c2_getObjectTypeId,
    dimsnowball1c2_getExtraSize,
};
