/* Moon seed bush and vine objects (DLL 0x17F). */

#include "dlls/objects/383.h"

#include "main/dll/partfx_interface.h"
#include "main/gamebits_api.h"
#include "main/objseq.h"
#include "main/object_render.h"

#define MOON_SEED_BUSH_ANIM_EVENT_PLANTED   1
#define MOON_SEED_BUSH_ANIM_EVENT_PARTICLES 2

#define MOON_SEED_BUSH_PRIMARY_PARTICLE_ID      0x70B
#define MOON_SEED_BUSH_SECONDARY_PARTICLE_ID    0x70C
#define MOON_SEED_BUSH_SECONDARY_PARTICLE_COUNT 0x28

#define MOON_SEED_BUSH_STATE_UNPLANTED 0
#define MOON_SEED_BUSH_STATE_PLANTED   1
#define MOON_SEED_BUSH_STATE_GROWN     2

#define MOON_SEED_BUSH_UPDATE_FLAG_RUN_SEQUENCE 1

int moonSeedBush_processAnimEvents(GameObject* obj, int unusedArg2, ObjSeqState* animUpdate) {
    MoonSeedBushState* state = obj->extra;
    const MoonSeedBushPlacement* placement = (const MoonSeedBushPlacement*)obj->anim.placementData;
    int eventIndex;
    int particleIndex;

    if (state->seedState == MOON_SEED_BUSH_STATE_UNPLANTED) {
        if (mainGetBit(placement->growthTriggerGameBit) != 0) {
            state->seedState = MOON_SEED_BUSH_STATE_GROWN;
        }
    }

    for (eventIndex = 0; eventIndex < animUpdate->eventCount; eventIndex++) {
        switch ((s32)animUpdate->eventIds[eventIndex]) {
        case MOON_SEED_BUSH_ANIM_EVENT_PLANTED:
            state->seedState = MOON_SEED_BUSH_STATE_PLANTED;
            if (placement->plantedGameBit != -1) {
                mainSetBits(placement->plantedGameBit, 1);
            }
            break;
        case MOON_SEED_BUSH_ANIM_EVENT_PARTICLES:
            (*gPartfxInterface)->spawnObject((void*)obj, MOON_SEED_BUSH_PRIMARY_PARTICLE_ID, NULL, 2, -1, NULL);
            for (particleIndex = 0; particleIndex < MOON_SEED_BUSH_SECONDARY_PARTICLE_COUNT; particleIndex++) {
                (*gPartfxInterface)->spawnObject((void*)obj, MOON_SEED_BUSH_SECONDARY_PARTICLE_ID, NULL, 2, -1, NULL);
            }
            break;
        }
    }

    return state->seedState != MOON_SEED_BUSH_STATE_GROWN;
}

int moonSeedBush_getExtraSize(void) {
    return sizeof(MoonSeedBushState);
}

int moonSeedBush_getObjectTypeId(void) {
    return 0;
}

void moonSeedBush_free(void) {
}

void moonSeedBush_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    s32 isVisible = visible;

    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void moonSeedBush_hitDetect(void) {
}

void moonSeedBush_update(GameObject* obj) {
    MoonSeedBushState* state = obj->extra;
    const MoonSeedBushPlacement* placement = (const MoonSeedBushPlacement*)obj->anim.placementData;
    int sequenceFlags;

    if ((state->updateFlags & MOON_SEED_BUSH_UPDATE_FLAG_RUN_SEQUENCE) == 0) {
        return;
    }
    if (placement->preemptTriggerId != 0 && state->seedState != MOON_SEED_BUSH_STATE_UNPLANTED) {
        sequenceFlags = placement->sequenceFlags;
        (*gObjectTriggerInterface)->preempt((int)obj, placement->preemptTriggerId);
    } else {
        sequenceFlags = -1;
    }
    {
        u8 sequence = placement->sequenceIndex;
        s32 sequenceIndex = (s8)sequence;

        if (sequenceIndex != -1) {
            (*gObjectTriggerInterface)->runSequence(sequenceIndex, (void*)obj, sequenceFlags);
        }
    }

    state->updateFlags &= ~MOON_SEED_BUSH_UPDATE_FLAG_RUN_SEQUENCE;
}

void moonSeedBush_init(GameObject* obj, const MoonSeedBushPlacement* placement) {
    MoonSeedBushState* state = obj->extra;

    state->updateFlags = MOON_SEED_BUSH_UPDATE_FLAG_RUN_SEQUENCE;
    obj->anim.rotX = (s16)(placement->rotXByte << 8);
    obj->animEventCallback = moonSeedBush_processAnimEvents;
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
    obj->anim.rootMotionScale = (f32)(u32)placement->scaleByte / 64.0f;
    if (!obj->anim.rootMotionScale) {
        obj->anim.rootMotionScale = 1.0f;
    }
    obj->anim.rootMotionScale *= obj->anim.modelInstance->rootMotionScaleBase;
    if (placement->plantedGameBit != -1) {
        state->seedState = mainGetBit(placement->plantedGameBit);
    } else {
        state->seedState = MOON_SEED_BUSH_STATE_UNPLANTED;
    }
}

void moonSeedBush_release(void) {
}

void moonSeedBush_initialise(void) {
}

ObjectDescriptor gMoonSeedBushObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)moonSeedBush_initialise,
    (ObjectDescriptorCallback)moonSeedBush_release,
    0,
    (ObjectDescriptorCallback)moonSeedBush_init,
    (ObjectDescriptorCallback)moonSeedBush_update,
    (ObjectDescriptorCallback)moonSeedBush_hitDetect,
    (ObjectDescriptorCallback)moonSeedBush_render,
    (ObjectDescriptorCallback)moonSeedBush_free,
    (ObjectDescriptorCallback)moonSeedBush_getObjectTypeId,
    moonSeedBush_getExtraSize,
};
