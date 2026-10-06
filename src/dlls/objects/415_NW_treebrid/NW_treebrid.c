/*
 * NW_treebrid (DLL 0x19F).
 *
 * Moves a nearby group-4 object to path point zero and starts the placement's
 * sequence when its game bit is set. Animation events emit particle bursts.
 */
#include "dlls/objects/415_NW_treebrid.h"

#include "main/dll/partfx_interface.h"
#include "main/gamebits_api.h"
#include "main/obj_path.h"
#include "main/object_render.h"
#include "main/objseq.h"
#include "main/objtype.h"

#define NW_TREE_BRIDGE_TARGET_OBJECT_GROUP           4
#define NW_TREE_BRIDGE_PATH_INDEX                    0
#define NW_TREE_BRIDGE_TARGET_SEARCH_DISTANCE        100.0f
#define NW_TREE_BRIDGE_TARGET_SEARCH_ATTEMPTS        4
#define NW_TREE_BRIDGE_RENDER_SCALE                  1.0f
#define NW_TREE_BRIDGE_PREEMPT_SEQUENCE_ID           0x154
#define NW_TREE_BRIDGE_PREEMPT_SEQUENCE_FLAGS        1
#define NW_TREE_BRIDGE_GAMEBIT_SEQUENCE_FLAGS        (-1)
#define NW_TREE_BRIDGE_SPECIAL_OBJECT_SEQUENCE_ID    0x5D
#define NW_TREE_BRIDGE_SEQUENCE_ID_0                 0
#define NW_TREE_BRIDGE_SEQUENCE_ID_1                 1
#define NW_TREE_BRIDGE_EVENT_LARGE_BURST             1
#define NW_TREE_BRIDGE_EVENT_MEDIUM_BURST            2
#define NW_TREE_BRIDGE_EVENT_SMALL_BURST             3
#define NW_TREE_BRIDGE_LARGE_BURST_PARTICLE_ID       0xCC
#define NW_TREE_BRIDGE_MEDIUM_SEQUENCE_0_PARTICLE_ID 0xCD
#define NW_TREE_BRIDGE_SMALL_SEQUENCE_0_PARTICLE_ID  0xCE
#define NW_TREE_BRIDGE_MEDIUM_SEQUENCE_1_PARTICLE_ID 0xCF
#define NW_TREE_BRIDGE_SMALL_SEQUENCE_1_PARTICLE_ID  0xD0
#define NW_TREE_BRIDGE_MEDIUM_SPECIAL_PARTICLE_ID    0xD3
#define NW_TREE_BRIDGE_SMALL_SPECIAL_PARTICLE_ID     0xD4
#define NW_TREE_BRIDGE_PARTICLE_MODE                 1
#define NW_TREE_BRIDGE_LARGE_BURST_COUNT             200
#define NW_TREE_BRIDGE_MEDIUM_BURST_COUNT            100
#define NW_TREE_BRIDGE_SMALL_BURST_COUNT             5

int nwTreeBridge_processAnimEvents(GameObject* obj, int unusedArg, ObjSeqState* animUpdate) {
    NwTreeBridgeState* state;
    int eventIndex;
    int particlesRemaining;
    u8 eventId;

    (void)unusedArg;
    state = obj->extra;
    eventIndex = 0;
    while (eventIndex < animUpdate->eventCount) {
        eventId = animUpdate->eventIds[eventIndex];
        switch (eventId) {
        case NW_TREE_BRIDGE_EVENT_LARGE_BURST:
            particlesRemaining = NW_TREE_BRIDGE_LARGE_BURST_COUNT;
            do {
                (*gPartfxInterface)
                    ->spawnEffect(obj, NW_TREE_BRIDGE_LARGE_BURST_PARTICLE_ID, NULL, NW_TREE_BRIDGE_PARTICLE_MODE, -1,
                                  NULL);
                particlesRemaining--;
            } while (particlesRemaining != 0);
            break;
        case NW_TREE_BRIDGE_EVENT_MEDIUM_BURST:
            particlesRemaining = NW_TREE_BRIDGE_MEDIUM_BURST_COUNT;
            if (obj->anim.romDefNo == NW_TREE_BRIDGE_SPECIAL_OBJECT_SEQUENCE_ID) {
                do {
                    (*gPartfxInterface)
                        ->spawnEffect(obj, NW_TREE_BRIDGE_MEDIUM_SPECIAL_PARTICLE_ID, NULL,
                                      NW_TREE_BRIDGE_PARTICLE_MODE, -1, NULL);
                    particlesRemaining--;
                } while (particlesRemaining != 0);
            } else if (state->sequenceId == NW_TREE_BRIDGE_SEQUENCE_ID_0) {
                do {
                    (*gPartfxInterface)
                        ->spawnEffect(obj, NW_TREE_BRIDGE_MEDIUM_SEQUENCE_0_PARTICLE_ID, NULL,
                                      NW_TREE_BRIDGE_PARTICLE_MODE, -1, NULL);
                    particlesRemaining--;
                } while (particlesRemaining != 0);
            } else if (state->sequenceId == NW_TREE_BRIDGE_SEQUENCE_ID_1) {
                do {
                    (*gPartfxInterface)
                        ->spawnEffect(obj, NW_TREE_BRIDGE_MEDIUM_SEQUENCE_1_PARTICLE_ID, NULL,
                                      NW_TREE_BRIDGE_PARTICLE_MODE, -1, NULL);
                    particlesRemaining--;
                } while (particlesRemaining != 0);
            }
            break;
        case NW_TREE_BRIDGE_EVENT_SMALL_BURST:
            particlesRemaining = NW_TREE_BRIDGE_SMALL_BURST_COUNT;
            if (obj->anim.romDefNo == NW_TREE_BRIDGE_SPECIAL_OBJECT_SEQUENCE_ID) {
                do {
                    (*gPartfxInterface)
                        ->spawnEffect(obj, NW_TREE_BRIDGE_SMALL_SPECIAL_PARTICLE_ID, NULL, NW_TREE_BRIDGE_PARTICLE_MODE,
                                      -1, NULL);
                    particlesRemaining--;
                } while (particlesRemaining != 0);
            } else if (state->sequenceId == NW_TREE_BRIDGE_SEQUENCE_ID_0) {
                do {
                    (*gPartfxInterface)
                        ->spawnEffect(obj, NW_TREE_BRIDGE_SMALL_SEQUENCE_0_PARTICLE_ID, NULL,
                                      NW_TREE_BRIDGE_PARTICLE_MODE, -1, NULL);
                    particlesRemaining--;
                } while (particlesRemaining != 0);
            } else if (state->sequenceId == NW_TREE_BRIDGE_SEQUENCE_ID_1) {
                do {
                    (*gPartfxInterface)
                        ->spawnEffect(obj, NW_TREE_BRIDGE_SMALL_SEQUENCE_1_PARTICLE_ID, NULL,
                                      NW_TREE_BRIDGE_PARTICLE_MODE, -1, NULL);
                    particlesRemaining--;
                } while (particlesRemaining != 0);
            }
            break;
        }
        eventIndex++;
    }
    return 0;
}

int nwTreeBridge_getExtraSize(void) {
    return sizeof(NwTreeBridgeState);
}

void nwTreeBridge_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                         s8 unusedVisible) {
    NwTreeBridgeState* state;
    f32 pathX, pathY, pathZ;

    (void)unusedVisible;
    state = obj->extra;
    objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, NW_TREE_BRIDGE_RENDER_SCALE);
    if (state->pathTarget != NULL) {
        ObjPath_GetPointWorldPosition(obj, NW_TREE_BRIDGE_PATH_INDEX, &pathX, &pathY, &pathZ, 0);
        state->pathTarget->anim.localPosX = pathX;
        state->pathTarget->anim.localPosY = pathY;
        state->pathTarget->anim.localPosZ = pathZ;
    }
}

void nwTreeBridge_update(GameObject* obj) {
    NwTreeBridgeState* state;
    int preemptSequenceId;
    f32 searchDistance;

    state = obj->extra;
    searchDistance = NW_TREE_BRIDGE_TARGET_SEARCH_DISTANCE;
    if (state->targetSearchAttempts != 0) {
        state->pathTarget =
            objGetNearestTypeTo(NW_TREE_BRIDGE_TARGET_OBJECT_GROUP, obj, &searchDistance);
        if (state->pathTarget != NULL) {
            state->targetSearchAttempts = 0;
        } else {
            state->targetSearchAttempts--;
        }
    } else if (state->sequenceStarted == 0) {
        preemptSequenceId = state->preemptSequenceId;
        if (preemptSequenceId != 0) {
            (*gObjectTriggerInterface)->preempt((int)obj, preemptSequenceId);
            (*gObjectTriggerInterface)
                ->runSequence((int)state->sequenceId, (void*)obj, NW_TREE_BRIDGE_PREEMPT_SEQUENCE_FLAGS);
            state->sequenceStarted = 1;
        } else if (mainGetBit((int)state->gameBit) != 0) {
            (*gObjectTriggerInterface)
                ->runSequence((int)state->sequenceId, (void*)obj, NW_TREE_BRIDGE_GAMEBIT_SEQUENCE_FLAGS);
            state->sequenceStarted = 1;
        }
    }
}

void nwTreeBridge_init(GameObject* obj, const NwTreeBridgePlacement* placement) {
    NwTreeBridgeState* state;

    state = obj->extra;
    obj->animEventCallback = nwTreeBridge_processAnimEvents;
    obj->anim.rotX = (s16)(placement->initialRotX << 8);
    obj->anim.rotY = placement->initialRotY;
    obj->anim.rotZ = placement->initialRotZ;
    state->sequenceId = placement->sequenceId;
    state->gameBit = placement->gameBit;
    if (mainGetBit((int)state->gameBit) != 0) {
        state->preemptSequenceId = NW_TREE_BRIDGE_PREEMPT_SEQUENCE_ID;
    }
    state->targetSearchAttempts = NW_TREE_BRIDGE_TARGET_SEARCH_ATTEMPTS;
}

ObjectDescriptor gNWTreeBridgeObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)nwTreeBridge_init,
    (ObjectDescriptorCallback)nwTreeBridge_update,
    0,
    (ObjectDescriptorCallback)nwTreeBridge_render,
    0,
    0,
    nwTreeBridge_getExtraSize,
};
