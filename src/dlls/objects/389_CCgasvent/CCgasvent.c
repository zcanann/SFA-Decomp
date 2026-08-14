/*
 * CCgasvent (DLL 0x185) - Crystal Caves gas vent.
 *
 * The vent emits gas while the room gas is active and no group-5 blocker is
 * within its distance threshold. The neighboring controller supervises the
 * complete vent group.
 */
#include "dlls/objects/389_CCgasvent.h"

#include "game/objects/object.h"
#include "main/dll/partfx_interface.h"
#include "main/gamebits_api.h"
#include "main/objtype.h"

#define CC_GAS_VENT_PARTICLE_GAS        0x3DF
#define CC_GAS_VENT_PARTICLE_SPAWN_MODE 0
#define CC_GAS_VENT_PARTICLE_MODEL_NONE -1

#define CC_GAS_VENT_DISTANCE_UNSET 3.4028235e38f
#define CC_GAS_VENT_BLOCK_DISTANCE 10.0f

#define CC_GAS_VENT_PHASE_BLOCKED 0
#define CC_GAS_VENT_PHASE_CLEAR   1

int ccGasVent_getExtraSize(void) {
    return sizeof(CCGasVentState);
}

void ccGasVent_free(GameObject* obj) {
    objFreeObjectType(obj, CC_GAS_VENT_OBJECT_GROUP);
}

void ccGasVent_render(void) {
}

void ccGasVent_update(GameObject* obj) {
    f32 blockerDistance = CC_GAS_VENT_DISTANCE_UNSET;
    CCGasVentState* state = obj->extra;

    if (mainGetBit(CC_GAS_VENT_ACTIVE_GAMEBIT) != 0) {
        objGetNearestTypeTo(CC_GAS_VENT_BLOCKER_OBJECT_GROUP, obj, &blockerDistance);
        switch (state->phase) {
        case CC_GAS_VENT_PHASE_BLOCKED:
            if (blockerDistance >= CC_GAS_VENT_BLOCK_DISTANCE) {
                state->phase = CC_GAS_VENT_PHASE_CLEAR;
            }
            break;
        case CC_GAS_VENT_PHASE_CLEAR:
            if (blockerDistance < CC_GAS_VENT_BLOCK_DISTANCE) {
                state->phase = CC_GAS_VENT_PHASE_BLOCKED;
            } else {
                (*gPartfxInterface)
                    ->spawnObject(obj, CC_GAS_VENT_PARTICLE_GAS, NULL, CC_GAS_VENT_PARTICLE_SPAWN_MODE,
                                  CC_GAS_VENT_PARTICLE_MODEL_NONE, NULL);
            }
            break;
        }
    }
}

void ccGasVent_init(GameObject* obj) {
    objAddObjectType(obj, CC_GAS_VENT_OBJECT_GROUP);
}

ObjectDescriptor gCCGasVentObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)ccGasVent_init,
    (ObjectDescriptorCallback)ccGasVent_update,
    0,
    (ObjectDescriptorCallback)ccGasVent_render,
    (ObjectDescriptorCallback)ccGasVent_free,
    0,
    ccGasVent_getExtraSize,
};
