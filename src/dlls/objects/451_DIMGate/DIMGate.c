/*
 * DIMGate (DLL 0x1C3) opens when an object with sequence ID 399 enters its
 * contact list and persists the open state through a game bit.
 */

#include "dlls/objects/451_DIMGate.h"

#include "main/gamebits_api.h"
#include "main/object_render.h"
#include "main/objhits.h"

#define DIM_GATE_TRIGGER_SEQUENCE_ID 399

int dimgate_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    (void)obj;
    (void)unused;
    (void)animUpdate;

    return 0;
}

int dimgate_getExtraSize(void) {
    return sizeof(DimGateState);
}

int dimgate_getObjectTypeId(void) {
    return 0;
}

void dimgate_free(void) {
}

void dimgate_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    s32 visibilityFlag = visible;

    if (visibilityFlag != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void dimgate_hitDetect(void) {
}

void dimgate_update(GameObject* obj) {
    DimGateState* state = obj->extra;
    DimGatePlacement* placement = (DimGatePlacement*)obj->anim.placementData;

    switch (state->mode) {
    case DIM_GATE_MODE_CLOSED: {
        int triggerFound;
        int contactIndex;

        if (((ObjHitsPriorityState*)obj->anim.hitReactState)->stateIndex != DIM_GATE_MODE_OPENING) {
            ObjHitbox_SetStateIndex(obj, obj->anim.hitReactState, DIM_GATE_MODE_OPENING);
        }
        triggerFound = 0;
        for (contactIndex = 0; contactIndex < obj->anim.hitboxTransformState->contactObjectCount; contactIndex++) {
            GameObject* contactObject = obj->anim.hitboxTransformState->contactObjects[contactIndex];

            if (contactObject->anim.romDefNo == DIM_GATE_TRIGGER_SEQUENCE_ID) {
                triggerFound = 1;
                break;
            }
        }
        if (triggerFound) {
            mainSetBits(placement->openGameBit, 1);
            if (((ObjHitsPriorityState*)obj->anim.hitReactState)->stateIndex != DIM_GATE_MODE_OPEN) {
                ObjHitbox_SetStateIndex(obj, obj->anim.hitReactState, DIM_GATE_MODE_OPEN);
            }
            state->mode = DIM_GATE_MODE_OPEN;
        }
        break;
    }
    case DIM_GATE_MODE_OPENING:
        break;
    case DIM_GATE_MODE_OPEN: {
        if (((ObjHitsPriorityState*)obj->anim.hitReactState)->stateIndex != DIM_GATE_MODE_OPEN) {
            ObjHitbox_SetStateIndex(obj, obj->anim.hitReactState, DIM_GATE_MODE_OPEN);
        }
        break;
    }
    }
}

void dimgate_init(GameObject* obj, DimGatePlacement* unusedPlacement) {
    DimGateState* state;
    DimGatePlacement* placement;

    (void)unusedPlacement;

    placement = (DimGatePlacement*)obj->anim.placementData;
    state = obj->extra;
    if (mainGetBit(placement->openGameBit) != 0) {
        state->mode = DIM_GATE_MODE_OPEN;
        obj->anim.currentMoveProgress = 1.0f;
    } else {
        state->mode = DIM_GATE_MODE_CLOSED;
    }
    obj->animEventCallback = dimgate_SeqFn;
    obj->anim.rotX = (s16)(placement->rotationXByte << 8);
    obj->objectFlags |= (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED);
}

void dimgate_release(void) {
}

void dimgate_initialise(void) {
}

ObjectDescriptor gDIMGateObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dimgate_initialise,
    (ObjectDescriptorCallback)dimgate_release,
    0,
    (ObjectDescriptorCallback)dimgate_init,
    (ObjectDescriptorCallback)dimgate_update,
    (ObjectDescriptorCallback)dimgate_hitDetect,
    (ObjectDescriptorCallback)dimgate_render,
    (ObjectDescriptorCallback)dimgate_free,
    (ObjectDescriptorCallback)dimgate_getObjectTypeId,
    dimgate_getExtraSize,
};
