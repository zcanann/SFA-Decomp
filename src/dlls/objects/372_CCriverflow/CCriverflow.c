#include "dlls/objects/372_CCriverflow.h"

#include "game/objects/object.h"
#include "main/gamebits_api.h"
#include "main/objtype.h"

#define CC_RIVER_FLOW_OBJECT_GROUP        0x14
#define CC_RIVER_FLOW_DEFAULT_SPEED       0xFF
#define CC_RIVER_FLOW_HEIGHT_OFFSET_SCALE 512.0f
#define CC_RIVER_FLOW_MINIMUM_HEIGHT      0.01f

int ccRiverFlow_getExtraSize(void) {
    return sizeof(CCRiverFlowState);
}

void ccRiverFlow_free(GameObject* obj) {
    CCRiverFlowState* state = obj->extra;

    if (state->active != 0) {
        objFreeObjectType(obj, CC_RIVER_FLOW_OBJECT_GROUP);
    }
}

void ccRiverFlow_render(void) {
}

void ccRiverFlow_update(GameObject* obj) {
    u32 isGameBitSet;
    CCRiverFlowPlacement* placement;
    CCRiverFlowState* state;

    placement = (CCRiverFlowPlacement*)obj->anim.placementData;
    if (placement->gameBit != -1) {
        state = obj->extra;
        isGameBitSet = mainGetBit((int)placement->gameBit);
        if (isGameBitSet != 0) {
            if (state->active != 0) {
                state->active = 0;
                objFreeObjectType(obj, CC_RIVER_FLOW_OBJECT_GROUP);
            }
        } else if (state->active == 0) {
            state->active = 1;
            objAddObjectType(obj, CC_RIVER_FLOW_OBJECT_GROUP);
        }
    }
}

void ccRiverFlow_init(GameObject* obj, CCRiverFlowPlacement* placement) {
    if (placement->gameBit == -1) {
        objAddObjectType(obj, CC_RIVER_FLOW_OBJECT_GROUP);
        ((CCRiverFlowState*)obj->extra)->active = 1;
    }

    obj->anim.rotX = placement->angle << 8;
    obj->anim.rootMotionScale = obj->anim.modelInstance->rootMotionScaleBase;
    obj->anim.rootMotionScale =
        (f32)(u32)placement->heightOffset / CC_RIVER_FLOW_HEIGHT_OFFSET_SCALE + obj->anim.rootMotionScale;
    if (obj->anim.rootMotionScale < CC_RIVER_FLOW_MINIMUM_HEIGHT) {
        obj->anim.rootMotionScale = CC_RIVER_FLOW_MINIMUM_HEIGHT;
    }
    if (placement->speed == 0) {
        placement->speed = CC_RIVER_FLOW_DEFAULT_SPEED;
    }
}

ObjectDescriptor gCCRiverFlowObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)ccRiverFlow_init,
    (ObjectDescriptorCallback)ccRiverFlow_update,
    0,
    (ObjectDescriptorCallback)ccRiverFlow_render,
    (ObjectDescriptorCallback)ccRiverFlow_free,
    0,
    ccRiverFlow_getExtraSize,
};
