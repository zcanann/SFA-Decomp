/*
 * DIMBridgeCo (DLL 0x1C8) - bridge cog main object for Dinosaur Island
 * Mission 2.  Watches one or more game bits and, when they become set, either
 * hides the cog or triggers an animation sequence depending on the game bit's
 * value; also fires sequence events from the SeqFn callback.
 */

#include "dlls/objects/456_DIMBridgeCo.h"

#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/objseq.h"
#include "main/object_render.h"
#include "main/objtype.h"

#define DIM_BRIDGE_COG_PANEL_GAME_BIT  0x17a
#define DIM_BRIDGE_COG_BRIDGE_GAME_BIT 0x1e3

#define DIM_BRIDGE_COG_OBJECT_GROUP           0xf
#define DIM_BRIDGE_COG_FLAG_WAIT_FOR_SEQUENCE 0x2

#define DIM_BRIDGE_COG_SEQUENCE_COMPLETE_COMMAND 1

#define DIM_BRIDGE_COG_PANEL_SEQUENCE_ID       0x1f
#define DIM_BRIDGE_COG_BRIDGE_SEQUENCE_BASE_ID 0x1d

#define DIM_BRIDGE_COG_ALL_USED_MASK          7
#define DIM_BRIDGE_COG_COG4_USED_MASK         4
#define DIM_BRIDGE_COG_COG3_USED_MASK         2
#define DIM_BRIDGE_COG_COG4_SEQUENCE_FLAG     2
#define DIM_BRIDGE_COG_COG3_SEQUENCE_FLAG     0x20
#define DIM_BRIDGE_COG_DEFAULT_SEQUENCE_SLOT  0
#define DIM_BRIDGE_COG_ACTIVE_SEQUENCE_SLOT   1
#define DIM_BRIDGE_COG_COMPLETE_SEQUENCE_SLOT 2
#define DIM_BRIDGE_COG_NO_SEQUENCE_ID         (-1)

#define DIM_BRIDGE_COG_STATE_INITIAL_VALUE 100
#define DIM_BRIDGE_COG_RENDER_SCALE        1.0f

int dimbridgecogmai_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    const DimBridgeCogPlacement* placement = (const DimBridgeCogPlacement*)obj->anim.placementData;

    (void)unused;

    animUpdate->movementState = 0;
    if ((placement->flags & DIM_BRIDGE_COG_FLAG_WAIT_FOR_SEQUENCE) != 0 &&
        animUpdate->curEventId == DIM_BRIDGE_COG_SEQUENCE_COMPLETE_COMMAND) {
        mainSetBits(placement->doneGameBit, 1);
        animUpdate->curEventId = 0;
    }
    return 0;
}

int dimbridgecogmai_getExtraSize(void) {
    return sizeof(DimBridgeCogState);
}

int dimbridgecogmai_getObjectTypeId(void) {
    return 0x0;
}

void dimbridgecogmai_free(GameObject* obj) {
    objFreeObjectType(obj, DIM_BRIDGE_COG_OBJECT_GROUP);
}

void dimbridgecogmai_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                            s8 visible) {
    s32 visibleValue = visible;

    if (visibleValue != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, DIM_BRIDGE_COG_RENDER_SCALE);
    }
}

void dimbridgecogmai_hitDetect(void) {
}

void dimbridgecogmai_update(GameObject* obj) {
    const DimBridgeCogPlacement* placement;
    int sequenceId;
    u8 usedCogMask;
    int slot;

    placement = (const DimBridgeCogPlacement*)obj->anim.placementData;
    if (mainGetBit(placement->watchGameBit) != 0) {
        if (placement->sequenceGate != -1) {
            switch (placement->watchGameBit) {
            case DIM_BRIDGE_COG_PANEL_GAME_BIT:
                if (mainGetBit(GAMEBIT_ITEM_DIMCog1_Used) != 0) {
                    obj->objectFlags |= OBJECT_OBJFLAG_UPDATE_DISABLED;
                    sequenceId = DIM_BRIDGE_COG_NO_SEQUENCE_ID;
                    slot = DIM_BRIDGE_COG_DEFAULT_SEQUENCE_SLOT;
                } else {
                    mainSetBits(placement->watchGameBit, 0);
                    sequenceId = DIM_BRIDGE_COG_PANEL_SEQUENCE_ID;
                    slot = DIM_BRIDGE_COG_ACTIVE_SEQUENCE_SLOT;
                }
                break;
            case DIM_BRIDGE_COG_BRIDGE_GAME_BIT:
                usedCogMask = mainGetBit(GAMEBIT_ITEM_DIMCog2_Used);
                usedCogMask |= mainGetBit(GAMEBIT_ITEM_DIMCog3_Used) << 1;
                usedCogMask |= mainGetBit(GAMEBIT_ITEM_DIMCog4_Used) << 2;
                if (usedCogMask == DIM_BRIDGE_COG_ALL_USED_MASK) {
                    obj->objectFlags |= OBJECT_OBJFLAG_UPDATE_DISABLED;
                    sequenceId = DIM_BRIDGE_COG_NO_SEQUENCE_ID;
                    slot = DIM_BRIDGE_COG_COMPLETE_SEQUENCE_SLOT;
                } else {
                    mainSetBits(placement->watchGameBit, 0);
                    sequenceId = DIM_BRIDGE_COG_BRIDGE_SEQUENCE_BASE_ID;
                    if ((usedCogMask & DIM_BRIDGE_COG_COG4_USED_MASK) != 0) {
                        sequenceId |= DIM_BRIDGE_COG_COG4_SEQUENCE_FLAG;
                        if ((usedCogMask & DIM_BRIDGE_COG_COG3_USED_MASK) != 0) {
                            sequenceId |= DIM_BRIDGE_COG_COG3_SEQUENCE_FLAG;
                        }
                    }
                    slot = DIM_BRIDGE_COG_ACTIVE_SEQUENCE_SLOT;
                }
                break;
            default:
                slot = DIM_BRIDGE_COG_DEFAULT_SEQUENCE_SLOT;
                break;
            }
            (*gObjectTriggerInterface)->runSequence(slot, (int*)obj, sequenceId);
        }
        if ((placement->flags & DIM_BRIDGE_COG_FLAG_WAIT_FOR_SEQUENCE) == 0) {
            mainSetBits(placement->doneGameBit, 1);
        }
    }
}

void dimbridgecogmai_init(GameObject* obj, const DimBridgeCogPlacement* placement) {
    DimBridgeCogState* state = obj->extra;

    state->unknown00 = DIM_BRIDGE_COG_STATE_INITIAL_VALUE;
    obj->anim.rotX = (s16)((u32)placement->rotationAngle << 8);
    obj->animEventCallback = dimbridgecogmai_SeqFn;
    objAddObjectType(obj, DIM_BRIDGE_COG_OBJECT_GROUP);
    if ((u8)mainGetBit(placement->doneGameBit) != 0) {
        obj->objectFlags |= OBJECT_OBJFLAG_UPDATE_DISABLED;
    }
    obj->objectFlags |= (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED);
}

void dimbridgecogmai_release(void) {
}

void dimbridgecogmai_initialise(void) {
}

ObjectDescriptor gDIMBridgeCogMaiObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dimbridgecogmai_initialise,
    (ObjectDescriptorCallback)dimbridgecogmai_release,
    0,
    (ObjectDescriptorCallback)dimbridgecogmai_init,
    (ObjectDescriptorCallback)dimbridgecogmai_update,
    (ObjectDescriptorCallback)dimbridgecogmai_hitDetect,
    (ObjectDescriptorCallback)dimbridgecogmai_render,
    (ObjectDescriptorCallback)dimbridgecogmai_free,
    (ObjectDescriptorCallback)dimbridgecogmai_getObjectTypeId,
    dimbridgecogmai_getExtraSize,
};
