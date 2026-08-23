/*
 * DLL 0x1CE - an unnamed, placement-driven hatch controller.
 *
 * The active-target descriptor has no OBJECTS.bin definitions. Its callbacks
 * coast an opened lid between two limits and, for variants other than
 * DIMHutDoor, wait for DIMSnowHorn or DIMCannonBa contact before setting the
 * placement game bit and spawning a DIMBridgeCo collectible.
 */

#include "dlls/objects/462.h"

#include "dlls/objects/237.h"
#include "dlls/objects/454_DIMCannon.h"
#include "main/frame_timing.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/object_render.h"
#include "sys/objects.h"
#include "main/resource.h"
#include "sys/objects/lifecycle.h"

#define DLL1CE_SEQUENCE_ID_DIM_HUT_DOOR          0x334
#define DLL1CE_KEY_SEQUENCE_ID_DIM_SNOW_HORN     0x18f
#define DLL1CE_CONTENTS_OBJECT_ID_DIM_BRIDGE_COG 0x246
#define DLL1CE_CONTENTS_GATE_GAMEBIT             0x46d

#define DLL1CE_OPEN_PROGRESS_MAX     82.0f
#define DLL1CE_OPEN_PROGRESS_MIN     -5.0f
#define DLL1CE_OPEN_VELOCITY_FORWARD 0.1f
#define DLL1CE_OPEN_VELOCITY_REVERSE -0.1f
#define DLL1CE_CONTENTS_HEIGHT       8.0f
#define DLL1CE_RENDER_SCALE          1.0f

void* gDll1CEResource;

int dll_1CE_getExtraSize(void) {
    return sizeof(Dll1CEState);
}

int dll_1CE_getObjectTypeId(void) {
    return 0;
}

void dll_1CE_free(void) {
    if (gDll1CEResource != NULL) {
        Resource_Release(gDll1CEResource);
    }
    gDll1CEResource = NULL;
}

void dll_1CE_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    s32 isVisible = visible;

    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, DLL1CE_RENDER_SCALE);
    }
}

void dll_1CE_hitDetect(void) {
}

void dll_1CE_update(GameObject* obj) {
    const Dll1CEPlacementView* placement = (const Dll1CEPlacementView*)obj->anim.placementData;
    Dll1CEState* state = obj->extra;
    ObjHitsPriorityState* hitState;

    if (obj->anim.alpha == 0) {
        return;
    }
    if (state->unlockCountdown <= 0) {
        hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
        hitState->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
        if (state->opened == 1) {
            state->openProgress = state->openVelocity * timeDelta + state->openProgress;
            if (state->openProgress > DLL1CE_OPEN_PROGRESS_MAX) {
                state->openProgress = DLL1CE_OPEN_PROGRESS_MAX;
                state->openVelocity = DLL1CE_OPEN_VELOCITY_REVERSE;
            } else if (state->openProgress < DLL1CE_OPEN_PROGRESS_MIN) {
                state->openProgress = DLL1CE_OPEN_PROGRESS_MIN;
                state->openVelocity = DLL1CE_OPEN_VELOCITY_FORWARD;
            }
        }
    }
    if (obj->anim.romDefNo == DLL1CE_SEQUENCE_ID_DIM_HUT_DOOR) {
        return;
    }
    {
        int contactOffset;
        int i;
        ObjHitboxTransformState* contactState;
        int contactCount;
        int keyFound = 0;

        contactOffset = 0;
        contactState = obj->anim.hitboxTransformState;
        contactCount = contactState->contactObjectCount;
        for (i = 0; i < contactCount; i++) {
            GameObject* contact =
                *(GameObject**)((u8*)contactState + contactOffset + offsetof(ObjHitboxTransformState, contactObjects));

            if (contact->anim.romDefNo == DLL1CE_KEY_SEQUENCE_ID_DIM_SNOW_HORN ||
                contact->anim.romDefNo == DIM_CANNON_BALL_SEQUENCE_ID) {
                keyFound = 1;
                break;
            }
            contactOffset += sizeof(contactState->contactObjects[0]);
        }
        if (!keyFound) {
            return;
        }
    }
    {
        if ((state->unlockCountdown -= 1) > 0) {
            return;
        }
    }
    mainSetBits(placement->openedGameBit, 1);
    state->opened = 1;
    if ((u32)placement->contentsSpawnBitValue != mainGetBit(DLL1CE_CONTENTS_GATE_GAMEBIT)) {
        return;
    }
    if ((u8)Obj_CanSetupObject() == 0) {
        return;
    }
    {
        CollectibleSetup* contentsSetup =
            (CollectibleSetup*)Obj_AllocObjectSetup(sizeof(CollectibleSetup), DLL1CE_CONTENTS_OBJECT_ID_DIM_BRIDGE_COG);

        contentsSetup->base.posX = placement->base.posX;
        contentsSetup->base.posY = DLL1CE_CONTENTS_HEIGHT + placement->base.posY;
        contentsSetup->base.posZ = placement->base.posZ;
        contentsSetup->base.color[0] = placement->base.color[0];
        contentsSetup->base.color[1] = placement->base.color[1];
        contentsSetup->base.color[2] = placement->base.color[2];
        contentsSetup->base.color[3] = placement->base.color[3];
        contentsSetup->hideGameBit = GAMEBIT_ITEM_DIMCog3_Got;
        contentsSetup->visibilityGameBit = -1;
        contentsSetup->counterGameBit = -1;
        contentsSetup->unk1A = 5;
        contentsSetup->rotXByte = (u8)(obj->anim.rotX >> 8);
        objSetupObject(&contentsSetup->base, 5, obj->anim.mapEventSlot, -1, 0);
    }
}

void dll_1CE_init(GameObject* obj, const Dll1CEPlacementView* placement) {
    Dll1CEState* state;
    ObjHitsPriorityState* hitState;

    obj->anim.rotX = (s16)(((s16)placement->rotationXByte) << 8);
    obj->objectFlags = (u16)(obj->objectFlags | OBJECT_OBJFLAG_HITDETECT_DISABLED);
    state = obj->extra;
    state->unlockCountdown = 1;
    if (mainGetBit(placement->openedGameBit) != 0) {
        state->unlockCountdown = 0;
        hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
        hitState->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
        obj->anim.alpha = 0;
    }
    state->openVelocity = DLL1CE_OPEN_VELOCITY_REVERSE;
}

void dll_1CE_release(void) {
}

void dll_1CE_initialise(void) {
}

ObjectDescriptor gDll1CEObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll_1CE_initialise,
    (ObjectDescriptorCallback)dll_1CE_release,
    0,
    (ObjectDescriptorCallback)dll_1CE_init,
    (ObjectDescriptorCallback)dll_1CE_update,
    (ObjectDescriptorCallback)dll_1CE_hitDetect,
    (ObjectDescriptorCallback)dll_1CE_render,
    (ObjectDescriptorCallback)dll_1CE_free,
    (ObjectDescriptorCallback)dll_1CE_getObjectTypeId,
    dll_1CE_getExtraSize,
};
