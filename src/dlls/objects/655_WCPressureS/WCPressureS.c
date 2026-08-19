/*
 * WCPressureS (DLL 655) - a weighted pressure plate in the Walled City
 * (WC). The plate lowers while something heavy rests on it and rises again
 * when the weight is removed, latching a "solved" game bit while pressed.
 * Each update scans the object's hit list for entities standing higher than
 * triggerHeight above the plate, tracks up to WCPRESSURES_TRACKED_COUNT of
 * them with their saved XZ positions, and counts the plate pressed while any
 * tracked entity stays put. A 4-mode machine (RAISED -> LOWERING -> PRESSED
 * -> RISING) animates localPosY between the setup Y and Y - pressDepth,
 * plays a sfx at the transitions, sets/clears solvedBit and swaps the plate
 * texture while down. activateBit, when set, gates the whole object inert.
 * The animEventCallback snapshots tracked-tile positions or resets the
 * object and clears solvedBit.
 */
#include "main/audio/sfx_play_api.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/objtexture.h"
#include "main/debug.h"
#include "main/dll/WC/dll_028F_wcpressures.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/object_render.h"
#include "main/objtype.h"
#include "main/objseq.h"

#define WCPRESSURES_EXTRA_SIZE        0x7c
#define WCPRESSURES_OBJECT_GROUP      0x31
#define WCPRESSURES_RENDER_TYPE_BASE  0x400
#define WCPRESSURES_RENDER_TYPE_SHIFT 0xb

#define WCPRESSURES_MODE_RAISED   0
#define WCPRESSURES_MODE_RISING   1
#define WCPRESSURES_MODE_PRESSED  2
#define WCPRESSURES_MODE_LOWERING 3

#define WCPRESSURES_FOUND_TIMER  5
#define WCPRESSURES_SOLVED_TIMER 0x1e

#define WCPRESSURES_CALLBACK_NONE           0
#define WCPRESSURES_CALLBACK_SNAPSHOT_TILES 1
#define WCPRESSURES_CALLBACK_RESET          2

#define WCPRESSURES_TEXTURE_DEFAULT 0
#define WCPRESSURES_TEXTURE_PRESSED 1
#define WCPRESSURES_TEXTURE_SHIFT   8

int wcpressures_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    WCPressuresState* state = (WCPressuresState*)obj->extra;
    WCPressuresSetup* setup = (WCPressuresSetup*)obj->anim.placementData;
    u8 i;

    if (animUpdate->curEventId == WCPRESSURES_CALLBACK_SNAPSHOT_TILES) {
        for (i = 0; i < WCPRESSURES_TRACKED_COUNT; i++) {
            if ((void*)state->objects[i] != NULL) {
                state->savedPos[i].x = state->objects[i]->anim.localPosX;
                state->savedPos[i].z = state->objects[i]->anim.localPosZ;
            }
        }
        animUpdate->curEventId = WCPRESSURES_CALLBACK_NONE;
    } else if (animUpdate->curEventId == WCPRESSURES_CALLBACK_RESET) {
        for (i = 0; i < WCPRESSURES_TRACKED_COUNT; i++) {
            state->objects[i] = 0;
        }
        /* sic: setup->x is stored to the Z slot and overwritten just below,
           so localPosX (obj+0xc) is left unrestored - faithful to retail */
        obj->anim.localPosZ = setup->base.posX;
        obj->anim.localPosY = setup->base.posY;
        obj->anim.localPosZ = setup->base.posZ;
        mainSetBits(setup->solvedBit, 0);
        animUpdate->curEventId = WCPRESSURES_CALLBACK_NONE;
    }

    return 0;
}

int wcpressures_getExtraSize(void) {
    return sizeof(WCPressuresState);
}

int wcpressures_getObjectTypeId(GameObject* obj) {
    ObjAnimComponent* objAnim = &obj->anim;
    WCPressuresSetup* setup = (WCPressuresSetup*)obj->anim.placementData;
    int modelIndex = setup->modelIndex;
    int modelCount = objAnim->modelInstance->modelCount;

    if (modelIndex >= modelCount) {
        modelIndex = 0;
    }
    return (modelIndex << WCPRESSURES_RENDER_TYPE_SHIFT) | WCPRESSURES_RENDER_TYPE_BASE;
}

void wcpressures_free(GameObject* obj) {
    objFreeObjectType(obj, WCPRESSURES_OBJECT_GROUP);
}

void wcpressures_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible) {
    if (visible != 0) {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
    }
}

void wcpressures_hitDetect(void) {
}

static inline void wcpressures_addTrackedObject(GameObject* obj, GameObject* trackedObject) {
    WCPressuresState* state = (WCPressuresState*)obj->extra;
    u8 trackedIndex;

    for (trackedIndex = 0; state->objects[trackedIndex] != NULL || trackedIndex == WCPRESSURES_TRACKED_COUNT - 1;
         trackedIndex++)
        ;
    state->objects[trackedIndex] = trackedObject;
    state->savedPos[trackedIndex].x = trackedObject->anim.localPosX;
    state->savedPos[trackedIndex].z = trackedObject->anim.localPosZ;
}

static inline u8 wcpressures_scanTrackedObjects(WCPressuresState* state) {
    GameObject* trackedObject;
    u8 slotIndex;
    int foundStationaryObject;

    foundStationaryObject = 0;
    for (slotIndex = 0; slotIndex < WCPRESSURES_TRACKED_COUNT; slotIndex++) {
        trackedObject = state->objects[slotIndex];
        if (trackedObject != NULL) {
            if (state->savedPos[slotIndex].x == trackedObject->anim.localPosX &&
                state->savedPos[slotIndex].z == trackedObject->anim.localPosZ) {
                foundStationaryObject = 1;
            } else {
                state->objects[slotIndex] = NULL;
            }
        }
    }
    return foundStationaryObject;
}

void wcpressures_update(GameObject* obj) {
    WCPressuresSetup* setup = (WCPressuresSetup*)obj->anim.placementData;
    WCPressuresState* state = (WCPressuresState*)obj->extra;
    GameObject* contact;
    int contactIndex;
    f32 pressedY;

    if (setup->activateBit > 0 && mainGetBit(setup->activateBit) == 0) {
        logPrintf(sWCPressuresActivateFormat, setup->activateBit);
        return;
    }
    if ((state->pressTimer -= 1) < 0) {
        state->pressTimer = 0;
    }
    if (obj->anim.hitboxTransformState->contactObjectCount > 0) {
        for (contactIndex = 0; contactIndex < obj->anim.hitboxTransformState->contactObjectCount; contactIndex++) {
            contact = (GameObject*)obj->anim.hitboxTransformState->contactObjects[contactIndex];
            if (contact->anim.localPosY - obj->anim.localPosY > (f32)(u32)setup->triggerHeight) {
                wcpressures_addTrackedObject(obj, contact);
            }
        }
    }
    {
        u8 foundStationaryObject = wcpressures_scanTrackedObjects((WCPressuresState*)obj->extra);

        if ((int)foundStationaryObject != 0) {
            state->pressTimer = WCPRESSURES_FOUND_TIMER;
        }
    }
    pressedY = setup->y - (f32)(u32)setup->pressDepth;
    switch (state->mode) {
    case WCPRESSURES_MODE_RAISED:
        if (state->pressTimer != 0 && obj->anim.localPosY >= pressedY) {
            Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_c7);
            state->mode = WCPRESSURES_MODE_LOWERING;
        }
        break;
    case WCPRESSURES_MODE_LOWERING:
        obj->anim.localPosY = obj->anim.localPosY - 0.05f * timeDelta;
        if (obj->anim.localPosY < pressedY) {
            mainSetBits(setup->solvedBit, 1);
            state->mode = WCPRESSURES_MODE_PRESSED;
            obj->anim.localPosY = pressedY;
        }
        break;
    case WCPRESSURES_MODE_PRESSED:
        if (mainGetBit(setup->solvedBit) == 0) {
            Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_c7);
            state->mode = WCPRESSURES_MODE_RISING;
        }
        break;
    case WCPRESSURES_MODE_RISING:
        obj->anim.localPosY = 0.05f * timeDelta + obj->anim.localPosY;
        if (obj->anim.localPosY > setup->y) {
            obj->anim.localPosY = setup->y;
            state->mode = WCPRESSURES_MODE_RAISED;
        }
        break;
    }
    {
        ObjTextureRuntimeSlot* texture = objFindTexture(obj, WCPRESSURES_TEXTURE_DEFAULT, WCPRESSURES_TEXTURE_DEFAULT);
        if (texture != 0) {
            texture->textureId =
                state->mode == WCPRESSURES_MODE_PRESSED ? WCPRESSURES_TEXTURE_PRESSED : WCPRESSURES_TEXTURE_DEFAULT;
            texture->textureId = texture->textureId << WCPRESSURES_TEXTURE_SHIFT;
        }
    }
}

void wcpressures_init(GameObject* obj, WCPressuresSetup* setup) {
    ObjAnimComponent* objAnim = &obj->anim;
    WCPressuresState* state = (WCPressuresState*)obj->extra;
    s16 objType;
    u16 objFlags;
    s8 modelIndex;
    int i;

    objType = (s16)(setup->objectTypeHi << 8);
    obj->anim.rotX = objType;
    objFlags = obj->objectFlags | (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED);
    obj->objectFlags = objFlags;
    modelIndex = setup->modelIndex;
    objAnim->bankIndex = modelIndex;
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount) {
        objAnim->bankIndex = 0;
    }

    if (mainGetBit(setup->solvedBit) != 0) {
        obj->anim.localPosY = setup->base.posY - setup->pressDepth;
        state->pressTimer = WCPRESSURES_SOLVED_TIMER;
        state->mode = WCPRESSURES_MODE_PRESSED;
    }

    objAddObjectType(obj, WCPRESSURES_OBJECT_GROUP);
    for (i = 0; i < WCPRESSURES_TRACKED_COUNT; i++) {
        state->objects[i] = 0;
    }
    obj->animEventCallback = wcpressures_SeqFn;
}

void wcpressures_release(void) {
}

void wcpressures_initialise(void) {
}

ObjectDescriptor gWCPressureSObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)wcpressures_initialise,
    (ObjectDescriptorCallback)wcpressures_release,
    0,
    (ObjectDescriptorCallback)wcpressures_init,
    (ObjectDescriptorCallback)wcpressures_update,
    (ObjectDescriptorCallback)wcpressures_hitDetect,
    (ObjectDescriptorCallback)wcpressures_render,
    (ObjectDescriptorCallback)wcpressures_free,
    (ObjectDescriptorCallback)wcpressures_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)wcpressures_getExtraSize,
};

char sWCPressuresActivateFormat[] = " Avitvate %i ";
