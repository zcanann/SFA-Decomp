/*
 * DLL 0x01FF implements a small carryable-object behavior.
 */
#include "dlls/objects/511.h"

#include "dolphin/pad.h"
#include "game/objects/object.h"
#include "main/frame_timing.h"
#include "main/obj_message.h"
#include "main/objhits.h"
#include "main/object_render.h"
#include "main/pad.h"
#include "main/track_dolphin_api.h"
#include "sys/objects.h"

#define DLL1FF_SPECIAL_SEQUENCE_ID     0x146
#define DLL1FF_OBJECT_TYPE_DEFAULT     0
#define DLL1FF_OBJECT_TYPE_SPECIAL     2
#define DLL1FF_CARRY_STATE_RESTING     0
#define DLL1FF_CARRY_STATE_HELD        1
#define DLL1FF_CARRY_STATE_RELEASING   2
#define DLL1FF_GRAB_MESSAGE_PARAM_HIGH 0x28
#define DLL1FF_EXCLUDED_SURFACE_TYPE   14
#define DLL1FF_SURFACE_SNAP_RANGE      40.0f
#define DLL1FF_GRAVITY                 0.1f
#define DLL1FF_MODEL_SCALE             1.0f
#define DLL1FF_MSG_GRAB                0x100008

int dll_1FF_getExtraSize(void) {
    return sizeof(Dll1FFState);
}

int dll_1FF_getObjectTypeId(GameObject* obj) {
    if (obj->anim.romDefNo == DLL1FF_SPECIAL_SEQUENCE_ID) {
        return DLL1FF_OBJECT_TYPE_SPECIAL;
    }
    return DLL1FF_OBJECT_TYPE_DEFAULT;
}

void dll_1FF_free(void) {
}

/* visible is -1 while held (userData2 set), otherwise a 0/non-0 flag; gate
   shadow fade-out on whether a trigger sequence is active. */
void dll_1FF_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    s32 isVisible;
    if (obj->userData2 != 0) {
        isVisible = visible;
        if (isVisible != -1) {
            return;
        }
    } else {
        isVisible = visible;
        if (isVisible == 0) {
            return;
        }
    }
    if (obj->anim.modelInstance->shadowType == OBJ_SHADOW_TYPE_MODEL_GEOMETRIC) {
        if (obj->seqIndex == -1) {
            obj->anim.modelState->flags &= ~(long long)OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        } else {
            obj->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        }
    }
    objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, DLL1FF_MODEL_SCALE);
}

void dll_1FF_hitDetect(void) {
}

void dll_1FF_update(GameObject* obj) {
    GameObject* player;
    Dll1FFState* state;
    int nextCarryState[1];
    int surfaceCount;
    GameObject* landedObject;
    int surfaceIndex;
    u8 contactSlot;
    TrackGroundHit* surface;
    TrackGroundHit** hitLists[2];

    state = obj->extra;
    player = Obj_GetPlayerObject();
    if (state->carryState == DLL1FF_CARRY_STATE_RESTING) {
        nextCarryState[0] = DLL1FF_CARRY_STATE_RESTING;
        if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0 && obj->userData2 == 0) {
            state->messageParamLow = nextCarryState[0];
            state->messageParamHigh = DLL1FF_GRAB_MESSAGE_PARAM_HIGH;
            buttonDisable(0, PAD_BUTTON_A);
            nextCarryState[0] = DLL1FF_CARRY_STATE_HELD;
        }
        state->carryState = nextCarryState[0];
        if (state->carryState != DLL1FF_CARRY_STATE_RESTING) {
            state->messagePending = 1;
        }
        if (obj->userData2 == 0) {
            ObjHits_EnableObject(obj);
            obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
            obj->anim.velocityY = -(DLL1FF_GRAVITY * timeDelta - obj->anim.velocityY);
            obj->anim.localPosY = obj->anim.velocityY * timeDelta + obj->anim.localPosY;
            surfaceCount = trackGetHeight(obj, obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ,
                                                hitLists, 0, 1);
            landedObject = NULL;
            for (surfaceIndex = 0; surfaceIndex < surfaceCount; surfaceIndex++) {
                surface = hitLists[0][surfaceIndex];
                if ((s8)surface->surfaceType != DLL1FF_EXCLUDED_SURFACE_TYPE) {
                    if (obj->anim.localPosY < surface->height) {
                        if (obj->anim.localPosY > surface->height - DLL1FF_SURFACE_SNAP_RANGE || surfaceIndex == 0) {
                            landedObject = surface->object;
                            obj->anim.localPosY = surface->height;
                            obj->anim.velocityY = 0.0f;
                        }
                    }
                }
            }
            if (landedObject != NULL) {
                ObjHitboxTransformState* hitboxState = landedObject->anim.hitboxTransformState;
                contactSlot = hitboxState->contactObjectCount;
                hitboxState->contactObjectCount += 1;
                hitboxState->contactObjects[(s8)contactSlot] = obj;
            }
        }
    } else {
        ObjHits_DisableObject(obj);
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        if ((getButtonsJustPressed(0) & PAD_BUTTON_A) != 0) {
            state->messagePending = 0;
            buttonDisable(0, PAD_BUTTON_A);
        }
        if (obj->userData2 == 1) {
            state->carryState = DLL1FF_CARRY_STATE_RELEASING;
        }
        if (state->carryState == DLL1FF_CARRY_STATE_RELEASING && obj->userData2 == 0) {
            state->carryState = DLL1FF_CARRY_STATE_RESTING;
            state->messagePending = 0;
        }
        if (state->messagePending != 0) {
            ObjMsg_SendToObject(player, DLL1FF_MSG_GRAB, obj,
                                ((int)state->messageParamHigh << 16) | ((int)state->messageParamLow & 0xffff));
        }
    }
}

void dll_1FF_init(GameObject* obj, const Dll1FFPlacementView* placement) {
    obj->anim.rotX = (s16)((s32)placement->rotationXByte << 8);
    obj->anim.rotY = -0x8000;
}

void dll_1FF_release(void) {
}

void dll_1FF_initialise(void) {
}

ObjectDescriptor gDll1FFObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    dll_1FF_initialise,
    dll_1FF_release,
    0,
    (ObjectDescriptorCallback)dll_1FF_init,
    (ObjectDescriptorCallback)dll_1FF_update,
    dll_1FF_hitDetect,
    (ObjectDescriptorCallback)dll_1FF_render,
    dll_1FF_free,
    (ObjectDescriptorCallback)dll_1FF_getObjectTypeId,
    dll_1FF_getExtraSize,
};
