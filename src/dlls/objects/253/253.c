/*
 * DLL 0xFD - target-following sequence controller.
 *
 * The object mirrors a placement-selected group member and exposes an
 * interaction that is gated by game bits and UI-event readiness.
 */
#include "dlls/objects/253.h"
#include "main/game_ui_interface.h"
#include "main/object_render.h"
#include "main/objseq.h"
#include "main/objtype.h"
#include "main/gamebits_api.h"
#include "main/objprint_render_api.h"

#define DLL_FD_RENDER_SCALE         1.0f
#define DLL_FD_TARGET_SEARCH_RADIUS 1e+02f

#define DLL_FD_TARGET_INTERACT_FLAG  0x20
#define DLL_FD_NO_GAME_BIT           -1
#define DLL_FD_NO_EVENT              -1
#define DLL_FD_NO_SEQUENCE           -1

int dll_FD_getExtraSize(void) {
    return sizeof(DllFDState);
}

int dll_FD_getObjectTypeId(void) {
    return 0;
}

void dll_FD_free(void) {
}

void dll_FD_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible) {
    s32 isVisible = visible;
    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, fwdArg2, fwdArg3, fwdArg4, fwdArg5, DLL_FD_RENDER_SCALE);
    }
}

void dll_FD_hitDetect(GameObject* obj) {
    if (((obj->anim.modelInstance->flags & OBJDEF_FLAG_HAS_MODELS) != 0) &&
        (obj->anim.hitVolumeTransforms != NULL)) {
        objUpdateHitVolumeTransforms(obj);
    }
}

void dll_FD_update(GameObject* obj) {
    u8 mode;
    GameObject* target;
    u32 gameBitValue;
    int eventReady;
    DllFDPlacement* placement;
    DllFDState* state;
    f32 maxDistance;

    maxDistance = DLL_FD_TARGET_SEARCH_RADIUS;
    placement = (DllFDPlacement*)obj->anim.placementData;
    state = obj->extra;
    if (state->target == NULL) {
        target = objGetNearestTypeTo((u32)placement->targetGroup, obj, &maxDistance);
        state->target = target;
        if (state->target == NULL) {
            return;
        }
        if (placement->stateGameBit == DLL_FD_NO_GAME_BIT) {
            state->isActivated = 0;
        } else {
            gameBitValue = mainGetBit(placement->stateGameBit);
            state->isActivated = gameBitValue;
        }
        if ((state->isActivated != 0) && (placement->preemptSequenceId != DLL_FD_NO_SEQUENCE)) {
            state->mode = DLL_FD_MODE_RUN_INITIAL_SEQUENCE;
        } else {
            state->mode = DLL_FD_MODE_INTERACTIVE;
        }
    }
    obj->anim.localPosX = state->target->anim.localPosX;
    obj->anim.localPosY = state->target->anim.localPosY;
    obj->anim.localPosZ = state->target->anim.localPosZ;
    obj->anim.rotX = state->target->anim.rotX;
    obj->anim.rotZ = state->target->anim.rotZ;
    obj->anim.rotY = state->target->anim.rotY;
    mode = state->mode;
    switch (mode) {
    case DLL_FD_MODE_RUN_INITIAL_SEQUENCE:
        state->target->anim.resetHitboxFlags &= ~DLL_FD_TARGET_INTERACT_FLAG;
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        (*gObjectTriggerInterface)->preempt((int)obj, placement->preemptSequenceId);
        (*gObjectTriggerInterface)->runSequence(placement->sequenceId, obj, placement->sequenceArg);
        state->mode = DLL_FD_MODE_FINISHED;
        break;
    case DLL_FD_MODE_INTERACTIVE:
        if ((state->isActivated != 0) && ((placement->flags & DLL_FD_FLAG_KEEP_INTERACTIVE_WHEN_ACTIVATED) == 0)) {
            state->target->anim.resetHitboxFlags &= ~DLL_FD_TARGET_INTERACT_FLAG;
            obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            state->mode = DLL_FD_MODE_FINISHED;
        } else if ((placement->enableGameBit != DLL_FD_NO_GAME_BIT) &&
                   (gameBitValue = mainGetBit(placement->enableGameBit), gameBitValue == 0)) {
            state->target->anim.resetHitboxFlags &= ~DLL_FD_TARGET_INTERACT_FLAG;
            obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            state->mode = DLL_FD_MODE_WAIT_ENABLE;
        } else if (((obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0) &&
                   ((placement->eventId == DLL_FD_NO_EVENT) ||
                    (eventReady = (*gGameUIInterface)->isItemBeingUsed(placement->eventId), eventReady != 0))) {
            if ((placement->flags & DLL_FD_FLAG_CLEAR_ENABLE_BIT) != 0) {
                mainSetBits(placement->enableGameBit, 0);
            }
            if (placement->stateGameBit != DLL_FD_NO_GAME_BIT) {
                mainSetBits(placement->stateGameBit, 1);
            }
            obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            state->isActivated = 1;
            (*gObjectTriggerInterface)->runSequence(placement->sequenceId, obj, -1);
        } else {
            state->target->anim.resetHitboxFlags |= DLL_FD_TARGET_INTERACT_FLAG;
            obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
        }
        break;
    case DLL_FD_MODE_WAIT_ENABLE:
        gameBitValue = mainGetBit(placement->enableGameBit);
        if (gameBitValue != 0) {
            state->mode = DLL_FD_MODE_INTERACTIVE;
        }
        break;
    case DLL_FD_MODE_FINISHED:
        break;
    }
}

void dll_FD_init(GameObject* obj) {
    DllFDState* state = obj->extra;

    state->mode = DLL_FD_MODE_UNINITIALISED;
    state->target = NULL;
    obj->objectFlags |= OBJECT_OBJFLAG_HIDDEN;
}

void dll_FD_release(void) {
}

void dll_FD_initialise(void) {
}

ObjectDescriptor gDllFDObjDescriptor = {
    0,                                                /* reserved0 */
    0,                                                /* reserved1 */
    0,                                                /* reserved2 */
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,                 /* slotCountAndFlags */
    (ObjectDescriptorCallback)dll_FD_initialise,      /* initialise */
    (ObjectDescriptorCallback)dll_FD_release,         /* release */
    0,                                                /* slot02 */
    (ObjectDescriptorCallback)dll_FD_init,            /* init */
    (ObjectDescriptorCallback)dll_FD_update,          /* update */
    (ObjectDescriptorCallback)dll_FD_hitDetect,       /* hitDetect */
    (ObjectDescriptorCallback)dll_FD_render,          /* render */
    (ObjectDescriptorCallback)dll_FD_free,            /* free */
    (ObjectDescriptorCallback)dll_FD_getObjectTypeId, /* getObjectTypeId */
    dll_FD_getExtraSize,                              /* getExtraSize */
};
