/*
 * KaldachomMe object (DLL slot 214).
 *
 * Drives a linked mouth animation toward a requested progress and selects
 * linked mouth objects from the owning Kaldachom's placement ID.
 */
#include "dlls/objects/214_KaldachomMe.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#include "sys/objects.h"

ObjectDescriptor gKaldachomMeObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)KaldachomMe_initialise,
    (ObjectDescriptorCallback)KaldachomMe_release,
    0,
    (ObjectDescriptorCallback)KaldachomMe_init,
    (ObjectDescriptorCallback)KaldachomMe_update,
    (ObjectDescriptorCallback)KaldachomMe_hitDetect,
    (ObjectDescriptorCallback)KaldachomMe_render,
    (ObjectDescriptorCallback)KaldachomMe_free,
    (ObjectDescriptorCallback)KaldachomMe_getObjectTypeId,
    KaldachomMe_getExtraSize,
};

#define KALDACHOMME_ONE               1.0f
#define KALDACHOMME_ZERO              0.0f
#define KALDACHOMME_LINKED_MOUTH_STEP 0.025f

void kaldachomme_setLinkedMouthMode(GameObject* obj, KaldachomMeLinkedMode mode) {
    KaldachomMeState* state;
    GameObject* linkedObj;

    if (obj == NULL) {
        return;
    }
    switch (obj->anim.placement->ident) {
    case 0x43d14:
        linkedObj = ObjList_FindObjectById(0x4b3b5);
        break;
    case 0x41be9:
        linkedObj = ObjList_FindObjectById(0x4b3f9);
        break;
    case 0x41cc4:
        linkedObj = ObjList_FindObjectById(0x4b402);
        break;
    case 0x41cc5:
        linkedObj = ObjList_FindObjectById(0x4b403);
        break;
    case 0x41cc6:
        linkedObj = ObjList_FindObjectById(0x4b404);
        break;
    case 0x41cc7:
        linkedObj = ObjList_FindObjectById(0x4b40b);
        break;
    case 0x41cc8:
        linkedObj = ObjList_FindObjectById(0x4b40c);
        break;
    case 0x41cc9:
        linkedObj = ObjList_FindObjectById(0x4b40f);
        break;
    case 0x41cd2:
        linkedObj = ObjList_FindObjectById(0x4b410);
        break;
    case 0x41ccc:
        linkedObj = ObjList_FindObjectById(0x4b411);
        break;
    case 0x41cd5:
        linkedObj = ObjList_FindObjectById(0x4b414);
        break;
    case 0x41cd6:
        linkedObj = ObjList_FindObjectById(0x4b415);
        break;
    case 0x41cd9:
        linkedObj = ObjList_FindObjectById(0x4b453);
        break;
    default:
        return;
    }
    state = linkedObj->extra;
    if (state != NULL) {
        switch (mode) {
        case KALDACHOMME_LINKED_MODE_MOVE_0:
            state->targetProgress = KALDACHOMME_ONE;
            state->progress = KALDACHOMME_ZERO;
            state->step = KALDACHOMME_LINKED_MOUTH_STEP;
            state->moveId = 0;
            break;
        case KALDACHOMME_LINKED_MODE_MOVE_1:
            state->targetProgress = KALDACHOMME_ONE;
            state->progress = KALDACHOMME_ZERO;
            state->step = KALDACHOMME_LINKED_MOUTH_STEP;
            state->moveId = 1;
            break;
        }
    }
}

int KaldachomMe_getExtraSize(void) {
    return sizeof(KaldachomMeState);
}

int KaldachomMe_getObjectTypeId(void) {
    return 0;
}

void KaldachomMe_free(GameObject* obj) {
    (void)obj;
}

void KaldachomMe_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible) {
    if (visible != 0) {
        objRenderModelAndHitVolumes(obj, fwdArg2, fwdArg3, fwdArg4, fwdArg5, KALDACHOMME_ONE);
    }
}

void KaldachomMe_hitDetect(GameObject* obj) {
    (void)obj;
}

void KaldachomMe_update(GameObject* obj) {
    f32 target;
    f32 current;
    f32 step;
    KaldachomMeState* state;

    state = obj->extra;
    current = state->progress;
    target = state->targetProgress;
    if (current != target) {
        step = state->step;
        if (step > KALDACHOMME_ZERO) {
            if (current < target) {
                state->progress = current + step * timeDelta;
            } else {
                state->progress = target;
            }
        } else {
            if (current > target) {
                state->progress = current + step * timeDelta;
            } else {
                state->progress = target;
            }
        }
    }
    ObjAnim_SetCurrentMove(obj, state->moveId, state->progress, 0);
}

void KaldachomMe_init(GameObject* obj, KaldachomMePlacement* placement) {
    obj->anim.rotZ = (s16)(placement->rotZByte << 8);
    obj->anim.rotY = (s16)(placement->rotYByte << 8);
    obj->anim.rotX = (s16)(placement->rotXByte << 8);
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
    ObjAnim_SetCurrentMove(obj, 0, KALDACHOMME_ZERO, 0);
}

void KaldachomMe_release(void) {
}

void KaldachomMe_initialise(void) {
}
