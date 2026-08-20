/*
 * DLL 0xFC - target-following trigger controller.
 *
 * The object follows the nearest member of a placement-selected group. Its
 * interaction can run a fixed or random trigger sequence and persist the
 * result through game bits.
 */
#include "dlls/objects/252.h"
#include "main/gamebits_api.h"
#include "main/object_render.h"
#include "main/objseq.h"
#include "main/objtype.h"
#include "main/objprint_render_api.h"
#include "main/vecmath.h"

#define DLL_FC_TARGET_INTERACT_FLAG 0x20
#define DLL_FC_NO_GAME_BIT          -1
#define DLL_FC_TARGET_SEARCH_RADIUS 100.0f

int dll_FC_getExtraSize_ret_8(void) {
    return sizeof(DllFCState);
}

int dll_FC_getObjectTypeId(void) {
    return 0;
}

void dll_FC_free_nop(void) {
}

void dll_FC_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible) {
    s32 isVisible = visible;
    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, fwdArg2, fwdArg3, fwdArg4, fwdArg5, 1.0f);
    }
}

void dll_FC_hitDetect(GameObject* obj) {
    ObjAnimComponent* anim = (ObjAnimComponent*)obj;

    if ((anim->modelInstance->flags & OBJDEF_FLAG_HAS_MODELS) == 0) {
        return;
    }
    if (anim->hitVolumeTransforms == NULL) {
        return;
    }
    objUpdateHitVolumeTransforms(obj);
}

void dll_FC_update(GameObject* obj) {
    DllFCPlacement* placement;
    DllFCState* state;
    u32 rememberedGameBitValue;
    u32 triggerId;
    f32 maxDistance;

    maxDistance = DLL_FC_TARGET_SEARCH_RADIUS;
    placement = (DllFCPlacement*)obj->anim.placementData;
    state = obj->extra;

    if (state->target == NULL) {
        state->target = objGetNearestTypeTo(placement->targetGroup, obj, &maxDistance);
        if (state->target == NULL) {
            return;
        }
        if ((int)placement->rememberedGameBit == DLL_FC_NO_GAME_BIT) {
            state->rememberedGameBitValue = 0;
        } else {
            rememberedGameBitValue = mainGetBit((int)placement->rememberedGameBit);
            state->rememberedGameBitValue = rememberedGameBitValue;
        }
        state->mode = DLL_FC_MODE_LATCHED;
    }

    obj->anim.localPosX = state->target->anim.localPosX;
    obj->anim.localPosY = state->target->anim.localPosY;
    obj->anim.localPosZ = state->target->anim.localPosZ;
    obj->anim.rotX = state->target->anim.rotX;
    obj->anim.rotZ = state->target->anim.rotZ;
    obj->anim.rotY = state->target->anim.rotY;

    switch (state->mode) {
    case DLL_FC_MODE_FINISHED:
        break;
    case DLL_FC_MODE_LATCHED:
        if ((state->rememberedGameBitValue != 0) && ((placement->flags & DLL_FC_FLAG_REMEMBERED_DONE) == 0)) {
            state->target->anim.resetHitboxFlags &= ~DLL_FC_TARGET_INTERACT_FLAG;
            obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            state->mode = DLL_FC_MODE_FINISHED;
        } else if (((int)placement->gateGameBit != DLL_FC_NO_GAME_BIT) &&
                   (mainGetBit((int)placement->gateGameBit) == 0)) {
            state->target->anim.resetHitboxFlags &= ~DLL_FC_TARGET_INTERACT_FLAG;
            obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            state->mode = DLL_FC_MODE_WAIT_GATE;
        } else if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0) {
            if ((placement->flags & DLL_FC_FLAG_CLEAR_GATE_BIT) != 0) {
                mainSetBits((int)placement->gateGameBit, 0);
            }
            if ((int)placement->rememberedGameBit != DLL_FC_NO_GAME_BIT) {
                mainSetBits((int)placement->rememberedGameBit, 1);
            }
            if ((placement->flags & DLL_FC_FLAG_RANDOM_TRIGGER) != 0) {
                triggerId = randomGetRange((int)placement->triggerIdMin, placement->triggerIdMax);
                state->triggerId = triggerId;
            } else {
                state->triggerId += 1;
                if (state->triggerId > placement->triggerIdMax) {
                    state->triggerId = placement->triggerIdMin;
                }
            }
            obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            state->rememberedGameBitValue = 1;
            (*gObjectTriggerInterface)->runSequence(state->triggerId, (void*)obj, -1);
        } else {
            state->target->anim.resetHitboxFlags |= DLL_FC_TARGET_INTERACT_FLAG;
            obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
        }
        break;
    case DLL_FC_MODE_WAIT_GATE:
        if (mainGetBit((int)placement->gateGameBit) != 0) {
            state->mode = DLL_FC_MODE_LATCHED;
        }
        break;
    }
}

void dll_FC_init(GameObject* obj, DllFCPlacement* placement) {
    DllFCState* state;

    state = obj->extra;
    state->mode = DLL_FC_MODE_UNINITIALISED;
    state->triggerId = placement->triggerIdMax;
    obj->objectFlags |= OBJECT_OBJFLAG_HIDDEN;
}

void dll_FC_release_nop(void) {
}

void dll_FC_initialise_nop(void) {
}

ObjectDescriptor gDllFCObjDescriptor = {
    0,                                                /* reserved0 */
    0,                                                /* reserved1 */
    0,                                                /* reserved2 */
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,                 /* slotCountAndFlags */
    (ObjectDescriptorCallback)dll_FC_initialise_nop,  /* initialise */
    (ObjectDescriptorCallback)dll_FC_release_nop,     /* release */
    0,                                                /* slot02 */
    (ObjectDescriptorCallback)dll_FC_init,            /* init */
    (ObjectDescriptorCallback)dll_FC_update,          /* update */
    (ObjectDescriptorCallback)dll_FC_hitDetect,       /* hitDetect */
    (ObjectDescriptorCallback)dll_FC_render,          /* render */
    (ObjectDescriptorCallback)dll_FC_free_nop,        /* free */
    (ObjectDescriptorCallback)dll_FC_getObjectTypeId, /* getObjectTypeId */
    dll_FC_getExtraSize_ret_8,                        /* getExtraSize */
};
