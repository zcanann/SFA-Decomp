/*
 * CannonClaw object (DLL slot 207).
 *
 * Plays its arm animation until Tricky's placement game bit is set, then
 * disables its hit volumes and rendering.
 */
#include "dlls/objects/207_CannonClaw.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/object_render.h"
#include "sys/objects.h"
#include "main/objhits.h"
#include "sys/objects/lifecycle.h"

#define CANNON_CLAW_TRICKY_OBJECT_ID 0x1723
#define CANNON_CLAW_ARM_MOVE_ID      0x208
#define CANNON_CLAW_ANIM_SPEED       0.005f
#define CANNON_CLAW_STATUS_ACTIVE    0
#define CANNON_CLAW_STATUS_DISABLED  1

typedef struct CannonClawGatePlacement {
    ObjPlacement base;     /* 0x00 */
    u8 pad18[2];           /* 0x18 */
    s16 activationGameBit; /* 0x1A */
} CannonClawGatePlacement;

STATIC_ASSERT(offsetof(CannonClawGatePlacement, activationGameBit) == 0x1A);

int cannonclaw_getExtraSize(void) {
    return 0;
}

int cannonclaw_getObjectTypeId(void) {
    return 0;
}

void cannonclaw_free(GameObject* obj) {
    (void)obj;
}

void cannonclaw_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible) {
    if (visible != 0) {
        switch (obj->userData1) {
        case CANNON_CLAW_STATUS_ACTIVE:
            objRenderModelAndHitVolumes(obj, fwdArg2, fwdArg3, fwdArg4, fwdArg5, 1.0f);
            break;
        default:
            break;
        }
    }
}

void cannonclaw_hitDetect(GameObject* obj) {
    (void)obj;
}

void cannonclaw_update(GameObject* obj) {
    GameObject* trickyObj;
    CannonClawGatePlacement* gatePlacement;

    getTrickyObject();
    trickyObj = ObjList_FindObjectById(CANNON_CLAW_TRICKY_OBJECT_ID);
    if (obj->userData1 != CANNON_CLAW_STATUS_ACTIVE) {
        return;
    }
    if (obj->anim.currentMove != CANNON_CLAW_ARM_MOVE_ID) {
        ObjAnim_SetCurrentMove(obj, CANNON_CLAW_ARM_MOVE_ID, 0.0f, 0);
    }
    ObjAnim_AdvanceCurrentMove(obj, CANNON_CLAW_ANIM_SPEED, timeDelta, NULL);
    if (trickyObj == NULL) {
        return;
    }
    gatePlacement = (CannonClawGatePlacement*)trickyObj->anim.placementData;
    if (mainGetBit(gatePlacement->activationGameBit) == 0) {
        return;
    }
    obj->userData1 = CANNON_CLAW_STATUS_DISABLED;
    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    ObjHits_DisableObject(obj);
}

void cannonclaw_init(GameObject* obj, CannonClawPlacement* placement) {
    s8 rotXScale = placement->rotXScale;
    s16 rotX = rotXScale << 8;

    obj->anim.rotX = rotX;
}

void cannonclaw_release(void) {
}

void cannonclaw_initialise(void) {
}

ObjectDescriptor gCannonClawObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)cannonclaw_initialise,
    (ObjectDescriptorCallback)cannonclaw_release,
    0,
    (ObjectDescriptorCallback)cannonclaw_init,
    (ObjectDescriptorCallback)cannonclaw_update,
    (ObjectDescriptorCallback)cannonclaw_hitDetect,
    (ObjectDescriptorCallback)cannonclaw_render,
    (ObjectDescriptorCallback)cannonclaw_free,
    (ObjectDescriptorCallback)cannonclaw_getObjectTypeId,
    cannonclaw_getExtraSize,
};
