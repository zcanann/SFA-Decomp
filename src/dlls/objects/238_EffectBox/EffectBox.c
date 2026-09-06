/*
 * Oriented box-trigger volume (DLL slot 238 / 0xEE).
 *
 * Each update transforms the selected objects into the box's local space. The
 * placement selects the player, Tricky, or object group 5 and can gate the
 * trigger with a game bit. Player and group targets receive mode-specific
 * actions when they enter the box; the Tricky action is a no-op.
 */
#include "dlls/objects/238_EffectBox.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "main/dll/player_api.h"
#include "main/gamebits.h"
#include "main/object_render.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/objtype.h"

#define EFFECTBOX_TARGET_OBJECT_GROUP 5
#define EFFECTBOX_OBJECT_TYPE_ID      0
#define EFFECTBOX_NO_GAME_BIT         -1
#define EFFECTBOX_PLAYER_ACTION       1

#define EFFECTBOX_RENDER_SCALE 1.0f
#define EFFECTBOX_PI           3.1415927f
#define EFFECTBOX_ANGLE_SCALE  32768.0f
#define EFFECTBOX_ZERO         0.0f

typedef void (*EffectBoxActionCallback)(GameObject* obj, int actionArg);

typedef struct EffectBoxTargetInterface {
    void* callbacks[10];
    EffectBoxActionCallback applyAction;
} EffectBoxTargetInterface;

STATIC_ASSERT(offsetof(EffectBoxTargetInterface, applyAction) == 0x28);

int EffectBox_getExtraSize(void) {
    return 0;
}

int EffectBox_getObjectTypeId(void) {
    return EFFECTBOX_OBJECT_TYPE_ID;
}

void EffectBox_free(GameObject* obj) {
    Obj_UnregisterEffectBox(obj);
}

void EffectBox_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible) {
    if (visible != 0) {
        objRenderModelAndHitVolumes(obj, fwdArg2, fwdArg3, fwdArg4, fwdArg5, EFFECTBOX_RENDER_SCALE);
    }
}

void EffectBox_hitDetect(GameObject* obj) {
    (void)obj;
}

void EffectBox_update(GameObject* obj) {
    GameObject** targets;
    EffectBoxPlacement* placement;
    GameObject* singleTarget;
    int targetCount;
    int targetIndex;
    GameObject* target;
    f32 yawCos;
    f32 yawSin;
    f32 pitchCos;
    f32 pitchSin;
    f32 negativeExtentX;
    f32 negativeExtentZ;
    f32 extentX;
    f32 extentY;
    f32 extentZ;
    f32 offsetX;
    f32 offsetY;
    f32 offsetZ;
    f32 projection;
    int gateGameBit;

    placement = (EffectBoxPlacement*)obj->anim.placementData;
    gateGameBit = obj->userData2;
    if (gateGameBit <= EFFECTBOX_NO_GAME_BIT || placement->gameBitValue != mainGetBit(gateGameBit)) {
        yawCos = mathCosf((EFFECTBOX_PI * (f32)(-(placement->rotYaw << 8))) / EFFECTBOX_ANGLE_SCALE);
        yawSin = mathSinf((EFFECTBOX_PI * (f32)(-(placement->rotYaw << 8))) / EFFECTBOX_ANGLE_SCALE);
        pitchCos = mathCosf((EFFECTBOX_PI * (f32)(-(placement->rotPitch << 8))) / EFFECTBOX_ANGLE_SCALE);
        pitchSin = mathSinf((EFFECTBOX_PI * (f32)(-(placement->rotPitch << 8))) / EFFECTBOX_ANGLE_SCALE);
        extentX = placement->extentX;
        extentY = (f32)(placement->extentY << 1);
        extentZ = placement->extentZ;
        switch (placement->targetMode) {
        case EFFECTBOX_TARGET_PLAYER:
            singleTarget = Obj_GetPlayerObject();
            if (singleTarget == NULL) {
                return;
            }
            targets = &singleTarget;
            targetCount = 1;
            break;
        case EFFECTBOX_TARGET_TRICKY:
            singleTarget = getTrickyObject();
            if (singleTarget == NULL) {
                return;
            }
            targets = &singleTarget;
            targetCount = 1;
            break;
        case EFFECTBOX_TARGET_GROUP:
            targets = (GameObject**)objGetAllOfType(EFFECTBOX_TARGET_OBJECT_GROUP, &targetCount);
            if (targets == NULL) {
                return;
            }
            break;
        }
        targetIndex = 0;
        negativeExtentX = -extentX;
        negativeExtentZ = -extentZ;
        for (; targetIndex < targetCount; targetIndex++) {
            target = targets[targetIndex];
            offsetX = target->anim.localPosX;
            offsetY = target->anim.localPosY;
            offsetZ = target->anim.localPosZ;
            offsetX -= obj->anim.localPosX;
            offsetY -= obj->anim.localPosY;
            offsetZ -= obj->anim.localPosZ;
            projection = offsetX * yawCos + offsetZ * yawSin;
            if (projection > negativeExtentX && projection < extentX) {
                projection = (-offsetX) * yawSin + offsetZ * yawCos;
                projection = (-offsetY) * pitchSin + projection * pitchCos;
                if (projection > negativeExtentZ && projection < extentZ) {
                    projection = offsetY * pitchCos + projection * pitchSin;
                    if (projection >= EFFECTBOX_ZERO && projection < extentY) {
                        switch (placement->targetMode) {
                        case EFFECTBOX_TARGET_TRICKY:
                            break;
                        case EFFECTBOX_TARGET_PLAYER:
                            playerSetStateValue(target, EFFECTBOX_PLAYER_ACTION, (f32)placement->actionArg);
                            break;
                        case EFFECTBOX_TARGET_GROUP:
                            ((EffectBoxTargetInterface*)*target->anim.dll)->applyAction(target, placement->actionArg);
                            break;
                        }
                    }
                }
            }
        }
    }
}

void EffectBox_init(GameObject* obj, EffectBoxPlacement* placement) {
    s16 gateGameBit;
    u32 objectFlags;

    if (obj->userData1 == 0) {
        Obj_RegisterEffectBox(obj);
    }
    obj->userData1 = 1;
    gateGameBit = placement->gameBitIndex;
    if (gateGameBit > EFFECTBOX_NO_GAME_BIT) {
        obj->userData2 = gateGameBit;
    } else {
        obj->userData2 = EFFECTBOX_NO_GAME_BIT;
    }
    objectFlags = obj->objectFlags | (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED);
    obj->objectFlags = objectFlags;
}

void EffectBox_release(void) {
}

void EffectBox_initialise(void) {
}

ObjectDescriptor gEffectBoxObjDescriptor = {
    0,                                                   /* reserved0 */
    0,                                                   /* reserved1 */
    0,                                                   /* reserved2 */
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,                    /* slotCountAndFlags */
    (ObjectDescriptorCallback)EffectBox_initialise,      /* initialise */
    (ObjectDescriptorCallback)EffectBox_release,         /* release */
    0,                                                   /* slot02 */
    (ObjectDescriptorCallback)EffectBox_init,            /* init */
    (ObjectDescriptorCallback)EffectBox_update,          /* update */
    (ObjectDescriptorCallback)EffectBox_hitDetect,       /* hitDetect */
    (ObjectDescriptorCallback)EffectBox_render,          /* render */
    (ObjectDescriptorCallback)EffectBox_free,            /* free */
    (ObjectDescriptorCallback)EffectBox_getObjectTypeId, /* getObjectTypeId */
    EffectBox_getExtraSize,                              /* getExtraSize */
};
