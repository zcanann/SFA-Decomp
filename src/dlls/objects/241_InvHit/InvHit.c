/*
 * InvHit (DLL 0xF1) - invisible hit-volume helper objects. One placement
 * definition drives several behaviours selected by InvHitState.mode
 * (placement byte 0x1A, modes 0..7):
 *   0  proximity damage: scan the player (and Tricky) and bump the
 *      hit-priority counters once they fall inside userData2 range.
 *   1  attach to an owner object's hit list (ObjList_ContainsObject).
 *   2  passive shape/radius hit volume.
 *   3  publish the object's world position to gInvHitPublishedPos while the
 *      player exists.
 *   4  homing/tethered projectile: ease toward the owner's target,
 *      clamp to a growing reach around an anchor, spawn fx, and snap to
 *      ground via trackGetHeight.
 *   5  like 3 but gated on the player having a lock-on target.
 *   6  fixed primary-radius hit volume.
 *   7  self-free once the owner's hit list no longer references it.
 * InvHit_free releases the expgfx source for mode 4.
 */
#include "dlls/objects/241_InvHit.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/dll/partfx_interface.h"
#include "main/dll/player_target.h"
#include "main/dll_000A_expgfx.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#include "main/objhits.h"
#include "main/track_dolphin_api.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/obj_list.h"

#define INVHIT_OBJECT_TYPE_ID 0
#define INVHIT_RENDER_SCALE   1.0f

#define INVHIT_PLAYER_CLASS_ID            1
#define INVHIT_STANDARD_HIT_FLAGS         0x45
#define INVHIT_HIT_MASK                   0x10
#define INVHIT_FIXED_RADIUS               0x23
#define INVHIT_HOMING_RADIUS              0xA
#define INVHIT_FIXED_HIT_PRIORITY         0xB
#define INVHIT_SELF_FREE_HIT_PRIORITY     0xA
#define INVHIT_ATTACH_HIT_PRIORITY        0x11
#define INVHIT_DEFAULT_HIT_VOLUME_ID      1
#define INVHIT_HOMING_LIFETIME            0x78
#define INVHIT_HOMING_SMOOTH_TIME         48.0f
#define INVHIT_HOMING_REACH_PADDING       10.0f
#define INVHIT_HOMING_GROUND_THRESHOLD    20.0f
#define INVHIT_HOMING_TRAIL_EFFECT_ID     0x25
#define INVHIT_HOMING_SECONDARY_EFFECT_ID 0x56

/* Published world position for modes 3 and 5. */
f32 gInvHitPublishedPos[4];

int InvHit_getExtraSize(void) {
    return sizeof(InvHitState);
}

int InvHit_getObjectTypeId(void) {
    return INVHIT_OBJECT_TYPE_ID;
}

void InvHit_free(GameObject* obj) {
    InvHitState* state = obj->extra;

    switch (state->mode) {
    case INVHIT_MODE_HOMING_PROJECTILE:
        (*gExpgfxInterface)->freeSource2((u32)obj);
        break;
    }
}

void InvHit_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5) {
    objRenderModelAndHitVolumes(obj, fwdArg2, fwdArg3, fwdArg4, fwdArg5, INVHIT_RENDER_SCALE);
}

void InvHit_hitDetect(void) {
}

ObjectDescriptor gInvHitObjDescriptor = {
    0,                                                /* reserved0 */
    0,                                                /* reserved1 */
    0,                                                /* reserved2 */
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,                 /* slotCountAndFlags */
    (ObjectDescriptorCallback)InvHit_initialise,      /* initialise */
    (ObjectDescriptorCallback)InvHit_release,         /* release */
    0,                                                /* slot02 */
    (ObjectDescriptorCallback)InvHit_init,            /* init */
    (ObjectDescriptorCallback)InvHit_update,          /* update */
    (ObjectDescriptorCallback)InvHit_hitDetect,       /* hitDetect */
    (ObjectDescriptorCallback)InvHit_render,          /* render */
    (ObjectDescriptorCallback)InvHit_free,            /* free */
    (ObjectDescriptorCallback)InvHit_getObjectTypeId, /* getObjectTypeId */
    InvHit_getExtraSize,                              /* getExtraSize */
};

void InvHit_update(GameObject* obj) {
    InvHitState* state = obj->extra;
    GameObject* target;
    obj->anim.previousLocalPosX = obj->anim.localPosX;
    obj->anim.previousLocalPosY = obj->anim.localPosY;
    obj->anim.previousLocalPosZ = obj->anim.localPosZ;
    switch (state->mode) {
    case INVHIT_MODE_PROXIMITY_DAMAGE: {
        GameObject* victim = Obj_GetPlayerObject();
        while (victim != NULL) {
            f32 deltaX = obj->anim.localPosX - victim->anim.localPosX;
            f32 deltaY = obj->anim.localPosY - victim->anim.localPosY;
            f32 deltaZ = obj->anim.localPosZ - victim->anim.localPosZ;
            f32 distance = sqrtf(deltaX * deltaX + deltaY * deltaY + deltaZ * deltaZ);
            if (distance < (f32)obj->userData2) {
                ObjHitsPriorityState* victimHits = (ObjHitsPriorityState*)victim->anim.hitReactState;
                victimHits->priorityHitCount += 1;
                victimHits->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
                ((ObjHitsPriorityState*)obj->anim.hitReactState)->priorityHitCount += 1;
            }
            if (victim->anim.classId == INVHIT_PLAYER_CLASS_ID) {
                victim = getTrickyObject();
            } else {
                victim = NULL;
            }
        }
        break;
    }
    case INVHIT_MODE_PUBLISH_POS:
        if (Obj_GetPlayerObject() != NULL) {
            gInvHitPublishedPos[0] = obj->anim.worldPosX;
            gInvHitPublishedPos[1] = obj->anim.worldPosY;
            gInvHitPublishedPos[2] = obj->anim.worldPosZ;
        }
        break;
    case INVHIT_MODE_LOCKON_GATE: {
        GameObject* player = Obj_GetPlayerObject();
        u32 targetAddress = Player_GetTargetObject((int)player);
        if (player != NULL && targetAddress != 0) {
            gInvHitPublishedPos[0] = obj->anim.worldPosX;
            gInvHitPublishedPos[1] = obj->anim.worldPosY;
            gInvHitPublishedPos[2] = obj->anim.worldPosZ;
        }
        break;
    }
    case INVHIT_MODE_ATTACH:
        ObjList_ContainsObject((GameObject*)obj->userData1);
        break;
    case INVHIT_MODE_SELF_FREE: {
        ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
        ObjHitsPriorityState* ownerHitState = (ObjHitsPriorityState*)((GameObject*)obj->userData1)->anim.hitReactState;
        int ownerHitIndex;

        for (ownerHitIndex = 0; ownerHitIndex < ownerHitState->priorityHitCount; ownerHitIndex++) {
            if ((GameObject*)ownerHitState->hitObjects[ownerHitIndex] == obj) {
                hitState->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
                Obj_FreeObject(obj);
            }
        }
        break;
    }
    case INVHIT_MODE_HOMING_PROJECTILE: {
        ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
        TrackGroundHit** hits[2];
        f32 anchorDeltaX;
        f32 anchorDeltaZ;
        f32 maxReach;
        int groundHitCount;
        f32 groundThreshold;
        int groundHitIndex;

        obj->userData2 -= framesThisStep;
        if (hitState->lastHitObject != 0) {
            hitState->flags = 0;
        }
        target = (GameObject*)obj->userData1;
        if (target != NULL) {
            f32 targetDeltaX;
            f32 targetDeltaZ;
            f32 smoothTime;
            f32 step;
            f32 anchorDistance;

            if (ObjList_ContainsObject(target) == 0) {
                break;
            }
            targetDeltaX = target->anim.localPosX - obj->anim.localPosX;
            targetDeltaZ = target->anim.localPosZ - obj->anim.localPosZ;
            smoothTime = INVHIT_HOMING_SMOOTH_TIME;
            step = targetDeltaX / smoothTime;
            obj->anim.localPosX = step * timeDelta + obj->anim.localPosX;
            step = targetDeltaZ / smoothTime;
            obj->anim.localPosZ = step * timeDelta + obj->anim.localPosZ;
            targetDeltaX = target->anim.localPosX - state->anchorX;
            targetDeltaZ = target->anim.localPosZ - state->anchorZ;
            maxReach = INVHIT_HOMING_REACH_PADDING + sqrtf(targetDeltaX * targetDeltaX + targetDeltaZ * targetDeltaZ);
            anchorDeltaX = obj->anim.localPosX - state->anchorX;
            anchorDeltaZ = obj->anim.localPosZ - state->anchorZ;
            anchorDistance = sqrtf(anchorDeltaX * anchorDeltaX + anchorDeltaZ * anchorDeltaZ);
            if (anchorDistance > maxReach) {
                f32 reachScale = maxReach / anchorDistance;
                anchorDeltaX *= reachScale;
                anchorDeltaZ *= reachScale;
                obj->anim.localPosX = state->anchorX + anchorDeltaX;
                obj->anim.localPosZ = state->anchorZ + anchorDeltaZ;
            }
            (*gPartfxInterface)->spawnObject(obj, INVHIT_HOMING_TRAIL_EFFECT_ID, NULL, 0, -1, NULL);
            (*gPartfxInterface)->spawnObject(obj, INVHIT_HOMING_SECONDARY_EFFECT_ID, NULL, 0, -1, NULL);
        }
        {
            s8 hitCount =
                (s8)trackGetHeight(obj, obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, hits, 0, 0);
            groundHitIndex = 0;
            groundHitCount = hitCount;
        }
        groundThreshold = INVHIT_HOMING_GROUND_THRESHOLD;
        for (; groundHitIndex < groundHitCount; groundHitIndex++) {
            f32 groundHeight = hits[0][groundHitIndex]->height;
            f32 objectY = obj->anim.localPosY;
            if (groundHeight < groundThreshold + objectY && groundHeight > objectY - groundThreshold) {
                obj->anim.localPosY = groundHeight;
                groundHitIndex = groundHitCount;
            }
        }
        break;
    }
    }
}

void InvHit_init(GameObject* obj, InvHitObjectDef* setup) {
    InvHitState* state = obj->extra;
    ObjHitsPriorityState* hitState;

    state->mode = setup->mode;
    hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
    hitState->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
    switch (state->mode) {
    case INVHIT_MODE_PROXIMITY_DAMAGE:
        obj->userData2 = setup->radius;
        break;
    case INVHIT_MODE_FIXED_RADIUS:
        hitState->shapeFlags = OBJHITS_SHAPE_SPHERE;
        hitState->primaryRadius = INVHIT_FIXED_RADIUS;
        hitState->flags |= INVHIT_STANDARD_HIT_FLAGS;
        hitState->hitVolumePriority = INVHIT_FIXED_HIT_PRIORITY;
        hitState->hitVolumeId = INVHIT_DEFAULT_HIT_VOLUME_ID;
        hitState->activeHitboxMode = 0;
        hitState->resetHitboxMode = 0;
        hitState->objectHitMask = INVHIT_HIT_MASK;
        hitState->skeletonHitMask = INVHIT_HIT_MASK;
        hitState->lateralResponseWeight = 0;
        hitState->axialResponseWeight = 0;
        break;
    case INVHIT_MODE_PUBLISH_POS:
        obj->userData2 = setup->radius;
        obj->userData1 = 0;
        break;
    case INVHIT_MODE_LOCKON_GATE:
        obj->userData2 = setup->radius;
        obj->userData1 = 0;
        break;
    case INVHIT_MODE_SELF_FREE:
        hitState->shapeFlags = OBJHITS_SHAPE_SPHERE;
        hitState->primaryRadius = setup->radius;
        hitState->flags |= INVHIT_STANDARD_HIT_FLAGS;
        hitState->activeHitboxMode = 0;
        hitState->hitVolumePriority = INVHIT_SELF_FREE_HIT_PRIORITY;
        hitState->hitVolumeId = 0;
        hitState->resetHitboxMode = 0;
        hitState->objectHitMask = INVHIT_HIT_MASK;
        hitState->skeletonHitMask = INVHIT_HIT_MASK;
        hitState->lateralResponseWeight = 0;
        hitState->axialResponseWeight = 0;
        break;
    case INVHIT_MODE_ATTACH:
        hitState->shapeFlags = OBJHITS_SHAPE_SPHERE;
        hitState->primaryRadius = setup->radius;
        hitState->flags |= INVHIT_STANDARD_HIT_FLAGS;
        hitState->activeHitboxMode = 0;
        hitState->hitVolumePriority = INVHIT_FIXED_HIT_PRIORITY;
        hitState->hitVolumeId = INVHIT_DEFAULT_HIT_VOLUME_ID;
        hitState->resetHitboxMode = 0;
        hitState->hitVolumePriority = INVHIT_ATTACH_HIT_PRIORITY;
        hitState->hitVolumeId = INVHIT_DEFAULT_HIT_VOLUME_ID;
        hitState->objectHitMask = INVHIT_HIT_MASK;
        hitState->skeletonHitMask = INVHIT_HIT_MASK;
        hitState->lateralResponseWeight = 0;
        hitState->axialResponseWeight = 0;
        break;
    case INVHIT_MODE_PASSIVE_VOLUME:
        hitState->shapeFlags = setup->shapeFlags;
        hitState->primaryRadius = setup->radius;
        hitState->flags |= OBJHITS_PRIORITY_STATE_ENABLED;
        hitState->activeHitboxMode = 0;
        hitState->resetHitboxMode = 0;
        hitState->lateralResponseWeight = 0;
        hitState->axialResponseWeight = 0;
        break;
    case INVHIT_MODE_HOMING_PROJECTILE:
        hitState->shapeFlags = OBJHITS_SHAPE_SPHERE;
        hitState->primaryRadius = INVHIT_HOMING_RADIUS;
        hitState->flags = OBJHITS_PRIORITY_STATE_ENABLED | OBJHITS_PRIORITY_STATE_NO_SEPARATION_RESPONSE;
        hitState->objectHitMask = INVHIT_HIT_MASK;
        obj->userData2 = INVHIT_HOMING_LIFETIME;
        {
            GameObject* anchorObj = *(GameObject**)&setup->anchorObj;
            if (anchorObj != NULL) {
                state->anchorX = anchorObj->anim.localPosX;
                state->anchorZ = (*(GameObject**)&setup->anchorObj)->anim.localPosZ;
            }
        }
        break;
    }
    obj->objectFlags |= (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED);
}

void InvHit_release(void) {
}

void InvHit_initialise(void) {
}
