/*
 * DLL 0x1DA moves a small physics object, reflects its velocity from world
 * geometry, and persists its resting position.
 */

#include "dlls/objects/474.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/vecmath_distance_api.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#include "main/track_bbox_api.h"
#include "main/track_dolphin_api.h"
#include "sys/objects.h"
#include "main/audio/sfx_play_api.h"
#include "main/dll/savegame_object_api.h"
#include "main/objhits.h"

int dll_1DA_getExtraSize(void) {
    return sizeof(Dll1DAState);
}

int dll_1DA_getObjectTypeId(void) {
    return 0;
}

void dll_1DA_free(void) {
}

void dll_1DA_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    s32 isVisible = visible;

    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void dll_1DA_hitDetect(GameObject* obj) {
    GameObject* hitObject;
    GameObject* player;
    f32 scale;
    int hitType = ObjHits_GetPriorityHit(obj, &hitObject, NULL, NULL);

    if (hitType == 0xE) {
        player = Obj_GetPlayerObject();
        (void)Vec_distance(&obj->anim.worldPosX, &player->anim.worldPosX);
        obj->anim.velocityX = hitObject->anim.velocityX * (scale = 0.5f);
        obj->anim.velocityZ = hitObject->anim.velocityZ * scale;
        Sfx_PlayFromObject(obj, SFXTRIG_en_birdymornin11_1f9);
    }
}

void dll_1DA_update(GameObject* obj) {
    Dll1DAState* state;
    f32 inverseVelocityX;
    f32 inverseVelocityY;
    f32 inverseVelocityZ;
    f32 collisionSpeed;
    f32 scale;
    f32 damping;
    f32 reflectedScale;
    int hitCount;
    TrackGroundHit** groundHits;
    int groundHitIndex;
    TrackLineIntersectResult collision;

    state = obj->extra;
    if (state->grounded != 0) {
        obj->anim.velocityX = obj->anim.velocityX * (scale = 0.85f);
        obj->anim.velocityZ = obj->anim.velocityZ * scale;
    } else {
        obj->anim.velocityX = obj->anim.velocityX * (scale = 0.9f);
        obj->anim.velocityZ = obj->anim.velocityZ * scale;
    }

    if (obj->anim.velocityX < 0.1f && obj->anim.velocityX > -0.1f && obj->anim.velocityZ < 0.1f &&
        obj->anim.velocityZ > -0.1f) {
        obj->anim.velocityX = (scale = 0.0f);
        obj->anim.velocityZ = scale;
    }

    objMove(obj, obj->anim.velocityX * timeDelta, 0.0f, obj->anim.velocityZ * timeDelta);
    hitCount = trackGetLineIntersect(&obj->anim.previousLocalPosX, &obj->anim.localPosX, 6.5f, 1, &collision, obj, 8, -1,
                                  0xff, 0);
    if (hitCount != 0) {
        inverseVelocityX = -obj->anim.velocityX;
        inverseVelocityY = -obj->anim.velocityY;
        inverseVelocityZ = -obj->anim.velocityZ;
        collisionSpeed = sqrtf(inverseVelocityZ * inverseVelocityZ +
                               (inverseVelocityX * inverseVelocityX + inverseVelocityY * inverseVelocityY));
        if (collisionSpeed != 0.0f) {
            f32 inverseSpeed = 1.0f / collisionSpeed;

            inverseVelocityX = inverseVelocityX * inverseSpeed;
            inverseVelocityY = inverseVelocityY * inverseSpeed;
            inverseVelocityZ = inverseVelocityZ * inverseSpeed;
        }

        reflectedScale = 2.0f * (inverseVelocityZ * collision.normalZ +
                                 (inverseVelocityX * collision.normalX + inverseVelocityY * collision.normalY));
        obj->anim.velocityX = collision.normalX * reflectedScale;
        obj->anim.velocityY = collision.normalY * reflectedScale;
        obj->anim.velocityZ = collision.normalZ * reflectedScale;
        obj->anim.velocityX = obj->anim.velocityX - inverseVelocityX;
        obj->anim.velocityY = obj->anim.velocityY - inverseVelocityY;
        obj->anim.velocityZ = obj->anim.velocityZ - inverseVelocityZ;
        obj->anim.velocityX = obj->anim.velocityX * (damping = 0.8f * collisionSpeed);
        obj->anim.velocityY = obj->anim.velocityY * (0.5f * collisionSpeed);
        obj->anim.velocityZ = obj->anim.velocityZ * damping;
    }

    obj->anim.localPosY = -(0.2f * timeDelta - obj->anim.localPosY);
    hitCount =
        trackGetHeight(obj, obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &groundHits, 0, 0x11);
    state->grounded = 0;
    groundHitIndex = 0;
    for (; hitCount > 0; hitCount--) {
        if (obj->anim.localPosY < 5.0f + groundHits[groundHitIndex]->height) {
            obj->anim.localPosY = groundHits[groundHitIndex]->height;
            ObjHits_AddContactObject(groundHits[groundHitIndex]->object, obj);
            state->grounded = 1;
            break;
        }
        groundHitIndex++;
    }

    if (obj->anim.localPosY < state->floorHeight) {
        obj->anim.localPosY = state->floorHeight;
    }

    saveGame_saveObjectPos(obj);
}

void dll_1DA_init(GameObject* obj) {
    Dll1DAState* state = obj->extra;

    state->floorHeight = obj->anim.localPosY;
    obj->anim.localPosY += 1.0f;
}

void dll_1DA_release(void) {
}

void dll_1DA_initialise(void) {
}

ObjectDescriptor gDll1DAObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll_1DA_initialise,
    (ObjectDescriptorCallback)dll_1DA_release,
    0,
    (ObjectDescriptorCallback)dll_1DA_init,
    (ObjectDescriptorCallback)dll_1DA_update,
    (ObjectDescriptorCallback)dll_1DA_hitDetect,
    (ObjectDescriptorCallback)dll_1DA_render,
    (ObjectDescriptorCallback)dll_1DA_free,
    (ObjectDescriptorCallback)dll_1DA_getObjectTypeId,
    dll_1DA_getExtraSize,
};
