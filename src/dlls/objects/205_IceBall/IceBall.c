/*
 * IceBall (DLL slot 205) - projectile shared by several enemy variants.
 *
 * The projectile applies gravity and drag until it hits a character or
 * surface. An impact hides it, emits variant-specific particles, and leaves a
 * short camera-shake cooldown before the object is freed.
 */
#include "dlls/objects/208_Grimble.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/camera.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#include "main/obj_list.h"
#include "sys/objects.h"
#include "main/audio/sfx_play_api.h"
#include "main/objhits.h"
#include "sys/objects/lifecycle.h"
#include "dlls/objects/205_IceBall.h"

#define ICEBALL_HIT_VOLUME_SLOT 10
#define ICEBALL_PARTICLE_COUNT  25
#define ICEBALL_LIFETIME_FRAMES 180
#define ICEBALL_IMPACT_FRAMES   120
#define ICEBALL_GRAVITY         0.07f
#define ICEBALL_DRAG            0.97f
#define ICEBALL_SPIN_STEP       910
#define ICEBALL_HIT_RADIUS      5

#define ICEBALL_MSG_NOTIFY_OWNER            0x80 /* callback message sent to the active owner on impact */
#define ICEBALL_OWNER_CALLBACK_2CB_OFFSET   0x20
#define ICEBALL_OWNER_CALLBACK_OTHER_OFFSET 0x24

typedef void (*IceBallOwnerCallback)(GameObject* owner, int message);
typedef void (*IceBallOwnerCallbackWithArg)(GameObject* owner, int message, int arg);

static inline u8 iceBall_isOwnerActive(GameObject* owner) {
    int objectIndex;
    int objectCount;
    GameObject** objects = ObjList_GetObjects(&objectIndex, &objectCount);

    while (objectIndex < objectCount) {
        if (owner == objects[objectIndex++]) {
            return 1;
        }
    }
    return 0;
}

void iceBall_handleSurfaceImpact(GameObject* obj) {
    s16 sequenceId = obj->anim.romDefNo;
    int particleIndex;

    if (sequenceId == 0x2cb) {
        for (particleIndex = 0; particleIndex < ICEBALL_PARTICLE_COUNT; particleIndex++) {
            (*gPartfxInterface)->spawnObject((void*)obj, 834, NULL, 1, -1, NULL);
        }
    } else if (sequenceId == 100 || sequenceId == 0x30a) {
        for (particleIndex = 0; particleIndex < ICEBALL_PARTICLE_COUNT; particleIndex++) {
            (*gPartfxInterface)->spawnObject((void*)obj, 836, NULL, 1, -1, NULL);
        }
    }

    Sfx_PlayFromObject(obj, SFXTRIG_mn_lummy311_26a);
    CameraShake_Enable();
    CameraShake_SetOffset(1.0f);
}

void iceBall_handleCharacterImpact(GameObject* obj) {
    s16 sequenceId;
    int particleIndex;

    CameraShake_Enable();
    CameraShake_SetOffset(1.0f);
    Sfx_PlayFromObject(obj, SFXTRIG_mn_lummy311_26a);
    sequenceId = obj->anim.romDefNo;
    if (sequenceId == 0x2cb) {
        if (obj->ownerObj != NULL) {
            if (iceBall_isOwnerActive(obj->ownerObj)) {
                (*(IceBallOwnerCallback*)((u8*)*((GameObject*)obj->ownerObj)->anim.dll +
                                          ICEBALL_OWNER_CALLBACK_2CB_OFFSET))((GameObject*)obj->ownerObj,
                                                                              ICEBALL_MSG_NOTIFY_OWNER);
            }
        }
        for (particleIndex = 0; particleIndex < ICEBALL_PARTICLE_COUNT; particleIndex++) {
            (*gPartfxInterface)->spawnObject((void*)obj, 832, NULL, 1, -1, NULL);
        }
    } else if (sequenceId == 100) {
        if (obj->ownerObj != NULL) {
            if (iceBall_isOwnerActive(obj->ownerObj)) {
                (*(IceBallOwnerCallback*)((u8*)*((GameObject*)obj->ownerObj)->anim.dll +
                                          ICEBALL_OWNER_CALLBACK_OTHER_OFFSET))((GameObject*)obj->ownerObj,
                                                                                ICEBALL_MSG_NOTIFY_OWNER);
            }
        }
        for (particleIndex = 0; particleIndex < ICEBALL_PARTICLE_COUNT; particleIndex++) {
            (*gPartfxInterface)->spawnObject((void*)obj, 835, NULL, 1, -1, NULL);
        }
    } else if (sequenceId == 0x30a) {
        if (obj->ownerObj != NULL) {
            if (iceBall_isOwnerActive(obj->ownerObj)) {
                (*(IceBallOwnerCallbackWithArg*)((u8*)*((GameObject*)obj->ownerObj)->anim.dll +
                                                 ICEBALL_OWNER_CALLBACK_OTHER_OFFSET))((GameObject*)obj->ownerObj,
                                                                                       ICEBALL_MSG_NOTIFY_OWNER, 0);
            }
        }
        for (particleIndex = 0; particleIndex < ICEBALL_PARTICLE_COUNT; particleIndex++) {
            (*gPartfxInterface)->spawnObject((void*)obj, 835, NULL, 1, -1, NULL);
        }
    }
}

int IceBall_getExtraSize(void) {
    return 2;
}

int IceBall_getObjectTypeId(void) {
    return 0;
}

void IceBall_free(GameObject* obj) {
    (void)obj;

    CameraShake_Disable();
}

void IceBall_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible) {
    s32 visible32 = visible;

    if (visible32 != 0) {
        objRenderModelAndHitVolumes(obj, fwdArg2, fwdArg3, fwdArg4, fwdArg5, 1.0f);
    }
}

void IceBall_hitDetect(GameObject* obj) {
    (void)obj;
}

void IceBall_update(GameObject* obj) {
    GameObject* objAddress;

    objAddress = obj;
    objAddress->userData1 = (s32)((f32)objAddress->userData1 - timeDelta);
    if (objAddress->userData1 < 0) {
        Obj_FreeObject(objAddress);
        return;
    }
    if (objAddress->anim.alpha == 0) {
        return;
    }
    objAddress->anim.velocityY -= ICEBALL_GRAVITY * timeDelta;
    objAddress->anim.velocityY *= ICEBALL_DRAG;
    objAddress->anim.rotX += ICEBALL_SPIN_STEP;
    objAddress->anim.rotZ += ICEBALL_SPIN_STEP;
    objAddress->anim.rotY += ICEBALL_SPIN_STEP;
    objMove(objAddress, objAddress->anim.velocityX * timeDelta, objAddress->anim.velocityY * timeDelta,
            objAddress->anim.velocityZ * timeDelta);
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)objAddress, ICEBALL_HIT_VOLUME_SLOT, 1, 0);
    ObjHitbox_SetSphereRadius((ObjAnimComponent*)objAddress, ICEBALL_HIT_RADIUS);
    ObjHits_EnableObject(objAddress);
    if (((ObjHitsPriorityState*)objAddress->anim.hitReactState)->lastHitObject != 0 &&
        (((ObjHitsPriorityState*)objAddress->anim.hitReactState)->lastHitObject ==
             (u32)Obj_GetPlayerObject() ||
         ((ObjHitsPriorityState*)objAddress->anim.hitReactState)->lastHitObject ==
             (u32)getTrickyObject())) {
        iceBall_handleCharacterImpact(objAddress);
        objAddress->anim.alpha = 0;
        objAddress->userData1 = ICEBALL_IMPACT_FRAMES;
        ((ObjHitsPriorityState*)objAddress->anim.hitReactState)->flags &=
            ~OBJHITS_PRIORITY_STATE_ENABLED;
    } else if (((ObjHitsPriorityState*)objAddress->anim.hitReactState)->contactFlags != 0) {
        iceBall_handleSurfaceImpact(objAddress);
        objAddress->anim.alpha = 0;
        objAddress->userData1 = ICEBALL_IMPACT_FRAMES;
        ((ObjHitsPriorityState*)objAddress->anim.hitReactState)->flags &=
            ~OBJHITS_PRIORITY_STATE_ENABLED;
    }
}

void IceBall_init(GameObject* obj) {
    obj->userData1 = ICEBALL_LIFETIME_FRAMES;
    ObjHits_DisableObject(obj);
    obj->anim.alpha = 0xff;
}

void IceBall_release(void) {
}

void IceBall_initialise(void) {
}

ObjectDescriptor gIceBallObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)IceBall_initialise,
    (ObjectDescriptorCallback)IceBall_release,
    0,
    (ObjectDescriptorCallback)IceBall_init,
    (ObjectDescriptorCallback)IceBall_update,
    (ObjectDescriptorCallback)IceBall_hitDetect,
    (ObjectDescriptorCallback)IceBall_render,
    (ObjectDescriptorCallback)IceBall_free,
    (ObjectDescriptorCallback)IceBall_getObjectTypeId,
    IceBall_getExtraSize,
};
