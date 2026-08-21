/*
 * Pollen object (DLL slot 217).
 *
 * Simulates a drifting pollen mote, handles its collision response, and
 * spawns pollen fragments when its vertical motion crosses zero.
 */
#include "dlls/objects/217_Pollen.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/camera.h"
#include "main/dll/partfx_interface.h"
#include "main/dll/dll_00DA_pollenfragment_api.h"
#include "main/dll_000A_expgfx.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/audio/sfx_play_api.h"
#include "main/objhits.h"
#include "main/vecmath.h"

#define POLLEN_FRAGMENT_SETUP_SIZE          0x24
#define POLLEN_FRAGMENT_SETUP_KIND          5
#define POLLEN_FRAGMENT_BURST_COUNTER_START 5
#define POLLEN_FRAGMENT_RANDOM_ANGLE_MAX    0xffff
#define POLLEN_FRAGMENT_RANDOM_OFFSET_MIN   -50
#define POLLEN_FRAGMENT_RANDOM_OFFSET_MAX   50

#define POLLEN_HIT_VOLUME_SLOT             22
#define POLLEN_HITBOX_RADIUS               7
#define POLLEN_MOTE_PARTICLE_COUNTER_START 2
#define POLLEN_DESPAWN_DELAY               60
#define POLLEN_GRAVITY                     0.045f
#define POLLEN_PARTFX_MOTE                 0x4ba
#define POLLEN_MODEL_FLAGS                 0x810

ObjectDescriptor gPollenObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)Pollen_initialise,
    (ObjectDescriptorCallback)Pollen_release,
    0,
    (ObjectDescriptorCallback)Pollen_init,
    (ObjectDescriptorCallback)Pollen_update,
    (ObjectDescriptorCallback)Pollen_hitDetect,
    (ObjectDescriptorCallback)Pollen_render,
    (ObjectDescriptorCallback)Pollen_free,
    (ObjectDescriptorCallback)Pollen_getObjectTypeId,
    Pollen_getExtraSize,
};

int Pollen_getExtraSize(void) {
    return sizeof(PollenState);
}

int Pollen_getObjectTypeId(void) {
    return 0;
}

void Pollen_free(GameObject* obj) {
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void Pollen_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible) {
    s32 visible32 = visible;

    if (visible32 != 0) {
        objRenderModelAndHitVolumes(obj, fwdArg2, fwdArg3, fwdArg4, fwdArg5, 1.0f);
    }
}

void Pollen_hitDetect(GameObject* obj) {
    if (((ObjHitsPriorityState*)obj->anim.hitReactState)->contactFlags != 0) {
        f32 zeroVelocity;
        obj->anim.localPosX = ((ObjHitsPriorityState*)obj->anim.hitReactState)->contactPosX;
        obj->anim.localPosY = ((ObjHitsPriorityState*)obj->anim.hitReactState)->contactPosY;
        obj->anim.localPosZ = ((ObjHitsPriorityState*)obj->anim.hitReactState)->contactPosZ;
        zeroVelocity = 0.0f;
        obj->anim.velocityX = zeroVelocity;
        obj->anim.velocityY = zeroVelocity;
        obj->anim.velocityZ = zeroVelocity;
        obj->anim.alpha = 0;
        ObjHits_DisableObject(obj);
    }
}

void Pollen_update(GameObject* obj) {
    PollenState* state;
    int particleCounter;

    state = obj->extra;
    if (state->despawnTimer != 0) {
        state->despawnTimer -= 1;
    } else {
        f32 previousVelocityY = obj->anim.velocityY;
        obj->anim.velocityY = -(POLLEN_GRAVITY * timeDelta - previousVelocityY);
        if (previousVelocityY >= 0.0f && obj->anim.velocityY <= 0.0f) {
            Pollen_burst(obj);
            Sfx_PlayFromObject(obj, SFXTRIG_majring2);
            obj->anim.alpha = 0;
        }
        objMove(obj, obj->anim.velocityX * timeDelta, obj->anim.velocityY * timeDelta, obj->anim.velocityZ * timeDelta);
        ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, POLLEN_HIT_VOLUME_SLOT, 1, 0);
        ObjHitbox_SetSphereRadius((ObjAnimComponent*)obj, POLLEN_HITBOX_RADIUS);
        ObjHits_EnableObject(obj);
        if (((ObjHitsPriorityState*)obj->anim.hitReactState)->lastHitObject != 0 &&
            (((ObjHitsPriorityState*)obj->anim.hitReactState)->lastHitObject == (u32)Obj_GetPlayerObject() ||
             ((ObjHitsPriorityState*)obj->anim.hitReactState)->lastHitObject == (u32)getTrickyObject())) {
            CameraShake_Enable();
            CameraShake_SetOffset(1.0f);
            Sfx_PlayFromObject(obj, SFXTRIG_id_b6);
            obj->anim.alpha = 0;
            state->despawnTimer = POLLEN_DESPAWN_DELAY;
            ObjHits_DisableObject(obj);
        }
        if (obj->anim.alpha == 0xff) {
            particleCounter = POLLEN_MOTE_PARTICLE_COUNTER_START;
            do {
                (*gPartfxInterface)->spawnObject((void*)obj, POLLEN_PARTFX_MOTE, NULL, 1, -1, NULL);
            } while (particleCounter-- != 0);
        }
    }
    if (obj->anim.alpha == 0 && state->despawnTimer == 0) {
        Obj_FreeObject(obj);
    }
}

u8 Pollen_burst(GameObject* obj) {
    int burstCounter;
    PollenState* state;
    ObjPlacement* fragmentSetup;
    GameObject* fragment;
    u8 loadingLocked;

    state = obj->extra;
    loadingLocked = Obj_CanSetupObject();
    if (loadingLocked == 0) {
        return loadingLocked;
    }
    burstCounter = POLLEN_FRAGMENT_BURST_COUNTER_START;
    do {
        fragmentSetup = Obj_AllocObjectSetup(POLLEN_FRAGMENT_SETUP_SIZE, POLLEN_FRAGMENT_OBJECT_ID);
        fragmentSetup->posX = obj->anim.localPosX;
        fragmentSetup->posY = obj->anim.localPosY;
        fragmentSetup->posZ = obj->anim.localPosZ;
        fragmentSetup->color[0] = 1;
        fragmentSetup->color[1] = 1;
        fragmentSetup->color[2] = 0xff;
        fragmentSetup->color[3] = 0xff;
        fragment = objSetupObject(fragmentSetup, POLLEN_FRAGMENT_SETUP_KIND, -1, -1, NULL);
        if (fragment != NULL) {
            fragment->anim.rotY = 0;
            fragment->anim.rotX = randomGetRange(0, POLLEN_FRAGMENT_RANDOM_ANGLE_MAX);
            fragment->anim.velocityX =
                0.03f * (f32)(s32)randomGetRange(POLLEN_FRAGMENT_RANDOM_OFFSET_MIN, POLLEN_FRAGMENT_RANDOM_OFFSET_MAX) +
                obj->anim.velocityX;
            fragment->anim.velocityY =
                0.01f * (f32)(s32)randomGetRange(POLLEN_FRAGMENT_RANDOM_OFFSET_MIN, POLLEN_FRAGMENT_RANDOM_OFFSET_MAX) +
                obj->anim.velocityY;
            fragment->anim.velocityZ =
                0.03f * (f32)(s32)randomGetRange(POLLEN_FRAGMENT_RANDOM_OFFSET_MIN, POLLEN_FRAGMENT_RANDOM_OFFSET_MAX) +
                obj->anim.velocityZ;
            fragment->ownerObj = obj;
        }
    } while (burstCounter-- != 0);
    state->despawnTimer = POLLEN_DESPAWN_DELAY;
}

void Pollen_init(GameObject* obj) {
    PollenState* state = obj->extra;
    state->phaseX = randomGetRange(-0x8000, 0x7fff);
    state->driftVelocity = 0.01f * (f32)(s32)randomGetRange(4000, 5000);
    state->phaseY = randomGetRange(-0x8000, 0x7fff);
    state->settleVelocity = 0.0f;
    state->phaseSpeed = randomGetRange(230, 500);
    state->unk10 = 0;
    state->despawnTimer = 0;
    obj->anim.alpha = 0xff;
    ObjHits_DisableObject(obj);
    {
        ObjModelState* modelStateAddress = obj->anim.modelState;
        if (modelStateAddress != NULL) {
            modelStateAddress->flags |= POLLEN_MODEL_FLAGS;
        }
    }
}

void Pollen_release(void) {
}

void Pollen_initialise(void) {
}
