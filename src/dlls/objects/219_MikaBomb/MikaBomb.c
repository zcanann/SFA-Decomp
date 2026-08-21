/*
 * MikaBomb object (DLL slot 219).
 *
 * Simulates a thrown bomb until it hits the player or its sampled ground
 * plane, then spawns an explosion effect and fades out.
 */
#include "dlls/objects/219_MikaBomb.h"
#include "dlls/objects/220_MikaBombShadow.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/camera_shake_api.h"
#include "main/dll/modgfx_interface.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#include "main/resource.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/track_dolphin_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/objhits.h"
#include "main/vecmath.h"

#define MIKABOMB_HIT_VOLUME_SLOT 5

#define MIKABOMB_CHILD_OBJ_SHADOW   0xc
#define MIKABOMB_SHADOW_SETUP_SIZE  0x20
#define MIKABOMB_EFFECT_RESOURCE_ID 0x5b

#define MIKABOMB_EXPLOSION_SPAWN_MIN    5
#define MIKABOMB_EXPLOSION_SPAWN_MAX    10
#define MIKABOMB_EXPLOSION_HITBOX_SCALE 5.0f
#define MIKABOMB_CAMERA_SHAKE_MAGNITUDE 3.0f
#define MIKABOMB_CAMERA_SHAKE_DURATION  10.0f
#define MIKABOMB_CAMERA_SHAKE_FALLOFF   6.0f

const Dll5BSpawnCountRange gMikaBombExplosionSpawnCountRange = {MIKABOMB_EXPLOSION_SPAWN_MIN,
                                                                MIKABOMB_EXPLOSION_SPAWN_MAX};

ObjectDescriptor gMikaBombObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)MikaBomb_initialise,
    (ObjectDescriptorCallback)MikaBomb_release,
    0,
    (ObjectDescriptorCallback)MikaBomb_init,
    (ObjectDescriptorCallback)MikaBomb_update,
    (ObjectDescriptorCallback)MikaBomb_hitDetect,
    (ObjectDescriptorCallback)MikaBomb_render,
    (ObjectDescriptorCallback)MikaBomb_free,
    (ObjectDescriptorCallback)MikaBomb_getObjectTypeId,
    MikaBomb_getExtraSize,
};

int MikaBomb_getExtraSize(void) {
    return sizeof(MikaBombState);
}

int MikaBomb_getObjectTypeId(void) {
    return 0;
}

void MikaBomb_free(GameObject* obj, int mode) {
    MikaBombState* state = obj->extra;
    if (state->shadowObj != NULL && mode == 0) {
        Obj_FreeObject(state->shadowObj);
        state->shadowObj = NULL;
    }
    (*gModgfxInterface)->detachSource((void*)obj);
}

void MikaBomb_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible) {
    s32 visible32 = visible;

    if (visible32 != 0) {
        objRenderModelAndHitVolumes(obj, fwdArg2, fwdArg3, fwdArg4, fwdArg5, gMikaBombRenderScale);
    }
}

void MikaBomb_hitDetect(GameObject* obj) {
    (void)obj;
}

void MikaBomb_update(GameObject* obj) {
    MikaBombState* state = obj->extra;
    u32 alpha = obj->anim.alpha;

    if (alpha < 0xff) {
        f32 alphaFloat = alpha;
        f32 fadeStep;
        if (alphaFloat - (fadeStep = gMikaBombFadeRate * timeDelta) > gMikaBombZero) {
            obj->anim.alpha = alpha - fadeStep;
        } else {
            Sfx_StopObjectChannel(obj, 0x7f);
            obj->anim.alpha = 0;
            Obj_FreeObject(obj);
            return;
        }
    } else {
        obj->anim.velocityY -= gMikaBombGravityAccel * timeDelta;
        if (obj->anim.velocityY < *(f32*)&gMikaBombMinFallVelocity) {
            obj->anim.velocityY = gMikaBombMinFallVelocity;
        }
        objMove(obj, obj->anim.velocityX * timeDelta, obj->anim.velocityY * timeDelta, obj->anim.velocityZ * timeDelta);
    }

    if (obj->anim.alpha == 0xff || state->exploded != 0) {
        Dll5BSpawnCountRange playerSpawnCountRange;
        Dll5BSpawnCountRange groundSpawnCountRange;
        ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, MIKABOMB_HIT_VOLUME_SLOT, 1, 0);
        ObjHits_EnableObject(obj);
        if (((ObjHitsPriorityState*)obj->anim.hitReactState)->lastHitObject != 0 &&
            ((ObjHitsPriorityState*)obj->anim.hitReactState)->lastHitObject == (u32)Obj_GetPlayerObject()) {
            if (obj->anim.alpha == 0xff) {
                MikaBombState* impactState = obj->extra;
                u32 effectId;
                playerSpawnCountRange = gMikaBombExplosionSpawnCountRange;
                Sfx_PlayFromObject(obj, SFXTRIG_dsmk2_c);
                effectId = randomGetRange(0, 2);
                (*impactState->resource)->spawn(obj, effectId, NULL, 2, -1, &playerSpawnCountRange);
                ObjHitbox_SetSphereRadius(
                    (ObjAnimComponent*)obj,
                    (s32)(MIKABOMB_EXPLOSION_HITBOX_SCALE * (f32)(u32)obj->anim.modelInstance->primaryHitboxRadius));
                CameraShake_StartDampened(MIKABOMB_CAMERA_SHAKE_MAGNITUDE, MIKABOMB_CAMERA_SHAKE_DURATION,
                                  MIKABOMB_CAMERA_SHAKE_FALLOFF);
                obj->anim.alpha = 0xfe;
                Obj_FreeObject(impactState->shadowObj);
                impactState->shadowObj = NULL;
            }
            ObjHits_DisableObject(obj);
        } else {
            if (obj->anim.localPosY <= state->groundY && obj->anim.alpha == 0xff) {
                MikaBombState* impactState = obj->extra;
                u32 effectId;
                groundSpawnCountRange = gMikaBombExplosionSpawnCountRange;
                Sfx_PlayFromObject(obj, SFXTRIG_dsmk2_c);
                effectId = randomGetRange(0, 2);
                (*impactState->resource)->spawn(obj, effectId, NULL, 2, -1, &groundSpawnCountRange);
                ObjHitbox_SetSphereRadius(
                    (ObjAnimComponent*)obj,
                    (s32)(MIKABOMB_EXPLOSION_HITBOX_SCALE * (f32)(u32)obj->anim.modelInstance->primaryHitboxRadius));
                CameraShake_StartDampened(MIKABOMB_CAMERA_SHAKE_MAGNITUDE, MIKABOMB_CAMERA_SHAKE_DURATION,
                                  MIKABOMB_CAMERA_SHAKE_FALLOFF);
                obj->anim.alpha = 0xfe;
                Obj_FreeObject(impactState->shadowObj);
                impactState->shadowObj = NULL;
                state->exploded = 1;
            }
        }
    }
}

void MikaBomb_init(GameObject* obj) {
    MikaBombState* state = obj->extra;
    f32 groundDistance;
    ObjPlacement* shadowSetup;
    f32 zeroVelocity;

    ObjHits_DisableObject(obj);
    obj->anim.alpha = 0xff;
    zeroVelocity = gMikaBombZero;
    obj->anim.velocityX = zeroVelocity;
    obj->anim.velocityY = gMikaBombInitialVelocityY;
    obj->anim.velocityZ = zeroVelocity;
    obj->anim.rotY = -0x4000;
    obj->anim.rotX = 0;
    obj->anim.rotZ = 0;
    trackGetHeightAboveGround(obj, obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &groundDistance, 0);
    state->groundY = obj->anim.localPosY - groundDistance;
    if (Obj_CanSetupObject() != 0) {
        shadowSetup = Obj_AllocObjectSetup(MIKABOMB_SHADOW_SETUP_SIZE, MIKABOMB_CHILD_OBJ_SHADOW);
        shadowSetup->posX = obj->anim.localPosX;
        shadowSetup->posY = obj->anim.localPosY;
        shadowSetup->posZ = obj->anim.localPosZ;
        shadowSetup->color[0] = 1;
        shadowSetup->color[1] = 1;
        shadowSetup->color[2] = 0xff;
        shadowSetup->color[3] = 0xff;
        state->shadowObj = loadObjectAtObject(obj, shadowSetup);
        state->shadowObj->ownerObj = obj;
    } else {
        state->shadowObj = NULL;
    }
    state->resource = Resource_Acquire(MIKABOMB_EFFECT_RESOURCE_ID, 1);
    state->exploded = 0;
}

void MikaBomb_release(void) {
}

void MikaBomb_initialise(void) {
}
