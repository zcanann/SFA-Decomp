/* DLL 0x19D (slot 413) - moving particle-effect object. */
#include "dlls/objects/413.h"

#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/partfx_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/frame_timing.h"
#include "main/objhits.h"
#include "main/audio/sfx_play_api.h"
#include "main/render_lactions_api.h"
#include "sys/objects/lifecycle.h"

#define DLL19D_HIT_VOLUME_SLOT              0xE
#define DLL19D_DEFAULT_HIT_TYPE             1
#define DLL19D_VARIANT_HIT_TYPE             3
#define DLL19D_PARTFX_IMPACT                0x2A0
#define DLL19D_PARTFX_TRAIL                 0x29D
#define DLL19D_PARTFX_PULSE_A               0x29E
#define DLL19D_PARTFX_PULSE_B               0x29F
#define DLL19D_PARTFX_PULSE_C               0x2A1
#define DLL19D_IMPACT_PARTFX_MODE           1
#define DLL19D_FLIGHT_PARTFX_MODE           4
#define DLL19D_IGNORED_HIT_SEQUENCE_ID      0x248
#define DLL19D_STOP_ACTION_ID               1
#define DLL19D_DEFAULT_ACTION_ID            0x201
#define DLL19D_VARIANT_ONE_ACTION_ID        0x203
#define DLL19D_VARIANT_TWO_ACTION_ID        0x204
#define DLL19D_EFFECT_TIMER_RESET           0x32
#define DLL19D_DESPAWN_TIMER_RESET          0x32
#define DLL19D_SPIN_PHASE_STEP              0x5DC
#define DLL19D_FLAG_POSITION_INITIALIZED    0x1
#define DLL19D_FLAG_STOP_ACTION_INITIALIZED 0x2

int dll413_getExtraSize(void) {
    return sizeof(Dll19DState);
}

int dll413_getObjectTypeId(void) {
    return 0;
}

void dll413_free(GameObject* obj) {
    Dll19DState* state = obj->extra;

    if ((state->flags & DLL19D_FLAG_STOP_ACTION_INITIALIZED) == 0) {
        getLActions(obj, obj, DLL19D_STOP_ACTION_ID, 0, 0, 0);
        state->flags |= DLL19D_FLAG_STOP_ACTION_INITIALIZED;
    }
    (*gExpgfxInterface)->freeSource2(obj);
}

void dll413_render(void) {
}

void dll413_hitDetect(GameObject* obj) {
    Dll19DState* state;
    const Dll19DPlacement* placement;
    ObjHitsPriorityState* hitState;
    PartFxSpawnParams spawnParams;
    GameObject* lastHitObject;

    state = obj->extra;
    placement = (const Dll19DPlacement*)obj->anim.placementData;
    spawnParams.posX = 0.0f;
    spawnParams.posY = 0.0f;
    spawnParams.posZ = 0.0f;
    spawnParams.scale = (f32)(int)placement->variant;

    hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
    lastHitObject = (GameObject*)hitState->lastHitObject;
    if (lastHitObject == NULL) {
        return;
    }
    if (lastHitObject->anim.romDefNo == DLL19D_IGNORED_HIT_SEQUENCE_ID) {
        return;
    }

    (*gPartfxInterface)->spawnEffect(obj, DLL19D_PARTFX_IMPACT, &spawnParams, DLL19D_IMPACT_PARTFX_MODE, -1, NULL);
    (*gPartfxInterface)->spawnEffect(obj, DLL19D_PARTFX_IMPACT, &spawnParams, DLL19D_IMPACT_PARTFX_MODE, -1, NULL);
    (*gPartfxInterface)->spawnEffect(obj, DLL19D_PARTFX_IMPACT, &spawnParams, DLL19D_IMPACT_PARTFX_MODE, -1, NULL);
    state->despawnTimer = DLL19D_DESPAWN_TIMER_RESET;
}

void dll413_update(GameObject* obj) {
    Dll19DState* state;
    const Dll19DPlacement* placement;
    ObjHitsPriorityState* hitState;
    PartFxSpawnParams spawnParams;
    int lifetime;
    u32 frames;
    f32 zero;

    state = obj->extra;
    placement = (const Dll19DPlacement*)obj->anim.placementData;
    spawnParams.posX = 0.0f;
    spawnParams.posY = 0.0f;
    spawnParams.posZ = 0.0f;
    spawnParams.scale = (f32)(int)placement->variant;

    if ((state->flags & DLL19D_FLAG_POSITION_INITIALIZED) == 0) {
        state->positionX = obj->anim.localPosX;
        state->positionY = obj->anim.localPosY;
        state->positionZ = obj->anim.localPosZ;
        state->flags |= DLL19D_FLAG_POSITION_INITIALIZED;
    }

    hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
    if (hitState->contactFlags != 0) {
        Sfx_PlayFromObject(obj, SFXTRIG_npu_216);
        (*gPartfxInterface)->spawnEffect(obj, DLL19D_PARTFX_IMPACT, &spawnParams, DLL19D_IMPACT_PARTFX_MODE, -1, NULL);
        (*gPartfxInterface)->spawnEffect(obj, DLL19D_PARTFX_IMPACT, &spawnParams, DLL19D_IMPACT_PARTFX_MODE, -1, NULL);
        (*gPartfxInterface)->spawnEffect(obj, DLL19D_PARTFX_IMPACT, &spawnParams, DLL19D_IMPACT_PARTFX_MODE, -1, NULL);
        state->despawnTimer = DLL19D_DESPAWN_TIMER_RESET;
    }

    if (state->despawnTimer != 0) {
        if ((state->flags & DLL19D_FLAG_STOP_ACTION_INITIALIZED) == 0) {
            getLActions(obj, obj, DLL19D_STOP_ACTION_ID, 0, 0, 0);
            state->flags |= DLL19D_FLAG_STOP_ACTION_INITIALIZED;
        }
        zero = 0.0f;
        obj->anim.velocityX = zero;
        obj->anim.velocityY = zero;
        obj->anim.velocityZ = zero;
        ObjHits_ClearHitVolumes(&obj->anim);
        state->despawnTimer -= 1;
        if (state->despawnTimer <= 0) {
            Obj_FreeObject(obj);
        }
    } else {
        obj->anim.previousLocalPosX = obj->anim.localPosX;
        obj->anim.previousLocalPosY = obj->anim.localPosY;
        obj->anim.previousLocalPosZ = obj->anim.localPosZ;

        obj->anim.rotX = (s16)(obj->anim.rotX + state->angularVelocityX * framesThisStep);
        obj->anim.rotZ = (s16)(obj->anim.rotZ + state->angularVelocityZ * framesThisStep);
        (*gPartfxInterface)->spawnEffect(obj, DLL19D_PARTFX_TRAIL, &spawnParams, DLL19D_FLIGHT_PARTFX_MODE, -1, NULL);

        if ((state->effectTimer -= framesThisStep) <= 0) {
            (*gPartfxInterface)
                ->spawnEffect(obj, DLL19D_PARTFX_PULSE_A, &spawnParams, DLL19D_FLIGHT_PARTFX_MODE, -1, NULL);
            (*gPartfxInterface)
                ->spawnEffect(obj, DLL19D_PARTFX_PULSE_B, &spawnParams, DLL19D_FLIGHT_PARTFX_MODE, -1, NULL);
            (*gPartfxInterface)
                ->spawnEffect(obj, DLL19D_PARTFX_PULSE_C, &spawnParams, DLL19D_FLIGHT_PARTFX_MODE, -1, NULL);
            state->effectTimer = DLL19D_EFFECT_TIMER_RESET;
        }

        state->positionX = obj->anim.velocityX * timeDelta + state->positionX;
        state->positionY = obj->anim.velocityY * timeDelta + state->positionY;
        state->positionZ = obj->anim.velocityZ * timeDelta + state->positionZ;
        state->spinPhase = state->spinPhase + framesThisStep * DLL19D_SPIN_PHASE_STEP;
        obj->anim.localPosX = state->positionX;
        obj->anim.localPosY = state->positionY;
        obj->anim.localPosZ = state->positionZ;

        frames = framesThisStep;
        lifetime = obj->userData1;
        obj->userData1 = lifetime - frames;
        if ((int)(lifetime - frames) < 0) {
            Obj_FreeObject(obj);
        }
    }
}

void dll413_init(GameObject* obj) {
    const Dll19DPlacement* placement;
    int hitType;

    placement = (const Dll19DPlacement*)obj->anim.placementData;

    if (placement->variant != 0) {
        hitType = DLL19D_VARIANT_HIT_TYPE;
    } else {
        hitType = DLL19D_DEFAULT_HIT_TYPE;
    }
    ObjHits_SetHitVolumeSlot(&obj->anim, DLL19D_HIT_VOLUME_SLOT, hitType, 0);

    if (placement->variant == 1) {
        getLActions(obj, obj, DLL19D_VARIANT_ONE_ACTION_ID, 0, 0, 0);
    } else if (placement->variant == 2) {
        getLActions(obj, obj, DLL19D_VARIANT_TWO_ACTION_ID, 0, 0, 0);
    } else {
        getLActions(obj, obj, DLL19D_DEFAULT_ACTION_ID, 0, 0, 0);
    }
}

void dll413_release(void) {
}

void dll413_initialise(void) {
}

ObjectDescriptor gDll19DObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll413_initialise,
    (ObjectDescriptorCallback)dll413_release,
    0,
    (ObjectDescriptorCallback)dll413_init,
    (ObjectDescriptorCallback)dll413_update,
    (ObjectDescriptorCallback)dll413_hitDetect,
    (ObjectDescriptorCallback)dll413_render,
    (ObjectDescriptorCallback)dll413_free,
    (ObjectDescriptorCallback)dll413_getObjectTypeId,
    dll413_getExtraSize,
};
