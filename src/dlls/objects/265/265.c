/*
 * DLL 0x109 - a "carryable that breaks and respawns" placed object.
 *
 * Driven by a carryable interface (gCarryableInterface). On a priority
 * hit while being carried it plays a break fx + sfx, sets a sphere
 * hitbox, and (when object loading is locked) drops a replacement setup
 * object at its position. It then disables itself, snaps back to its
 * placement position, and runs a respawn timer; once the timer expires
 * and the object is off-screen (frustum cull) it re-enables and resets.
 * Rendering is suppressed while broken or respawning (phase != 0), and
 * otherwise falls through to the carryable visibility test.
 */
#include "dlls/objects/265.h"

#include "dlls/objects/458_DIMExplosio.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/carryable_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/frustum.h"
#include "main/audio/sfx_play_api.h"
#include "main/objhits.h"

#define BREAKABLE_CARRYABLE_HIT_VOLUME_SLOT 5
#define BREAKABLE_CARRYABLE_HITBOX_RADIUS   0x28
#define BREAKABLE_CARRYABLE_HITBOX_TYPE     4

#define BREAKABLE_CARRYABLE_RESPAWN_DELAY 300.0f

#define BREAKABLE_CARRYABLE_EXPLOSION_SETUP_FLAGS 5
#define BREAKABLE_CARRYABLE_EFFECT_A_ID           0x355
#define BREAKABLE_CARRYABLE_EFFECT_B_ID           0x352
#define BREAKABLE_CARRYABLE_EFFECT_MODEL_ID       -1

#define BREAKABLE_CARRYABLE_INIT_ARG          0x21
#define BREAKABLE_CARRYABLE_ROTATION_SHIFT    8
#define BREAKABLE_CARRYABLE_SUPPRESS_POS_SAVE 1

int breakableCarryable_getExtraSize(void) {
    return sizeof(BreakableCarryableState);
}

int breakableCarryable_getObjectTypeId(void) {
    return 0;
}

void breakableCarryable_free(GameObject* obj) {
    (*gCarryableInterface)->free(obj);
}

void breakableCarryable_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    BreakableCarryableState* state = obj->extra;
    if (state->phase == BREAKABLE_CARRYABLE_PHASE_INTACT) {
        if ((*gCarryableInterface)->updateRenderState(obj, visible) != 0) {
            objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
        }
    }
}

void breakableCarryable_hitDetect(void) {
}

void breakableCarryable_update(GameObject* obj) {
    BreakableCarryableState* state;
    BreakableCarryablePlacement* placement;
    ObjPlacement* setup;
    u32 hitVolumeIndex;

    state = obj->extra;
    placement = (BreakableCarryablePlacement*)obj->anim.placementData;
    switch (state->phase) {
    case BREAKABLE_CARRYABLE_PHASE_INTACT:
        (*gCarryableInterface)->updateHeld(obj, state);
        if (ObjHits_GetPriorityHit(obj, NULL, NULL, &hitVolumeIndex) != 0) {
            (*gCarryableInterface)->stopCarrying(obj, state);
            Sfx_PlayFromObject(obj, SFXTRIG_crtsmsh6);
            ObjHitbox_SetSphereRadius((ObjAnimComponent*)obj, BREAKABLE_CARRYABLE_HITBOX_RADIUS);
            ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, BREAKABLE_CARRYABLE_HIT_VOLUME_SLOT,
                                     BREAKABLE_CARRYABLE_HITBOX_TYPE, 0);
            if (Obj_CanSetupObject() != 0) {
                setup = Obj_AllocObjectSetup(sizeof(DimExplosionPlacement), DIM_EXPLOSION_OBJECT_ID);
                setup->posX = obj->anim.localPosX;
                setup->posY = obj->anim.localPosY;
                setup->posZ = obj->anim.localPosZ;
                objSetupObject(setup, BREAKABLE_CARRYABLE_EXPLOSION_SETUP_FLAGS, obj->anim.mapEventSlot, -1,
                                obj->anim.parent);
            }
            (*gPartfxInterface)
                ->spawnObject(obj, BREAKABLE_CARRYABLE_EFFECT_A_ID, NULL, 0, BREAKABLE_CARRYABLE_EFFECT_MODEL_ID, NULL);
            (*gPartfxInterface)
                ->spawnObject(obj, BREAKABLE_CARRYABLE_EFFECT_B_ID, NULL, 0, BREAKABLE_CARRYABLE_EFFECT_MODEL_ID, NULL);
            state->phase = BREAKABLE_CARRYABLE_PHASE_BREAKING;
        }
        break;
    case BREAKABLE_CARRYABLE_PHASE_BREAKING:
        ObjHits_ClearHitVolumes((ObjAnimComponent*)obj);
        ObjHits_DisableObject(obj);
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        state->phase = BREAKABLE_CARRYABLE_PHASE_RESPAWNING;
        state->respawnTimer = 0.0f;
        obj->anim.localPosX = placement->base.posX;
        obj->anim.localPosY = placement->base.posY;
        obj->anim.localPosZ = placement->base.posZ;
        break;
    case BREAKABLE_CARRYABLE_PHASE_RESPAWNING:
        state->respawnTimer += timeDelta;
        if (state->respawnTimer > BREAKABLE_CARRYABLE_RESPAWN_DELAY) {
            if (ViewFrustum_IsSphereVisible(&obj->anim.localPosX, obj->anim.hitboxScale * obj->anim.rootMotionScale) ==
                0) {
                ObjHits_EnableObject(obj);
                obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
                state->phase = BREAKABLE_CARRYABLE_PHASE_INTACT;
            }
        }
        break;
    }
}

void breakableCarryable_init(GameObject* obj, BreakableCarryablePlacement* placement) {
    obj->anim.rotX = (s16)((s32)placement->rotXByte << BREAKABLE_CARRYABLE_ROTATION_SHIFT);
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
    (*gCarryableInterface)->init(obj, obj->extra, BREAKABLE_CARRYABLE_INIT_ARG);
    (*gCarryableInterface)->setSuppressPositionSave(obj->extra, BREAKABLE_CARRYABLE_SUPPRESS_POS_SAVE);
}

void breakableCarryable_release(void) {
}

void breakableCarryable_initialise(void) {
}

ObjectDescriptor gBreakableCarryableObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)breakableCarryable_initialise,
    (ObjectDescriptorCallback)breakableCarryable_release,
    0,
    (ObjectDescriptorCallback)breakableCarryable_init,
    (ObjectDescriptorCallback)breakableCarryable_update,
    (ObjectDescriptorCallback)breakableCarryable_hitDetect,
    (ObjectDescriptorCallback)breakableCarryable_render,
    (ObjectDescriptorCallback)breakableCarryable_free,
    (ObjectDescriptorCallback)breakableCarryable_getObjectTypeId,
    breakableCarryable_getExtraSize,
};
