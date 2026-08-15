/*
 * DIMWoodDoor (DLL 0x1CB) - a burnable wooden door object.
 *
 * The door advances its current move animation and offsets its local Z by a
 * speed that decays toward rest. Once opened, object type 0x338 fades past an
 * animation threshold; otherwise the door scans its proximity list for a
 * triggering sequence object, opens, sets its game bit, and plays a sound.
 */

#include "dlls/objects/459_DIMWoodDoor.h"

#include "dlls/objects/454_DIMCannon.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/object_render.h"

#define DIM_WOOD_DOOR_FADE_OBJECT_ID          0x338
#define DIM_WOOD_DOOR_SNOW_HORN_SEQUENCE_ID   0x18f
#define DIM_WOOD_DOOR_STATE_OPEN              0
#define DIM_WOOD_DOOR_STATE_CLOSED            3
#define DIM_WOOD_DOOR_ALPHA_FADE_PER_FRAME    16
#define DIM_WOOD_DOOR_RENDER_SCALE            1.0f
#define DIM_WOOD_DOOR_REST_SPEED              0.0f
#define DIM_WOOD_DOOR_RISE_SPEED_DECAY        0.95f
#define DIM_WOOD_DOOR_FADE_PROGRESS_THRESHOLD 0.9f
#define DIM_WOOD_DOOR_OPEN_ANIMATION_SPEED    0.025f
#define DIM_WOOD_DOOR_OPEN_RISE_SPEED         -4.0f

int dimwooddoor2_getExtraSize(void) {
    return sizeof(DimWoodDoorState);
}

int dimwooddoor2_getObjectTypeId(void) {
    return 0x0;
}

void dimwooddoor2_free(void) {
}

void dimwooddoor2_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    s32 visibleValue = visible;

    if (visibleValue != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, DIM_WOOD_DOOR_RENDER_SCALE);
    }
}

void dimwooddoor2_hitDetect(void) {
}

void dimwooddoor2_update(GameObject* obj) {
    const DimWoodDoorPlacement* placement = (const DimWoodDoorPlacement*)obj->anim.placementData;
    DimWoodDoorState* state = obj->extra;
    ObjHitsPriorityState* hitState;

    ObjAnim_AdvanceCurrentMove(obj, state->animationSpeed, timeDelta, 0);
    obj->anim.localPosZ = obj->anim.localPosZ + state->riseSpeed;
    {
        f32 riseSpeed = state->riseSpeed;
        f32 restSpeed = DIM_WOOD_DOOR_REST_SPEED;

        if (riseSpeed != restSpeed) {
            state->riseSpeed *= DIM_WOOD_DOOR_RISE_SPEED_DECAY;
            state->riseSpeed = (state->riseSpeed < restSpeed) ? state->riseSpeed : restSpeed;
        }
    }
    if (state->doorState <= DIM_WOOD_DOOR_STATE_OPEN && placement->base.objectId == DIM_WOOD_DOOR_FADE_OBJECT_ID &&
        obj->anim.currentMoveProgress > DIM_WOOD_DOOR_FADE_PROGRESS_THRESHOLD) {
        int alpha = obj->anim.alpha - framesThisStep * DIM_WOOD_DOOR_ALPHA_FADE_PER_FRAME;

        if (alpha < 0) {
            alpha = 0;
        }
        hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
        hitState->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
        obj->anim.alpha = alpha;
    } else {
        int triggerFound;
        int contactIndex;

        triggerFound = 0;
        for (contactIndex = 0; contactIndex < obj->anim.hitboxTransformState->contactObjectCount; contactIndex++) {
            GameObject* contact = obj->anim.hitboxTransformState->contactObjects[contactIndex];

            if (contact->anim.romDefNo == DIM_WOOD_DOOR_SNOW_HORN_SEQUENCE_ID ||
                contact->anim.romDefNo == DIM_CANNON_BALL_SEQUENCE_ID) {
                triggerFound = 1;
                break;
            }
        }
        if (triggerFound) {
            state->animationSpeed = DIM_WOOD_DOOR_OPEN_ANIMATION_SPEED;
            state->riseSpeed = DIM_WOOD_DOOR_OPEN_RISE_SPEED;
            state->doorState = DIM_WOOD_DOOR_STATE_OPEN;
            mainSetBits(placement->openedGameBit, 1);
            Sfx_PlayFromObject(obj, SFXTRIG_wp_dsmk2_c);
        }
    }
}

void dimwooddoor2_init(GameObject* obj, const DimWoodDoorPlacement* placement) {
    DimWoodDoorState* state;
    ObjHitsPriorityState* hitState;
    f32 zero;

    obj->anim.rotX = (s16)(((s16)placement->rotationXByte) << 8);
    obj->objectFlags = (u16)(obj->objectFlags | (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED));
    state = obj->extra;
    state->doorState = DIM_WOOD_DOOR_STATE_CLOSED;
    zero = DIM_WOOD_DOOR_REST_SPEED;
    state->animationSpeed = zero;
    state->riseSpeed = zero;
    if (mainGetBit(placement->openedGameBit) != 0) {
        state->doorState = DIM_WOOD_DOOR_STATE_OPEN;
        hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
        hitState->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
        obj->anim.alpha = 0;
    }
}

void dimwooddoor2_release(void) {
}

void dimwooddoor2_initialise(void) {
}

ObjectDescriptor gDIMWoodDoor2ObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dimwooddoor2_initialise,
    (ObjectDescriptorCallback)dimwooddoor2_release,
    0,
    (ObjectDescriptorCallback)dimwooddoor2_init,
    (ObjectDescriptorCallback)dimwooddoor2_update,
    (ObjectDescriptorCallback)dimwooddoor2_hitDetect,
    (ObjectDescriptorCallback)dimwooddoor2_render,
    (ObjectDescriptorCallback)dimwooddoor2_free,
    (ObjectDescriptorCallback)dimwooddoor2_getObjectTypeId,
    dimwooddoor2_getExtraSize,
};
