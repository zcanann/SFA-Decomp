/*
 * LGTControlL (DLL 684) - a switch object that drives nearby point
 * lights from a game bit.
 *
 * It owns no light of its own. Each frame update reads its gameBit; when the
 * bit's value changes it walks LGT_POINTLIGHT_GROUP and, for every point light
 * within `radius`, calls pointlight_setEffectState with the new bit value
 * (CONTROLLIGHT_MODE_DIRECT) or its inverse (CONTROLLIGHT_MODE_INVERTED). The
 * last-seen bit is cached so the sweep only runs on a transition; lastBit
 * starts at CONTROLLIGHT_LAST_BIT_INVALID to force the first update.
 */
#include "dlls/objects/684_LGTControlL.h"

#include "main/gamebits_api.h"
#include "main/objtype.h"
#include "main/vecmath.h"
#include "main/dll/LGT/dll_02A9_lgtpointlight.h"

#define CONTROLLIGHT_MODE_DIRECT      0
#define CONTROLLIGHT_MODE_INVERTED    1
#define CONTROLLIGHT_LAST_BIT_INVALID 0xff

int ControlLight_getExtraSize(void) {
    return sizeof(ControlLightState);
}

int ControlLight_getObjectTypeId(void) {
    return 0;
}

void ControlLight_free(void) {
}

void ControlLight_render(void) {
}

void ControlLight_hitDetect(void) {
}

void ControlLight_update(GameObject* obj) {
    u8 newBit;
    u32 bit;
    ControlLightState* state;
    GameObject* self = obj;
    state = self->extra;
    newBit = mainGetBit(state->gameBit);
    bit = newBit;

    if (bit != state->lastBit) {
        switch (state->invertMode) {
        case CONTROLLIGHT_MODE_DIRECT: {
            f32 radius = state->radius;
            int count;
            int i;
            GameObject* lightObj;
            GameObject** objs = (GameObject**)objGetAllOfType(LGT_POINTLIGHT_GROUP, &count);
            GameObject** lightIter;
            for (i = 0, lightIter = objs; i < count; i++) {
                lightObj = *lightIter;
                if (Vec_distance(&self->anim.worldPosX, &lightObj->anim.worldPosX) < radius) {
                    pointlight_setEffectState(lightObj, newBit);
                }
                lightIter++;
            }
            break;
        }
        case CONTROLLIGHT_MODE_INVERTED: {
            f32 radius = state->radius;
            int count;
            GameObject* lightObj;
            int i;
            int invBit;
            GameObject** objs = (GameObject**)objGetAllOfType(LGT_POINTLIGHT_GROUP, &count);
            GameObject** lightIter;
            i = 0, lightIter = objs;
            invBit = bit == 0;
            for (; i < count; i++) {
                lightObj = *lightIter;
                if (Vec_distance(&self->anim.worldPosX, &lightObj->anim.worldPosX) < radius) {
                    pointlight_setEffectState(lightObj, invBit);
                }
                lightIter++;
            }
            break;
        }
        }
    }

    state->lastBit = newBit;
}

void ControlLight_init(GameObject* obj, ControlLightSetup* setup) {
    ControlLightState* state = obj->extra;

    state->gameBit = setup->gameBit;
    state->radius = setup->radius;
    state->invertMode = setup->invertMode % 2;
    state->lastBit = CONTROLLIGHT_LAST_BIT_INVALID;
}

void ControlLight_release(void) {
}

void ControlLight_initialise(void) {
}

ObjectDescriptor gControlLightObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)ControlLight_initialise,
    (ObjectDescriptorCallback)ControlLight_release,
    0,
    (ObjectDescriptorCallback)ControlLight_init,
    (ObjectDescriptorCallback)ControlLight_update,
    (ObjectDescriptorCallback)ControlLight_hitDetect,
    (ObjectDescriptorCallback)ControlLight_render,
    (ObjectDescriptorCallback)ControlLight_free,
    (ObjectDescriptorCallback)ControlLight_getObjectTypeId,
    ControlLight_getExtraSize,
};
