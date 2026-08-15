/* Spirit-door orbit marker gated by its placement game bit. */

#include "dlls/objects/343_SpiritDoorS.h"

#include "main/gamebits_api.h"
#include "main/objfx.h"
#include "main/object_render.h"
#include "main/objtype.h"

#define SPIRIT_DOOR_SPIRIT_PULSE_TYPE 5
#define SPIRIT_DOOR_SPIRIT_MAX_ALPHA  0xFF

f32 gSpiritDoorSpiritPulseScale = 0.7f;

int spiritDoorSpirit_getExtraSize(void) {
    return sizeof(SpiritDoorSpiritState);
}

int spiritDoorSpirit_getObjectTypeId(void) {
    return 0;
}

void spiritDoorSpirit_free(GameObject* obj) {
    objFreeObjectType(obj, SPIRIT_DOOR_SPIRIT_OBJECT_GROUP);
}

void spiritDoorSpirit_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                             s8 visible) {
    SpiritDoorSpiritState* state = obj->extra;
    if (visible == 0 || state->active == 0) {
        return;
    }

    objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
}

void spiritDoorSpirit_hitDetect(void) {
}

void spiritDoorSpirit_update(GameObject* obj) {
    SpiritDoorSpiritState* state = obj->extra;
    SpiritDoorSpiritPlacement* placement = (SpiritDoorSpiritPlacement*)obj->anim.placement;
    u8 active;

    if (state->active == 0) {
        state->active = active = (u8)(mainGetBit(placement->gateGameBit) == 0);
        if (active != 0) {
            objAddObjectType(obj, SPIRIT_DOOR_SPIRIT_OBJECT_GROUP);
        }
        if (obj->anim.alpha != 0) {
            obj->anim.alpha--;
        }
    } else {
        objfx_spawnPulseBurst(obj, gSpiritDoorSpiritPulseScale, SPIRIT_DOOR_SPIRIT_PULSE_TYPE, 0, 0, NULL);
        state->active = active = (u8)(mainGetBit(placement->gateGameBit) == 0);
        if (active == 0) {
            objFreeObjectType(obj, SPIRIT_DOOR_SPIRIT_OBJECT_GROUP);
        }
        if (obj->anim.alpha < SPIRIT_DOOR_SPIRIT_MAX_ALPHA) {
            obj->anim.alpha++;
        }
    }
}

void spiritDoorSpirit_init(GameObject* obj) {
    SpiritDoorSpiritState* state = obj->extra;
    state->active = 0;
    obj->anim.alpha = 0;
}

void spiritDoorSpirit_release(void) {
}

void spiritDoorSpirit_initialise(void) {
}

ObjectDescriptor gSpiritDoorSpiritObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)spiritDoorSpirit_initialise,
    (ObjectDescriptorCallback)spiritDoorSpirit_release,
    0,
    (ObjectDescriptorCallback)spiritDoorSpirit_init,
    (ObjectDescriptorCallback)spiritDoorSpirit_update,
    (ObjectDescriptorCallback)spiritDoorSpirit_hitDetect,
    (ObjectDescriptorCallback)spiritDoorSpirit_render,
    (ObjectDescriptorCallback)spiritDoorSpirit_free,
    (ObjectDescriptorCallback)spiritDoorSpirit_getObjectTypeId,
    spiritDoorSpirit_getExtraSize,
};
