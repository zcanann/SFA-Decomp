#include "dlls/objects/412.h"

#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/dll_0082_modgfx.h"
#include "main/frame_timing.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/object_render.h"
#include "main/resource.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/audio/sfx_play_api.h"

#define DLL19C_EFFECT_RESOURCE_ID 0x82
#define DLL19C_CHILD_OBJECT_ID    0x248
#define DLL19C_REARM_GAMEBIT      0x1D4

#define DLL19C_SPAWN_TIMER         100
#define DLL19C_CHILD_HEIGHT_OFFSET 50.0f
#define DLL19C_FULL_ALPHA          0xFF
#define DLL19C_RENDER_SCALE        1.0f
#define DLL19C_OBJECT_SETUP_FLAGS  5
#define DLL19C_EFFECT_SPAWN_FLAGS  1

int dll412_getExtraSize(void) {
    return sizeof(Dll19CState);
}

int dll412_getObjectTypeId(void) {
    return 0;
}

void dll412_free(void) {
}

void dll412_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    s32 isVisible = visible;

    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, DLL19C_RENDER_SCALE);
    }
}

void dll412_hitDetect(void) {
}

void dll412_update(GameObject* obj) {
    const Dll19CPlacement* placement;
    Dll19CState* state;
    Dll82Interface** effectResource;
    ObjPlacement* childSetup;
    u8 canSetupObject;

    placement = (const Dll19CPlacement*)obj->anim.placementData;
    state = obj->extra;
    if (obj->userData2 != 0) {
        if (mainGetBit(DLL19C_REARM_GAMEBIT) != 0) {
            obj->userData2 = 0;
        }
    }
    if (obj->userData2 == 0) {
        if (mainGetBit(GAMEBIT_WM_KrazTest1TorchesActive) != 0) {
            effectResource = Resource_Acquire(DLL19C_EFFECT_RESOURCE_ID, 1);
            (*effectResource)->spawn(obj, 0, NULL, DLL19C_EFFECT_SPAWN_FLAGS, -1, NULL);
            (*effectResource)->spawn(obj, 1, NULL, DLL19C_EFFECT_SPAWN_FLAGS, -1, NULL);
            Sfx_PlayFromObject(0, SFXTRIG_hitpos_6);
            Resource_Release(effectResource);
            state->spawnTimerRate = 1;
            obj->userData2 = 1;
        }
    }
    if (state->spawnTimerRate != 0) {
        state->spawnTimer = (s16)(state->spawnTimer - state->spawnTimerRate * framesThisStep);
    }
    if (state->spawnTimer <= 0 && placement->disableChildSpawn == 0 &&
        (canSetupObject = Obj_CanSetupObject()) > 0) {
        childSetup = Obj_AllocObjectSetup(sizeof(ObjPlacement), DLL19C_CHILD_OBJECT_ID);
        childSetup->posX = placement->base.posX;
        childSetup->posY = DLL19C_CHILD_HEIGHT_OFFSET + placement->base.posY;
        childSetup->posZ = placement->base.posZ;
        childSetup->objectId = DLL19C_CHILD_OBJECT_ID;
        childSetup->ident = -1;
        childSetup->color[0] = placement->base.color[0];
        childSetup->color[1] = placement->base.color[1];
        childSetup->color[2] = placement->base.color[2];
        childSetup->color[3] = placement->base.color[3];
        objSetupObject(childSetup, DLL19C_OBJECT_SETUP_FLAGS, obj->anim.mapEventSlot, -1, obj->anim.parent);
        state->spawnTimer = DLL19C_SPAWN_TIMER;
        state->spawnTimerRate = 0;
    }
}

void dll412_init(GameObject* obj, const Dll19CPlacement* placement) {
    register int objectAddress = (int)obj;
    register int stateAddress = (int)((GameObject*)objectAddress)->extra;

    ((GameObject*)objectAddress)->anim.rotX = (s16)((int)placement->initialYaw << 8);
    ((GameObject*)objectAddress)->userData2 = 0;
    ((Dll19CState*)stateAddress)->spawnTimer = DLL19C_SPAWN_TIMER;
    ((Dll19CState*)stateAddress)->spawnTimerRate = 0;
    ((Dll19CState*)stateAddress)->unknown0 = 0;
    ((GameObject*)objectAddress)->anim.renderAlpha = DLL19C_FULL_ALPHA;
    ((GameObject*)objectAddress)->anim.alpha = DLL19C_FULL_ALPHA;
}

void dll412_release(void) {
}

void dll412_initialise(void) {
}

ObjectDescriptor gDll19CObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll412_initialise,
    (ObjectDescriptorCallback)dll412_release,
    0,
    (ObjectDescriptorCallback)dll412_init,
    (ObjectDescriptorCallback)dll412_update,
    (ObjectDescriptorCallback)dll412_hitDetect,
    (ObjectDescriptorCallback)dll412_render,
    (ObjectDescriptorCallback)dll412_free,
    (ObjectDescriptorCallback)dll412_getObjectTypeId,
    dll412_getExtraSize,
};
