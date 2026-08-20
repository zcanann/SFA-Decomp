/*
 * DIMbosscrackpar (DLL 0x1E6) - DarkIce Mines boss crack-particle
 * emitters. While a placement-selected game bit is set, each object emits
 * both its crack-specific effect and a fixed glow effect.
 */
#include "dlls/objects/486_DIMbosscrac.h"

#include "game/objects/object.h"
#include "main/dll/expgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/gamebits_api.h"

#define DIMBOSSCRACKPAR_BASE_PARTICLE_ID 0x4C6
#define DIMBOSSCRACKPAR_GLOW_PARTICLE_ID 0x4C8


int DIMbosscrackpar_SeqFn(GameObject* obj) {
    DIMbosscrackparPlacementView* placement = (DIMbosscrackparPlacementView*)obj->anim.placementData;

    if (mainGetBit(placement->triggerGameBit) == 0) {
        return 0;
    }
    (*gPartfxInterface)
        ->spawnObject(obj, placement->particleEffectOffset + DIMBOSSCRACKPAR_BASE_PARTICLE_ID, NULL, 2, -1, NULL);
    (*gPartfxInterface)->spawnObject(obj, DIMBOSSCRACKPAR_GLOW_PARTICLE_ID, NULL, 2, -1, NULL);
    return 0;
}

int DIMbosscrackpar_getExtraSize(void) {
    return 0;
}

int DIMbosscrackpar_getObjectTypeId(void) {
    return 0;
}

void DIMbosscrackpar_free(GameObject* obj) {
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void DIMbosscrackpar_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                            s8 visible) {
    if (visible == 0) {
        return;
    }
}

void DIMbosscrackpar_hitDetect(void) {
}

void DIMbosscrackpar_update(GameObject* obj) {
    DIMbosscrackparPlacementView* placement = (DIMbosscrackparPlacementView*)obj->anim.placementData;

    if (mainGetBit(placement->triggerGameBit) != 0) {
        (*gPartfxInterface)
            ->spawnObject(obj, placement->particleEffectOffset + DIMBOSSCRACKPAR_BASE_PARTICLE_ID, NULL, 2, -1, NULL);
        (*gPartfxInterface)->spawnObject(obj, DIMBOSSCRACKPAR_GLOW_PARTICLE_ID, NULL, 2, -1, NULL);
    }
}

void DIMbosscrackpar_init(GameObject* obj, DIMbosscrackparPlacementView* placement) {
    obj->anim.rotX = 0;
    obj->anim.rootMotionScale = 0.1f;
    obj->animEventCallback = DIMbosscrackpar_SeqFn;
    obj->anim.rotX = placement->rotationXByte << 8;
    obj->anim.rotY = placement->rotationYByte << 8;
    obj->anim.rotZ = placement->rotationZByte << 8;
}

void DIMbosscrackpar_release(void) {
}

void DIMbosscrackpar_initialise(void) {
}

ObjectDescriptor gDIMbosscrackparObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    DIMbosscrackpar_initialise,
    DIMbosscrackpar_release,
    0,
    (ObjectDescriptorCallback)DIMbosscrackpar_init,
    (ObjectDescriptorCallback)DIMbosscrackpar_update,
    DIMbosscrackpar_hitDetect,
    (ObjectDescriptorCallback)DIMbosscrackpar_render,
    (ObjectDescriptorCallback)DIMbosscrackpar_free,
    (ObjectDescriptorCallback)DIMbosscrackpar_getObjectTypeId,
    DIMbosscrackpar_getExtraSize,
};
