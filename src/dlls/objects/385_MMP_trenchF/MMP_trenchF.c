/*
 * MMP_trenchF (DLL 0x181) - Moon Mountain Pass trench particle emitter.
 *
 * This object emits particles at randomized offsets while its placement
 * gate is enabled.
 */
#include "dlls/objects/385_MMP_trenchF.h"

#include "game/objects/object.h"
#include "main/dll/expgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/vecmath.h"

#define MMP_TRENCH_FX_PARTICLE_BURST      0x71F
#define MMP_TRENCH_FX_PARTICLE_AMBIENT    0x720
#define MMP_TRENCH_FX_PARTICLE_SPAWN_MODE 0x200001
#define MMP_TRENCH_FX_MODEL_NONE          -1

PartFxSpawnParams gMMPTrenchFxAmbientSpawnParams;

int mmpTrenchFx_getExtraSize(void) {
    return sizeof(MMPTrenchFxState);
}

int mmpTrenchFx_getObjectTypeId(void) {
    return 0;
}

void mmpTrenchFx_free(GameObject* obj) {
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void mmpTrenchFx_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    if (visible == 0) {
        return;
    }
}

void mmpTrenchFx_hitDetect(void) {
}

void mmpTrenchFx_update(GameObject* obj) {
    MMPTrenchFxState* state = obj->extra;

    if (state->enableGameBit == -1 || mainGetBit(state->enableGameBit) != 0) {
        state->burstCooldown -= timeDelta;
        if (state->burstCooldown < 0.0f) {
            state->burstSpawnParams.scale = 1.0f;
            state->burstSpawnParams.posX = randomGetRange(-state->extentX, state->extentX);
            state->burstSpawnParams.posY = randomGetRange(-state->extentY, state->extentY);
            state->burstSpawnParams.posZ = randomGetRange(-state->extentZ, state->extentZ);
            vecRotateZXY(state->emitAngles, &state->burstSpawnParams.posX);
            state->burstSpawnParams.posX += obj->anim.localPosX;
            state->burstSpawnParams.posY += obj->anim.localPosY;
            state->burstSpawnParams.posZ += obj->anim.localPosZ;
            state->burstCooldown = randomGetRange(0x64, 0xC8);
            state->burstTimer = randomGetRange(0x32, 0x64);
        }
        state->burstTimer -= timeDelta;
        if (state->burstTimer > 0.0f) {
            (*gPartfxInterface)
                ->spawnObject((void*)obj, MMP_TRENCH_FX_PARTICLE_BURST, &state->burstSpawnParams,
                              MMP_TRENCH_FX_PARTICLE_SPAWN_MODE, MMP_TRENCH_FX_MODEL_NONE, NULL);
        }
        gMMPTrenchFxAmbientSpawnParams.scale = 1.0f;
        gMMPTrenchFxAmbientSpawnParams.posX = randomGetRange(-state->extentX, state->extentX);
        gMMPTrenchFxAmbientSpawnParams.posY = randomGetRange(-state->extentY, state->extentY);
        gMMPTrenchFxAmbientSpawnParams.posZ = randomGetRange(-state->extentZ, state->extentZ);
        vecRotateZXY(state->emitAngles, &gMMPTrenchFxAmbientSpawnParams.posX);
        gMMPTrenchFxAmbientSpawnParams.posX += obj->anim.localPosX;
        gMMPTrenchFxAmbientSpawnParams.posY += obj->anim.localPosY;
        gMMPTrenchFxAmbientSpawnParams.posZ += obj->anim.localPosZ;
        (*gPartfxInterface)
            ->spawnObject((void*)obj, MMP_TRENCH_FX_PARTICLE_AMBIENT, &gMMPTrenchFxAmbientSpawnParams,
                          MMP_TRENCH_FX_PARTICLE_SPAWN_MODE, MMP_TRENCH_FX_MODEL_NONE, NULL);
    }
}

void mmpTrenchFx_init(GameObject* obj, const MMPTrenchFxPlacement* placement) {
    MMPTrenchFxState* state = obj->extra;
    s16 angle;

    state->enableGameBit = placement->enableGameBit;
    state->extentX = (u16)(placement->extentX << 2);
    state->extentZ = (u16)(placement->extentZ << 2);
    state->extentY = (u16)(placement->extentY << 2);
    angle = (s16)(((s32)placement->emitAngleZ) << 8);
    state->emitAngles[2] = angle;
    obj->anim.rotZ = angle;
    angle = (s16)(((s32)placement->emitAngleY) << 8);
    state->emitAngles[1] = angle;
    obj->anim.rotY = angle;
    angle = (s16)(((s32)placement->emitAngleX) << 8);
    state->emitAngles[0] = angle;
    obj->anim.rotX = angle;
    obj->anim.rootMotionScale = 0.1f;
}

void mmpTrenchFx_release(void) {
}

void mmpTrenchFx_initialise(void) {
}

ObjectDescriptor gMMPTrenchFxObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)mmpTrenchFx_initialise,
    (ObjectDescriptorCallback)mmpTrenchFx_release,
    0,
    (ObjectDescriptorCallback)mmpTrenchFx_init,
    (ObjectDescriptorCallback)mmpTrenchFx_update,
    (ObjectDescriptorCallback)mmpTrenchFx_hitDetect,
    (ObjectDescriptorCallback)mmpTrenchFx_render,
    (ObjectDescriptorCallback)mmpTrenchFx_free,
    (ObjectDescriptorCallback)mmpTrenchFx_getObjectTypeId,
    mmpTrenchFx_getExtraSize,
};
