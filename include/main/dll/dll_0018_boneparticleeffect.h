#ifndef MAIN_DLL_DLL_0018_BONEPARTICLEEFFECT_H_
#define MAIN_DLL_DLL_0018_BONEPARTICLEEFFECT_H_

#include "dlls/object_descriptor.h"
#include "main/dll/partfx_interface.h"
#include "main/dll/boneparticleeffect_interface.h"
#include "game/objects/object.h"

typedef struct BoneParticleEffectDllInterface {
    u32 reserved0;
    u32 reserved1;
    u32 reserved2;
    u32 slotCountAndFlags;
    ObjectDescriptorCallback initialise;
    ObjectDescriptorCallback release;
    ObjectDescriptorCallback slot02;
    ObjectDescriptorCallback slot03;
    ObjectDescriptorCallback slot04;
    ObjectDescriptorCallback spawnAtBones;
    ObjectDescriptorCallback slot06;
    ObjectDescriptorCallback update;
    ObjectDescriptorCallback slot08;
    ObjectDescriptorCallback slot09;
} BoneParticleEffectDllInterface;

STATIC_ASSERT(sizeof(BoneParticleEffectDllInterface) == 0x38);
STATIC_ASSERT(offsetof(BoneParticleEffectDllInterface, spawnAtBones) == 0x24);
STATIC_ASSERT(offsetof(BoneParticleEffectDllInterface, update) == 0x2C);

extern BoneParticleEffectDllInterface boneParticleEffect_funcs;

void boneParticleEffect_func08_nop(void);
void boneParticleEffect_func06_nop(void);
void boneParticleEffect_func04_nop(void);
void boneParticleEffect_func03_nop(void);
void boneParticleEffect_release(void);
void boneParticleEffect_update(void* ctx, int renderParam, GameObject* obj);
void boneParticleEffect_initialise(void);
void boneParticleEffect_spawnAtBones(GameObject* obj, int effectId, void* extraArg, u8 probability,
                                     const PartFxSpawnParams* spawnParams);

#endif /* MAIN_DLL_DLL_0018_BONEPARTICLEEFFECT_H_ */
