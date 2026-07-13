#ifndef MAIN_DLL_DLL_0018_BONEPARTICLEEFFECT_H_
#define MAIN_DLL_DLL_0018_BONEPARTICLEEFFECT_H_

#include "ghidra_import.h"
#include "main/dll/boneparticleeffect_interface.h"
#include "main/game_object.h"

typedef u8 BoneFxJRow[16];

typedef struct BoneFxVtx
{
    u16 sx;
    u16 sy;
    u16 sz;
    u16 pad;
    f32 w;
    f32 vx;
    f32 vy;
    f32 vz;
} BoneFxVtx;

/* One 0x10-byte rendered particle slot in a gBoneParticleEffectBuffers buffer. */
typedef struct ParticleSlot
{
    s16 posX, posY, posZ;
    u16 pad;
    s16 texU, texV;
    u8 red, green, blue, alpha;
} ParticleSlot;

void boneParticleEffect_func08_nop(void);
void boneParticleEffect_func06_nop(void);
void boneParticleEffect_func04_nop(void);
void boneParticleEffect_func03_nop(void);
void boneParticleEffect_release(void);
void boneParticleEffect_update(void* ctx, int renderParam, u8* obj);
void boneParticleEffect_initialise(void);
void boneParticleEffect_spawnAtBones(GameObject* obj, int effectId, void* extraArg, u8 prob, short* src);

#endif /* MAIN_DLL_DLL_0018_BONEPARTICLEEFFECT_H_ */
