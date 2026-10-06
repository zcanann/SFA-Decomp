#ifndef MAIN_OBJFX_H_
#define MAIN_OBJFX_H_

#include "dolphin/mtx/vec_types.h"
#include "global.h"
#include "game/objects/object.h"
#include "main/objfx_hit_emitter_api.h"
#include "main/dll/partfx_interface.h"

typedef struct ModelLightStruct ModelLightStruct;

void objDoHitParticleFx(GameObject* obj, f32 scale, PartFxSpawnParams* origin, u8 type, ModelLightStruct* light);
void objfx_spawnCrystalOrbitEffects(GameObject* obj, s16* state, f32 period, f32 xMul, f32 yMul, f32 xOff, f32 yOff,
                                    u8 flags);
void objfx_spawnRandomBurst(GameObject* obj, u8 type, u8 count, PartFxSpawnParams* origin, f32 mult, u8 flagByte);
void objfx_spawnMaskedHitEffect(GameObject* obj, f32 scale, u8 type, u8 mode, u8 mask, PartFxSpawnParams* origin);
void objfx_spawnLightPulse(GameObject* obj, f32 radius, int type, int colorIndex, int mode, f32 intensity,
                           PartFxSpawnParams* origin);
void objfx_spawnDirectionalBurst(GameObject* obj, u8 idx, f32 scale, u8 kind, u8 mode, u8 chance, f32 mult,
                                 PartFxSpawnParams* origin, int flags);
void objfx_spawnArcedBurst(GameObject* obj, u8 idx, f32 scale, u8 kind, u8 mode, int chance, f32 radiusEnd,
                           f32 radiusStart, f32 height, PartFxSpawnParams* origin, int flags);
void objfx_spawnBoxBurst(GameObject* obj, u8 idx, f32 scale, u8 kind, u8 mode, u8 chance, f32 scaleX, f32 scaleY,
                         f32 scaleZ, PartFxSpawnParams* origin, int flags);
void projectileDoParticleFx(GameObject* obj, f32 scale, int mode);
void itemPickupDoParticleFx(GameObject* obj, f32 scale, int mode, u8 count);
void objfx_spawnPulseBurst(GameObject* obj, f32 scale, int type, int count, int mode, f32* offset);
void spawnExplosion(GameObject* source, f32 scale, u8 kind, u8 flag4, u8 flag8, u8 flag10, u8 doShake, u8 flag20,
                    u8 initialFlags);

#define spawnExplosionLegacy(source, scale, kind, flag4, flag8, flag10, doShake, flag20, initialFlags)                 \
    ((void (*)(GameObject*, f32, int, int, int, int, int, int, int))spawnExplosion)(                                   \
        (GameObject*)(source), (scale), (kind), (flag4), (flag8), (flag10), (doShake), (flag20), (initialFlags))

void objfx_spawnHitEffectBurst(GameObject* obj, f32 scale, u8 effect, u8 variant, u8 count, PartFxSpawnParams* origin);

#endif /* MAIN_OBJFX_H_ */
