#ifndef MAIN_OBJFX_H_
#define MAIN_OBJFX_H_

#include "dolphin/mtx/vec_types.h"
#include "global.h"
#include "game/objects/object.h"
#include "main/objfx_hit_emitter_api.h"

void objDoHitParticleFx(void* obj, f32 scale, void* origin, u8 type, void* light);
void objfx_spawnCrystalOrbitEffects(GameObject* obj, s16* state, f32 period, f32 xMul, f32 yMul, f32 xOff, f32 yOff,
                                    u8 flags);
void objfx_spawnRandomBurst(void* obj, u8 type, u8 count, void* origin, f32 mult, u8 flagByte);
void objfx_spawnMaskedHitEffect(void* obj, f32 scale, u8 type, u8 mode, u8 mask, void* origin);
void objfx_spawnLightPulse(GameObject* obj, f32 radius, int type, int colorIndex, int mode, f32 intensity, void* light);
void objfx_spawnDirectionalBurst(void* obj, u8 idx, f32 scale, u8 kind, u8 mode, u8 chance, f32 mult, void* origin,
                                 int flags);
void objfx_spawnArcedBurst(void* obj, u8 idx, f32 scale, u8 kind, u8 mode, int chance, f32 angleBase, f32 angleLow,
                           f32 angleHigh, void* origin, int flags);
void objfx_spawnBoxBurst(void* obj, u8 idx, f32 scale, u8 kind, u8 mode, u8 chance, f32 scaleX, f32 scaleY, f32 scaleZ,
                         void* origin, int flags);
void projectileDoParticleFx(void* obj, f32 scale, int mode);
void itemPickupDoParticleFx(void* obj, f32 scale, int mode, u8 count);
void objfx_spawnPulseBurst(void* obj, f32 scale, int type, int count, int mode, f32* offset);
void spawnExplosion(GameObject* source, f32 scale, u8 kind, u8 flag4, u8 flag8, u8 flag10, u8 doShake, u8 flag20,
                    u8 initialFlags);

#define spawnExplosionLegacy(source, scale, kind, flag4, flag8, flag10, doShake, flag20, initialFlags)                 \
    ((void (*)(GameObject*, f32, int, int, int, int, int, int, int))spawnExplosion)(                                   \
        (GameObject*)(source), (scale), (kind), (flag4), (flag8), (flag10), (doShake), (flag20), (initialFlags))

void objfx_spawnHitEffectBurst(void* obj, f32 scale, u8 effect, u8 variant, u8 count, GameObject* origin);

#endif /* MAIN_OBJFX_H_ */
