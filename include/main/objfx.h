#ifndef MAIN_OBJFX_H_
#define MAIN_OBJFX_H_

#include "global.h"
#include "main/game_object.h"

void objLightFn_8009a1dc(void *obj, f32 scale, void *origin, u8 type, void *light);
void objfx_spawnRandomBurst(void* obj, u8 type, u8 count, void* origin, u8 flagByte, f32 mult);
void objfx_spawnMaskedHitEffect(void* obj, u8 type, u8 mode, u8 mask, void* origin, f32 scale);
void objfx_spawnLightPulse(GameObject* obj, u8 type, int colorIndex, u8 mode, void* light, f32 radius,
                           f32 intensity);
void objfx_spawnDirectionalBurst(void* obj, u8 idx, f32 scale, u8 kind, u8 mode, u8 chance, f32 mult,
                                 void* origin, int flags);
void projectileParticleFxFn_80099660(void* obj, int mode);
#if defined(OBJFX_SPAWN_EXPLOSION_POINTER_LEGACY)
void spawnExplosion(int* source, f32 scale, int kind, int flag4, int flag8, int flag10, int doShake, int flag20,
                    int initialFlags);
#elif defined(OBJFX_SPAWN_EXPLOSION_REORDERED_LEGACY)
void spawnExplosion(int source, int kind, int flag4, int flag8, int flag10, int doShake, int flag20,
                    int initialFlags, f32 scale);
#else
void spawnExplosion(GameObject* source, f32 scale, u8 kind, u8 flag4, u8 flag8, u8 flag10, u8 doShake, u8 flag20,
                    u8 initialFlags);
#endif

#define objfx_spawnLightPulseLegacy(obj, radius, type, colorIndex, mode, intensity, light)                        \
    ((void (*)(GameObject*, f32, int, int, int, f32, void*))objfx_spawnLightPulse)(                              \
        (GameObject*)(obj), (radius), (type), (colorIndex), (mode), (intensity), (void*)(light))

#define objfx_spawnDirectionalBurstLegacy(obj, idx, scale, kind, mode, chance, mult, origin, flags)               \
    ((void (*)(void*, int, f32, int, int, int, f32, void*, int))objfx_spawnDirectionalBurst)(                    \
        (void*)(obj), (idx), (scale), (kind), (mode), (chance), (mult), (void*)(origin), (flags))

#define projectileParticleFxFn_80099660Legacy(obj, scale, mode)                                                   \
    ((void (*)(void*, f32, int))projectileParticleFxFn_80099660)((void*)(obj), (scale), (mode))

#define spawnExplosionLegacy(source, scale, kind, flag4, flag8, flag10, doShake, flag20, initialFlags)            \
    ((void (*)(GameObject*, f32, int, int, int, int, int, int, int))spawnExplosion)(                              \
        (GameObject*)(source), (scale), (kind), (flag4), (flag8), (flag10), (doShake), (flag20), (initialFlags))

void objfx_spawnHitEmitterAtPos(f32* pos, u8 a, u8 b, u8 c, u8 d);

#endif /* MAIN_OBJFX_H_ */
