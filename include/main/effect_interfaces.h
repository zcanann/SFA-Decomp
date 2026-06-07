#ifndef MAIN_EFFECT_INTERFACES_H_
#define MAIN_EFFECT_INTERFACES_H_

#include "global.h"

typedef void (*EffectSpawnObjectFn)(void *obj, int effectId, void *params, int mode,
                                    int modelId, void *extraArg);
typedef void (*EffectUpdateFrameStateFn)(int reset);
typedef void (*EffectFreeObjectFn)(void *obj);

typedef struct EffectInterface {
  u8 pad00[0x08];
  EffectSpawnObjectFn spawnObject;
  EffectUpdateFrameStateFn updateFrameState;
  u8 pad10[0x18 - 0x10];
  EffectFreeObjectFn freeObject;
} EffectInterface;

STATIC_ASSERT(offsetof(EffectInterface, spawnObject) == 0x08);
STATIC_ASSERT(offsetof(EffectInterface, updateFrameState) == 0x0C);
STATIC_ASSERT(offsetof(EffectInterface, freeObject) == 0x18);

typedef void (*WaterfxSpawnRippleFn)(f32 x, f32 y, f32 z, f32 radius, int flags);
typedef void (*WaterfxSpawnSurfaceRippleFn)(f32 x, f32 y, f32 z, f32 radius, int flags,
                                            int count);

typedef struct WaterfxInterface {
  u8 pad00[0x10];
  WaterfxSpawnRippleFn spawnRipple;
  WaterfxSpawnSurfaceRippleFn spawnSurfaceRipple;
} WaterfxInterface;

STATIC_ASSERT(offsetof(WaterfxInterface, spawnRipple) == 0x10);
STATIC_ASSERT(offsetof(WaterfxInterface, spawnSurfaceRipple) == 0x14);

#endif /* MAIN_EFFECT_INTERFACES_H_ */
