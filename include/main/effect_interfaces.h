#ifndef MAIN_EFFECT_INTERFACES_H_
#define MAIN_EFFECT_INTERFACES_H_

#include "global.h"
#include "main/dll/modgfx_interface.h"

struct GameObject;

typedef void (*EffectSpawnObjectFn)(void *obj, int effectId, void *params, int mode,
                                    int modelId, void *extraArg);
typedef void (*EffectOnMapSetupFn)(void);
typedef void (*EffectUpdateFrameStateFn)(int reset);
typedef void (*EffectFreeObjectFn)(void *obj);

/*
 * PartFxSpawnParams - the s16*-typed spawn-parameter packet passed to the
 * per-effect Effect*_func04 handlers (modgfx/dim_partfx/df_partfx and the
 * gameplay.c spawners). Offset/width layout observed consistent across all
 * handlers (s16 head + f32 block). The float block is consistently passed as
 * scale plus a local position/vector triple, though individual effect ids may
 * reinterpret one of those floats as an effect-specific magnitude.
 */
typedef struct PartFxSpawnParams {
    union {
        struct {
            s16 unk0;
            s16 unk2;
            s16 unk4;
            s16 unk6;
        };
        struct {
            s16 rotX;
            s16 rotY;
            s16 rotZ;
            s16 pad06;
        };
        struct {
            s16 arg0;
            s16 arg1;
            s16 arg2;
            s16 arg3;
        };
    };
    f32 scale;
    f32 posX;
    f32 posY;
    f32 posZ;
} PartFxSpawnParams;

STATIC_ASSERT(sizeof(PartFxSpawnParams) == 0x18);
STATIC_ASSERT(offsetof(PartFxSpawnParams, scale) == 0x08);
STATIC_ASSERT(offsetof(PartFxSpawnParams, posX) == 0x0C);
STATIC_ASSERT(offsetof(PartFxSpawnParams, posY) == 0x10);
STATIC_ASSERT(offsetof(PartFxSpawnParams, posZ) == 0x14);

typedef struct EffectInterface {
  u8 pad00[0x04];
  EffectOnMapSetupFn onMapSetup;
  EffectSpawnObjectFn spawnObject;
  EffectUpdateFrameStateFn updateFrameState;
  u8 pad10[0x18 - 0x10];
  EffectFreeObjectFn freeObject;
} EffectInterface;

STATIC_ASSERT(offsetof(EffectInterface, onMapSetup) == 0x04);
STATIC_ASSERT(offsetof(EffectInterface, spawnObject) == 0x08);
STATIC_ASSERT(offsetof(EffectInterface, updateFrameState) == 0x0C);
STATIC_ASSERT(offsetof(EffectInterface, freeObject) == 0x18);

extern EffectInterface **gPartfxInterface;

#endif /* MAIN_EFFECT_INTERFACES_H_ */
