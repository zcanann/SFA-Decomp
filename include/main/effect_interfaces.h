#ifndef MAIN_EFFECT_INTERFACES_H_
#define MAIN_EFFECT_INTERFACES_H_

#include "global.h"

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

typedef void (*ModgfxDetachSourceFn)(void *sourceObject);
typedef void (*ModgfxOnMapSetupFn)(void);
typedef void (*ModgfxUpdateActiveEffectsFn)(int unused0, int unused1, int unused2);
typedef void (*ModgfxReleaseAllFn)(void);
typedef void (*ModgfxFreeSourceEffectsFn)(void *sourceObject);
typedef int (*ModgfxRenderEffectsFn)(void *drawContext, int arg1, int arg2,
                                     u8 sourceOnly, void *sourceObject);
typedef void (*ModgfxMarkSourceFrameUpdatedFn)(void *unused);
typedef int (*ModgfxSpawnEffectFn)(void *spawnContext, int flags, int vertexCount,
                                   void *vertices, int colorCount, void *colors,
                                   int textureAssetId, void *textureResource);
typedef void (*ModgfxReleaseHandleFn)(s16 *handle);
typedef void (*ModgfxBeginSequenceFn)(void *sourceObject, int sourceMode,
                                      int effectType, int word40, int word3C);
typedef void (*ModgfxResetSequenceSpawnsFn)(void);
typedef void (*ModgfxAddSequenceSpawnFn)(int modelOrResource, f32 posX, f32 posY,
                                         f32 posZ, s16 param14, void *param10);
typedef void (*ModgfxNextSequenceParamFn)(void);
typedef void (*ModgfxSetSequenceParamIndexFn)(s16 index);
typedef void (*ModgfxSetSequenceParamValueFn)(s16 value);
typedef void (*ModgfxSetSequenceParamsFn)(void *params);
typedef void (*ModgfxSpawnSequenceFn)(void *sourceObject, void *vertices,
                                      int vertexCount, void *colors, int colorCount,
                                      int textureAssetId, void *textureResource);
typedef void (*ModgfxAddSequenceFlagsFn)(u32 flags);
typedef s16 (*ModgfxGetLastSpawnHandleFn)(void);

typedef struct ModgfxInterface {
  u8 pad00[0x04];
  ModgfxOnMapSetupFn onMapSetup;
  ModgfxSpawnEffectFn spawnEffect;
  ModgfxUpdateActiveEffectsFn updateActiveEffects;
  ModgfxReleaseAllFn releaseAll;
  ModgfxFreeSourceEffectsFn freeSourceEffects;
  ModgfxDetachSourceFn detachSource;
  ModgfxRenderEffectsFn renderEffects;
  ModgfxReleaseHandleFn releaseHandle;
  u8 pad24[0x30 - 0x24];
  ModgfxMarkSourceFrameUpdatedFn markSourceFrameUpdated;
  ModgfxBeginSequenceFn beginSequence;
  ModgfxResetSequenceSpawnsFn resetSequenceSpawns;
  ModgfxAddSequenceSpawnFn addSequenceSpawn;
  ModgfxNextSequenceParamFn nextSequenceParam;
  ModgfxSetSequenceParamIndexFn setSequenceParamIndex;
  ModgfxSetSequenceParamValueFn setSequenceParamValue;
  ModgfxSetSequenceParamsFn setSequenceParams;
  ModgfxSpawnSequenceFn spawnSequence;
  ModgfxAddSequenceFlagsFn addSequenceFlags;
  ModgfxGetLastSpawnHandleFn getLastSpawnHandle;
} ModgfxInterface;

STATIC_ASSERT(offsetof(ModgfxInterface, spawnEffect) == 0x08);
STATIC_ASSERT(offsetof(ModgfxInterface, updateActiveEffects) == 0x0C);
STATIC_ASSERT(offsetof(ModgfxInterface, releaseAll) == 0x10);
STATIC_ASSERT(offsetof(ModgfxInterface, freeSourceEffects) == 0x14);
STATIC_ASSERT(offsetof(ModgfxInterface, detachSource) == 0x18);
STATIC_ASSERT(offsetof(ModgfxInterface, renderEffects) == 0x1C);
STATIC_ASSERT(offsetof(ModgfxInterface, releaseHandle) == 0x20);
STATIC_ASSERT(offsetof(ModgfxInterface, markSourceFrameUpdated) == 0x30);
STATIC_ASSERT(offsetof(ModgfxInterface, beginSequence) == 0x34);
STATIC_ASSERT(offsetof(ModgfxInterface, resetSequenceSpawns) == 0x38);
STATIC_ASSERT(offsetof(ModgfxInterface, addSequenceSpawn) == 0x3C);
STATIC_ASSERT(offsetof(ModgfxInterface, nextSequenceParam) == 0x40);
STATIC_ASSERT(offsetof(ModgfxInterface, setSequenceParamIndex) == 0x44);
STATIC_ASSERT(offsetof(ModgfxInterface, setSequenceParamValue) == 0x48);
STATIC_ASSERT(offsetof(ModgfxInterface, setSequenceParams) == 0x4C);
STATIC_ASSERT(offsetof(ModgfxInterface, spawnSequence) == 0x50);
STATIC_ASSERT(offsetof(ModgfxInterface, addSequenceFlags) == 0x54);
STATIC_ASSERT(offsetof(ModgfxInterface, getLastSpawnHandle) == 0x58);

extern ModgfxInterface **gModgfxInterface;

#endif /* MAIN_EFFECT_INTERFACES_H_ */
