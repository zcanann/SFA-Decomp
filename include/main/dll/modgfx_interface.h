#ifndef MAIN_DLL_MODGFX_INTERFACE_H_
#define MAIN_DLL_MODGFX_INTERFACE_H_

#include "game/objects/object_fwd.h"
#include "global.h"
#include "main/dll/modgfx_types.h"
#include "main/dll/partfx_interface.h"

typedef void (*ModgfxResourceSpawnFn)(GameObject* obj, int variant, PartFxSpawnParams* spawnParams, int spawnFlags,
                                      int modelId, void* extraArgs);
typedef void (*ModgfxDetachSourceFn)(GameObject* sourceObject);
typedef void (*ModgfxOnMapSetupFn)(void);
typedef void (*ModgfxUpdateActiveEffectsFn)(int unused0, int unused1, int unused2);
typedef void (*ModgfxReleaseAllFn)(void);
typedef void (*ModgfxFreeSourceEffectsFn)(GameObject* sourceObject);
typedef int (*ModgfxRenderEffectsFn)(void* drawContext, int unused1, int unused2, u8 sourceOnly,
                                     GameObject* sourceObject);
typedef void (*ModgfxMarkSourceFrameUpdatedFn)(void* unused);
typedef s16 (*ModgfxSpawnEffectFn)(ModgfxSpawnContext* spawnContext, int unused, int vertexCount,
                                   ModgfxEffectVertex* vertices, int triangleCount, s16* triangleIndices,
                                   int textureAssetId, Texture* textureResource);
typedef void (*ModgfxReleaseHandleFn)(s16* handle);
typedef void (*ModgfxNextSpawnGenerationFn)(void);
typedef void (*ModgfxSetSourceByte13BFn)(GameObject* sourceObject, char value);
typedef void (*ModgfxRequestSourceReleaseFn)(GameObject* sourceObject);
typedef void (*ModgfxBeginSequenceFn)(GameObject* sourceObject, u8 variant, u8 initialStateByte, int drawGroupCount,
                                      int drawGroupStride);
typedef void (*ModgfxResetSequenceCommandsFn)(void);
typedef void (*ModgfxAddSequenceCommandFn)(int commandFlags, f32 valueX, f32 valueY, f32 valueZ, s16 parameter,
                                           s16* vertexIndices);
typedef void (*ModgfxNextStageFn)(void);
typedef void (*ModgfxSetStageIndexFn)(s16 index);
typedef void (*ModgfxSetStageDurationFn)(s16 value);
typedef void (*ModgfxSetStageDurationsFn)(s16* params);
typedef void (*ModgfxSpawnSequenceFn)(PartFxSpawnParams* spawnParams, ModgfxEffectVertex* vertices, int vertexCount,
                                      s16* triangleIndices, int triangleCount, int textureAssetId,
                                      Texture* textureResource);
typedef void (*ModgfxAddSequenceFlagsFn)(u32 flags);
typedef s16 (*ModgfxGetLastSpawnHandleFn)(void);

typedef struct ModgfxResourceVTable {
    u8 pad00[4];
    ModgfxResourceSpawnFn spawnEffect;
} ModgfxResourceVTable;

typedef struct ModgfxResource {
    ModgfxResourceVTable* vtable;
} ModgfxResource;

STATIC_ASSERT(offsetof(ModgfxResourceVTable, spawnEffect) == 0x04);

typedef struct ModgfxInterface {
    u32 reserved;
    ModgfxOnMapSetupFn onMapSetup;
    ModgfxSpawnEffectFn spawnEffect;
    ModgfxUpdateActiveEffectsFn updateActiveEffects;
    ModgfxReleaseAllFn releaseAll;
    ModgfxFreeSourceEffectsFn freeSourceEffects;
    ModgfxDetachSourceFn detachSource;
    ModgfxRenderEffectsFn renderEffects;
    ModgfxReleaseHandleFn releaseHandle;
    ModgfxNextSpawnGenerationFn nextSpawnGeneration;
    ModgfxSetSourceByte13BFn setSourceByte13B;
    ModgfxRequestSourceReleaseFn requestSourceRelease;
    ModgfxMarkSourceFrameUpdatedFn markSourceFrameUpdated;
    ModgfxBeginSequenceFn beginSequence;
    ModgfxResetSequenceCommandsFn resetSequenceCommands;
    ModgfxAddSequenceCommandFn addSequenceCommand;
    ModgfxNextStageFn nextStage;
    ModgfxSetStageIndexFn setStageIndex;
    ModgfxSetStageDurationFn setStageDuration;
    ModgfxSetStageDurationsFn setStageDurations;
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
STATIC_ASSERT(offsetof(ModgfxInterface, nextSpawnGeneration) == 0x24);
STATIC_ASSERT(offsetof(ModgfxInterface, setSourceByte13B) == 0x28);
STATIC_ASSERT(offsetof(ModgfxInterface, requestSourceRelease) == 0x2C);
STATIC_ASSERT(offsetof(ModgfxInterface, markSourceFrameUpdated) == 0x30);
STATIC_ASSERT(offsetof(ModgfxInterface, beginSequence) == 0x34);
STATIC_ASSERT(offsetof(ModgfxInterface, resetSequenceCommands) == 0x38);
STATIC_ASSERT(offsetof(ModgfxInterface, addSequenceCommand) == 0x3C);
STATIC_ASSERT(offsetof(ModgfxInterface, nextStage) == 0x40);
STATIC_ASSERT(offsetof(ModgfxInterface, setStageIndex) == 0x44);
STATIC_ASSERT(offsetof(ModgfxInterface, setStageDuration) == 0x48);
STATIC_ASSERT(offsetof(ModgfxInterface, setStageDurations) == 0x4C);
STATIC_ASSERT(offsetof(ModgfxInterface, spawnSequence) == 0x50);
STATIC_ASSERT(offsetof(ModgfxInterface, addSequenceFlags) == 0x54);
STATIC_ASSERT(offsetof(ModgfxInterface, getLastSpawnHandle) == 0x58);

STATIC_ASSERT(sizeof(ModgfxInterface) == 0x5C);

typedef struct ModgfxDescriptor {
    u32 reserved[3];
    u32 slotCountAndFlags;
    void (*initialise)(void);
    void (*release)(void);
    ModgfxInterface interface;
    u32 unknownTail;
} ModgfxDescriptor;

STATIC_ASSERT(offsetof(ModgfxDescriptor, interface) == 0x18);
STATIC_ASSERT(offsetof(ModgfxDescriptor, unknownTail) == 0x74);
STATIC_ASSERT(sizeof(ModgfxDescriptor) == 0x78);

extern ModgfxDescriptor gModgfxDescriptor;
extern ModgfxInterface** gModgfxInterface;

#endif /* MAIN_DLL_MODGFX_INTERFACE_H_ */
