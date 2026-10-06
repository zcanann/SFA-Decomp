#ifndef MAIN_DLL_PARTFX_INTERFACE_H_
#define MAIN_DLL_PARTFX_INTERFACE_H_

#include "main/vec_types.h"

#include "game/objects/object_fwd.h"

typedef enum PartfxFlags {
    PARTFXFLAG_NONE = 0x0,
    PARTFXFLAG_1 = 0x1,
    PARTFXFLAG_2 = 0x2,
    PARTFXFLAG_4 = 0x4,
    PARTFXFLAG_10 = 0x10,
    PARTFXFLAG_800 = 0x800,
    PARTFXFLAG_10000 = 0x10000,
    PARTFXFLAG_200000 = 0x200000
} PartfxFlags;

/* Shared SRT layout. Effect IDs may interpret the rotation halfwords or
 * scale/position values as particle-specific parameters. */
typedef MatrixTransform PartFxSpawnParams;

/* The optional data packet is effect-specific (colors, velocity, alpha or variant). */
typedef int (*PartFxSpawnEffectFn)(GameObject* sourceObj, int effectId, PartFxSpawnParams* spawnParams, int spawnFlags,
                                   s8 sourceParam, void* extraArgs);
typedef void (*PartFxOnMapSetupFn)(void);
typedef void (*PartFxUpdateFrameStateFn)(int unused);

typedef struct PartFxInterface {
    u32 reserved;
    PartFxOnMapSetupFn onMapSetup;
    PartFxSpawnEffectFn spawnEffect;
    PartFxUpdateFrameStateFn updateFrameState;
} PartFxInterface;

STATIC_ASSERT(sizeof(PartFxInterface) == 0x10);
STATIC_ASSERT(offsetof(PartFxInterface, onMapSetup) == 0x04);
STATIC_ASSERT(offsetof(PartFxInterface, spawnEffect) == 0x08);
STATIC_ASSERT(offsetof(PartFxInterface, updateFrameState) == 0x0C);

extern PartFxInterface** gPartfxInterface;

#endif /* MAIN_DLL_PARTFX_INTERFACE_H_ */
