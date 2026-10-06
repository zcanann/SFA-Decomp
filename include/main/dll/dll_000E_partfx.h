#ifndef MAIN_DLL_DLL_000E_PARTFX_H_
#define MAIN_DLL_DLL_000E_PARTFX_H_

#include "types.h"
#include "main/dll/partfx_interface.h"
#include "game/objects/object_fwd.h"

typedef int (*PartFxResourceSpawnFn)(GameObject*, int, PartFxSpawnParams*, u32, s8, void*);

typedef struct PartFxResourceVTable {
    u8 reserved[8];
    PartFxResourceSpawnFn spawnEffect;
} PartFxResourceVTable;

STATIC_ASSERT(offsetof(PartFxResourceVTable, spawnEffect) == 0x08);

typedef struct PartFxResource {
    PartFxResourceVTable* vtable;
} PartFxResource;

typedef struct PartFxDescriptor {
    u32 reserved[3];
    u32 slotCountAndFlags;
    void (*initialise)(void);
    void (*release)(void);
    PartFxInterface interface;
} PartFxDescriptor;

STATIC_ASSERT(sizeof(PartFxDescriptor) == 0x28);
STATIC_ASSERT(offsetof(PartFxDescriptor, interface) == 0x18);
extern PartFxDescriptor gPartfxDescriptor;

void partfx_onMapSetup(void);
void partfx_initialise(void);
void partfx_updateFrameState(int unused);
void partfx_release(void);
int partfx_spawnEffect(GameObject* sourceObj, int effectId, PartFxSpawnParams* spawnParams, int spawnFlags,
                       s8 sourceParam, void* extraArgs);

#endif /* MAIN_DLL_DLL_000E_PARTFX_H_ */
