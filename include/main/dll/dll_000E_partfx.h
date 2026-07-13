#ifndef MAIN_DLL_DLL_000E_PARTFX_H_
#define MAIN_DLL_DLL_000E_PARTFX_H_

#include "types.h"
#include "main/dll/partfx_interface.h"

typedef int (*PartFxSpawnCallback)(s16*, int, PartFxSpawnParams*, u32, u8, void*);

typedef struct PartFxResourceVTable {
    u8 pad00[0x08];
    PartFxSpawnCallback spawnObject;
} PartFxResourceVTable;

STATIC_ASSERT(offsetof(PartFxResourceVTable, spawnObject) == 0x08);

typedef struct PartFxResource {
    PartFxResourceVTable* vtable;
} PartFxResource;

typedef struct PartFxSpawnContext {
    int effectId;
    f32* startPos;
} PartFxSpawnContext;

void partfx_onMapSetup(void);
void partfx_initialise(void);
void partfx_updateFrameState(void);
void partfx_release(void);
int partfx_spawnObject(s16* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags, u8 modelId,
                       f32* extraArgs);

#endif /* MAIN_DLL_DLL_000E_PARTFX_H_ */
