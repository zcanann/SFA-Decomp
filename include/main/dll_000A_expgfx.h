#ifndef MAIN_EXPGFX_H_
#define MAIN_EXPGFX_H_

#include "types.h"
#include "main/dll/expgfx_interface.h"
#include "dlls/object_descriptor.h"
#include "main/dll/expgfx_resource_api.h"
#include "main/dll/effectspawnconfig_struct.h"

typedef struct ExpgfxDescriptor {
    u32 reserved[3];
    u32 slotCountAndFlags;
    void (*initialise)(void);
    void (*release)(void);
    ExpgfxInterface interface;
} ExpgfxDescriptor;

STATIC_ASSERT(sizeof(ExpgfxDescriptor) == 0x48);
STATIC_ASSERT(offsetof(ExpgfxDescriptor, interface) == 0x18);
extern ExpgfxDescriptor gExpgfxDescriptor;

void expgfxRemove(void* slotPoolBase, int poolIndex, int slotIndex, int skipTextureFree, int flushSlot);
void expgfxRemoveAll(void);
int expgfxGetSlot(short* poolIndexOut, short* slotIndexOut, short slotType, int preferredPoolIndex, GameObject* sourceObject);
void expgfx_initSlotQuad(void* slot);
void expgfx_updateActivePools(u8 sourceMode, int frameCount, int resetSourceFrameState);
int expgfx_addToTable(void* resourceHandle, GameObject* sourceObject, GameObject* sourceParent,
                      s16 resourceId);
int expgfx_updateSourceFrameFlags(GameObject* sourceObject);
void expgfx_ownerFree3(GameObject* sourceObject);
void expgfx_func0B_nop(void);
void expgfx_func0A_nop(void);
int expgfx_func09(void);
void expgfx_renderSourcePools(GameObject* sourceObject, int sourceMode);
void drawGlow(void* slotPoolBase, int poolIndex);
void renderParticles(void);
void expgfx_free2(GameObject* sourceObject);
void expgfx_free(GameObject* sourceObject);
void expgfx_resetAllPools(void);
void expgfx_updateFrameState(int sourceMode, int frameCount, int unused0, int unused1);
int expgfx_addremove(EffectSpawnConfig* config, int preferredPoolIndex, int slotType, int planeOffsetSetId);
void expgfx_onMapSetup(void);
void expgfx_release(void);
void expgfx_initialise(void);

#endif /* MAIN_EXPGFX_H_ */
