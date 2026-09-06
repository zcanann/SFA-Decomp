#ifndef MAIN_EXPGFX_H_
#define MAIN_EXPGFX_H_

#include "types.h"
#include "main/dll/expgfx_interface.h"
#include "dlls/object_descriptor.h"
#include "main/dll/expgfx_resource_api.h"

typedef struct ExpgfxDllInterface {
    u32 reserved0;
    u32 reserved1;
    u32 reserved2;
    u32 slotCountAndFlags;
    ObjectDescriptorCallback initialise;
    ObjectDescriptorCallback release;
    ObjectDescriptorCallback slot02;
    ObjectDescriptorCallback onMapSetup;
    ObjectDescriptorCallback addremove;
    ObjectDescriptorCallback updateFrameState;
    ObjectDescriptorCallback resetAllPools;
    ObjectDescriptorCallback free;
    ObjectDescriptorCallback free2;
    ObjectDescriptorCallback slot09;
    ObjectDescriptorCallback slot0A;
    ObjectDescriptorCallback slot0B;
    ObjectDescriptorCallback ownerFree3;
    ObjectDescriptorCallback updateSourceFrameFlags;
} ExpgfxDllInterface;

extern ExpgfxDllInterface expgfx_funcs;

void expgfxRemove(u32 slotPoolBase, int poolIndex, int slotIndex, int skipTextureFree, int flushSlot);
void expgfxRemoveAll(void);
int expgfxGetSlot(short* poolIndexOut, short* slotIndexOut, short slotType, int preferredPoolIndex, u32 sourceId);
void expgfx_initSlotQuad(void* slot);
void expgfx_updateActivePools(u8 sourceMode, int sourceId, int resetSourceFrameState);
int expgfx_addToTable(u32 resourceHandle, u32 sourceId, u32 attachedTableKey, s16 resourceId);
int expgfx_updateSourceFrameFlags(void* sourceObject);
void expgfx_ownerFree3(u32 sourceId);
void expgfx_func0B_nop(void);
void expgfx_func0A_nop(void);
int expgfx_func09(void);
void expgfx_renderSourcePools(int sourceId, int sourceMode);
void drawGlow(u32 slotPoolBase, int poolIndex);
void renderParticles(void);
void expgfx_free2(u32 sourceId);
void expgfx_free(u32 sourceId);
void expgfx_resetAllPools(void);
void expgfx_updateFrameState(int sourceMode, int sourceId);
struct ExpgfxSpawnConfig;
int expgfx_addremove(struct ExpgfxSpawnConfig* config, int preferredPoolIndex, int slotType, int planeOffsetSetId);
void expgfx_onMapSetup(void);
void expgfx_release(void);
void expgfx_initialise(void);

#endif /* MAIN_EXPGFX_H_ */
