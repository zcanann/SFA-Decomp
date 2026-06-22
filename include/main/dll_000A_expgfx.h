#ifndef MAIN_EXPGFX_H_
#define MAIN_EXPGFX_H_

#include "ghidra_import.h"
#include "main/effect_interfaces.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor14 expgfx_funcs;
extern ExpgfxInterface **gExpgfxInterface;

void expgfxRemove(u32 slotPoolBase,int poolIndex,int slotIndex,int skipTextureFree,int flushSlot);
void expgfxRemoveAll(void);
int expgfxGetSlot(short *poolIndexOut,short *slotIndexOut,short slotType,
                       int preferredPoolIndex,u32 sourceId);
void expgfx_initSlotQuad(void *slot);
void expgfx_updateActivePools(u8 sourceMode,int sourceId,int resetSourceFrameState);
int expgfx_addToTable(u32 resourceHandle,u32 sourceId,u32 attachedTableKey,s16 resourceId);
int expgfx_updateSourceFrameFlags(void *sourceObject);
void expgfx_ownerFree3(u32 sourceId);
void expgfx_func0B_nop(void);
void expgfx_func0A_nop(void);
int expgfx_func09(void);
void expgfx_renderSourcePools(int sourceId,int sourceMode);
void drawGlow(u32 slotPoolBase,int poolIndex);
void renderParticles(void);
void expgfx_updateResourceEntries(int unused);
int expgfx_acquireResourceEntry(int resourceId);
void expgfx_free2(u32 sourceId);
void expgfx_free(u32 sourceId);
void expgfx_resetAllPools(void);
void expgfx_updateFrameState(int sourceMode,int sourceId);
struct ExpgfxSpawnConfig;
int expgfx_addremove(struct ExpgfxSpawnConfig *config, int preferredPoolIndex, int slotType,
                     u8 boundsTemplateId);
void expgfx_onMapSetup(void);
void expgfx_release(void);
void expgfx_initialise(void);

#endif /* MAIN_EXPGFX_H_ */
