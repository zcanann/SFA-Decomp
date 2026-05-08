#ifndef MAIN_EXPGFX_H_
#define MAIN_EXPGFX_H_

#include "ghidra_import.h"

void expgfx_release(uint slotPoolBase,int poolIndex,int slotIndex,int freeTexture,int clearActive);
void expgfx_initialise(void);
int expgfx_reserveSlot(short *poolIndexOut,undefined2 *slotIndexOut,short slotType,
                       int preferredPoolIndex,uint sourceId);
void expgfx_initSlotQuad(void *slot);
void FUN_8009bd84(undefined8 param_1,double param_2,double param_3,double param_4,double param_5,
                 double param_6,undefined8 param_7,undefined8 param_8);
int expgfx_addToTable(uint textureOrResource,uint key0,uint key1,s16 slotType);
int expgfx_updateSourceFrameFlags(void *sourceObject);
void expgfx_free0C(u32 sourceId);
void expgfx_func0B_nop(void);
void expgfx_func0A_nop(void);
int expgfx_func09_ret_0(void);
void expgfx_renderSourcePools(int sourceId,int sourceMode);
void expgfx_renderPool(uint slotPoolBase,int poolIndex);
void expgfx_queueStandalonePools(void);
void expgfx_free08(u32 sourceId);
void expgfx_releaseSourceSlots(u32 sourceId);
void expgfx_resetAllPools(void);
void expgfx_updateFrameState(int sourceMode,int sourceId);
struct ExpgfxSpawnConfig;
int expgfx_addremove(struct ExpgfxSpawnConfig *config, int preferredPoolIdx, short slotType, u8 boundsTemplateId);
void expgfx_resetPoolResources(void);
void expgfx_releaseSlotPoolHandles(void);

#endif /* MAIN_EXPGFX_H_ */
