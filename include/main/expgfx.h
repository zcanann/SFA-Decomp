#ifndef MAIN_EXPGFX_H_
#define MAIN_EXPGFX_H_

#include "ghidra_import.h"

void expgfxRemove(uint slotPoolBase,int poolIndex,int slotIndex,int freeTexture,int clearActive);
void expgfxRemoveAll(void);
int expgfxGetSlot(short *poolIndexOut,short *slotIndexOut,short slotType,
                       int preferredPoolIndex,uint sourceId);
void expgfx_initSlotQuad(void *slot);
void FUN_8009bd84(undefined8 param_1,double param_2,double param_3,double param_4,double param_5,
                 double param_6,undefined8 param_7,undefined8 param_8);
int expgfx_addToTable(uint textureOrResource,uint key0,uint key1,s16 slotType);
int expgfx_updateSourceFrameFlags(void *sourceObject);
void expgfx_func0C(u32 sourceId);
void expgfx_func0B(void);
void expgfx_func0A(void);
int expgfx_func09(void);
void expgfx_renderSourcePools(int sourceId,int sourceMode);
void drawGlow(uint slotPoolBase,int poolIndex);
void renderParticles(void);
void expgfx_func08(u32 sourceId);
void expgfx_free(u32 sourceId);
void expgfx_resetAllPools(void);
void expgfx_updateFrameState(int sourceMode,int sourceId);
struct ExpgfxSpawnConfig;
int expgfx_addremove(struct ExpgfxSpawnConfig *config, int preferredPoolIdx, short slotType, u8 boundsTemplateId);
void expgfx_onMapSetup(void);
void expgfx_release(void);
void expgfx_initialise(undefined8 param_1,undefined8 param_2,undefined8 param_3,
                       undefined8 param_4,undefined8 param_5,undefined8 param_6,
                       undefined8 param_7,undefined8 param_8);

#endif /* MAIN_EXPGFX_H_ */
