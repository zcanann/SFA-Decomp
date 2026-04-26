#ifndef MAIN_EXPGFX_H_
#define MAIN_EXPGFX_H_

#include "ghidra_import.h"

void expgfx_release(uint slotPoolBase,int poolIndex,int slotIndex,int freeTexture,int clearActive);
void expgfx_initialise(void);
int expgfx_reserveSlot(short *param_1,undefined2 *param_2,short param_3,int param_4,uint param_5);
void expgfx_initSlotQuad(void *slot);
void FUN_8009bd84(undefined8 param_1,double param_2,double param_3,double param_4,double param_5,
                 double param_6,undefined8 param_7,undefined8 param_8);
int expgfx_addToTable(uint textureOrResource,uint key0,uint key1,s16 slotType);
int expgfx_updateSourceFrameFlags(void *sourceObject);
void fn_8009E004(void);
void fn_8009E024(void);
void fn_8009E028(void);
int fn_8009E02C(void);
void expgfx_renderSourcePools(int sourceId,int sourceMode);
void expgfx_renderPool(uint slotPoolBase,int poolIndex);
void expgfx_queueStandalonePools(void);
void fn_8009EEB8(void);
void expgfx_releaseSourceSlots();
void expgfx_resetAllPools(void);
void expgfx_updateFrameState(int sourceMode,int sourceId);
void expgfx_addremove(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5,
                      undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,
                      undefined4 param_10,short param_11,undefined param_12,undefined4 param_13,
                      undefined4 param_14,undefined4 param_15,undefined4 param_16);
void fn_8009FCDC(void);
void fn_8009FE7C(void);

#endif /* MAIN_EXPGFX_H_ */
