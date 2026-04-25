#ifndef MAIN_EXPGFX_H_
#define MAIN_EXPGFX_H_

#include "ghidra_import.h"

void expgfx_release(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                    undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                    undefined4 param_9,undefined4 param_10,int param_11,int param_12,uint param_13,
                    undefined4 param_14,undefined4 param_15,undefined4 param_16);
void expgfx_initialise(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                       undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
undefined4 expgfx_reserveSlot(short *param_1,undefined2 *param_2,short param_3,int param_4,
                              int param_5);
void expgfx_initSlotQuad(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                         undefined8 param_5,undefined8 param_6,undefined8 param_7,
                         undefined8 param_8,undefined2 *param_9);
void FUN_8009bd84(undefined8 param_1,double param_2,double param_3,double param_4,double param_5,
                 double param_6,undefined8 param_7,undefined8 param_8);
int expgfx_addToTable(int textureOrResource,int key0,int key1,s16 slotType);
int fn_8009DF0C(void *sourceObject);
void fn_8009E004(void);
void fn_8009E024(void);
void fn_8009E028(void);
int fn_8009E02C(void);
void fn_8009E034();
void fn_8009E13C();
void fn_8009ECE4(void);
void fn_8009EEB8(void);
void fn_8009EED8();
void fn_8009EFDC(void);
void expgfx_updateFrameState(int sourceMode,int sourceId);
void expgfx_addremove(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5,
                      undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,
                      undefined4 param_10,short param_11,undefined param_12,undefined4 param_13,
                      undefined4 param_14,undefined4 param_15,undefined4 param_16);
void fn_8009FCDC(void);
void fn_8009FE7C(void);

#endif /* MAIN_EXPGFX_H_ */
