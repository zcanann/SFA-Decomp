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
void FUN_8009b994(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9);
void FUN_8009bd84(undefined8 param_1,double param_2,double param_3,double param_4,double param_5,
                 double param_6,undefined8 param_7,undefined8 param_8);
int expgfx_addToTable(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                      undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                      int param_9,int param_10,int param_11,undefined4 param_12);
void FUN_8009bf6c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
void expgfx_processCurrentSourceBounds(void);
void FUN_8009c0b4(void);
void FUN_8009c0b8(void);
void FUN_8009c0bc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
void FUN_8009c11c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
void FUN_8009c120(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
void FUN_8009c124(undefined8 param_1,undefined8 param_2,double param_3,double param_4,double param_5
                 ,double param_6,undefined8 param_7,undefined8 param_8);
void expgfx_addremove(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5,
                      undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,
                      undefined4 param_10,short param_11,undefined param_12,undefined4 param_13,
                      undefined4 param_14,undefined4 param_15,undefined4 param_16);

#endif /* MAIN_EXPGFX_H_ */
