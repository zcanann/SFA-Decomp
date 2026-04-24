#ifndef MAIN_LIGHTMAP_H_
#define MAIN_LIGHTMAP_H_

#include "ghidra_import.h"

void FUN_8005ab70(void);
undefined4 FUN_8005af70(int param_1);
undefined4 FUN_8005af9c(int param_1);
undefined4 FUN_8005afac(int param_1,int param_2,int param_3);
int * fn_8005B11C(void);
int FUN_8005b024(void);
void FUN_8005b12c(float *param_1,float *param_2);
undefined4 FUN_8005b220(void);
int FUN_8005b398(undefined8 param_1,double param_2);
int FUN_8005b54c(int param_1,int *param_2,int *param_3,int *param_4,uint *param_5);
void lightmap_sortQueuedRenderKeys(int queueBase,int keyCount);
void FUN_8005b744(void);
void FUN_8005bc0c(void);
void FUN_8005bdbc(void);
void FUN_8005c24c(void);
void fn_8005C8CC(void);
void FUN_8005c8ac(void);
void FUN_8005c8b0(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9);
void FUN_8005cc24(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
void FUN_8005cff0(int param_1);
uint FUN_8005d00c(void);
undefined4 FUN_8005d018(char param_1);
uint FUN_8005d06c(void);
uint FUN_8005d078(void);
uint FUN_8005d084(void);
void FUN_8005d090(int param_1);
void FUN_8005d0ac(int param_1);
void FUN_8005d114(int param_1);
uint FUN_8005d130(void);
void FUN_8005d144(int param_1);
void FUN_8005d160(int param_1);
void FUN_8005d17c(int param_1);
void FUN_8005d1e8(int param_1);
void fn_8005D108(int param_1,int param_2,int param_3);
void FUN_8005d314(undefined4 param_1,undefined param_2,undefined param_3,undefined param_4);
void FUN_8005d340(undefined4 param_1,undefined param_2,undefined param_3,undefined param_4,
                 undefined param_5);
void FUN_8005d370(undefined4 param_1,undefined param_2,undefined param_3,undefined param_4,
                 undefined param_5);
void FUN_8005d3a0(void);
void FUN_8005d3a4(void);
void lightmap_queueObjectRenderEntry(int object,int sortGroup,int depthBias);
void lightmap_sortQueuedRenderPackets(void);
void FUN_8005d5f4(int param_1,int param_2,int param_3);
void FUN_8005d85c(int param_1,int param_2,float *param_3);
void FUN_8005d984(int param_1,int param_2,float *param_3);
void FUN_8005daec(int param_1,int param_2,float *param_3);
void lightmap_renderQueuedObject(ushort *object);
void lightmap_flushQueuedRenderPackets(void);
void FUN_8005e1d8(undefined4 param_1,undefined4 param_2,int param_3);

#endif /* MAIN_LIGHTMAP_H_ */
