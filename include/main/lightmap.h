#ifndef MAIN_LIGHTMAP_H_
#define MAIN_LIGHTMAP_H_

#include "ghidra_import.h"

void FUN_8005acec(void);
undefined4 FUN_8005b068(int param_1);
undefined4 FUN_8005b094(int param_1);
undefined4 FUN_8005b0a8(int param_1,int param_2,int param_3);
int * fn_8005B11C(void);
int FUN_8005b128(void);
void FUN_8005b224(float *param_1,float *param_2);
undefined4 FUN_8005b2e8(void);
int FUN_8005b478(undefined8 param_1,double param_2);
int FUN_8005b60c(int param_1,int *param_2,int *param_3,int *param_4,uint *param_5);
void lightmap_sortQueuedRenderKeys(int queueBase,int keyCount);
void FUN_8005b7d0(void);
void FUN_8005bc3c(void);
void FUN_8005be04(void);
void FUN_8005c2f0(void);
void fn_8005C8CC(void);
void FUN_8005c964(void);
void FUN_8005c968(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9);
void FUN_8005cbc8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
void FUN_8005cea0(int param_1);
uint FUN_8005cec4(void);
undefined4 FUN_8005ced0(char param_1);
uint FUN_8005cf2c(void);
uint FUN_8005cf38(void);
uint FUN_8005cf44(void);
void FUN_8005cf50(int param_1);
void FUN_8005cf74(int param_1);
void FUN_8005cfe8(int param_1);
uint FUN_8005d00c(void);
void FUN_8005d024(int param_1);
void FUN_8005d048(int param_1);
void FUN_8005d06c(int param_1);
void FUN_8005d0e4(int param_1);
void fn_8005D108(int param_1,int param_2,int param_3);
void FUN_8005d238(undefined4 param_1,undefined param_2,undefined param_3,undefined param_4);
void FUN_8005d264(undefined4 param_1,undefined param_2,undefined param_3,undefined param_4,
                 undefined param_5);
void FUN_8005d294(undefined4 param_1,undefined param_2,undefined param_3,undefined param_4,
                 undefined param_5);
void FUN_8005d2c4(void);
void FUN_8005d2c8(void);
void lightmap_queueObjectRenderEntry(int object,int sortGroup,int depthBias);
void lightmap_sortQueuedRenderPackets(void);
void FUN_8005d530(int param_1,int param_2,int param_3);
void FUN_8005d668(int param_1,int param_2,float *param_3);
void FUN_8005d818(int param_1,int param_2,float *param_3);
void FUN_8005da10(int param_1,int param_2,float *param_3);
void lightmap_renderQueuedObject(ushort *object);
void lightmap_flushQueuedRenderPackets(void);
void FUN_8005e010(undefined4 param_1,undefined4 param_2,int param_3);

#endif /* MAIN_LIGHTMAP_H_ */
