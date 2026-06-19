#ifndef MAIN_LIGHTMAP_H_
#define MAIN_LIGHTMAP_H_

#include "ghidra_import.h"

void updateVisibleGeometry(void);
u32 FUN_8005af70(int param_1);
u32 FUN_8005af9c(int param_1);
int coordsToMapCell(f32 x, f32 z);
int * fn_8005B11C(void);
int FUN_8005b024(void);
void FUN_8005b12c(float *param_1,float *param_2);
u32 FUN_8005b220(void);
int FUN_8005b398(u64 param_1,double param_2);
int FUN_8005b54c(int param_1,int *param_2,int *param_3,int *param_4,u32 *param_5);
void lightmap_sortQueuedRenderKeys(int queueBase,int keyCount);
void FUN_8005b744(void);
void FUN_8005bc0c(void);
void FUN_8005bdbc(void);
void FUN_8005c24c(void);
void fn_8005C8CC(void);
void FUN_8005c8ac(void);
void FUN_8005c8b0(u64 param_1,double param_2,double param_3,double param_4,u64 param_5
                 ,u64 param_6,u64 param_7,u64 param_8,int param_9);
void FUN_8005cc24(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_8005cff0(int param_1);
u32 FUN_8005d00c(void);
u32 FUN_8005d018(char param_1);
u32 FUN_8005d06c(void);
u32 FUN_8005d078(void);
u32 FUN_8005d084(void);
void FUN_8005d090(int param_1);
void FUN_8005d0ac(int param_1);
void FUN_8005d114(int param_1);
u32 FUN_8005d130(void);
void FUN_8005d144(int param_1);
void FUN_8005d160(int param_1);
void FUN_8005d17c(int param_1);
void FUN_8005d1e8(int param_1);
void fn_8005D108(int param_1,int param_2,int param_3);
void FUN_8005d314(u32 param_1,u8 param_2,u8 param_3,u8 param_4);
void FUN_8005d340(u32 param_1,u8 param_2,u8 param_3,u8 param_4,
                 u8 param_5);
void FUN_8005d370(u32 param_1,u8 param_2,u8 param_3,u8 param_4,
                 u8 param_5);
void FUN_8005d3a0(void);
void FUN_8005d3a4(void);
void lightmap_queueObjectRenderEntry(int object,int sortGroup,int depthBias);
void lightmap_queueExternalRenderEntry(u32 slotPoolBase,u32 poolIndex,float *position);
void lightmap_sortQueuedRenderPackets(void);
void FUN_8005d5f4(int param_1,int param_2,int param_3);
void FUN_8005d85c(int param_1,int param_2,float *param_3);
void FUN_8005d984(int param_1,int param_2,float *param_3);
void FUN_8005daec(int param_1,int param_2,float *param_3);
void lightmap_renderQueuedObject(u16 *object);
void lightmap_flushQueuedRenderPackets(void);
void FUN_8005e1d8(u32 param_1,u32 param_2,int param_3);

#endif /* MAIN_LIGHTMAP_H_ */
