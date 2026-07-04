#ifndef MAIN_SHADER_H_
#define MAIN_SHADER_H_

#include "ghidra_import.h"
#include "main/frustum.h"

int objShouldLoad(int obj, s8 viewSlot, int mapEventGroup);
void FUN_80055d0c(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_80055d10(void);
int fn_80056800(int param_1);
u32 FUN_80055ee8(void);
u32 FUN_80055ef0(void);
void FUN_80055ef8(int param_1,u32 param_2);
int FUN_80056000(int param_1,int param_2,u32 param_3);
void FUN_800562d0(u32 param_1,int param_2,int param_3);
void FUN_800563e8(int param_1,float *param_2,float *param_3);
void FUN_80056418(int param_1,int param_2,int param_3,int param_4,int param_5);
int FUN_80056448(int param_1,int param_2,int param_3,int param_4);
void FUN_8005652c(u32 param_1,u32 param_2,int param_3,int param_4);
void FUN_800565f8(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,u32 param_11,u32 param_12,
                 int param_13,u32 param_14,u32 param_15,u32 param_16);
void FUN_800565fc(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
int FUN_80056600(void);
void FUN_80056608(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 char param_9);
void FUN_800566c8(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,int *param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
void FUN_800566cc(void);
int FUN_800566e0(void);
void FUN_800566e8(u64 param_1,u64 param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_800566ec(int param_1,int param_2,int *param_3,int *param_4,int *param_5,int *param_6,
                 int param_7,int param_8,int param_9);
void FUN_800569f4(void);
void FUN_80056a20(void);
void FUN_80056a4c(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_80056a50(double param_1,double param_2,double param_3,u64 param_4,u64 param_5
                 ,u64 param_6,u64 param_7,u64 param_8);
void FUN_80056a88(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,short param_11,short param_12,int param_13,
                 u32 param_14,u32 param_15,u32 param_16);
void FUN_80056c88(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
int FUN_80056c8c(void);
int FUN_80056cdc(int param_1,int param_2);
void FUN_80056cf4(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,u16 *param_11,int param_12);
void FUN_80056cf8(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_80056cfc(void);
void FUN_80057048(int param_1);
int FUN_8005709c(int param_1,int param_2,int param_3);
void FUN_800571f8(u8 *param_1);
void FUN_80057270(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_80057274(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
u32 FUN_800575b4(double param_1,float *param_2);
u32 FUN_80057690(int param_1);
void FUN_800579cc(u32 *param_1);
u32 FUN_80057ce8(u32 param_1,u32 param_2,int param_3);
void FUN_80057ea0(float *param_1,int param_2);
void FUN_80057fd0(void);


/* extern-cleanup: defining-file public prototypes */
void mapReloadWithFadeout(void);
void initMaps(void);
void unloadMap(void);
void beginLoadingMap(void);
void goToNextMapLayer(void);
void goToPrevMapLayer(void);
void trackLoadBlockEnd(void* blk, int blockId, int slotIdx, int layer);
void playerVecFn_8005a9b0(void);

#endif /* MAIN_SHADER_H_ */
