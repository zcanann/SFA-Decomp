#ifndef MAIN_OBJPRINT_DOLPHIN_H_
#define MAIN_OBJPRINT_DOLPHIN_H_

#include "ghidra_import.h"

void FUN_8003d6f8(int param_1);
void FUN_8003d97c(u16 *param_1,int param_2);
void FUN_8003db90(void);
void FUN_8003df64(u32 param_1,u32 param_2,int *param_3,float *param_4);
void FUN_8003e0ec(u32 param_1,u32 param_2,int *param_3,float *param_4,float *param_5,
                 u32 param_6,u32 param_7,u32 param_8);
void FUN_8003e358(int param_1,u32 param_2,int *param_3);
void FUN_8003e4a0(u32 param_1,u32 param_2,int *param_3,int *param_4,u32 param_5,
                 u8 *param_6,u8 *param_7);
char fn_8003EA84(u32 param_1,u32 param_2,int *param_3,u32 param_4,int param_5,
                int param_6);
void fn_8003EEEC(u32 param_1,u32 param_2,int *param_3,int *param_4);
void FUN_8003f3b4(u32 param_1,u32 param_2,int param_3);
void fn_8003F8EC(u32 param_1,u32 param_2,int param_3);
void FUN_8003f9f8(void);
void fn_8003FDA8(u32 param_1,u32 param_2,int param_3);
void FUN_800400ac(u32 param_1,u32 param_2,int param_3,u32 param_4);
void FUN_800400b0(void);
void FUN_800401a0(float *param_1,float *param_2,short *param_3,int param_4,u16 *param_5,
                 int param_6);
void FUN_8004034c(u8 param_1,u8 param_2,u8 param_3);
void FUN_8004036c(u32 param_1);
void FUN_80040374(int param_1);
void FUN_80040434(int param_1);
void FUN_800404cc(int param_1);
void FUN_800406cc(int param_1);
void FUN_80040784(u32 param_1,u32 param_2,u32 param_3);
void FUN_80040a88(int param_1);
void FUN_80040cd0(u8 param_1);
void FUN_80040cdc(int param_1,int *param_2);
int FUN_80040d44(int param_1);
void FUN_80040d88(void);
void FUN_80040d94(void);
void FUN_80040da0(void);
void FUN_800411ac(int param_1,int *param_2);
void FUN_80041248(int param_1,int *param_2);
void FUN_800412e4(int param_1,int *param_2);
void FUN_80041380(int param_1,int *param_2);
void FUN_8004141c(int param_1,int *param_2);
void FUN_800414b8(int param_1,int *param_2);
void FUN_8004151c(int param_1,int *param_2);
void FUN_800415b8(int param_1,int *param_2);
void FUN_80041664(int param_1,int *param_2);
void FUN_80041710(int param_1,int *param_2);
void FUN_800417ac(int param_1,int *param_2);
void FUN_80041858(int param_1,int *param_2);
void FUN_80041904(int param_1,int *param_2);
void FUN_800419a0(int param_1,int *param_2);
void FUN_80041a3c(int param_1,int *param_2);
void FUN_80041ad8(int param_1,int *param_2);
void FUN_80041b74(int param_1,int *param_2);
void FUN_80041c10(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9);
int FUN_80041ff8(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                int param_9);
void FUN_800427c8(void);
void FUN_80042800(void);
u32 FUN_80042830(void);
u32 FUN_80042838(void);
u32 FUN_8004286c(void);
int FUN_80042b9c(int param_1,int param_2,int param_3);
int FUN_80042bec(u32 param_1,int param_2);
void FUN_80042c18(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,u32 *param_11);
u8 * FUN_80042f88(int param_1);
void FUN_80043030(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void clearLoadedFileFlags_blocks1(void);


/* extern-cleanup: defining-file public prototypes */
void objRenderShadow2(int* obj, int* obj2, u8* m, int p4);
void modelDoRenderInstrs(int* obj, int* obj2, u8* m, u8 mode);
void objRenderChild(int* child, int* parent, u8 p3);

#endif /* MAIN_OBJPRINT_DOLPHIN_H_ */
