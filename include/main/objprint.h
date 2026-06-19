#ifndef MAIN_OBJPRINT_H_
#define MAIN_OBJPRINT_H_

#include "ghidra_import.h"
#include "main/objtexture.h"

void objAnimFn_80038f38(int param_1,char *param_2);
void FUN_80039130(u32 param_1,int *param_2);
void FUN_800392e0(u32 *param_1);
void FUN_800392ec(u32 param_1,u8 *param_2,u16 param_3);
void FUN_80039370(u32 param_1,u32 param_2,u16 *param_3,u32 param_4);
void FUN_80039468(u32 param_1,u32 param_2,u16 param_3,short param_4,u32 param_5,
                 u32 param_6);
u32 * FUN_80039518(void);
int FUN_80039520(int param_1,u32 param_2);
void FUN_80039580(int param_1,u32 param_2,float *param_3);
int FUN_8003964c(int param_1,u32 param_2);
void FUN_800396cc(int param_1,int param_2);
u32 FUN_8003988c(double param_1,double param_2,int param_3,short *param_4);
u32 FUN_80039a28(int param_1,int param_2);
void FUN_80039bc4(double param_1,u32 param_2,char *param_3,int param_4);
void FUN_80039e6c(double param_1,short *param_2,char *param_3,int param_4);
void FUN_8003a1c4(int param_1,int param_2);
void fn_8003A328(double param_1,short *param_2,char *param_3);
void FUN_8003a420(u32 param_1,u32 param_2,float *param_3,int param_4,short *param_5,
                 u32 param_6,short param_7);
void FUN_8003a8ac(u32 param_1,u32 param_2,int param_3,int param_4);
void FUN_8003a9c8(int param_1,u32 param_2,u16 param_3,u16 param_4);
void FUN_8003aa48(int param_1);
void FUN_8003aaf0(int param_1,u32 *param_2,int param_3,int param_4,int param_5);
void FUN_8003ac24(int param_1,u32 *param_2,int param_3);
void FUN_8003ad08(int param_1,u32 *param_2,int param_3,int param_4);
void FUN_8003add8(u32 param_1,u32 param_2,int param_3,u32 param_4,u32 param_5,
                 u32 param_6);
void FUN_8003b06c(short *param_1,u32 param_2,int param_3,u32 param_4);
void FUN_8003b1a4(int param_1,int param_2);
void FUN_8003b280(int param_1,int param_2);
void FUN_8003b444(short *param_1,char *param_2);
void FUN_8003b540(u8 param_1,u8 param_2,u8 param_3,u8 param_4);
void FUN_8003b56c(u16 param_1,u16 param_2,u16 param_3);
void FUN_8003b590(u32 param_1,u32 param_2,int *param_3);
void FUN_8003b7dc(int param_1);
void FUN_8003b818(int param_1);
void FUN_8003b870(u32 param_1);
void FUN_8003b878(u32 param_1,u32 param_2,u32 param_3,u32 param_4,
                 int param_5,u32 param_6);
u8 FUN_8003ba68(void);
void FUN_8003ba74(u8 param_1);
u32 FUN_8003ba80(float *param_1,float *param_2);
u32 FUN_8003bbfc(float *param_1,u16 *param_2,u16 *param_3,u16 *param_4);
void FUN_8003bda0(u32 param_1,u32 param_2,float *param_3,float *param_4);
void FUN_8003be6c(void);
void FUN_8003c10c(int param_1,int *param_2);
u32 FUN_8003c1f8(int param_1,int *param_2,int param_3);
void FUN_8003cb48(u32 param_1,u32 param_2,int param_3);


/* extern-cleanup: defining-file public prototypes */
void modelCalcVtxGroupMtxs(int p1, int p2);
void staffMtxFn_8003b620(int staff, int obj, int model, int a, int b, int c);
void fn_80039B54(int obj, s16* curve, s16* state, f32 val);

#endif /* MAIN_OBJPRINT_H_ */
