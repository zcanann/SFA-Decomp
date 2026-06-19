#ifndef MAIN_PI_DOLPHIN_H_
#define MAIN_PI_DOLPHIN_H_

#include "ghidra_import.h"

u32 mapLoadDataFile(int param_1, int param_2);
void FUN_800443fc(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_80044400(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,u32 param_11,u32 param_12,u32 *param_13,
                 int param_14,u32 param_15,u32 param_16);
u32 FUN_80044404(int param_1);
void FUN_80044424(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void piRomLoadSection(int param_1,int param_2,int param_3);
void FUN_80044840(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,u32 *param_11,u32 *param_12,
                 int param_13,u32 param_14,int param_15,u32 param_16);
void FUN_80044bc4(u32 param_1,u32 param_2,u32 *param_3,u32 *param_4,
                 int param_5,u32 param_6,int param_7);
void FUN_80044d44(u32 param_1,u32 param_2,u32 *param_3,u32 *param_4,
                 int param_5,u32 param_6,int param_7);
void FUN_80044e24(u32 param_1,u32 param_2,u32 *param_3,u32 *param_4,
                 u32 *param_5);
void FUN_80044f74(int param_1,int *param_2,int *param_3,u32 *param_4,int param_5);
void FUN_80044fc4(u32 param_1,u32 param_2,u32 *param_3);
void FUN_80045148(u32 param_1,u32 param_2,u32 *param_3);
u32 FUN_800452f8(int param_1);
void FUN_80045328(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
int FUN_800455b8(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                int param_9,u32 param_10,u32 param_11,u32 param_12,
                u32 param_13,u32 param_14,u32 param_15,u32 param_16);
int FUN_80045734(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                int param_9);
void FUN_800458ac(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_800458b0(void);
void FUN_800458fc(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_80045900(void);
void FUN_80045a58(void);
void FUN_80045b94(void);
void FUN_80045bd0(void);
void FUN_80045bd4(u8 param_1,u8 param_2,u8 param_3);
void FUN_80045be8(void);
u32 FUN_80045c4c(char param_1);
void FUN_80045d68(u8 param_1);
void FUN_80045da4(void);
void fn_8004A8F8(char param_1);
void FUN_80045fcc(void);
void FUN_8004600c(void);
u32 FUN_800461b4(int *param_1,int *param_2);
void FUN_80046270(int param_1,int param_2,int param_3);
void FUN_800462f8(u32 param_1,u32 param_2,u8 param_3,u32 param_4,int param_5);
void fn_8004B11C(u32 param_1,u32 param_2,u8 param_3);
u32 FUN_800469d0(int param_1);
int FUN_80046a00(int *param_1);
void fn_8004B394(void);
u32 FUN_80046cd0(int *param_1,int param_2,int param_3,int param_4,u8 param_5);
void FUN_80046f44(u32 *param_1);
void FUN_80046f84(int *param_1);
void FUN_80046fd4(void);
u32 FUN_80047000(int param_1,u32 param_2,int param_3);
void FUN_80047d88(char *param_1,char param_2,char param_3,u32 *param_4,u32 *param_5);
void FUN_80047fdc(double param_1,u8 param_2);
void FUN_80048000(void);
void FUN_8004800c(double param_1,double param_2,double param_3,double param_4,double param_5,
                 u8 param_6);
void FUN_80048048(u32 *param_1,u32 *param_2);
u8 FUN_80048094(void);
int FUN_800480a0(int param_1,int param_2);
void FUN_800480b4(int param_1,int param_2);
void FUN_8004812c(int param_1,int param_2);
void FUN_80048178(void);
void FUN_8004817c(u32 param_1,u32 param_2,u32 param_3,u32 param_4,u32 param_5);
void FUN_800487e0(float *param_1);
void FUN_80048bc4(void);
void FUN_80048f00(int param_1);
void FUN_80049024(void);
void FUN_80049260(void);
void FUN_8004938c(int param_1);
void FUN_80049390(void);
void FUN_80049910(u32 *param_1);
void FUN_80049ee0(void);
void FUN_80049fb0(u32 *param_1);
void FUN_8004a094(void);
void FUN_8004a2c4(void);
void FUN_8004a394(double param_1,u32 *param_2,float *param_3);
void FUN_8004a670(double param_1,u32 *param_2,float *param_3);
void FUN_8004a94c(double param_1,u32 *param_2,float *param_3);
void FUN_8004ac40(int param_1,float *param_2);
void FUN_8004adc4(int param_1);
void FUN_8004afc0(float *param_1);
void FUN_8004b41c(u32 param_1,u32 param_2,int param_3,int param_4,int param_5);
void FUN_8004b8cc(u32 param_1);
void FUN_8004b960(u32 param_1,u32 param_2,u32 param_3,u32 param_4);
void FUN_8004bc68(char param_1);
void FUN_8004bd68(void);
void FUN_8004be30(char param_1);
void FUN_8004bf28(int param_1,char param_2,u32 param_3);
void FUN_8004c174(int param_1,char param_2);
void FUN_8004c178(int param_1,float *param_2);


/* extern-cleanup: defining-file public prototypes */
void setDisplayCopyFilter(void);
void gxTransformFn_8004a83c(void);
void allocSomething32bytes(void);
void initViewport(void);
void tvInit(void);
void fn_8004AFA0(int* q, int* elem, int idx);
void fn_8004AB5C(int* q, int* elem, int idx, u32 d, char* obj);

#endif /* MAIN_PI_DOLPHIN_H_ */
