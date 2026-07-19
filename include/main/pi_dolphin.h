#ifndef MAIN_PI_DOLPHIN_H_
#define MAIN_PI_DOLPHIN_H_

#include "ghidra_import.h"
#include "main/pi_dolphin_api.h"

void FUN_800443fc(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_80044400(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,u32 param_11,u32 param_12,u32 *param_13,
                 int param_14,u32 param_15,u32 param_16);
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
void FUN_800458fc(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_8004800c(double param_1,double param_2,double param_3,double param_4,double param_5,
                 u8 param_6);


/* extern-cleanup: defining-file public prototypes */
void setDisplayCopyFilter(void);
void gxTransformFn_8004a83c(void);
void allocSomething32bytes(void);
void initViewport(void);
void tvInit(void);
void pathSearchExpandNode(int* q, int* elem, int idx);
void pathSearchEnqueuePoint(int* q, int* elem, int idx, u32 d, char* obj);


#include "main/mldf_fileid.h"

double SeekTwiceBeforeRead();

#endif /* MAIN_PI_DOLPHIN_H_ */
