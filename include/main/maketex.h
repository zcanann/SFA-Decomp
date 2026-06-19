#ifndef MAIN_MAKETEX_H_
#define MAIN_MAKETEX_H_

#include "ghidra_import.h"

void FUN_8007e77c(u64 param_1,double param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_8007ea1c(u32 param_1,u32 param_2,u32 param_3,u32 param_4);
u32 FUN_8007ea90(u32 param_1,u32 param_2,u32 param_3);
u32 FUN_8007eac4(u32 param_1,u32 param_2,u32 param_3);
int FUN_8007eb04(u32 param_1);
void FUN_8007f00c(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,u32 param_11,u32 param_12,
                 u32 param_13,u8 *param_14,u32 param_15,u32 param_16);
void FUN_8007f010(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
void FUN_8007f014(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
u32
FUN_8007f350(u64 param_1,double param_2,u64 param_3,u64 param_4,
            u64 param_5,u64 param_6,u64 param_7,u64 param_8,char param_9
            ,u32 param_10,u32 param_11,u32 param_12,u32 param_13,
            u32 param_14,u32 param_15,u32 param_16);
int FUN_8007f358(int *param_1,int *param_2,int param_3);
int FUN_8007f3c8(int *param_1,int param_2,int param_3);
void FUN_8007f400(int param_1,int param_2);
int FUN_8007f56c(int *param_1,int param_2,int param_3);
void FUN_8007f5ec(int param_1,int param_2);
u32 FUN_8007f66c(int param_1);
u32 FUN_8007f6c8(float *param_1);
void FUN_8007f6e4(u32 *param_1);
void FUN_8007f718(float *param_1,short param_2);
u32 FUN_8007f764(float *param_1);
void FUN_8007f7a4(void);
void FUN_8007f7b4(void);
u8 FUN_8007f7c0(void);
void FUN_8007f7cc(double param_1,double param_2,double param_3,double param_4,u16 param_5,
                 u16 param_6,u16 param_7);
u32 FUN_8007f810(void);
u32 FUN_8007f818(int param_1);
int FUN_8007f924(int param_1);
u32 FUN_8007f944(int param_1,u16 param_2);
void FUN_8007f960(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_8007fa8c(int param_1,int param_2);
void FUN_8007fb48(int param_1);
void FUN_8007fb80(u32 param_1,u32 param_2,short param_3,u32 param_4,
                 u32 param_5,u32 param_6,u32 param_7,u32 param_8);


/* extern-cleanup: defining-file public prototypes */
void seqClearTaskTexts(void);
void endObjSequence(int seq);
void cameraFocusNpc(int param1, u8* obj);

#endif /* MAIN_MAKETEX_H_ */
