#ifndef MAIN_LIGHT_H_
#define MAIN_LIGHT_H_

#include "ghidra_import.h"
#include "main/objanim_update.h"

void vfpblock1_update(int obj);
void FUN_801fbcd0(int obj);
void FUN_801fbd04(int param_1);
void FUN_801fbd24(int param_1);
void FUN_801fbd90(u32 param_1);
void FUN_801fbdf4(u16 *param_1,int param_2);
void FUN_801fbdf8(int obj);
void FUN_801fbe2c(u32 param_1);
void FUN_801fbed8(int param_1);
void FUN_801fc16c(int obj);
void FUN_801fc1a0(int param_1,int p1,int p2,int p3,int p4,s8 visible);
void FUN_801fc1d8(void);
void FUN_801fc75c(u64 param_1,u64 param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9);
void FUN_801fc944(int obj);
void seqpoint_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void FUN_801fc998(u64 param_1,u64 param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9);
void FUN_801fcbf4(u16 *param_1,int param_2);
u32
FUN_801fcccc(u64 param_1,double param_2,double param_3,u64 param_4,u64 param_5,
            u64 param_6,u64 param_7,u64 param_8,int param_9,u32 param_10,
            ObjAnimUpdateState *animUpdate,u32 param_12,u32 param_13,u32 param_14,
            u32 param_15,u32 param_16);
void FUN_801fd0c4(int param_1,int p1,int p2,int p3,int p4,s8 visible);
void FUN_801fd0ec(int param_1);
void FUN_801fd408(u16 *param_1,int param_2);
void FUN_801fd40c(u32 param_1);


/* extern-cleanup: defining-file public prototypes */
void vfpdoorswitch_updateExplodingVariant(int obj);

#endif /* MAIN_LIGHT_H_ */
