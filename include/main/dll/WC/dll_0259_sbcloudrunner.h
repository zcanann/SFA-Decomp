#ifndef MAIN_DLL_WC_WCLEVCONTROL_H_
#define MAIN_DLL_WC_WCLEVCONTROL_H_

#include "ghidra_import.h"
#include "main/objanim_update.h"

void FUN_801ee668(u16 *param_1,int param_2);
void FUN_801ee7bc(short *param_1,int param_2,u32 param_3,u32 param_4,
                 u32 param_5,u32 param_6,u32 param_7,u32 param_8);
void FUN_801eeafc(u16 *param_1,int param_2,u32 param_3,u32 param_4,
                 u32 param_5,u32 param_6,u32 param_7,u32 param_8);
void FUN_801eefcc(u32 param_1,u32 param_2,int param_3);
void FUN_801eefd0(u32 param_1,int param_2);
void FUN_801ef1a4(int param_1);
void FUN_801ef1e0(int param_1,u32 *param_2,u32 *param_3,u32 *param_4);
void FUN_801ef200(int param_1);
void FUN_801ef228(int param_1);
void FUN_801ef2c0(int param_1,int param_2,int param_3,int param_4,int param_5,s8 renderState);
void FUN_801ef3f8(u16 *param_1,u32 param_2,int param_3,u32 param_4,
                 u32 param_5,u32 param_6,u32 param_7,u32 param_8);
void FUN_801ef980(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u16 *param_9,u32 param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
void FUN_801ef984(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
int SB_CloudRunner_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate);

#endif /* MAIN_DLL_WC_WCLEVCONTROL_H_ */
