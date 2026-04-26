#ifndef MAIN_OBJLIB_H_
#define MAIN_OBJLIB_H_

#include "ghidra_import.h"

void FUN_800356f0(int param_1);
int ObjHitbox_AllocRotatedBounds(ushort *param_1,uint param_2);
void FUN_8003582c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,int param_12,int param_13,
                 int param_14,undefined4 param_15,undefined4 param_16);
void FUN_8003597c(undefined4 param_1,undefined4 param_2,int param_3,uint param_4,int param_5);
void ObjHitbox_SetStateIndex(int param_1,int param_2,int param_3);
void ObjHits_SetTargetMask(int param_1,undefined param_2);
void FUN_80035b84(int param_1,undefined2 param_2);
void FUN_80035d58(int param_1,undefined2 param_2,short param_3,short param_4);
void ObjHits_ClearHitVolumes(int param_1);
void ObjHits_SetHitVolumeMasks(int param_1,undefined param_2,undefined param_3,int param_4);
void ObjHits_SetHitVolumeSlot(int param_1,undefined param_2,undefined param_3,int param_4);
void ObjHits_ClearSourceMask(int param_1,byte param_2);
void ObjHits_SetSourceMask(int param_1,byte param_2);
void ObjHits_ClearFlags(int param_1,ushort param_2);
void ObjHits_SetFlags(int param_1,ushort param_2);
void FUN_8003606c(int param_1);
void FUN_80036080(int param_1);
void FUN_800360d4(int param_1);
void FUN_800360f0(int param_1);
ushort FUN_80036144(int param_1);
void FUN_80036154(int param_1);
int FUN_80036194(int param_1,uint param_2);
void FUN_80036200(int param_1);
undefined4 FUN_800365a4(int param_1,int param_2,char param_3,undefined param_4,undefined param_5);
undefined4
FUN_80036704(double param_1,double param_2,double param_3,int param_4,int param_5,char param_6,
            undefined param_7,undefined param_8);
void FUN_80036864(int param_1,int param_2);
int FUN_800368c4(int param_1,undefined4 *param_2,int *param_3,uint *param_4,undefined4 *param_5,
                undefined4 *param_6,undefined4 *param_7);
int FUN_800369d0(int param_1,undefined4 *param_2,int *param_3,uint *param_4);
void FUN_80036a98(undefined4 param_1,undefined4 param_2,undefined4 param_3,int param_4,
                 undefined4 param_5,int param_6,undefined4 param_7,undefined4 param_8);
void ObjHits_ResetWorkBuffers(void);
undefined4 ObjHitReact_GetResetObjects(undefined4 *param_1);
void ObjHits_InitWorkBuffers(void);
uint FUN_80036d5c(int param_1,int param_2);
void FUN_80036dcc(undefined4 param_1,undefined4 param_2,float *param_3);
void FUN_80036edc(undefined4 param_1,undefined4 param_2,float *param_3);
void FUN_80037008(undefined4 param_1,undefined4 param_2,float *param_3);
undefined4 * FUN_80037134(int param_1,int *param_2);
void FUN_80037180(int param_1,int param_2);
int FUN_800372f8(int param_1);
void FUN_8003735c(int param_1,int param_2);
void FUN_800374e4(void);
undefined4 FUN_8003751c(int param_1,int *param_2,int *param_3,int *param_4);
undefined4 FUN_80037584(int param_1,uint *param_2,uint *param_3,uint *param_4);
void FUN_8003762c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,uint param_12,uint param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16);
void FUN_80037844(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,uint param_12,uint param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16);
uint FUN_80037bd4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,uint param_10,uint param_11,uint param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16);
void FUN_80037ce0(int param_1,int param_2);
undefined4 FUN_80037d50(int param_1);
bool FUN_80037d74(int param_1);
int fn_80037B60(int param_1,float *param_2,undefined4 *param_3,float *param_4);
void FUN_80037fa8(undefined4 param_1,undefined4 param_2,uint param_3,uint param_4,uint param_5,
                 uint param_6,float *param_7);
void FUN_8003817c(int param_1,int param_2);
void FUN_800381f8(int param_1,int param_2,ushort param_3);
void FUN_80038238(void);
void FUN_80038318(int param_1);
undefined4 FUN_800383c0(int param_1,int param_2,undefined4 param_3);
undefined4 FUN_80038470(int param_1,short param_2);
undefined4 FUN_800384ec(int param_1);
void FUN_80038598(undefined4 param_1,undefined4 param_2,float *param_3);
undefined4 FUN_800386bc(int param_1);
void FUN_80038730(undefined4 param_1,undefined4 param_2,int param_3,float *param_4);
void FUN_800387ac(int param_1,int param_2,undefined4 *param_3,undefined4 *param_4,
                 undefined4 *param_5);
void FUN_800387ec(int param_1,int param_2,float *param_3);
void FUN_8003882c(int param_1,int param_2);
void FUN_800388b4(undefined4 param_1,undefined4 param_2,float *param_3,undefined4 *param_4,
                 float *param_5,int param_6);
int FUN_80038a34(ushort *param_1,int param_2,float *param_3);
void FUN_80038b0c(void);
void FUN_80038bac(int param_1,int param_2,uint param_3);
void FUN_80038bb0(char param_1,int param_2);

#endif /* MAIN_OBJLIB_H_ */
