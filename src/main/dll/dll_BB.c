#include "ghidra_import.h"
#include "main/dll/dll_BB.h"

extern undefined4 FUN_8000de08();
extern undefined4 FUN_8000f478();
extern undefined4 FUN_8000f584();
extern void* FUN_8000facc();
extern int FUN_8000fb04();
extern undefined4 FUN_8000fb0c();
extern undefined4 FUN_8000fc5c();
extern double FUN_80021434();
extern undefined4 FUN_80058e58();
extern undefined4 FUN_8007d858();
extern undefined4 FUN_80247eb8();
extern undefined4 FUN_80247ef8();
extern double FUN_80247f54();

extern undefined4 DAT_803de138;
extern undefined4 gCamcontrolState;
extern f64 DOUBLE_803e22d0;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803de148;
extern f32 FLOAT_803e22ac;
extern f32 FLOAT_803e22b0;
extern f32 FLOAT_803e22e8;
extern f32 FLOAT_803e22ec;

/*
 * --INFO--
 *
 * Function: FUN_80101c1c
 * EN v1.0 Address: 0x80101C1C
 * EN v1.0 Size: 1340b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80101c1c(short *param_1)
{
  float fVar1;
  float fVar2;
  short *psVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  float local_38;
  float local_34;
  float local_30;
  undefined8 local_28;
  undefined8 local_20;
  
  FUN_8000f478(0);
  psVar3 = FUN_8000facc();
  *psVar3 = *param_1;
  psVar3[1] = param_1[1];
  psVar3[2] = param_1[2];
  if (*(char *)((int)param_1 + 0x143) < '\0') {
    FUN_80247eb8((float *)(param_1 + 0xc),(float *)(psVar3 + 6),&local_38);
    dVar5 = FUN_80247f54(&local_38);
    if ((double)FLOAT_803e22b0 < dVar5) {
      FUN_80247ef8(&local_38,&local_38);
    }
    dVar6 = FUN_80021434(dVar5,(double)FLOAT_803e22e8,(double)FLOAT_803dc074);
    dVar5 = (double)FLOAT_803e22b0;
    if ((dVar5 <= dVar6) && (dVar5 = dVar6, (double)(FLOAT_803e22ec * FLOAT_803dc074) < dVar6)) {
      dVar5 = (double)(FLOAT_803e22ec * FLOAT_803dc074);
    }
    *(float *)(psVar3 + 6) = (float)(dVar5 * (double)local_38 + (double)*(float *)(psVar3 + 6));
    *(float *)(psVar3 + 8) = (float)(dVar5 * (double)local_34 + (double)*(float *)(psVar3 + 8));
    *(float *)(psVar3 + 10) = (float)(dVar5 * (double)local_30 + (double)*(float *)(psVar3 + 10));
  }
  else {
    *(undefined4 *)(psVar3 + 6) = *(undefined4 *)(param_1 + 0xc);
    *(undefined4 *)(psVar3 + 8) = *(undefined4 *)(param_1 + 0xe);
    *(undefined4 *)(psVar3 + 10) = *(undefined4 *)(param_1 + 0x10);
  }
  fVar2 = FLOAT_803e22b0;
  FLOAT_803de148 = *(float *)(param_1 + 0x5a);
  if (FLOAT_803e22b0 < *(float *)(param_1 + 0x7a)) {
    *(float *)(param_1 + 0x7a) =
         -(*(float *)(param_1 + 0x7c) * FLOAT_803dc074 - *(float *)(param_1 + 0x7a));
    fVar1 = *(float *)(param_1 + 0x7a);
    if ((fVar2 <= fVar1) && (fVar2 = fVar1, FLOAT_803e22ac < fVar1)) {
      fVar2 = FLOAT_803e22ac;
    }
    *(float *)(param_1 + 0x7a) = fVar2;
    if (*(char *)(gCamcontrolState + 0x139) == '\x02') {
      fVar2 = *(float *)(param_1 + 0x7a);
      dVar5 = (double)(FLOAT_803e22ac - fVar2 * fVar2 * fVar2);
    }
    else if (*(char *)(gCamcontrolState + 0x139) == '\x01') {
      dVar5 = (double)(FLOAT_803e22ac - *(float *)(param_1 + 0x7a) * *(float *)(param_1 + 0x7a));
    }
    else {
      dVar5 = (double)(FLOAT_803e22ac - *(float *)(param_1 + 0x7a));
    }
    dVar6 = (double)FLOAT_803e22b0;
    if ((dVar6 <= dVar5) && (dVar6 = dVar5, (double)FLOAT_803e22ac < dVar5)) {
      dVar6 = (double)FLOAT_803e22ac;
    }
    if ((*(byte *)((int)param_1 + 0x13f) & 8) != 0) {
      *(float *)(psVar3 + 6) =
           (float)(dVar6 * (double)(float)((double)*(float *)(psVar3 + 6) -
                                          (double)*(float *)(param_1 + 0x86)) +
                  (double)*(float *)(param_1 + 0x86));
    }
    if ((*(byte *)((int)param_1 + 0x13f) & 0x10) != 0) {
      *(float *)(psVar3 + 8) =
           (float)(dVar6 * (double)(float)((double)*(float *)(psVar3 + 8) -
                                          (double)*(float *)(param_1 + 0x88)) +
                  (double)*(float *)(param_1 + 0x88));
    }
    if ((*(byte *)((int)param_1 + 0x13f) & 0x20) != 0) {
      *(float *)(psVar3 + 10) =
           (float)(dVar6 * (double)(float)((double)*(float *)(psVar3 + 10) -
                                          (double)*(float *)(param_1 + 0x8a)) +
                  (double)*(float *)(param_1 + 0x8a));
    }
    FUN_8007d858();
    if ((*(byte *)((int)param_1 + 0x13f) & 1) != 0) {
      param_1[0x80] = param_1[0x83] - *psVar3;
      if (0x8000 < param_1[0x80]) {
        param_1[0x80] = param_1[0x80] + 1;
      }
      if (param_1[0x80] < -0x8000) {
        param_1[0x80] = param_1[0x80] + -1;
      }
      local_28 = (double)CONCAT44(0x43300000,(int)param_1[0x80] ^ 0x80000000);
      iVar4 = (int)((double)(float)(local_28 - DOUBLE_803e22d0) * dVar6);
      local_20 = (double)(longlong)iVar4;
      *psVar3 = param_1[0x83] - (short)iVar4;
    }
    if ((*(byte *)((int)param_1 + 0x13f) & 2) != 0) {
      param_1[0x81] = param_1[0x84] - psVar3[1];
      if (0x8000 < param_1[0x81]) {
        param_1[0x81] = param_1[0x81] + 1;
      }
      if (param_1[0x81] < -0x8000) {
        param_1[0x81] = param_1[0x81] + -1;
      }
      local_20 = (double)CONCAT44(0x43300000,(int)param_1[0x81] ^ 0x80000000);
      iVar4 = (int)((double)(float)(local_20 - DOUBLE_803e22d0) * dVar6);
      local_28 = (double)(longlong)iVar4;
      psVar3[1] = param_1[0x84] - (short)iVar4;
    }
    if ((*(byte *)((int)param_1 + 0x13f) & 4) != 0) {
      param_1[0x82] = param_1[0x85] - psVar3[2];
      if (0x8000 < param_1[0x82]) {
        param_1[0x82] = param_1[0x82] + 1;
      }
      if (param_1[0x82] < -0x8000) {
        param_1[0x82] = param_1[0x82] + -1;
      }
      local_20 = (double)CONCAT44(0x43300000,(int)param_1[0x82] ^ 0x80000000);
      iVar4 = (int)((double)(float)(local_20 - DOUBLE_803e22d0) * dVar6);
      local_28 = (double)(longlong)iVar4;
      psVar3[2] = param_1[0x85] - (short)iVar4;
    }
  }
  FUN_8000fc5c((double)FLOAT_803de148);
  FUN_8000de08(psVar3);
  FUN_80058e58((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
               (double)*(float *)(param_1 + 0x10),in_f4,in_f5,in_f6,in_f7,in_f8);
  iVar4 = FUN_8000fb04();
  DAT_803de138 = (short)iVar4;
  if ((int)DAT_803de138 != (int)*(char *)((int)param_1 + 0x13b)) {
    if ((int)DAT_803de138 < (int)*(char *)((int)param_1 + 0x13b)) {
      local_20 = (double)(longlong)(int)FLOAT_803dc074;
      DAT_803de138 = DAT_803de138 + (short)*(char *)(param_1 + 0x9e) * (short)(int)FLOAT_803dc074;
      if ((int)*(char *)((int)param_1 + 0x13b) < (int)DAT_803de138) {
        DAT_803de138 = (short)*(char *)((int)param_1 + 0x13b);
      }
    }
    else {
      local_20 = (double)(longlong)(int)FLOAT_803dc074;
      DAT_803de138 = DAT_803de138 - (short)*(char *)(param_1 + 0x9e) * (short)(int)FLOAT_803dc074;
      if ((int)DAT_803de138 < (int)*(char *)((int)param_1 + 0x13b)) {
        DAT_803de138 = (short)*(char *)((int)param_1 + 0x13b);
      }
    }
    FUN_8000fb0c(DAT_803de138);
  }
  *(undefined *)((int)param_1 + 0x13b) = 0;
  FUN_8000f584();
  return;
}
