#include "ghidra_import.h"
#include "main/dll/CAM/camstatic.h"

extern undefined4 FUN_8000e054();
extern undefined4 FUN_8000e0c0();
extern double FUN_80021434();
extern int FUN_80021884();
extern undefined4 FUN_801037c0();
extern undefined4 FUN_80103bec();
extern undefined4 FUN_801042dc();
extern undefined4 FUN_801047dc();
extern undefined4 FUN_80104990();
extern undefined4 FUN_80104c4c();
extern undefined4 FUN_80105338();
extern int FUN_80296bb8();
extern undefined4 FUN_80296ccc();
extern undefined4 FUN_80297334();

extern undefined4* DAT_803dd6d0;
extern undefined4 DAT_803de1a8;
extern f64 DOUBLE_803e2318;
extern f64 DOUBLE_803e2378;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803de1a4;
extern f32 FLOAT_803e2308;
extern f32 FLOAT_803e2324;
extern f32 FLOAT_803e232c;
extern f32 FLOAT_803e235c;
extern f32 FLOAT_803e2388;
extern f32 FLOAT_803e2398;
extern f32 FLOAT_803e239c;
extern f32 FLOAT_803e23a0;
extern f32 FLOAT_803e23a4;
extern f32 FLOAT_803e23a8;
extern f32 FLOAT_803e23ac;
extern f32 FLOAT_803e23b0;

/*
 * --INFO--
 *
 * Function: FUN_80105aac
 * EN v1.0 Address: 0x80105AAC
 * EN v1.0 Size: 1644b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80105aac(short *param_1)
{
  float fVar1;
  int iVar2;
  uint uVar3;
  short *psVar4;
  double dVar5;
  float local_148;
  undefined local_144 [4];
  undefined local_140 [4];
  undefined auStack_13c [4];
  undefined local_138 [4];
  float local_134;
  float local_130;
  undefined4 local_12c;
  float local_128;
  float local_124;
  undefined4 local_120;
  undefined auStack_11c [112];
  undefined auStack_ac [116];
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  longlong local_28;
  undefined4 local_20;
  uint uStack_1c;
  longlong local_18;
  
  psVar4 = *(short **)(param_1 + 0x52);
  if (psVar4 == (short *)0x0) {
    return;
  }
  if (psVar4[0x22] == 1) {
    FUN_80296ccc((int)psVar4,&local_148);
    FLOAT_803de1a4 = FLOAT_803dc074 * local_148;
    iVar2 = FUN_80296bb8((int)psVar4);
    if (iVar2 == 3) {
      *(float *)(DAT_803de1a8 + 0x14) = FLOAT_803e23a0;
      *(undefined *)(DAT_803de1a8 + 0xc2) = 8;
    }
    else {
      if (iVar2 < 3) {
        if (iVar2 == 1) {
          *(float *)(DAT_803de1a8 + 0x14) = FLOAT_803e232c;
          *(undefined *)(DAT_803de1a8 + 0xc2) = 0xff;
          goto LAB_80105bbc;
        }
        if (0 < iVar2) {
          *(float *)(DAT_803de1a8 + 0x14) = FLOAT_803e2398;
          *(undefined *)(DAT_803de1a8 + 0xc2) = 0xc;
          goto LAB_80105bbc;
        }
      }
      else if (iVar2 < 5) {
        *(float *)(DAT_803de1a8 + 0x14) = FLOAT_803e239c;
        *(undefined *)(DAT_803de1a8 + 0xc2) = 2;
        goto LAB_80105bbc;
      }
      *(undefined4 *)(DAT_803de1a8 + 0x14) = *(undefined4 *)(DAT_803de1a8 + 0x58);
      *(undefined *)(DAT_803de1a8 + 0xc2) = 8;
    }
  }
  else {
    FLOAT_803de1a4 = FLOAT_803dc074;
  }
LAB_80105bbc:
  *(undefined *)(param_1 + 0x9f) = 0;
  FUN_801047dc((int)param_1);
  FUN_801042dc();
  FUN_80105338((int)param_1,psVar4);
  FUN_8000e0c0((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8),
               (double)*(float *)(param_1 + 10),(float *)(param_1 + 0xc),(float *)(param_1 + 0xe),
               (float *)(param_1 + 0x10),*(int *)(param_1 + 0x18));
  FUN_80104c4c((int)param_1,(int)psVar4);
  FUN_80104990(param_1,1,8,(float *)(DAT_803de1a8 + 0xa0),(float *)(DAT_803de1a8 + 0xa4));
  fVar1 = FLOAT_803e232c;
  if (*(char *)(DAT_803de1a8 + 0xc6) < '\0') {
    *(float *)(param_1 + 0x98) = FLOAT_803e232c;
    *(float *)(param_1 + 0x96) = fVar1;
    if ((*(char *)(param_1 + 0x51) == '\x01') && (*(float *)(param_1 + 0x1c) < fVar1)) {
      *(byte *)(DAT_803de1a8 + 0xc6) = *(byte *)(DAT_803de1a8 + 0xc6) & 0x7f;
    }
    if ((FLOAT_803e23ac + *(float *)(psVar4 + 0xe) < *(float *)(param_1 + 0xe)) ||
       (*(float *)(param_1 + 0xe) < FLOAT_803e2388 + *(float *)(psVar4 + 0xe))) {
      *(byte *)(DAT_803de1a8 + 0xc6) = *(byte *)(DAT_803de1a8 + 0xc6) & 0x7f;
    }
  }
  else {
    *(undefined *)(DAT_803de1a8 + 0xc5) = *(undefined *)(param_1 + 0x51);
    if (((*(char *)(param_1 + 0xa1) != '\0') ||
        ((*(char *)(DAT_803de1a8 + 0xc5) == '\x01' && (FLOAT_803e232c <= *(float *)(param_1 + 0x1c))
         ))) && (-1 < *(char *)(DAT_803de1a8 + 200))) {
      if (((FLOAT_803e235c + *(float *)(psVar4 + 0xe) < *(float *)(param_1 + 0xe)) &&
          (*(float *)(param_1 + 0xe) < FLOAT_803e23a4 + *(float *)(psVar4 + 0xe))) &&
         (*(int *)(param_1 + 0x18) == 0)) {
        *(byte *)(DAT_803de1a8 + 0xc6) = *(byte *)(DAT_803de1a8 + 0xc6) & 0x7f | 0x80;
      }
    }
    if ((((*(byte *)(DAT_803de1a8 + 0xc5) & 0x10) != 0) &&
        (*(float *)(param_1 + 0x1c) < FLOAT_803e23a8)) &&
       (*(float *)(psVar4 + 0x14) <= FLOAT_803e232c)) {
      *(byte *)(DAT_803de1a8 + 200) = *(byte *)(DAT_803de1a8 + 200) & 0xbf | 0x40;
      *(undefined4 *)(DAT_803de1a8 + 0xbc) = *(undefined4 *)(param_1 + 0xe);
    }
  }
  if (*(char *)(DAT_803de1a8 + 200) < '\0') {
    if ((*(char *)(DAT_803de1a8 + 0xc5) == '\x01') || (*(char *)(param_1 + 0xa1) != '\0')) {
      *(char *)(DAT_803de1a8 + 199) = *(char *)(DAT_803de1a8 + 199) + '\x01';
    }
    else {
      *(undefined *)(DAT_803de1a8 + 199) = 0;
    }
    if (10 < *(byte *)(DAT_803de1a8 + 199)) {
      if (psVar4[0x22] == 1) {
        FUN_80297334((int)psVar4,&local_128,&local_124,&local_120);
      }
      else {
        local_128 = *(float *)(psVar4 + 0xc);
        local_124 = *(float *)(psVar4 + 0xe) + *(float *)(DAT_803de1a8 + 0x8c);
        local_120 = *(undefined4 *)(psVar4 + 0x10);
      }
      FUN_801037c0((double)FLOAT_803e2308,&local_128,(float *)(param_1 + 0xc),
                   (float *)(param_1 + 0xc),(int)auStack_ac,3,'\x01','\x01');
      *(undefined4 *)(param_1 + 0x5c) = *(undefined4 *)(param_1 + 0xc);
      *(undefined4 *)(param_1 + 0x5e) = *(undefined4 *)(param_1 + 0xe);
      *(undefined4 *)(param_1 + 0x60) = *(undefined4 *)(param_1 + 0x10);
      *(undefined *)(DAT_803de1a8 + 199) = 0;
    }
  }
  if (-1 < *(char *)(DAT_803de1a8 + 0xc6)) {
    if ((*(byte *)(DAT_803de1a8 + 0xc5) & 0x10) == 0) {
      *(undefined *)(DAT_803de1a8 + 0xc3) = 0;
    }
    else {
      *(char *)(DAT_803de1a8 + 0xc3) = *(char *)(DAT_803de1a8 + 0xc3) + '\x01';
    }
    if (5 < *(byte *)(DAT_803de1a8 + 0xc3)) {
      if (psVar4[0x22] == 1) {
        FUN_80297334((int)psVar4,&local_134,&local_130,&local_12c);
      }
      else {
        local_134 = *(float *)(psVar4 + 0xc);
        local_130 = *(float *)(psVar4 + 0xe) + *(float *)(DAT_803de1a8 + 0x8c);
        local_12c = *(undefined4 *)(psVar4 + 0x10);
      }
      FUN_801037c0((double)FLOAT_803e2308,&local_134,(float *)(param_1 + 0xc),
                   (float *)(param_1 + 0xc),(int)auStack_11c,3,'\x01','\x01');
      *(undefined4 *)(param_1 + 0x5c) = *(undefined4 *)(param_1 + 0xc);
      *(undefined4 *)(param_1 + 0x5e) = *(undefined4 *)(param_1 + 0xe);
      *(undefined4 *)(param_1 + 0x60) = *(undefined4 *)(param_1 + 0x10);
      *(undefined *)(DAT_803de1a8 + 0xc3) = 0;
    }
  }
  (**(code **)(*DAT_803dd6d0 + 0x38))
            ((double)*(float *)(DAT_803de1a8 + 0x8c),param_1,local_138,auStack_13c,local_140,
             local_144,0);
  iVar2 = FUN_80021884();
  *(undefined2 *)(DAT_803de1a8 + 0x80) = 0;
  *param_1 = (-0x8000 - (short)iVar2) - *(short *)(DAT_803de1a8 + 0x80);
  uVar3 = FUN_80021884();
  uStack_34 = (uVar3 & 0xffff) - (uint)(ushort)param_1[1];
  if (0x8000 < (int)uStack_34) {
    uStack_34 = uStack_34 - 0xffff;
  }
  if ((int)uStack_34 < -0x8000) {
    uStack_34 = uStack_34 + 0xffff;
  }
  uStack_34 = uStack_34 ^ 0x80000000;
  local_38 = 0x43300000;
  uStack_2c = (uint)*(byte *)(DAT_803de1a8 + 0xc2);
  local_30 = 0x43300000;
  dVar5 = FUN_80021434((double)(float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e2318),
                       (double)(FLOAT_803e2324 /
                               (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e2378)),
                       (double)FLOAT_803dc074);
  local_28 = (longlong)(int)dVar5;
  param_1[1] = param_1[1] + (short)(int)dVar5;
  FUN_80103bec((int)param_1,(int)psVar4);
  uStack_1c = (int)param_1[2] ^ 0x80000000;
  local_20 = 0x43300000;
  dVar5 = FUN_80021434((double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e2318),
                       (double)FLOAT_803e23b0,(double)FLOAT_803dc074);
  local_18 = (longlong)(int)dVar5;
  param_1[2] = param_1[2] - (short)(int)dVar5;
  FUN_8000e054((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
               (double)*(float *)(param_1 + 0x10),(float *)(param_1 + 6),(float *)(param_1 + 8),
               (float *)(param_1 + 10),*(int *)(param_1 + 0x18));
  return;
}
