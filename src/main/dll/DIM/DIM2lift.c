#include "ghidra_import.h"
#include "main/dll/DIM/DIM2lift.h"

extern undefined4 FUN_8000bb38();
extern undefined4 FUN_8000e670();
extern undefined4 FUN_8000faf8();
extern undefined4 FUN_80014acc();
extern undefined8 FUN_800201ac();
extern uint FUN_80022264();
extern int FUN_8002bac4();
extern void* FUN_8002becc();
extern undefined4 FUN_8002cc9c();
extern int FUN_8002e088();
extern uint FUN_8002e144();
extern undefined4 FUN_8003042c();
extern undefined4 FUN_80035eec();
extern undefined8 FUN_80035ff8();
extern undefined4 FUN_800379bc();
extern undefined4 FUN_801bc88c();

extern undefined4 DAT_803265a0;
extern undefined4 DAT_803265e0;
extern undefined4 DAT_803266e0;
extern undefined4 DAT_80326708;
extern undefined4 DAT_80326714;
extern undefined4 DAT_80326724;
extern undefined4 DAT_80326734;
extern undefined4 DAT_803adc4d;
extern undefined4 DAT_803dcb98;
extern undefined4 DAT_803dcba0;
extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd738;
extern undefined4 DAT_803de800;
extern undefined4 DAT_803de804;
extern f64 DOUBLE_803e5848;
extern f64 DOUBLE_803e5878;
extern f32 FLOAT_803e5840;
extern f32 FLOAT_803e5844;
extern f32 FLOAT_803e5850;
extern f32 FLOAT_803e5854;
extern f32 FLOAT_803e5858;
extern f32 FLOAT_803e585c;
extern f32 FLOAT_803e5860;
extern f32 FLOAT_803e5864;
extern f32 FLOAT_803e5868;
extern f32 FLOAT_803e586c;
extern f32 FLOAT_803e5870;
extern f32 FLOAT_803e5880;
extern f32 FLOAT_803e5884;
extern f32 FLOAT_803e5888;
extern f32 FLOAT_803e588c;
extern f32 FLOAT_803e5890;
extern f32 FLOAT_803e5894;
extern f32 FLOAT_803e5898;
extern f32 FLOAT_803e589c;
extern f32 FLOAT_803e58a0;
extern f32 FLOAT_803e58a4;
extern f32 FLOAT_803e58a8;
extern f32 FLOAT_803e58ac;
extern f32 FLOAT_803e58b0;
extern f32 FLOAT_803e58b4;
extern f32 FLOAT_803e58b8;
extern f32 FLOAT_803e58bc;

/*
 * --INFO--
 *
 * Function: FUN_801ba3cc
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801BA3CC
 * EN v1.1 Size: 180b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ba3cc(short *param_1,int param_2)
{
  int iVar1;
  
  param_1[2] = (ushort)*(byte *)(param_2 + 0x18) << 8;
  param_1[1] = (ushort)*(byte *)(param_2 + 0x19) << 8;
  *param_1 = (ushort)*(byte *)(param_2 + 0x1a) << 8;
  if (*(byte *)(param_2 + 0x1b) != 0) {
    *(float *)(param_1 + 4) =
         *(float *)(*(int *)(param_1 + 0x28) + 4) *
         ((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x1b)) - DOUBLE_803e5848) /
         FLOAT_803e5840);
  }
  *(float *)(*(int *)(param_1 + 0x5c) + 0x10) = FLOAT_803e5844;
  iVar1 = *(int *)(param_1 + 0x32);
  if (iVar1 != 0) {
    *(uint *)(iVar1 + 0x30) = *(uint *)(iVar1 + 0x30) | 0x810;
  }
  param_1[0x58] = param_1[0x58] | 0x2000;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ba480
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801BA480
 * EN v1.1 Size: 856b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801ba480(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
            undefined4 param_9,int param_10)
{
  char cVar1;
  uint uVar2;
  ushort local_18;
  undefined auStack_16 [2];
  short local_14 [4];
  
  if ((*(char *)(param_10 + 0x346) != '\0') || (*(char *)(param_10 + 0x27b) != '\0')) {
    (**(code **)(*DAT_803dd738 + 0x14))
              (param_9,*(undefined4 *)(param_10 + 0x2d0),0x10,local_14,auStack_16,&local_18);
    *(undefined *)(param_10 + 0x346) = 0;
    if (local_18 < 0x5a) {
      if ((local_18 < 0x1f) ||
         (((1 < (ushort)(local_14[0] - 3U) && (local_14[0] != 0xb)) && (local_14[0] != 0xc)))) {
        param_1 = (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,9);
      }
      else {
        param_1 = (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,2);
      }
    }
    else if ((local_14[0] == 0) || (local_14[0] == 0xf)) {
      *(undefined *)(param_10 + 0x346) = 0;
      if ((local_18 < 0x1aa) ||
         (uVar2 = (**(code **)(*DAT_803dd738 + 0x18))((double)FLOAT_803e5850,param_9,param_10),
         (uVar2 & 1) == 0)) {
        if (local_18 < 0xfa) {
          param_1 = (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,3);
        }
        else {
          if (6 < DAT_803de804) {
            DAT_803de804 = 0;
          }
          cVar1 = *(char *)(param_10 + 0x354);
          if (cVar1 == '\x02') {
            uVar2 = (uint)DAT_803de804;
            DAT_803de804 = DAT_803de804 + 1;
            param_1 = (**(code **)(*DAT_803dd70c + 0x14))
                                (param_9,param_10,(int)*(short *)(&DAT_80326724 + uVar2 * 2));
          }
          else {
            if (cVar1 < '\x02') {
              if ('\0' < cVar1) {
                uVar2 = (uint)DAT_803de804;
                DAT_803de804 = DAT_803de804 + 1;
                param_1 = (**(code **)(*DAT_803dd70c + 0x14))
                                    (param_9,param_10,(int)*(short *)(&DAT_80326734 + uVar2 * 2));
                goto LAB_801ba764;
              }
            }
            else if (cVar1 < '\x04') {
              uVar2 = (uint)DAT_803de804;
              DAT_803de804 = DAT_803de804 + 1;
              param_1 = (**(code **)(*DAT_803dd70c + 0x14))
                                  (param_9,param_10,(int)*(short *)(&DAT_80326714 + uVar2 * 2));
              goto LAB_801ba764;
            }
            param_1 = (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,3);
          }
        }
      }
      else {
        uVar2 = FUN_80022264(0,5);
        param_1 = (**(code **)(*DAT_803dd70c + 0x14))
                            (param_9,param_10,(int)*(short *)(&DAT_80326708 + uVar2 * 2));
      }
    }
    else {
      param_1 = (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,2);
    }
  }
LAB_801ba764:
  if ((*(short *)(param_10 + 0x274) == 3) || (*(short *)(param_10 + 0x274) == 7)) {
    DAT_803adc4d = DAT_803adc4d | 1;
  }
  else {
    DAT_803adc4d = DAT_803adc4d & 0xfe;
  }
  FUN_801bc88c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801ba7d8
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801BA7D8
 * EN v1.1 Size: 660b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801ba7d8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
            int param_10)
{
  short sVar1;
  uint uVar2;
  int iVar3;
  ushort local_18;
  undefined auStack_16 [2];
  short local_14 [4];
  
  iVar3 = *(int *)(param_9 + 0xb8);
  if ((*(char *)(param_10 + 0x346) != '\0') || (*(char *)(param_10 + 0x27b) != '\0')) {
    (**(code **)(*DAT_803dd738 + 0x14))
              (param_9,*(undefined4 *)(param_10 + 0x2d0),0x10,local_14,auStack_16,&local_18);
    *(undefined *)(param_10 + 0x346) = 0;
    if (local_18 < 0x5a) {
      if ((local_18 < 0x1f) ||
         (((1 < (ushort)(local_14[0] - 3U) && (local_14[0] != 0xb)) && (local_14[0] != 0xc)))) {
        param_1 = (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,9);
      }
      else {
        param_1 = (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,2);
      }
    }
    else if ((local_14[0] == 0) || (local_14[0] == 0xf)) {
      *(undefined *)(param_10 + 0x346) = 0;
      if ((local_18 < 0xf1) ||
         (uVar2 = (**(code **)(*DAT_803dd738 + 0x18))((double)FLOAT_803e5854,param_9,param_10),
         (uVar2 & 1) == 0)) {
        if ((*(ushort *)(iVar3 + 0x400) & 4) == 0) {
          param_1 = (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,3);
        }
        else {
          uVar2 = FUN_80022264(0,1);
          param_1 = (**(code **)(*DAT_803dd70c + 0x14))
                              (param_9,param_10,(int)*(short *)(&DAT_803dcba0 + uVar2 * 2));
        }
      }
      else {
        uVar2 = FUN_80022264(0,5);
        param_1 = (**(code **)(*DAT_803dd70c + 0x14))
                            (param_9,param_10,(int)*(short *)(&DAT_80326708 + uVar2 * 2));
      }
    }
    else {
      param_1 = (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,2);
    }
  }
  sVar1 = *(short *)(param_10 + 0x274);
  if (((sVar1 == 1) || (sVar1 == 4)) || (sVar1 == 5)) {
    DAT_803adc4d = DAT_803adc4d & 0xfe;
  }
  else {
    DAT_803adc4d = DAT_803adc4d | 1;
  }
  FUN_801bc88c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801baa6c
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801BAA6C
 * EN v1.1 Size: 240b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801baa6c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9
            ,int param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  int iVar2;
  undefined8 uVar3;
  
  FUN_8002bac4();
  iVar2 = *(int *)(param_9 + 0xb8);
  if (*(char *)(param_10 + 0x27b) != '\0') {
    *(undefined4 *)(param_10 + 0x2d0) = 0;
    *(undefined *)(param_10 + 0x25f) = 0;
    *(undefined *)(param_10 + 0x349) = 0;
    uVar3 = FUN_80035ff8(param_9);
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0x7f;
    iVar1 = FUN_8002bac4();
    FUN_800379bc(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,0xe0000,param_9
                 ,0,param_13,param_14,param_15,param_16);
    FUN_800201ac((int)*(short *)(iVar2 + 0x3f4),0);
    uVar3 = FUN_800201ac((int)*(short *)(iVar2 + 0x3f2),1);
    if (*(int *)(param_9 + 0x4c) == 0) {
      FUN_8002cc9c(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801bab5c
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801BAB5C
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801bab5c(undefined4 param_1,int param_2)
{
  if (*(char *)(param_2 + 0x346) != '\0') {
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,0);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801bac08
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801BAC08
 * EN v1.1 Size: 300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801bac08(int param_1,int param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,
            undefined4 param_6,undefined4 param_7,undefined4 param_8)
{
  float fVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  
  if (FLOAT_803e5858 < *(float *)(param_1 + 0x98)) {
    DAT_803de800 = DAT_803de800 & 0xffffffdf;
  }
  if (*(char *)(param_2 + 0x27a) != '\0') {
    DAT_803de800 = DAT_803de800 | 0x8020;
    FUN_8000faf8();
    dVar4 = (double)FLOAT_803e5864;
    FUN_8000e670((double)FLOAT_803e585c,(double)FLOAT_803e5860,dVar4);
    FUN_80014acc((double)FLOAT_803e5868);
    *(undefined2 *)(param_1 + 0xa2) = 0xffff;
    dVar3 = (double)FLOAT_803e586c;
    *(float *)(param_2 + 0x2a0) =
         (float)(dVar3 * (double)(float)((double)CONCAT44(0x43300000,
                                                          (int)*(char *)(param_2 + 0x354) + 1U ^
                                                          0x80000000) - DOUBLE_803e5878));
    fVar1 = FLOAT_803e5870;
    dVar2 = (double)FLOAT_803e5870;
    *(float *)(param_2 + 0x280) = FLOAT_803e5870;
    *(float *)(param_2 + 0x284) = fVar1;
    if (*(char *)(param_2 + 0x27a) != '\0') {
      FUN_8003042c(dVar2,dVar3,dVar4,in_f4,in_f5,in_f6,in_f7,in_f8,param_1,0x15,0,param_4,param_5,
                   param_6,param_7,param_8);
      *(undefined *)(param_2 + 0x346) = 0;
    }
  }
  (**(code **)(*DAT_803dd70c + 0x34))(param_1,param_2,0,0,&DAT_803dcb98);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801bad34
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801BAD34
 * EN v1.1 Size: 256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801bad34(int param_1,int param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,
            undefined4 param_6,undefined4 param_7,undefined4 param_8)
{
  float fVar1;
  int iVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if (*(char *)(param_2 + 0x27a) != '\0') {
    DAT_803de800 = DAT_803de800 | 0x2000;
    FUN_8000faf8();
    dVar4 = (double)FLOAT_803e5860;
    dVar5 = (double)FLOAT_803e5864;
    FUN_8000e670((double)FLOAT_803e585c,dVar4,dVar5);
    FUN_80014acc((double)FLOAT_803e5868);
    *(undefined2 *)(param_1 + 0xa2) = 0xffff;
    *(float *)(param_2 + 0x2a0) = FLOAT_803e5880;
    fVar1 = FLOAT_803e5870;
    dVar3 = (double)FLOAT_803e5870;
    *(float *)(param_2 + 0x280) = FLOAT_803e5870;
    *(float *)(param_2 + 0x284) = fVar1;
    if (*(char *)(param_2 + 0x27a) != '\0') {
      FUN_8003042c(dVar3,dVar4,dVar5,in_f4,in_f5,in_f6,in_f7,in_f8,param_1,0xe,0,param_4,param_5,
                   param_6,param_7,param_8);
      *(undefined *)(param_2 + 0x346) = 0;
    }
    if (*(short *)(iVar2 + 0x402) == 1) {
      *(float *)(*(int *)(iVar2 + 0x40c) + 0xa8) = FLOAT_803e5884;
    }
  }
  (**(code **)(*DAT_803dd70c + 0x34))(param_1,param_2,0,1,&DAT_803dcb98);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801bae34
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801BAE34
 * EN v1.1 Size: 216b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801bae34(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  undefined4 uVar2;
  
  *(float *)(param_10 + 0x2a0) = FLOAT_803e5888;
  fVar1 = FLOAT_803e5870;
  *(float *)(param_10 + 0x280) = FLOAT_803e5870;
  *(float *)(param_10 + 0x284) = fVar1;
  uVar2 = 0xffffffff;
  FUN_80035eec(param_9,10,1,-1);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e5870,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0xf,0,uVar2,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  if ((*(uint *)(param_10 + 0x314) & 1) != 0) {
    DAT_803de800 = DAT_803de800 | 0x4004;
    FUN_8000bb38(param_9,0x17d);
    FUN_8000faf8();
    FUN_8000e670((double)FLOAT_803e5860,(double)FLOAT_803e588c,(double)FLOAT_803e5890);
    FUN_80014acc((double)FLOAT_803e5894);
    FUN_800201ac(0x26b,1);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801baf0c
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801BAF0C
 * EN v1.1 Size: 300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801baf0c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  uint uVar2;
  
  if (*(char *)(param_10 + 0x27a) != '\0') {
    *(undefined2 *)(param_9 + 0xa2) = 0xffff;
    fVar1 = FLOAT_803e5870;
    *(float *)(param_10 + 0x280) = FLOAT_803e5870;
    *(float *)(param_10 + 0x284) = fVar1;
    *(float *)(param_10 + 0x2a0) = FLOAT_803e5898;
    uVar2 = FUN_80022264(0,1);
    if (uVar2 == 0) {
      if (*(char *)(param_10 + 0x27a) != '\0') {
        FUN_8003042c((double)FLOAT_803e5870,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,0xc,0,param_12,param_13,param_14,param_15,param_16);
        *(undefined *)(param_10 + 0x346) = 0;
      }
    }
    else if (*(char *)(param_10 + 0x27a) != '\0') {
      FUN_8003042c((double)FLOAT_803e5870,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0xd,0,param_12,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
  }
  (**(code **)(*DAT_803dd70c + 0x34))(param_9,param_10,0,0,&DAT_803266e0);
  (**(code **)(*DAT_803dd70c + 0x34))(param_9,param_10,7,1,&DAT_803266e0);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801bb038
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801BB038
 * EN v1.1 Size: 260b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801bb038(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  undefined4 uVar2;
  
  uVar2 = 0xffffffff;
  FUN_80035eec(param_9,9,1,-1);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    *(float *)(param_10 + 0x2a0) = FLOAT_803e589c;
    if (*(char *)(param_10 + 0x27a) != '\0') {
      FUN_8003042c((double)FLOAT_803e5870,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0x13,0,uVar2,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
    *(undefined2 *)(param_9 + 0xa2) = 0xffff;
    fVar1 = FLOAT_803e5870;
    *(float *)(param_10 + 0x280) = FLOAT_803e5870;
    *(float *)(param_10 + 0x284) = fVar1;
  }
  (**(code **)(*DAT_803dd70c + 0x34))(param_9,param_10,0,1,&DAT_803266e0);
  (**(code **)(*DAT_803dd70c + 0x30))(param_1,param_9,param_10,0xf0);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801bb13c
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801BB13C
 * EN v1.1 Size: 304b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801bb13c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  undefined4 uVar2;
  
  if (*(char *)(param_10 + 0x27a) != '\0') {
    *(float *)(param_10 + 0x2a0) = FLOAT_803e58a0;
    if (*(char *)(param_10 + 0x27a) != '\0') {
      FUN_8003042c((double)FLOAT_803e5870,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0x12,0,param_12,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
    *(undefined2 *)(param_9 + 0xa2) = 0xffff;
    fVar1 = FLOAT_803e5870;
    *(float *)(param_10 + 0x280) = FLOAT_803e5870;
    *(float *)(param_10 + 0x284) = fVar1;
  }
  if ((FLOAT_803e58a4 < *(float *)(param_9 + 0x98)) || (*(char *)(param_10 + 0x346) != '\0')) {
    uVar2 = 8;
  }
  else {
    if (FLOAT_803e58a8 < *(float *)(param_9 + 0x98)) {
      DAT_803de800 = DAT_803de800 | 0x10;
    }
    (**(code **)(*DAT_803dd70c + 0x34))(param_9,param_10,0,5,&DAT_803266e0);
    (**(code **)(*DAT_803dd70c + 0x30))(param_1,param_9,param_10,0xf0);
    uVar2 = 0;
  }
  return uVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_801bb26c
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801BB26C
 * EN v1.1 Size: 328b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801bb26c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  
  if (*(char *)(param_10 + 0x27a) != '\0') {
    *(float *)(param_10 + 0x2a0) = FLOAT_803e58ac;
    if (*(char *)(param_10 + 0x27a) != '\0') {
      FUN_8003042c((double)FLOAT_803e5870,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0x11,0,param_12,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
    *(undefined2 *)(param_9 + 0xa2) = 0xffff;
    fVar1 = FLOAT_803e5870;
    *(float *)(param_10 + 0x280) = FLOAT_803e5870;
    *(float *)(param_10 + 0x284) = fVar1;
  }
  if (*(float *)(param_9 + 0x98) <= FLOAT_803e58b0) {
    if (FLOAT_803e58b4 < *(float *)(param_9 + 0x98)) {
      DAT_803de800 = DAT_803de800 | 0x40;
    }
  }
  else {
    DAT_803de800 = DAT_803de800 & 0xffffffbf;
  }
  if ((*(uint *)(param_10 + 0x314) & 1) != 0) {
    DAT_803de800 = DAT_803de800 | 0x10000;
  }
  (**(code **)(*DAT_803dd70c + 0x34))(param_9,param_10,0,3,&DAT_803266e0);
  (**(code **)(*DAT_803dd70c + 0x30))(param_1,param_9,param_10,0xf0);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801bb3b4
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801BB3B4
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801bb3b4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  
  if (*(char *)(param_10 + 0x27a) != '\0') {
    *(float *)(param_10 + 0x2a0) = FLOAT_803e5898;
    if (*(char *)(param_10 + 0x27a) != '\0') {
      FUN_8003042c((double)FLOAT_803e5870,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0x11,0,param_12,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
    *(undefined2 *)(param_9 + 0xa2) = 0xffff;
    fVar1 = FLOAT_803e5870;
    *(float *)(param_10 + 0x280) = FLOAT_803e5870;
    *(float *)(param_10 + 0x284) = fVar1;
  }
  if (*(float *)(param_9 + 0x98) <= FLOAT_803e58b0) {
    if (FLOAT_803e58b8 < *(float *)(param_9 + 0x98)) {
      DAT_803de800 = DAT_803de800 | 0x40;
    }
  }
  else {
    DAT_803de800 = DAT_803de800 & 0xffffffbf;
  }
  if ((*(uint *)(param_10 + 0x314) & 0x200) != 0) {
    DAT_803de800 = DAT_803de800 | 0x10000;
    *(uint *)(param_10 + 0x314) = *(uint *)(param_10 + 0x314) & 0xfffffdff;
  }
  (**(code **)(*DAT_803dd70c + 0x34))(param_9,param_10,0,3,&DAT_803266e0);
  (**(code **)(*DAT_803dd70c + 0x30))(param_1,param_9,param_10,0xf0);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801bb50c
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801BB50C
 * EN v1.1 Size: 384b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801bb50c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  uint uVar2;
  undefined4 uVar3;
  
  uVar3 = 0xffffffff;
  FUN_80035eec(param_9,9,1,-1);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    *(undefined2 *)(param_9 + 0xa2) = 0xffff;
    fVar1 = FLOAT_803e5870;
    *(float *)(param_10 + 0x280) = FLOAT_803e5870;
    *(float *)(param_10 + 0x284) = fVar1;
    uVar2 = FUN_80022264(0,1);
    if (uVar2 == 0) {
      if (*(char *)(param_10 + 0x27a) != '\0') {
        FUN_8003042c((double)FLOAT_803e5870,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,0x10,0,uVar3,param_13,param_14,param_15,param_16);
        *(undefined *)(param_10 + 0x346) = 0;
      }
      *(float *)(param_10 + 0x2a0) = FLOAT_803e589c;
    }
    else {
      if (*(char *)(param_10 + 0x27a) != '\0') {
        FUN_8003042c((double)FLOAT_803e5870,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,0xb,0,uVar3,param_13,param_14,param_15,param_16);
        *(undefined *)(param_10 + 0x346) = 0;
      }
      *(float *)(param_10 + 0x2a0) = FLOAT_803e5898;
    }
  }
  if ((*(uint *)(param_10 + 0x314) & 0x200) != 0) {
    *(uint *)(param_10 + 0x314) = *(uint *)(param_10 + 0x314) & 0xfffffdff;
    DAT_803de800 = DAT_803de800 | 5;
  }
  uVar2 = FUN_80022264(0,1);
  (**(code **)(*DAT_803dd70c + 0x34))(param_9,param_10,0,uVar2,&DAT_803266e0);
  (**(code **)(*DAT_803dd70c + 0x30))(param_1,param_9,param_10,0xf0);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801bb68c
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801BB68C
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801bb68c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10)
{
  ushort *puVar1;
  undefined *puVar2;
  undefined *puVar3;
  int iVar4;
  undefined4 in_r10;
  undefined auStack_28 [2];
  undefined auStack_26 [2];
  ushort local_24 [6];
  
  *(float *)(param_10 + 0x280) = FLOAT_803e5870;
  if (((*(char *)(param_10 + 0x346) != '\0') || (*(char *)(param_10 + 0x27a) != '\0')) ||
     (*(short *)(param_9 + 0xa0) == 1)) {
    puVar1 = local_24;
    puVar2 = auStack_26;
    puVar3 = auStack_28;
    iVar4 = *DAT_803dd738;
    (**(code **)(iVar4 + 0x14))(param_9,*(undefined4 *)(param_10 + 0x2d0),0x10);
    FUN_8003042c((double)FLOAT_803e5870,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,*(undefined4 *)(&DAT_803265a0 + (uint)local_24[0] * 4),0,puVar1,puVar2,
                 puVar3,iVar4,in_r10);
    *(undefined4 *)(param_10 + 0x2a0) = *(undefined4 *)(&DAT_803265e0 + (uint)local_24[0] * 4);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  (**(code **)(*DAT_803dd70c + 0x20))(param_1,param_9,param_10,8);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801bb7a0
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801BB7A0
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801bb7a0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,int param_10
            ,undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e5870,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,2,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(float *)(param_10 + 0x2a0) = FLOAT_803e58bc;
  (**(code **)(*DAT_803dd70c + 0x20))(param_1,param_9,param_10,1);
  (**(code **)(*DAT_803dd70c + 0x30))(param_1,param_9,param_10,4);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801bb864
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801BB864
 * EN v1.1 Size: 120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801bb864(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  bool bVar1;
  float fVar2;
  
  bVar1 = *(char *)(param_10 + 0x27a) != '\0';
  if (bVar1) {
    if (bVar1) {
      FUN_8003042c((double)FLOAT_803e5870,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,1,0,param_12,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
    fVar2 = FLOAT_803e5870;
    *(float *)(param_10 + 0x280) = FLOAT_803e5870;
    *(float *)(param_10 + 0x284) = fVar2;
    *(undefined2 *)(param_9 + 0xa2) = 0xffff;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801bb8dc
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801BB8DC
 * EN v1.1 Size: 192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801bb8dc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 *param_10)
{
  uint uVar1;
  undefined2 *puVar2;
  int iVar3;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  
  uVar1 = FUN_8002e144();
  if ((uVar1 & 0xff) != 0) {
    puVar2 = FUN_8002becc(0x24,0x290);
    *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(param_9 + 0xc);
    *(undefined4 *)(puVar2 + 6) = *(undefined4 *)(param_9 + 0x10);
    *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(param_9 + 0x14);
    *(undefined *)(puVar2 + 2) = 1;
    *(undefined *)((int)puVar2 + 5) = 1;
    *(undefined *)(puVar2 + 3) = 0xff;
    *(undefined *)((int)puVar2 + 7) = 0xff;
    puVar2[0xf] = 0xffff;
    puVar2[0x10] = 0xffff;
    iVar3 = FUN_8002e088(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,5,
                         0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    if (iVar3 != 0) {
      *(undefined4 *)(iVar3 + 0x24) = *param_10;
      *(undefined4 *)(iVar3 + 0x28) = param_10[1];
      *(undefined4 *)(iVar3 + 0x2c) = param_10[2];
    }
  }
  return;
}
