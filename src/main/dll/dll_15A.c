#include "ghidra_import.h"
#include "main/dll/dll_15A.h"

extern undefined4 FUN_80013e4c();
extern undefined8 FUN_800201ac();
extern uint FUN_80021884();
extern undefined4 FUN_80021b8c();
extern uint FUN_80022264();
extern void* FUN_8002becc();
extern int FUN_8002e088();
extern uint FUN_8002e144();
extern undefined4 FUN_8003b9ec();
extern int FUN_80286838();
extern undefined4 FUN_80286884();
extern double FUN_80293900();

extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd6fc;
extern undefined4* DAT_803dd72c;
extern undefined4 DAT_803de748;
extern f64 DOUBLE_803e4660;
extern f32 FLOAT_803e4640;
extern f32 FLOAT_803e4644;
extern f32 FLOAT_803e4650;
extern f32 FLOAT_803e4658;
extern f32 FLOAT_803e466c;
extern f32 FLOAT_803e4670;

/*
 * --INFO--
 *
 * Function: FUN_8018393c
 * EN v1.0 Address: 0x8018393C
 * EN v1.0 Size: 1824b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8018393c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            int param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  uint uVar1;
  short *psVar2;
  int iVar3;
  undefined2 *puVar4;
  undefined8 uVar5;
  double dVar6;
  ushort local_38 [4];
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  
  uVar1 = FUN_8002e144();
  if ((uVar1 & 0xff) != 0) {
    uVar5 = FUN_800201ac((int)*(short *)(param_11 + 0xe),1);
    switch(*(char *)(param_11 + 0x11)) {
    case '\x01':
      puVar4 = FUN_8002becc(0x24,0x3d3);
      *(undefined4 *)(puVar4 + 4) = *(undefined4 *)(param_9 + 0xc);
      *(undefined4 *)(puVar4 + 6) = *(undefined4 *)(param_9 + 0x10);
      *(undefined4 *)(puVar4 + 8) = *(undefined4 *)(param_9 + 0x14);
      puVar4[0xd] = 400;
      psVar2 = (short *)FUN_8002e088(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                     puVar4,5,*(undefined *)(param_9 + 0xac),0xffffffff,
                                     *(uint **)(param_9 + 0x30),param_14,param_15,param_16);
      *(float *)(psVar2 + 0x12) = *(float *)(param_9 + 0xc) - *(float *)(param_10 + 0xc);
      *(float *)(psVar2 + 0x16) = *(float *)(param_9 + 0x14) - *(float *)(param_10 + 0x14);
      dVar6 = (double)(*(float *)(psVar2 + 0x12) * *(float *)(psVar2 + 0x12) +
                      *(float *)(psVar2 + 0x16) * *(float *)(psVar2 + 0x16));
      if (dVar6 != (double)FLOAT_803e4650) {
        dVar6 = FUN_80293900(dVar6);
        *(float *)(psVar2 + 0x12) = (float)((double)*(float *)(psVar2 + 0x12) / dVar6);
        *(float *)(psVar2 + 0x16) = (float)((double)*(float *)(psVar2 + 0x16) / dVar6);
      }
      uStack_1c = FUN_80022264(0,0x19);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      *(float *)(psVar2 + 0x12) =
           *(float *)(psVar2 + 0x12) *
           -(FLOAT_803e466c * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e4660) -
            FLOAT_803e4644);
      uStack_14 = FUN_80022264(0,0x19);
      local_30 = FLOAT_803e4644;
      uStack_14 = uStack_14 ^ 0x80000000;
      local_18 = 0x43300000;
      *(float *)(psVar2 + 0x16) =
           *(float *)(psVar2 + 0x16) *
           -(FLOAT_803e466c * (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e4660) -
            FLOAT_803e4644);
      *(float *)(psVar2 + 0x14) = FLOAT_803e4670;
      local_2c = FLOAT_803e4650;
      local_28 = FLOAT_803e4650;
      local_24 = FLOAT_803e4650;
      local_38[2] = 0;
      local_38[1] = 0;
      uVar1 = FUN_80022264(0xffffd8f0,10000);
      local_38[0] = (ushort)uVar1;
      FUN_80021b8c(local_38,(float *)(psVar2 + 0x12));
      uVar1 = FUN_80021884();
      iVar3 = (int)*psVar2 - (uVar1 & 0xffff);
      if (0x8000 < iVar3) {
        iVar3 = iVar3 + -0xffff;
      }
      if (iVar3 < -0x8000) {
        iVar3 = iVar3 + 0xffff;
      }
      *psVar2 = (short)iVar3;
      break;
    case '\x02':
      puVar4 = FUN_8002becc(0x24,0x3d4);
      uVar1 = FUN_80022264(0xffffff81,0x7e);
      *(char *)(puVar4 + 0xc) = (char)uVar1;
      *(undefined4 *)(puVar4 + 4) = *(undefined4 *)(param_9 + 0xc);
      *(undefined4 *)(puVar4 + 6) = *(undefined4 *)(param_9 + 0x10);
      *(undefined4 *)(puVar4 + 8) = *(undefined4 *)(param_9 + 0x14);
      puVar4[0xd] = 400;
      psVar2 = (short *)FUN_8002e088(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                     puVar4,5,*(undefined *)(param_9 + 0xac),0xffffffff,
                                     *(uint **)(param_9 + 0x30),param_14,param_15,param_16);
      *(float *)(psVar2 + 0x12) = *(float *)(param_9 + 0xc) - *(float *)(param_10 + 0xc);
      *(float *)(psVar2 + 0x16) = *(float *)(param_9 + 0x14) - *(float *)(param_10 + 0x14);
      dVar6 = (double)(*(float *)(psVar2 + 0x12) * *(float *)(psVar2 + 0x12) +
                      *(float *)(psVar2 + 0x16) * *(float *)(psVar2 + 0x16));
      if (dVar6 != (double)FLOAT_803e4650) {
        dVar6 = FUN_80293900(dVar6);
        *(float *)(psVar2 + 0x12) = (float)((double)*(float *)(psVar2 + 0x12) / dVar6);
        *(float *)(psVar2 + 0x16) = (float)((double)*(float *)(psVar2 + 0x16) / dVar6);
      }
      uStack_14 = FUN_80022264(0,0x19);
      uStack_14 = uStack_14 ^ 0x80000000;
      local_18 = 0x43300000;
      *(float *)(psVar2 + 0x12) =
           *(float *)(psVar2 + 0x12) *
           -(FLOAT_803e466c * (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e4660) -
            FLOAT_803e4644);
      uStack_1c = FUN_80022264(0,0x19);
      local_30 = FLOAT_803e4644;
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      *(float *)(psVar2 + 0x16) =
           *(float *)(psVar2 + 0x16) *
           -(FLOAT_803e466c * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e4660) -
            FLOAT_803e4644);
      *(float *)(psVar2 + 0x14) = FLOAT_803e4670;
      local_2c = FLOAT_803e4650;
      local_28 = FLOAT_803e4650;
      local_24 = FLOAT_803e4650;
      local_38[2] = 0;
      local_38[1] = 0;
      uVar1 = FUN_80022264(0xffffd8f0,10000);
      local_38[0] = (ushort)uVar1;
      FUN_80021b8c(local_38,(float *)(psVar2 + 0x12));
      uVar1 = FUN_80021884();
      iVar3 = (int)*psVar2 - (uVar1 & 0xffff);
      if (0x8000 < iVar3) {
        iVar3 = iVar3 + -0xffff;
      }
      if (iVar3 < -0x8000) {
        iVar3 = iVar3 + 0xffff;
      }
      *psVar2 = (short)iVar3;
      break;
    case '\x03':
      puVar4 = FUN_8002becc(0x24,0x3d5);
      uVar1 = FUN_80022264(0xffffff81,0x7e);
      *(char *)(puVar4 + 0xc) = (char)uVar1;
      *(undefined4 *)(puVar4 + 4) = *(undefined4 *)(param_9 + 0xc);
      *(undefined4 *)(puVar4 + 6) = *(undefined4 *)(param_9 + 0x10);
      *(undefined4 *)(puVar4 + 8) = *(undefined4 *)(param_9 + 0x14);
      puVar4[0xd] = 2000;
      psVar2 = (short *)FUN_8002e088(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                     puVar4,5,*(undefined *)(param_9 + 0xac),0xffffffff,
                                     *(uint **)(param_9 + 0x30),param_14,param_15,param_16);
      *(float *)(psVar2 + 0x12) = *(float *)(param_9 + 0xc) - *(float *)(param_10 + 0xc);
      *(float *)(psVar2 + 0x16) = *(float *)(param_9 + 0x14) - *(float *)(param_10 + 0x14);
      dVar6 = (double)(*(float *)(psVar2 + 0x12) * *(float *)(psVar2 + 0x12) +
                      *(float *)(psVar2 + 0x16) * *(float *)(psVar2 + 0x16));
      if (dVar6 != (double)FLOAT_803e4650) {
        dVar6 = FUN_80293900(dVar6);
        *(float *)(psVar2 + 0x12) = (float)((double)*(float *)(psVar2 + 0x12) / dVar6);
        *(float *)(psVar2 + 0x16) = (float)((double)*(float *)(psVar2 + 0x16) / dVar6);
      }
      uStack_14 = FUN_80022264(0,0x19);
      uStack_14 = uStack_14 ^ 0x80000000;
      local_18 = 0x43300000;
      *(float *)(psVar2 + 0x12) =
           *(float *)(psVar2 + 0x12) *
           -(FLOAT_803e466c * (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e4660) -
            FLOAT_803e4644);
      uStack_1c = FUN_80022264(0,0x19);
      local_30 = FLOAT_803e4644;
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      *(float *)(psVar2 + 0x16) =
           *(float *)(psVar2 + 0x16) *
           -(FLOAT_803e466c * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e4660) -
            FLOAT_803e4644);
      *(float *)(psVar2 + 0x14) = FLOAT_803e4670;
      local_2c = FLOAT_803e4650;
      local_28 = FLOAT_803e4650;
      local_24 = FLOAT_803e4650;
      local_38[2] = 0;
      local_38[1] = 0;
      uVar1 = FUN_80022264(0xffffd8f0,10000);
      local_38[0] = (ushort)uVar1;
      FUN_80021b8c(local_38,(float *)(psVar2 + 0x12));
      uVar1 = FUN_80021884();
      iVar3 = (int)*psVar2 - (uVar1 & 0xffff);
      if (0x8000 < iVar3) {
        iVar3 = iVar3 + -0xffff;
      }
      if (iVar3 < -0x8000) {
        iVar3 = iVar3 + 0xffff;
      }
      *psVar2 = (short)iVar3;
      break;
    case '\x05':
    case '\x06':
      if (*(char *)(param_11 + 0x11) == '\x05') {
        puVar4 = FUN_8002becc(0x30,0xb);
      }
      else {
        puVar4 = FUN_8002becc(0x30,0x3cd);
      }
      *(undefined *)(puVar4 + 0xd) = 0x14;
      puVar4[0x16] = 0xffff;
      puVar4[0xe] = 0xffff;
      *(undefined4 *)(puVar4 + 4) = *(undefined4 *)(param_9 + 0xc);
      dVar6 = (double)FLOAT_803e4658;
      *(float *)(puVar4 + 6) = (float)(dVar6 + (double)*(float *)(param_9 + 0x10));
      *(undefined4 *)(puVar4 + 8) = *(undefined4 *)(param_9 + 0x14);
      puVar4[0x12] = 0xffff;
      iVar3 = FUN_8002e088(dVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar4,5,
                           *(undefined *)(param_9 + 0xac),0xffffffff,*(uint **)(param_9 + 0x30),
                           param_14,param_15,param_16);
      (**(code **)(**(int **)(iVar3 + 0x68) + 0x2c))
                ((double)FLOAT_803e4650,(double)FLOAT_803e4644,(double)FLOAT_803e4650);
      break;
    case '\a':
    case '\b':
      FUN_800201ac((int)*(short *)(param_11 + 0xe),1);
      break;
    case '\t':
      uVar1 = FUN_8002e144();
      if ((uVar1 & 0xff) != 0) {
        puVar4 = FUN_8002becc(0x24,0x259);
        *(undefined4 *)(puVar4 + 4) = *(undefined4 *)(param_9 + 0xc);
        dVar6 = (double)FLOAT_803e4640;
        *(float *)(puVar4 + 6) = (float)(dVar6 + (double)*(float *)(param_9 + 0x10));
        *(undefined4 *)(puVar4 + 8) = *(undefined4 *)(param_9 + 0x14);
        *(undefined *)(puVar4 + 2) = 4;
        *(undefined *)(puVar4 + 3) = 200;
        puVar4[0x10] = 0xffff;
        puVar4[0xd] = 0x7f;
        FUN_8002e088(dVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar4,5,
                     *(undefined *)(param_9 + 0xac),0xffffffff,*(uint **)(param_9 + 0x30),param_14,
                     param_15,param_16);
      }
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8018405c
 * EN v1.0 Address: 0x8018405C
 * EN v1.0 Size: 80b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8018405c(int param_1)
{
  if (*(short *)(param_1 + 0xb4) != -1) {
    (**(code **)(*DAT_803dd6d0 + 0x4c))();
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801840ac
 * EN v1.0 Address: 0x801840AC
 * EN v1.0 Size: 56b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801840ac(void)
{
  (**(code **)(*DAT_803dd6fc + 0x18))();
  FUN_80013e4c(DAT_803de748);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801840e4
 * EN v1.0 Address: 0x801840E4
 * EN v1.0 Size: 272b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801840e4(void)
{
  short sVar1;
  int iVar2;
  int iVar3;
  char in_r8;
  int iVar4;
  
  iVar2 = FUN_80286838();
  iVar4 = *(int *)(iVar2 + 0xb8);
  iVar3 = (**(code **)(*DAT_803dd72c + 0x68))(*(undefined4 *)(*(int *)(iVar2 + 0x4c) + 0x14));
  if ((iVar3 == 0) ||
     (((sVar1 = *(short *)(iVar4 + 8), sVar1 != 0 && (sVar1 < 0x33)) ||
      (FLOAT_803e4650 < *(float *)(iVar4 + 4))))) {
    *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) | 0x4000;
  }
  else {
    if (*(int *)(iVar2 + 0xf8) == 0) {
      if (in_r8 == '\0') {
        *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) | 0x4000;
        goto LAB_801841d8;
      }
    }
    else if (in_r8 != -1) {
      *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) | 0x4000;
      goto LAB_801841d8;
    }
    FUN_8003b9ec(iVar2);
  }
LAB_801841d8:
  FUN_80286884();
  return;
}
