// Function: FUN_802bb1b4
// Entry: 802bb1b4
// Size: 352 bytes

/* WARNING: Removing unreachable block (ram,0x802bb2f4) */
/* WARNING: Removing unreachable block (ram,0x802bb1c4) */

undefined4
FUN_802bb1b4(double param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  short sVar2;
  uint uVar3;
  undefined4 uVar4;
  int iVar5;
  double dVar6;
  
  fVar1 = FLOAT_803e8ecc;
  iVar5 = *(int *)(param_9 + 0xb8);
  dVar6 = (double)FLOAT_803e8ecc;
  param_10[0xa5] = (uint)FLOAT_803e8ecc;
  param_10[0xa1] = (uint)fVar1;
  param_10[0xa0] = (uint)fVar1;
  *(float *)(param_9 + 0x24) = fVar1;
  *(float *)(param_9 + 0x28) = fVar1;
  *(float *)(param_9 + 0x2c) = fVar1;
  *param_10 = *param_10 | 0x200000;
  if (*(char *)((int)param_10 + 0x27a) != '\0') {
    param_10[0xa8] = (uint)FLOAT_803e8f14;
    if ((int)*(short *)(param_9 + 0xa0) != (int)DAT_803dd3b0) {
      FUN_8003042c(dVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                   (int)DAT_803dd3b0,0,param_12,param_13,param_14,param_15,param_16);
    }
    uVar3 = FUN_80022264(0x4b0,0x960);
    *(short *)(iVar5 + 0xa84) = (short)uVar3;
  }
  sVar2 = *(short *)(iVar5 + 0xa84) - (short)(int)param_1;
  *(short *)(iVar5 + 0xa84) = sVar2;
  if (sVar2 < 1) {
    uVar4 = 0xfffffffd;
  }
  else {
    if ((*(byte *)(param_9 + 0xaf) & 1) != 0) {
      if ((*(byte *)(iVar5 + 0xa8e) & 0x20) == 0) {
        (**(code **)(*DAT_803dd6d4 + 0x48))(5,param_9,0xffffffff);
      }
      else {
        uVar3 = FUN_80022264(0,2);
        (**(code **)(*DAT_803dd6d4 + 0x48))(uVar3 + 6,param_9,0xffffffff);
      }
      FUN_80014b68(0,0x100);
    }
    uVar4 = 0;
  }
  return uVar4;
}

