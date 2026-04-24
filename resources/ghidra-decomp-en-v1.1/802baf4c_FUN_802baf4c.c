// Function: FUN_802baf4c
// Entry: 802baf4c
// Size: 332 bytes

undefined4
FUN_802baf4c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  uint uVar2;
  undefined4 uVar3;
  int iVar4;
  
  fVar1 = FLOAT_803e8ecc;
  iVar4 = *(int *)(param_9 + 0xb8);
  param_10[0xa5] = (uint)FLOAT_803e8ecc;
  param_10[0xa1] = (uint)fVar1;
  param_10[0xa0] = (uint)fVar1;
  *(float *)(param_9 + 0x24) = fVar1;
  *(float *)(param_9 + 0x28) = fVar1;
  *(float *)(param_9 + 0x2c) = fVar1;
  *param_10 = *param_10 | 0x200000;
  if (*(char *)((int)param_10 + 0x27a) != '\0') {
    uVar2 = FUN_80022264(0,1);
    param_10[0xa8] = *(uint *)(&DAT_803dd3a8 + uVar2 * 4);
    FUN_8003042c((double)FLOAT_803e8ecc,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,(int)*(short *)(&DAT_803dd3a4 + uVar2 * 2),0,param_12,param_13,param_14,
                 param_15,param_16);
  }
  if (*(char *)((int)param_10 + 0x346) == '\0') {
    if ((*(byte *)(param_9 + 0xaf) & 1) != 0) {
      if ((*(byte *)(iVar4 + 0xa8e) & 0x20) == 0) {
        (**(code **)(*DAT_803dd6d4 + 0x48))(5,param_9,0xffffffff);
      }
      else {
        uVar2 = FUN_80022264(0,2);
        (**(code **)(*DAT_803dd6d4 + 0x48))(uVar2 + 6,param_9,0xffffffff);
      }
      FUN_80014b68(0,0x100);
    }
    uVar3 = 0;
  }
  else {
    uVar3 = 0xffffffff;
  }
  return uVar3;
}

