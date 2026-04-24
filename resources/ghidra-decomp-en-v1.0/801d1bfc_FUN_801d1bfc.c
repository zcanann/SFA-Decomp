// Function: FUN_801d1bfc
// Entry: 801d1bfc
// Size: 348 bytes

void FUN_801d1bfc(undefined2 *param_1,float *param_2,int param_3)

{
  undefined2 uVar2;
  uint uVar1;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x26);
  uVar2 = FUN_800221a0(0xfffffa24,0x5dc);
  param_1[2] = uVar2;
  uVar2 = FUN_800221a0(0xfffffa24,0x5dc);
  param_1[1] = uVar2;
  uVar2 = FUN_800221a0(0xfffffa24,0x5dc);
  *param_1 = uVar2;
  *(undefined *)(param_1 + 0x1b) = 0xff;
  param_1[3] = param_1[3] & 0xbfff;
  *(undefined4 *)(param_1 + 6) = *(undefined4 *)(iVar3 + 8);
  *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar3 + 0xc);
  *(undefined4 *)(param_1 + 10) = *(undefined4 *)(iVar3 + 0x10);
  if (param_3 != 0) {
    *(float *)(param_1 + 4) = FLOAT_803e52f8;
    *param_2 = FLOAT_803e52fc;
    uVar1 = FUN_800221a0(0,100);
    param_2[2] = FLOAT_803e5300 +
                 (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e5308);
    uVar1 = FUN_800221a0(0xffffff9c,100);
    param_2[1] = FLOAT_803e5304 *
                 (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e5308) +
                 param_2[3];
    param_2[4] = param_2[1] / param_2[2];
  }
  FUN_80035f20(param_1);
  FUN_80036044(param_1);
  return;
}

