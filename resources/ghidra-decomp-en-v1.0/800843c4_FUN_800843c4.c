// Function: FUN_800843c4
// Entry: 800843c4
// Size: 244 bytes

void FUN_800843c4(undefined4 *param_1,undefined4 param_2)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  uint uVar5;
  int unaff_r29;
  
  *param_1 = param_2;
  param_1[1] = 0xffffffff;
  iVar1 = (**(code **)(*DAT_803dca9c + 0x1c))(*param_1);
  uVar5 = 1;
  for (iVar4 = 0; iVar4 < 4; iVar4 = iVar4 + 1) {
    iVar2 = *(int *)(iVar1 + iVar4 * 4 + 0x1c);
    if ((-1 < iVar2) && (((int)*(char *)(iVar1 + 0x1b) & uVar5) == 0)) {
      iVar4 = 5;
      unaff_r29 = iVar2;
    }
    uVar5 = uVar5 << 1;
  }
  if (iVar4 == 6) {
    param_1[1] = unaff_r29;
    uVar3 = (**(code **)(*DAT_803dca9c + 0x1c))(param_1[1]);
    FUN_80083e00((double)FLOAT_803defb0,param_1,iVar1,uVar3,0);
  }
  else {
    *param_1 = 0xffffffff;
  }
  return;
}

