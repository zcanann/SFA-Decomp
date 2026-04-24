// Function: FUN_80084650
// Entry: 80084650
// Size: 244 bytes

void FUN_80084650(undefined4 *param_1,undefined4 param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  int unaff_r29;
  
  *param_1 = param_2;
  param_1[1] = 0xffffffff;
  iVar1 = (**(code **)(*DAT_803dd71c + 0x1c))(*param_1);
  uVar4 = 1;
  for (iVar3 = 0; iVar3 < 4; iVar3 = iVar3 + 1) {
    iVar2 = *(int *)(iVar1 + iVar3 * 4 + 0x1c);
    if ((-1 < iVar2) && (((int)*(char *)(iVar1 + 0x1b) & uVar4) == 0)) {
      iVar3 = 5;
      unaff_r29 = iVar2;
    }
    uVar4 = uVar4 << 1;
  }
  if (iVar3 == 6) {
    param_1[1] = unaff_r29;
    iVar3 = (**(code **)(*DAT_803dd71c + 0x1c))(param_1[1]);
    FUN_8008408c(param_1,iVar1,iVar3,'\0');
  }
  else {
    *param_1 = 0xffffffff;
  }
  return;
}

