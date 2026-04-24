// Function: FUN_801175a4
// Entry: 801175a4
// Size: 196 bytes

undefined4 FUN_801175a4(undefined4 param_1,int param_2)

{
  int iVar1;
  
  if (param_2 == 0) {
    iVar1 = FUN_802462a8(&DAT_803a54a0,FUN_8011750c,0,&DAT_803a54a0,0x1000,param_1,1);
    if (iVar1 == 0) {
      return 0;
    }
  }
  else {
    iVar1 = FUN_802462a8(&DAT_803a54a0,FUN_80117460,param_2,&DAT_803a54a0,0x1000,param_1,1);
    if (iVar1 == 0) {
      return 0;
    }
  }
  FUN_80244000(&DAT_803a4480,&DAT_803a4454,3);
  FUN_80244000(&DAT_803a4460,&DAT_803a4448,3);
  DAT_803dd658 = 1;
  return 1;
}

