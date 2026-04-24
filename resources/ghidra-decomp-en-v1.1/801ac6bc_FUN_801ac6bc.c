// Function: FUN_801ac6bc
// Entry: 801ac6bc
// Size: 320 bytes

void FUN_801ac6bc(int param_1,undefined *param_2)

{
  uint uVar1;
  int iVar2;
  
  (**(code **)(*DAT_803dd6e8 + 0x40))(0);
  uVar1 = FUN_80020078(0x3a3);
  if (uVar1 != 0) {
    FUN_800201ac(0x3a3,0);
    FUN_800201ac(0x3a2,0);
    FUN_800201ac(0x378,0);
    FUN_800201ac(0x3b9,0);
    iVar2 = FUN_8002bac4();
    iVar2 = FUN_80297a08(iVar2);
    if (iVar2 == 0) {
      iVar2 = 0;
    }
    else {
      iVar2 = (**(code **)(**(int **)(iVar2 + 0x68) + 0x48))();
    }
    FUN_800201ac(0x4e5,1);
    (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_1 + 0xac),1,1);
    if (iVar2 == 1) {
      (**(code **)(*DAT_803dd6e8 + 0x40))(1);
      *param_2 = 5;
      FUN_800201ac(0x379,1);
    }
    else {
      *param_2 = 6;
      FUN_800201ac(0xcb,1);
    }
  }
  return;
}

