// Function: FUN_801e7bdc
// Entry: 801e7bdc
// Size: 180 bytes

void FUN_801e7bdc(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if ((*(byte *)(iVar1 + 0x9d4) & 2) == 0) {
    FUN_8011f670(0);
  }
  else {
    FUN_800146e8(0x11,0x1e);
    FUN_800146c8();
    FUN_8011f9d4(1);
    FUN_800201ac(0x626,1);
    (**(code **)(**(int **)(*(int *)(iVar1 + 0x9b4) + 0x68) + 0x4c))
              (*(int *)(iVar1 + 0x9b4),*(undefined *)(iVar1 + 0x9d5));
    (**(code **)(*DAT_803dd6f4 + 4))(0,0xf5,0,0,0);
  }
  *(undefined *)(iVar1 + 0x9d4) = 0;
  return;
}

