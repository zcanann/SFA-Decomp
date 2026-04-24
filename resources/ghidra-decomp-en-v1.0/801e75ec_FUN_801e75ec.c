// Function: FUN_801e75ec
// Entry: 801e75ec
// Size: 180 bytes

void FUN_801e75ec(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if ((*(byte *)(iVar1 + 0x9d4) & 2) == 0) {
    FUN_8011f38c(0);
  }
  else {
    FUN_800146bc(0x11,0x1e);
    FUN_8001469c();
    FUN_8011f6f0(1);
    FUN_800200e8(0x626,1);
    (**(code **)(**(int **)(*(int *)(iVar1 + 0x9b4) + 0x68) + 0x4c))
              (*(int *)(iVar1 + 0x9b4),*(undefined *)(iVar1 + 0x9d5));
    (**(code **)(*DAT_803dca74 + 4))(0,0xf5,0,0,0);
  }
  *(undefined *)(iVar1 + 0x9d4) = 0;
  return;
}

