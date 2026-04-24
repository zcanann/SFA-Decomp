// Function: FUN_801e69c8
// Entry: 801e69c8
// Size: 328 bytes

undefined4 FUN_801e69c8(int param_1)

{
  int iVar1;
  int local_18;
  int local_14;
  int local_10 [2];
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  *(undefined *)(iVar1 + 0x9d6) = 0;
  FUN_80035f00();
  iVar1 = *(int *)(iVar1 + 0x9b4);
  (**(code **)(**(int **)(iVar1 + 0x68) + 0x54))(iVar1,local_10,&local_14,&local_18);
  local_14 = local_14 - local_10[0];
  iVar1 = FUN_80014670();
  if (((iVar1 != 0) || (local_18 <= local_14)) || (local_10[0] != 0)) {
    FUN_8001467c();
    FUN_8011f6f0(0);
    FUN_800200e8(0x626,0);
    if (local_14 < local_18) {
      FUN_800200e8(0x625,1);
    }
    else {
      FUN_800200e8(0x624,1);
    }
    FUN_8011f38c(2);
    (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),6,0);
    (**(code **)(*DAT_803dca74 + 4))(0,0xf3,0,0,0);
  }
  return 0;
}

