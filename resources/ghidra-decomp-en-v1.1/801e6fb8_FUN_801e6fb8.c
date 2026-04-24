// Function: FUN_801e6fb8
// Entry: 801e6fb8
// Size: 328 bytes

undefined4 FUN_801e6fb8(int param_1)

{
  byte bVar1;
  int iVar2;
  int local_18;
  int local_14;
  int local_10 [2];
  
  iVar2 = *(int *)(param_1 + 0xb8);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  *(undefined *)(iVar2 + 0x9d6) = 0;
  FUN_80035ff8(param_1);
  iVar2 = *(int *)(iVar2 + 0x9b4);
  (**(code **)(**(int **)(iVar2 + 0x68) + 0x54))(iVar2,local_10,&local_14,&local_18);
  local_14 = local_14 - local_10[0];
  bVar1 = FUN_8001469c();
  if (((bVar1 != 0) || (local_18 <= local_14)) || (local_10[0] != 0)) {
    FUN_800146a8();
    FUN_8011f9d4(0);
    FUN_800201ac(0x626,0);
    if (local_14 < local_18) {
      FUN_800201ac(0x625,1);
    }
    else {
      FUN_800201ac(0x624,1);
    }
    FUN_8011f670(2);
    (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_1 + 0xac),6,0);
    (**(code **)(*DAT_803dd6f4 + 4))(0,0xf3,0,0,0);
  }
  return 0;
}

