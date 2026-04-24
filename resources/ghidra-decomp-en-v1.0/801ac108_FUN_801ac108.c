// Function: FUN_801ac108
// Entry: 801ac108
// Size: 320 bytes

void FUN_801ac108(int param_1,undefined *param_2)

{
  int iVar1;
  
  (**(code **)(*DAT_803dca68 + 0x40))(0);
  iVar1 = FUN_8001ffb4(0x3a3);
  if (iVar1 != 0) {
    FUN_800200e8(0x3a3,0);
    FUN_800200e8(0x3a2,0);
    FUN_800200e8(0x378,0);
    FUN_800200e8(0x3b9,0);
    FUN_8002b9ec();
    iVar1 = FUN_802972a8();
    if (iVar1 == 0) {
      iVar1 = 0;
    }
    else {
      iVar1 = (**(code **)(**(int **)(iVar1 + 0x68) + 0x48))();
    }
    FUN_800200e8(0x4e5,1);
    (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),1,1);
    if (iVar1 == 1) {
      (**(code **)(*DAT_803dca68 + 0x40))(1);
      *param_2 = 5;
      FUN_800200e8(0x379,1);
    }
    else {
      *param_2 = 6;
      FUN_800200e8(0xcb,1);
    }
  }
  return;
}

