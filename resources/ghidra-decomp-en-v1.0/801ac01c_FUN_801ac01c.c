// Function: FUN_801ac01c
// Entry: 801ac01c
// Size: 236 bytes

void FUN_801ac01c(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  undefined *puVar3;
  
  puVar3 = *(undefined **)(param_1 + 0xb8);
  FUN_800200e8(0x3a3,0);
  FUN_800200e8(0x3a2,0);
  FUN_8002b9ec();
  iVar1 = FUN_802972a8();
  if (iVar1 == 0) {
    iVar1 = 0;
  }
  else {
    iVar1 = (**(code **)(**(int **)(iVar1 + 0x68) + 0x48))();
  }
  uVar2 = FUN_800481b0(0x17);
  FUN_80043560(uVar2,1);
  if (iVar1 == 1) {
    (**(code **)(*DAT_803dca68 + 0x40))(1);
    *puVar3 = 5;
    FUN_800200e8(0x37b,1);
  }
  else {
    *puVar3 = 6;
    FUN_800200e8(0xce,1);
  }
  FUN_800200e8(0x378,0);
  FUN_800200e8(0x3b9,0);
  return;
}

