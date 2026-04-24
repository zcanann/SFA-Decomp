// Function: FUN_801a0670
// Entry: 801a0670
// Size: 120 bytes

void FUN_801a0670(int param_1)

{
  int iVar1;
  uint uVar2;
  
  FUN_80037a5c(param_1,1);
  *(code **)(param_1 + 0xbc) = FUN_801a0200;
  iVar1 = *(int *)(param_1 + 0xb8);
  *(undefined4 *)(iVar1 + 100) = 0x1d0;
  *(undefined4 *)(iVar1 + 0x68) = 0x1d1;
  *(undefined2 *)(iVar1 + 0x70) = 0;
  *(undefined *)(iVar1 + 0x74) = 0;
  uVar2 = FUN_80020078(0x4d);
  if (uVar2 != 0) {
    FUN_800201ac(0x50,1);
  }
  return;
}

