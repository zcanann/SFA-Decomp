// Function: FUN_801a00f4
// Entry: 801a00f4
// Size: 120 bytes

void FUN_801a00f4(int param_1)

{
  int iVar1;
  
  FUN_80037964(param_1,1);
  *(code **)(param_1 + 0xbc) = FUN_8019fc84;
  iVar1 = *(int *)(param_1 + 0xb8);
  *(undefined4 *)(iVar1 + 100) = 0x1d0;
  *(undefined4 *)(iVar1 + 0x68) = 0x1d1;
  *(undefined2 *)(iVar1 + 0x70) = 0;
  *(undefined *)(iVar1 + 0x74) = 0;
  iVar1 = FUN_8001ffb4(0x4d);
  if (iVar1 != 0) {
    FUN_800200e8(0x50,1);
  }
  return;
}

