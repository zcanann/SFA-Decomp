// Function: FUN_801d07c0
// Entry: 801d07c0
// Size: 104 bytes

void FUN_801d07c0(int param_1)

{
  int iVar1;
  undefined *puVar2;
  
  puVar2 = *(undefined **)(param_1 + 0xb8);
  iVar1 = FUN_8001ffb4(0xbf);
  if (iVar1 == 0) {
    *puVar2 = 0;
  }
  else {
    *puVar2 = 4;
  }
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  return;
}

