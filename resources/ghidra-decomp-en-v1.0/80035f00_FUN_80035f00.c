// Function: FUN_80035f00
// Entry: 80035f00
// Size: 32 bytes

void FUN_80035f00(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x54);
  if (iVar1 == 0) {
    return;
  }
  *(ushort *)(iVar1 + 0x60) = *(ushort *)(iVar1 + 0x60) & 0xfffe;
  return;
}

