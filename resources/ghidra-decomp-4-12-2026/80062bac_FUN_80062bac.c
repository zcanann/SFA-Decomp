// Function: FUN_80062bac
// Entry: 80062bac
// Size: 32 bytes

void FUN_80062bac(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 100);
  if (iVar1 == 0) {
    return;
  }
  *(uint *)(iVar1 + 0x30) = *(uint *)(iVar1 + 0x30) & 0xffffdfdf;
  return;
}

