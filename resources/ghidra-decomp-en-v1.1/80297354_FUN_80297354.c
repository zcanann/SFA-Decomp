// Function: FUN_80297354
// Entry: 80297354
// Size: 56 bytes

void FUN_80297354(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (param_2 != 0) {
    *(uint *)(iVar1 + 0x360) = *(uint *)(iVar1 + 0x360) | 0x200000;
    return;
  }
  *(uint *)(iVar1 + 0x360) = *(uint *)(iVar1 + 0x360) & 0xffdfffff;
  return;
}

