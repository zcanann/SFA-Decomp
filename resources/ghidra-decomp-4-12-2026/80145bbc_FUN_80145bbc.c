// Function: FUN_80145bbc
// Entry: 80145bbc
// Size: 72 bytes

void FUN_80145bbc(int param_1)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  uVar1 = FUN_80020078(0x4e4);
  if (uVar1 != 0) {
    *(uint *)(iVar2 + 0x54) = *(uint *)(iVar2 + 0x54) | 0x10000;
  }
  return;
}

