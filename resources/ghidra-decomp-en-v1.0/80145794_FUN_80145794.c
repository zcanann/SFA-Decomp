// Function: FUN_80145794
// Entry: 80145794
// Size: 72 bytes

void FUN_80145794(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  iVar1 = FUN_8001ffb4(0x4e4);
  if (iVar1 != 0) {
    *(uint *)(iVar2 + 0x54) = *(uint *)(iVar2 + 0x54) | 0x10000;
  }
  return;
}

