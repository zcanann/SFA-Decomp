// Function: FUN_80234a9c
// Entry: 80234a9c
// Size: 48 bytes

void FUN_80234a9c(int param_1)

{
  uint uVar1;
  
  uVar1 = *(uint *)(*(int *)(param_1 + 0xb8) + 8);
  if (uVar1 != 0) {
    FUN_8001f448(uVar1);
  }
  return;
}

