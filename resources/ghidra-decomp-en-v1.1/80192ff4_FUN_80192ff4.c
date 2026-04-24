// Function: FUN_80192ff4
// Entry: 80192ff4
// Size: 48 bytes

void FUN_80192ff4(int param_1)

{
  uint uVar1;
  
  uVar1 = *(uint *)(*(int *)(param_1 + 0xb8) + 0x10);
  if (uVar1 != 0) {
    FUN_800238c4(uVar1);
  }
  return;
}

