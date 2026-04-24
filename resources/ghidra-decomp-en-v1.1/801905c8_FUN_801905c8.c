// Function: FUN_801905c8
// Entry: 801905c8
// Size: 72 bytes

void FUN_801905c8(int param_1)

{
  uint uVar1;
  
  uVar1 = *(uint *)(*(int *)(param_1 + 0xb8) + 0x108);
  if (uVar1 != 0) {
    FUN_800238c4(uVar1);
  }
  FUN_8003709c(param_1,0x1c);
  return;
}

