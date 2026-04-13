// Function: FUN_8014fe24
// Entry: 8014fe24
// Size: 72 bytes

void FUN_8014fe24(int param_1)

{
  uint uVar1;
  uint *puVar2;
  
  puVar2 = *(uint **)(param_1 + 0xb8);
  FUN_8003709c(param_1,3);
  uVar1 = *puVar2;
  if (uVar1 != 0) {
    FUN_800238c4(uVar1);
    *puVar2 = 0;
  }
  return;
}

