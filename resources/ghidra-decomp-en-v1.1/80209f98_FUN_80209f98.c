// Function: FUN_80209f98
// Entry: 80209f98
// Size: 72 bytes

void FUN_80209f98(int param_1)

{
  uint uVar1;
  uint *puVar2;
  
  if (param_1 != 0) {
    puVar2 = *(uint **)(param_1 + 0xb8);
    uVar1 = *puVar2;
    if (uVar1 != 0) {
      FUN_800238c4(uVar1);
      *puVar2 = 0;
    }
  }
  return;
}

