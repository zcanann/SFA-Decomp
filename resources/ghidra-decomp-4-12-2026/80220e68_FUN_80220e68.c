// Function: FUN_80220e68
// Entry: 80220e68
// Size: 64 bytes

void FUN_80220e68(int param_1)

{
  uint uVar1;
  uint *puVar2;
  
  puVar2 = *(uint **)(param_1 + 0xb8);
  uVar1 = *puVar2;
  if (uVar1 != 0) {
    FUN_800238c4(uVar1);
    *puVar2 = 0;
  }
  return;
}

