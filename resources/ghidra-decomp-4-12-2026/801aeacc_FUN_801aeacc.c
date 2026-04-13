// Function: FUN_801aeacc
// Entry: 801aeacc
// Size: 72 bytes

void FUN_801aeacc(int param_1)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  uVar1 = *(uint *)(iVar2 + 4);
  if (uVar1 != 0) {
    FUN_800238c4(uVar1);
  }
  uVar1 = *(uint *)(iVar2 + 8);
  if (uVar1 != 0) {
    FUN_800238c4(uVar1);
  }
  return;
}

