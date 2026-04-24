// Function: FUN_801f7938
// Entry: 801f7938
// Size: 64 bytes

void FUN_801f7938(int param_1)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  uVar1 = *(uint *)(iVar2 + 8);
  if (uVar1 != 0) {
    FUN_800238c4(uVar1);
  }
  *(undefined4 *)(iVar2 + 8) = 0;
  return;
}

