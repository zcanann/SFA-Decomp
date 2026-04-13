// Function: FUN_80216ca8
// Entry: 80216ca8
// Size: 64 bytes

void FUN_80216ca8(int param_1)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  uVar1 = *(uint *)(iVar2 + 0x10);
  if (uVar1 != 0) {
    FUN_800238c4(uVar1);
    *(undefined4 *)(iVar2 + 0x10) = 0;
  }
  return;
}

