// Function: FUN_801afbcc
// Entry: 801afbcc
// Size: 64 bytes

void FUN_801afbcc(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(int *)(iVar1 + 4) != 0) {
    FUN_8001f384();
    *(undefined4 *)(iVar1 + 4) = 0;
  }
  return;
}

