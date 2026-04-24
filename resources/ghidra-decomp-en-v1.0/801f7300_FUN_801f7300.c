// Function: FUN_801f7300
// Entry: 801f7300
// Size: 64 bytes

void FUN_801f7300(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(int *)(iVar1 + 8) != 0) {
    FUN_80023800();
  }
  *(undefined4 *)(iVar1 + 8) = 0;
  return;
}

