// Function: FUN_801ae518
// Entry: 801ae518
// Size: 72 bytes

void FUN_801ae518(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(int *)(iVar1 + 4) != 0) {
    FUN_80023800();
  }
  if (*(int *)(iVar1 + 8) != 0) {
    FUN_80023800();
  }
  return;
}

