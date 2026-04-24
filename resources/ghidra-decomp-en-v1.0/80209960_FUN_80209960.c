// Function: FUN_80209960
// Entry: 80209960
// Size: 72 bytes

void FUN_80209960(int param_1)

{
  int *piVar1;
  
  if (param_1 != 0) {
    piVar1 = *(int **)(param_1 + 0xb8);
    if (*piVar1 != 0) {
      FUN_80023800();
      *piVar1 = 0;
    }
  }
  return;
}

