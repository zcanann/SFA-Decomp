// Function: FUN_80220818
// Entry: 80220818
// Size: 64 bytes

void FUN_80220818(int param_1)

{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0xb8);
  if (*piVar1 != 0) {
    FUN_80023800();
    *piVar1 = 0;
  }
  return;
}

