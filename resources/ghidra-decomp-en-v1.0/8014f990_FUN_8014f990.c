// Function: FUN_8014f990
// Entry: 8014f990
// Size: 72 bytes

void FUN_8014f990(int param_1)

{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0xb8);
  FUN_80036fa4(param_1,3);
  if (*piVar1 != 0) {
    FUN_80023800();
    *piVar1 = 0;
  }
  return;
}

