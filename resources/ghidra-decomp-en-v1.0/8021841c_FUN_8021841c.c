// Function: FUN_8021841c
// Entry: 8021841c
// Size: 88 bytes

void FUN_8021841c(int param_1)

{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0xb8);
  if (*piVar1 != 0) {
    FUN_8001f384();
    *piVar1 = 0;
  }
  FUN_80036fa4(param_1,2);
  return;
}

