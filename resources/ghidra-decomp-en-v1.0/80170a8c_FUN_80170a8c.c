// Function: FUN_80170a8c
// Entry: 80170a8c
// Size: 100 bytes

void FUN_80170a8c(int param_1)

{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0xb8);
  if (*piVar1 != 0) {
    FUN_8001f384();
    *piVar1 = 0;
  }
  FUN_8000b824(param_1,0x42c);
  FUN_8000b824(param_1,0x42d);
  return;
}

