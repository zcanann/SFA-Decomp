// Function: FUN_8014e744
// Entry: 8014e744
// Size: 96 bytes

void FUN_8014e744(int param_1)

{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0xb8);
  FUN_80036fa4(param_1,3);
  FUN_8000b824(param_1,0x236);
  if (*piVar1 != 0) {
    FUN_80023800();
    *piVar1 = 0;
  }
  return;
}

