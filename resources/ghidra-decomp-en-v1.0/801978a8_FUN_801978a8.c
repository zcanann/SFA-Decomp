// Function: FUN_801978a8
// Entry: 801978a8
// Size: 64 bytes

void FUN_801978a8(int param_1)

{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0xb8);
  FUN_80036fa4(param_1,0x48);
  if (*piVar1 != 0) {
    FUN_80023800();
  }
  return;
}

