// Function: FUN_801aa818
// Entry: 801aa818
// Size: 96 bytes

void FUN_801aa818(int param_1,int param_2)

{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0xb8);
  if (*piVar1 != 0) {
    if (*(int *)(param_1 + 200) != 0) {
      FUN_80037cb0();
    }
    if (param_2 == 0) {
      FUN_8002cbc4(*piVar1);
    }
  }
  return;
}

