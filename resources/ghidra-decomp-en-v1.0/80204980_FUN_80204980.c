// Function: FUN_80204980
// Entry: 80204980
// Size: 72 bytes

void FUN_80204980(int param_1,int param_2)

{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0xb8);
  if ((param_2 == 0) && (*piVar1 != 0)) {
    FUN_8002cbc4();
    *piVar1 = 0;
  }
  return;
}

