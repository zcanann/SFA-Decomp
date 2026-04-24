// Function: FUN_802394e0
// Entry: 802394e0
// Size: 64 bytes

void FUN_802394e0(int param_1)

{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0xb8);
  FUN_80036fa4(param_1,0x48);
  if (*piVar1 != 0) {
    FUN_80023800();
  }
  return;
}

