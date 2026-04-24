// Function: FUN_80028488
// Entry: 80028488
// Size: 28 bytes

void FUN_80028488(undefined4 param_1,int param_2)

{
  if (*(int *)(param_2 + 0x58) != 0) {
    return;
  }
  *(code **)(param_2 + 0x38) = FUN_80072dfc;
  return;
}

