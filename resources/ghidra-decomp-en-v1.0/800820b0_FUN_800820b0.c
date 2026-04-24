// Function: FUN_800820b0
// Entry: 800820b0
// Size: 92 bytes

void FUN_800820b0(int param_1)

{
  if (*(int *)(param_1 + 0x94) != 0) {
    FUN_80023800();
    *(undefined4 *)(param_1 + 0x94) = 0;
    *(undefined4 *)(param_1 + 0x98) = 0;
  }
  if (*(int *)(param_1 + 0x2c) != 0) {
    FUN_80023800();
    *(undefined4 *)(param_1 + 0x2c) = 0;
  }
  return;
}

