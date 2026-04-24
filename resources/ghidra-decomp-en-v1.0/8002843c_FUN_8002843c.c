// Function: FUN_8002843c
// Entry: 8002843c
// Size: 76 bytes

void FUN_8002843c(int param_1)

{
  if (*(int *)(param_1 + 0x58) == 0) {
    *(undefined4 *)(param_1 + 0x38) = 0;
  }
  else {
    FUN_80023800();
    *(undefined4 *)(param_1 + 0x58) = 0;
  }
  return;
}

