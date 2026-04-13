// Function: FUN_8002854c
// Entry: 8002854c
// Size: 28 bytes

void FUN_8002854c(undefined4 param_1,int param_2)

{
  if (*(int *)(param_2 + 0x58) != 0) {
    return;
  }
  *(code **)(param_2 + 0x38) = FUN_80072f78;
  return;
}

