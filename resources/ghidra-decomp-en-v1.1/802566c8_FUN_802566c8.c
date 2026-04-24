// Function: FUN_802566c8
// Entry: 802566c8
// Size: 112 bytes

void FUN_802566c8(int param_1,int param_2,int param_3)

{
  FUN_80243e74();
  *(int *)(param_1 + 0x14) = param_2;
  *(int *)(param_1 + 0x18) = param_3;
  *(int *)(param_1 + 0x1c) = param_3 - param_2;
  if (*(int *)(param_1 + 0x1c) < 0) {
    *(int *)(param_1 + 0x1c) = *(int *)(param_1 + 0x1c) + *(int *)(param_1 + 8);
  }
  FUN_80243e9c();
  return;
}

