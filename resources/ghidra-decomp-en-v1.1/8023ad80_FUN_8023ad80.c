// Function: FUN_8023ad80
// Entry: 8023ad80
// Size: 28 bytes

void FUN_8023ad80(int param_1,byte param_2)

{
  if (param_1 == 0) {
    return;
  }
  *(byte *)(*(int *)(param_1 + 0xb8) + 0xad) = *(byte *)(*(int *)(param_1 + 0xb8) + 0xad) | param_2;
  return;
}

