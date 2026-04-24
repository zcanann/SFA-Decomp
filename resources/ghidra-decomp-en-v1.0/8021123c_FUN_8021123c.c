// Function: FUN_8021123c
// Entry: 8021123c
// Size: 52 bytes

void FUN_8021123c(int param_1)

{
  if (*(int *)(*(int *)(param_1 + 0xb8) + 4) != 0) {
    FUN_8001cb3c(*(int *)(param_1 + 0xb8) + 4);
  }
  return;
}

