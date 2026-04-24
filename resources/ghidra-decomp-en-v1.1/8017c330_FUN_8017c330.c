// Function: FUN_8017c330
// Entry: 8017c330
// Size: 80 bytes

void FUN_8017c330(int param_1)

{
  char in_r8;
  
  if ((in_r8 == '\0') || (*(int *)(param_1 + 0xf8) != 0)) {
    if (*(int *)(param_1 + 0xf8) != 0) {
      FUN_80041110();
    }
  }
  else {
    FUN_8003b9ec(param_1);
  }
  return;
}

