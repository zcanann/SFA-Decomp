// Function: FUN_801b3b84
// Entry: 801b3b84
// Size: 80 bytes

void FUN_801b3b84(int param_1)

{
  char in_r8;
  
  if ((in_r8 == '\0') || (*(int *)(param_1 + 0xf8) != 0)) {
    if (*(int *)(param_1 + 0xf8) != 0) {
      FUN_80041018();
    }
  }
  else {
    FUN_8003b8f4((double)FLOAT_803e490c);
  }
  return;
}

