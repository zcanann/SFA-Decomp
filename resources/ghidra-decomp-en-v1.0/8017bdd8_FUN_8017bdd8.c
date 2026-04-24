// Function: FUN_8017bdd8
// Entry: 8017bdd8
// Size: 80 bytes

void FUN_8017bdd8(int param_1)

{
  char in_r8;
  
  if ((in_r8 == '\0') || (*(int *)(param_1 + 0xf8) != 0)) {
    if (*(int *)(param_1 + 0xf8) != 0) {
      FUN_80041018();
    }
  }
  else {
    FUN_8003b8f4((double)FLOAT_803e3798);
  }
  return;
}

