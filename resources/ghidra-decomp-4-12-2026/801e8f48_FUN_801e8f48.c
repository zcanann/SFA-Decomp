// Function: FUN_801e8f48
// Entry: 801e8f48
// Size: 84 bytes

void FUN_801e8f48(int param_1)

{
  char in_r8;
  
  if (in_r8 != '\0') {
    if (*(short *)(param_1 + 0x46) == 0x468) {
      FUN_801e89a0();
    }
    else {
      FUN_8003b9ec(param_1);
    }
  }
  return;
}

