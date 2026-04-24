// Function: FUN_8018aa0c
// Entry: 8018aa0c
// Size: 84 bytes

void FUN_8018aa0c(int param_1)

{
  if ((**(byte **)(param_1 + 0xb8) >> 5 & 1) != 0) {
    FUN_80097070((double)FLOAT_803e3c24,param_1,2,
                 *(char *)(*(int *)(param_1 + 0x4c) + 0x19) + '\x06',4,0);
  }
  return;
}

