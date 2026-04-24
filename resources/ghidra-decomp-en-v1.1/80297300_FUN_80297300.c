// Function: FUN_80297300
// Entry: 80297300
// Size: 28 bytes

int FUN_80297300(int param_1)

{
  if (*(int *)(param_1 + 0xb8) != 0) {
    return (int)*(short *)(*(int *)(param_1 + 0xb8) + 0x80a);
  }
  return 0;
}

