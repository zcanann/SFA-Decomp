// Function: FUN_80295c5c
// Entry: 80295c5c
// Size: 44 bytes

undefined4 FUN_80295c5c(int param_1)

{
  if (*(short *)(*(int *)(param_1 + 0xb8) + 0x274) != 0x36) {
    return 0;
  }
  if ((*(byte *)(*(int *)(param_1 + 0xb8) + 0x3f3) >> 4 & 1) == 0) {
    return 0;
  }
  return 1;
}

