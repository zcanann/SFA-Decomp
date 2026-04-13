// Function: FUN_801aae2c
// Entry: 801aae2c
// Size: 148 bytes

void FUN_801aae2c(double param_1,int param_2,int param_3)

{
  if ((double)FLOAT_803e530c == param_1) {
    *(undefined *)(param_2 + 0x10) = 0xc;
    return;
  }
  if ((*(byte *)(param_2 + 0x11) & 2) != 0) {
    *(undefined *)(param_2 + 0x10) = 1;
    return;
  }
  if ((double)FLOAT_803e5310 <= param_1) {
    *(undefined *)(param_2 + 0x10) = 2;
    return;
  }
  if ((*(short *)(param_3 + 0xa0) == 0x18) && (FLOAT_803e5314 < *(float *)(param_3 + 0x98))) {
    *(undefined *)(param_2 + 0x10) = 8;
    return;
  }
  if (*(short *)(param_3 + 0xa0) == 0x19) {
    *(undefined *)(param_2 + 0x10) = 5;
    return;
  }
  *(undefined *)(param_2 + 0x10) = 0xb;
  return;
}

