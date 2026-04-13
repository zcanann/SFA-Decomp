// Function: FUN_8002e174
// Entry: 8002e174
// Size: 56 bytes

int FUN_8002e174(int param_1)

{
  if ((-1 < param_1) && (param_1 < DAT_803dd82c)) {
    return DAT_803dd834 + *(int *)(DAT_803dd830 + param_1 * 4) * 4;
  }
  return DAT_803dd834;
}

