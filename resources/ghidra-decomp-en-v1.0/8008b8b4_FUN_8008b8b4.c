// Function: FUN_8008b8b4
// Entry: 8008b8b4
// Size: 72 bytes

void FUN_8008b8b4(float *param_1)

{
  if (DAT_803dd12c == 0) {
    *param_1 = FLOAT_803df058;
  }
  else {
    *param_1 = (float)((double)CONCAT44(0x43300000,*(uint *)(DAT_803dd12c + 0x210) ^ 0x80000000) -
                      DOUBLE_803df090);
  }
  return;
}

