// Function: FUN_8008cc00
// Entry: 8008cc00
// Size: 68 bytes

void FUN_8008cc00(int *param_1,int *param_2)

{
  if (DAT_803dde04 != 0) {
    *param_1 = (int)*(float *)(DAT_803dde04 + 0x14);
    *param_2 = (int)*(float *)(DAT_803dde04 + 0x18);
  }
  return;
}

