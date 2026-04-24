// Function: FUN_8008bb40
// Entry: 8008bb40
// Size: 72 bytes

void FUN_8008bb40(float *param_1)

{
  if (DAT_803dddac == 0) {
    *param_1 = FLOAT_803dfcd8;
  }
  else {
    *param_1 = (float)((double)CONCAT44(0x43300000,*(uint *)(DAT_803dddac + 0x210) ^ 0x80000000) -
                      DOUBLE_803dfd10);
  }
  return;
}

