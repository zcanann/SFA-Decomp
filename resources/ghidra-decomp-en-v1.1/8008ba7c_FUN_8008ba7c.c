// Function: FUN_8008ba7c
// Entry: 8008ba7c
// Size: 156 bytes

undefined4 FUN_8008ba7c(float *param_1)

{
  float fVar1;
  
  if (DAT_803dddac == 0) {
    if (param_1 != (float *)0x0) {
      *param_1 = FLOAT_803dfcd8;
    }
    return 0;
  }
  fVar1 = *(float *)(DAT_803dddac + 0x20c);
  if ((fVar1 < FLOAT_803dfd08) && (FLOAT_803dfd04 <= fVar1)) {
    if (param_1 != (float *)0x0) {
      *param_1 = FLOAT_803dfd08 - fVar1;
    }
    return 0;
  }
  if (param_1 != (float *)0x0) {
    if (fVar1 < FLOAT_803dfd08) {
      *param_1 = FLOAT_803dfd04 - fVar1;
    }
    else {
      *param_1 = FLOAT_803dfd04 + (fVar1 - FLOAT_803dfd08);
    }
  }
  return 1;
}

