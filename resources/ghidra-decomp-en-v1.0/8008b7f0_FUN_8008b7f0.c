// Function: FUN_8008b7f0
// Entry: 8008b7f0
// Size: 156 bytes

undefined4 FUN_8008b7f0(float *param_1)

{
  float fVar1;
  
  if (DAT_803dd12c == 0) {
    if (param_1 != (float *)0x0) {
      *param_1 = FLOAT_803df058;
    }
    return 0;
  }
  fVar1 = *(float *)(DAT_803dd12c + 0x20c);
  if ((fVar1 < FLOAT_803df088) && (FLOAT_803df084 <= fVar1)) {
    if (param_1 != (float *)0x0) {
      *param_1 = FLOAT_803df088 - fVar1;
    }
    return 0;
  }
  if (param_1 != (float *)0x0) {
    if (fVar1 < FLOAT_803df088) {
      *param_1 = FLOAT_803df084 - fVar1;
    }
    else {
      *param_1 = FLOAT_803df084 + (fVar1 - FLOAT_803df088);
    }
  }
  return 1;
}

