// Function: FUN_8016b9f4
// Entry: 8016b9f4
// Size: 224 bytes

void FUN_8016b9f4(short *param_1)

{
  float *pfVar1;
  
  pfVar1 = *(float **)(param_1 + 0x5c);
  *pfVar1 = *pfVar1 - FLOAT_803db414;
  if (FLOAT_803e31fc < *pfVar1) {
    *param_1 = *param_1 + (short)(int)(FLOAT_803e3200 * FLOAT_803db414);
    param_1[2] = param_1[2] + (short)(int)(FLOAT_803e3204 * FLOAT_803db414);
    if (FLOAT_803e3208 < *pfVar1) {
      *(undefined *)(param_1 + 0x1b) = 0xff;
    }
    else {
      *(char *)(param_1 + 0x1b) = (char)(int)(FLOAT_803e320c * *pfVar1 * FLOAT_803e3210);
    }
  }
  else {
    FUN_8002cbc4();
  }
  return;
}

