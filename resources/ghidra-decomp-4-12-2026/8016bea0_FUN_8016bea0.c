// Function: FUN_8016bea0
// Entry: 8016bea0
// Size: 224 bytes

void FUN_8016bea0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)

{
  float *pfVar1;
  
  pfVar1 = *(float **)(param_9 + 0x5c);
  *pfVar1 = *pfVar1 - FLOAT_803dc074;
  if ((double)FLOAT_803e3e94 < (double)*pfVar1) {
    *param_9 = *param_9 + (short)(int)(FLOAT_803e3e98 * FLOAT_803dc074);
    param_9[2] = param_9[2] + (short)(int)(FLOAT_803e3e9c * FLOAT_803dc074);
    if (FLOAT_803e3ea0 < *pfVar1) {
      *(undefined *)(param_9 + 0x1b) = 0xff;
    }
    else {
      *(char *)(param_9 + 0x1b) = (char)(int)(FLOAT_803e3ea4 * *pfVar1 * FLOAT_803e3ea8);
    }
  }
  else {
    FUN_8002cc9c((double)*pfVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 (int)param_9);
  }
  return;
}

