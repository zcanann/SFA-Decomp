// Function: FUN_8016e6d4
// Entry: 8016e6d4
// Size: 180 bytes

void FUN_8016e6d4(int param_1,char param_2,char param_3)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (param_2 == '\0') {
    if (FLOAT_803e32b4 < *(float *)(iVar1 + 0x50)) {
      FUN_8000bb18(param_1,0xc1);
    }
    if (param_3 == '\0') {
      *(float *)(iVar1 + 0x50) = FLOAT_803e3324;
    }
    else {
      *(float *)(iVar1 + 0x50) = FLOAT_803e3328;
    }
  }
  else {
    if (*(float *)(iVar1 + 0x50) < FLOAT_803e32b4) {
      FUN_8000bb18(param_1,0xc0);
    }
    if (param_3 == '\0') {
      *(float *)(iVar1 + 0x50) = FLOAT_803e3320;
    }
    else {
      *(float *)(iVar1 + 0x50) = FLOAT_803e3288;
    }
  }
  return;
}

