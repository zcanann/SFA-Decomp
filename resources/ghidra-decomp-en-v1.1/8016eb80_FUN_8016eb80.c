// Function: FUN_8016eb80
// Entry: 8016eb80
// Size: 180 bytes

void FUN_8016eb80(uint param_1,char param_2,char param_3)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (param_2 == '\0') {
    if (FLOAT_803e3f4c < *(float *)(iVar1 + 0x50)) {
      FUN_8000bb38(param_1,0xc1);
    }
    if (param_3 == '\0') {
      *(float *)(iVar1 + 0x50) = FLOAT_803e3fbc;
    }
    else {
      *(float *)(iVar1 + 0x50) = FLOAT_803e3fc0;
    }
  }
  else {
    if (*(float *)(iVar1 + 0x50) < FLOAT_803e3f4c) {
      FUN_8000bb38(param_1,0xc0);
    }
    if (param_3 == '\0') {
      *(float *)(iVar1 + 0x50) = FLOAT_803e3fb8;
    }
    else {
      *(float *)(iVar1 + 0x50) = FLOAT_803e3f20;
    }
  }
  return;
}

