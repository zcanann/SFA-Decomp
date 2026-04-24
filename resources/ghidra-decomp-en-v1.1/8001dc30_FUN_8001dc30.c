// Function: FUN_8001dc30
// Entry: 8001dc30
// Size: 204 bytes

void FUN_8001dc30(double param_1,int param_2,char param_3)

{
  float fVar1;
  
  fVar1 = FLOAT_803df3dc;
  if ((double)FLOAT_803df3dc == param_1) {
    if (param_3 == '\0') {
      *(undefined4 *)(param_2 + 0x58) = 0;
      *(float *)(param_2 + 0x138) = fVar1;
    }
    else {
      *(undefined4 *)(param_2 + 0x58) = 2;
      *(float *)(param_2 + 0x138) = FLOAT_803df3e0;
    }
    *(char *)(param_2 + 0x4c) = param_3;
    return;
  }
  if (param_3 != '\0') {
    if ((*(int *)(param_2 + 0x58) == 0) || (*(int *)(param_2 + 0x58) == 3)) {
      *(undefined4 *)(param_2 + 0x58) = 1;
      *(float *)(param_2 + 0x13c) = FLOAT_803df3e0 / (float)((double)FLOAT_803df414 * param_1);
      *(float *)(param_2 + 0x138) = FLOAT_803df3dc;
    }
    *(undefined *)(param_2 + 0x4c) = 1;
    return;
  }
  if ((*(int *)(param_2 + 0x58) != 2) && (*(int *)(param_2 + 0x58) != 1)) {
    return;
  }
  *(undefined4 *)(param_2 + 0x58) = 3;
  *(float *)(param_2 + 0x13c) = FLOAT_803df418 / (float)((double)FLOAT_803df414 * param_1);
  *(float *)(param_2 + 0x138) = FLOAT_803df3e0;
  return;
}

