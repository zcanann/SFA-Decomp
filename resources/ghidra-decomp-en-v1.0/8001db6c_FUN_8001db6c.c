// Function: FUN_8001db6c
// Entry: 8001db6c
// Size: 204 bytes

void FUN_8001db6c(double param_1,int param_2,char param_3)

{
  float fVar1;
  
  fVar1 = FLOAT_803de75c;
  if ((double)FLOAT_803de75c == param_1) {
    if (param_3 == '\0') {
      *(undefined4 *)(param_2 + 0x58) = 0;
      *(float *)(param_2 + 0x138) = fVar1;
    }
    else {
      *(undefined4 *)(param_2 + 0x58) = 2;
      *(float *)(param_2 + 0x138) = FLOAT_803de760;
    }
    *(char *)(param_2 + 0x4c) = param_3;
    return;
  }
  if (param_3 != '\0') {
    if ((*(int *)(param_2 + 0x58) == 0) || (*(int *)(param_2 + 0x58) == 3)) {
      *(undefined4 *)(param_2 + 0x58) = 1;
      *(float *)(param_2 + 0x13c) = FLOAT_803de760 / (float)((double)FLOAT_803de794 * param_1);
      *(float *)(param_2 + 0x138) = FLOAT_803de75c;
    }
    *(undefined *)(param_2 + 0x4c) = 1;
    return;
  }
  if ((*(int *)(param_2 + 0x58) != 2) && (*(int *)(param_2 + 0x58) != 1)) {
    return;
  }
  *(undefined4 *)(param_2 + 0x58) = 3;
  *(float *)(param_2 + 0x13c) = FLOAT_803de798 / (float)((double)FLOAT_803de794 * param_1);
  *(float *)(param_2 + 0x138) = FLOAT_803de760;
  return;
}

