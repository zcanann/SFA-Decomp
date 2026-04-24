// Function: FUN_80010a6c
// Entry: 80010a6c
// Size: 484 bytes

void FUN_80010a6c(float *param_1)

{
  float fVar1;
  double dVar2;
  
  if ((int)param_1[0x24] < 4) {
    FUN_801378a8(s_curvesMove__There_must_be_at_lea_802c60c8);
  }
  if ((((code *)param_1[0x25] == (code *)0x80010ce4) || ((code *)param_1[0x25] == FUN_80010dc0)) &&
     (((uint)param_1[0x24] & 3) != 0)) {
    FUN_801378a8(s_curvesMove__There_must_be_a_mult_802c6100);
  }
  param_1[3] = FLOAT_803de658;
  param_1[4] = 0.0;
  while ((int)param_1[4] < (int)param_1[0x24] + -3) {
    FUN_8000fe8c(param_1,5);
    param_1[3] = param_1[3] + param_1[5];
    if (((code *)param_1[0x25] == (code *)0x80010ce4) || ((code *)param_1[0x25] == FUN_80010dc0)) {
      param_1[4] = (float)((int)param_1[4] + 4);
    }
    else {
      param_1[4] = (float)((int)param_1[4] + 1);
    }
  }
  if (param_1[0x20] == 0.0) {
    param_1[4] = 0.0;
  }
  else {
    param_1[4] = (float)((int)param_1[0x24] + -4);
  }
  FUN_8000fe8c(param_1,0x14);
  fVar1 = FLOAT_803de658;
  if (param_1[0x20] == 0.0) {
    *param_1 = FLOAT_803de658;
    param_1[1] = fVar1;
    param_1[2] = fVar1;
  }
  else {
    *param_1 = FLOAT_803de674;
    param_1[1] = param_1[0x19];
    param_1[2] = param_1[3];
  }
  if (param_1[0x21] != 0.0) {
    dVar2 = (double)(*(code *)param_1[0x25])((double)*param_1,param_1[0x21],param_1 + 0x1d);
    param_1[0x1a] = (float)dVar2;
  }
  if (param_1[0x22] != 0.0) {
    dVar2 = (double)(*(code *)param_1[0x25])((double)*param_1,param_1[0x22],param_1 + 0x1e);
    param_1[0x1b] = (float)dVar2;
  }
  if (param_1[0x23] != 0.0) {
    dVar2 = (double)(*(code *)param_1[0x25])((double)*param_1,param_1[0x23],param_1 + 0x1f);
    param_1[0x1c] = (float)dVar2;
  }
  return;
}

