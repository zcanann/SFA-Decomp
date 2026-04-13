// Function: FUN_80010a8c
// Entry: 80010a8c
// Size: 484 bytes

void FUN_80010a8c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 float *param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  code *pcVar2;
  double dVar3;
  
  if ((int)param_9[0x24] < 4) {
    param_1 = FUN_80137c30(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           s_curvesMove__There_must_be_at_lea_802c6848,param_10,param_11,param_12,
                           param_13,param_14,param_15,param_16);
  }
  pcVar2 = (code *)param_9[0x25];
  if (((pcVar2 == (code *)0x80010d04) || (pcVar2 == FUN_80010de0)) &&
     (((uint)param_9[0x24] & 3) != 0)) {
    FUN_80137c30(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 s_curvesMove__There_must_be_a_mult_802c6880,pcVar2,param_11,param_12,param_13,
                 param_14,param_15,param_16);
  }
  param_9[3] = FLOAT_803df2d8;
  param_9[4] = 0.0;
  while ((int)param_9[4] < (int)param_9[0x24] + -3) {
    FUN_8000feac();
    param_9[3] = param_9[3] + param_9[5];
    if (((code *)param_9[0x25] == (code *)0x80010d04) || ((code *)param_9[0x25] == FUN_80010de0)) {
      param_9[4] = (float)((int)param_9[4] + 4);
    }
    else {
      param_9[4] = (float)((int)param_9[4] + 1);
    }
  }
  if (param_9[0x20] == 0.0) {
    param_9[4] = 0.0;
  }
  else {
    param_9[4] = (float)((int)param_9[0x24] + -4);
  }
  FUN_8000feac();
  fVar1 = FLOAT_803df2d8;
  if (param_9[0x20] == 0.0) {
    *param_9 = FLOAT_803df2d8;
    param_9[1] = fVar1;
    param_9[2] = fVar1;
  }
  else {
    *param_9 = FLOAT_803df2f4;
    param_9[1] = param_9[0x19];
    param_9[2] = param_9[3];
  }
  if (param_9[0x21] != 0.0) {
    dVar3 = (double)(*(code *)param_9[0x25])((double)*param_9,param_9[0x21],param_9 + 0x1d);
    param_9[0x1a] = (float)dVar3;
  }
  if (param_9[0x22] != 0.0) {
    dVar3 = (double)(*(code *)param_9[0x25])((double)*param_9,param_9[0x22],param_9 + 0x1e);
    param_9[0x1b] = (float)dVar3;
  }
  if (param_9[0x23] != 0.0) {
    dVar3 = (double)(*(code *)param_9[0x25])((double)*param_9,param_9[0x23],param_9 + 0x1f);
    param_9[0x1c] = (float)dVar3;
  }
  return;
}

