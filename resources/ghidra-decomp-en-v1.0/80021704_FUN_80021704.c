// Function: FUN_80021704
// Entry: 80021704
// Size: 80 bytes

void FUN_80021704(float *param_1,float *param_2)

{
  FUN_802931a0((double)((param_1[2] - param_2[2]) * (param_1[2] - param_2[2]) +
                       (*param_1 - *param_2) * (*param_1 - *param_2) +
                       (param_1[1] - param_2[1]) * (param_1[1] - param_2[1])));
  return;
}

