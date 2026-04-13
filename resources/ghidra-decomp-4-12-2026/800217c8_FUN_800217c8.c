// Function: FUN_800217c8
// Entry: 800217c8
// Size: 80 bytes

void FUN_800217c8(float *param_1,float *param_2)

{
  FUN_80293900((double)((param_1[2] - param_2[2]) * (param_1[2] - param_2[2]) +
                       (*param_1 - *param_2) * (*param_1 - *param_2) +
                       (param_1[1] - param_2[1]) * (param_1[1] - param_2[1])));
  return;
}

