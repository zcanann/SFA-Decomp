// Function: FUN_800216d0
// Entry: 800216d0
// Size: 52 bytes

double FUN_800216d0(float *param_1,float *param_2)

{
  return (double)((param_1[2] - param_2[2]) * (param_1[2] - param_2[2]) +
                 (*param_1 - *param_2) * (*param_1 - *param_2) +
                 (param_1[1] - param_2[1]) * (param_1[1] - param_2[1]));
}

