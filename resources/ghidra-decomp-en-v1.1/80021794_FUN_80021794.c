// Function: FUN_80021794
// Entry: 80021794
// Size: 52 bytes

double FUN_80021794(float *param_1,float *param_2)

{
  return (double)((param_1[2] - param_2[2]) * (param_1[2] - param_2[2]) +
                 (*param_1 - *param_2) * (*param_1 - *param_2) +
                 (param_1[1] - param_2[1]) * (param_1[1] - param_2[1]));
}

