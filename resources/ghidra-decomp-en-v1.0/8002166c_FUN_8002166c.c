// Function: FUN_8002166c
// Entry: 8002166c
// Size: 36 bytes

double FUN_8002166c(float *param_1,float *param_2)

{
  return (double)((*param_1 - *param_2) * (*param_1 - *param_2) +
                 (param_1[2] - param_2[2]) * (param_1[2] - param_2[2]));
}

