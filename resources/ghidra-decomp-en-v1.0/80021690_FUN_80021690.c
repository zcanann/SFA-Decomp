// Function: FUN_80021690
// Entry: 80021690
// Size: 64 bytes

void FUN_80021690(float *param_1,float *param_2)

{
  FUN_802931a0((double)((*param_1 - *param_2) * (*param_1 - *param_2) +
                       (param_1[2] - param_2[2]) * (param_1[2] - param_2[2])));
  return;
}

