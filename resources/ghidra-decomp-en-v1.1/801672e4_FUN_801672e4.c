// Function: FUN_801672e4
// Entry: 801672e4
// Size: 240 bytes

void FUN_801672e4(float *param_1,float *param_2,float *param_3)

{
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  
  local_38 = *param_2;
  local_34 = param_2[1];
  local_30 = param_2[2];
  FUN_800228f0(&local_38);
  FUN_80022974(param_3,&local_38,&local_20);
  FUN_800228f0(&local_20);
  FUN_80022974(&local_20,&local_38,&local_2c);
  FUN_800228f0(&local_2c);
  *param_1 = -local_20;
  param_1[1] = -local_1c;
  param_1[2] = -local_18;
  param_1[4] = -local_2c;
  param_1[5] = -local_28;
  param_1[6] = -local_24;
  param_1[8] = -local_38;
  param_1[9] = -local_34;
  param_1[10] = -local_30;
  return;
}

