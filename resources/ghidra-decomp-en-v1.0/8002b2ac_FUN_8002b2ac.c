// Function: FUN_8002b2ac
// Entry: 8002b2ac
// Size: 208 bytes

void FUN_8002b2ac(undefined4 *param_1,short *param_2,undefined4 param_3)

{
  undefined4 local_b8;
  undefined4 local_b4;
  undefined4 local_b0;
  short local_ac;
  short local_aa;
  short local_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  undefined auStack148 [68];
  undefined auStack80 [72];
  
  local_a0 = -*(float *)(param_2 + 6);
  local_9c = -*(float *)(param_2 + 8);
  local_98 = -*(float *)(param_2 + 10);
  local_ac = -*param_2;
  local_aa = -param_2[1];
  local_a8 = -param_2[2];
  local_a4 = FLOAT_803de890;
  FUN_80021ba0(auStack80,&local_ac);
  FUN_80021608(auStack80,auStack148);
  FUN_80247494(auStack148,param_3,&local_b8);
  *param_1 = local_b8;
  param_1[1] = local_b4;
  param_1[2] = local_b0;
  return;
}

