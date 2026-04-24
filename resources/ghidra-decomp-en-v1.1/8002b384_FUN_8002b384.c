// Function: FUN_8002b384
// Entry: 8002b384
// Size: 208 bytes

void FUN_8002b384(float *param_1,short *param_2,float *param_3)

{
  float local_b8;
  float local_b4;
  float local_b0;
  short local_ac;
  short local_aa;
  short local_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float afStack_94 [17];
  float afStack_50 [18];
  
  local_a0 = -*(float *)(param_2 + 6);
  local_9c = -*(float *)(param_2 + 8);
  local_98 = -*(float *)(param_2 + 10);
  local_ac = -*param_2;
  local_aa = -param_2[1];
  local_a8 = -param_2[2];
  local_a4 = FLOAT_803df510;
  FUN_80021c64(afStack_50,(int)&local_ac);
  FUN_800216cc(afStack_50,afStack_94);
  FUN_80247bf8(afStack_94,param_3,&local_b8);
  *param_1 = local_b8;
  param_1[1] = local_b4;
  param_1[2] = local_b0;
  return;
}

