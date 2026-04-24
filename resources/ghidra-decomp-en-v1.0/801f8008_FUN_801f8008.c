// Function: FUN_801f8008
// Entry: 801f8008
// Size: 176 bytes

void FUN_801f8008(undefined2 *param_1,int param_2)

{
  undefined2 uVar1;
  undefined2 uVar2;
  float local_38;
  float local_34;
  float local_30;
  undefined2 local_2c;
  undefined2 local_2a;
  undefined2 local_28;
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  
  local_38 = *(float *)(param_2 + 4);
  local_34 = *(float *)(param_2 + 8);
  local_30 = *(float *)(param_2 + 0xc);
  local_20 = FLOAT_803e5fb0;
  local_1c = FLOAT_803e5fb0;
  local_18 = FLOAT_803e5fb0;
  local_24 = FLOAT_803e5fb4;
  local_28 = 0;
  local_2a = 0;
  local_2c = *param_1;
  FUN_80021ac8(&local_2c,&local_38);
  uVar1 = FUN_800217c0((double)local_38,(double)local_34);
  uVar2 = FUN_800217c0((double)local_30,(double)local_34);
  param_1[1] = uVar2;
  param_1[2] = uVar1;
  return;
}

