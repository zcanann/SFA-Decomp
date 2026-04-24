// Function: FUN_801f83b4
// Entry: 801f83b4
// Size: 308 bytes

void FUN_801f83b4(short *param_1)

{
  short *psVar1;
  float local_38;
  float local_34;
  float local_30;
  ushort local_2c;
  short local_2a;
  undefined2 local_28;
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  
  psVar1 = *(short **)(param_1 + 0x5c);
  local_38 = DAT_802c2c80;
  local_34 = DAT_802c2c84;
  local_30 = *(float *)(psVar1 + 6);
  psVar1[2] = psVar1[2] + *psVar1;
  local_20 = FLOAT_803e6c34;
  local_1c = FLOAT_803e6c34;
  local_18 = FLOAT_803e6c34;
  local_24 = FLOAT_803e6c30;
  local_28 = 0;
  local_2a = 0;
  local_2c = psVar1[2];
  FUN_80021b8c(&local_2c,&local_38);
  local_20 = FLOAT_803e6c34;
  local_1c = FLOAT_803e6c34;
  local_18 = FLOAT_803e6c34;
  local_24 = FLOAT_803e6c30;
  local_28 = 0;
  local_2a = psVar1[4];
  local_2c = 0;
  FUN_80021b8c(&local_2c,&local_38);
  *(float *)(param_1 + 6) = local_38 + *(float *)(psVar1 + 8);
  *(float *)(param_1 + 8) = local_34 + *(float *)(psVar1 + 10);
  *(float *)(param_1 + 10) = local_30 + *(float *)(psVar1 + 0xc);
  *param_1 = *param_1 + psVar1[1] * (short)(int)FLOAT_803dc074;
  return;
}

