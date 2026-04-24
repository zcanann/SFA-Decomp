// Function: FUN_80061954
// Entry: 80061954
// Size: 1156 bytes

void FUN_80061954(undefined4 param_1,float *param_2,float *param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float local_18;
  float local_14;
  float local_10;
  
  fVar1 = param_2[6] - param_2[9];
  fVar3 = param_2[7] - param_2[10];
  fVar5 = param_2[8] - param_2[0xb];
  fVar2 = param_2[0x15] - param_2[9];
  fVar4 = param_2[0x16] - param_2[10];
  fVar6 = param_2[0x17] - param_2[0xb];
  local_18 = fVar4 * fVar5 - fVar6 * fVar3;
  local_14 = -(fVar2 * fVar5 - fVar6 * fVar1);
  local_10 = fVar2 * fVar3 - fVar4 * fVar1;
  FUN_80247794(&local_18,&local_18);
  *param_3 = -local_18;
  param_3[1] = -local_14;
  param_3[2] = -local_10;
  param_3[3] = -(param_3[2] * param_2[0xb] + *param_3 * param_2[9] + param_3[1] * param_2[10]);
  fVar1 = param_2[0x12] - param_2[0xf];
  fVar3 = param_2[0x13] - param_2[0x10];
  fVar5 = param_2[0x14] - param_2[0x11];
  fVar2 = param_2[3] - param_2[0xf];
  fVar4 = param_2[4] - param_2[0x10];
  fVar6 = param_2[5] - param_2[0x11];
  local_18 = fVar4 * fVar5 - fVar6 * fVar3;
  local_14 = -(fVar2 * fVar5 - fVar6 * fVar1);
  local_10 = fVar2 * fVar3 - fVar4 * fVar1;
  FUN_80247794(&local_18,&local_18);
  param_3[5] = -local_18;
  param_3[6] = -local_14;
  param_3[7] = -local_10;
  param_3[8] = -(param_3[7] * param_2[0x11] + param_3[5] * param_2[0xf] + param_3[6] * param_2[0x10]
                );
  fVar1 = param_2[0xf] - param_2[0xc];
  fVar3 = param_2[0x10] - param_2[0xd];
  fVar5 = param_2[0x11] - param_2[0xe];
  fVar2 = *param_2 - param_2[0xc];
  fVar4 = param_2[1] - param_2[0xd];
  fVar6 = param_2[2] - param_2[0xe];
  local_18 = fVar4 * fVar5 - fVar6 * fVar3;
  local_14 = -(fVar2 * fVar5 - fVar6 * fVar1);
  local_10 = fVar2 * fVar3 - fVar4 * fVar1;
  FUN_80247794(&local_18,&local_18);
  param_3[10] = -local_18;
  param_3[0xb] = -local_14;
  param_3[0xc] = -local_10;
  param_3[0xd] = -(param_3[0xc] * param_2[0xe] +
                  param_3[10] * param_2[0xc] + param_3[0xb] * param_2[0xd]);
  fVar1 = param_2[9] - *param_2;
  fVar3 = param_2[10] - param_2[1];
  fVar5 = param_2[0xb] - param_2[2];
  fVar2 = param_2[0xc] - *param_2;
  fVar4 = param_2[0xd] - param_2[1];
  fVar6 = param_2[0xe] - param_2[2];
  local_18 = fVar4 * fVar5 - fVar6 * fVar3;
  local_14 = -(fVar2 * fVar5 - fVar6 * fVar1);
  local_10 = fVar2 * fVar3 - fVar4 * fVar1;
  FUN_80247794(&local_18,&local_18);
  param_3[0xf] = -local_18;
  param_3[0x10] = -local_14;
  param_3[0x11] = -local_10;
  param_3[0x12] =
       -(param_3[0x11] * param_2[2] + param_3[0xf] * *param_2 + param_3[0x10] * param_2[1]);
  fVar1 = param_2[0x12] - param_2[0x15];
  fVar3 = param_2[0x13] - param_2[0x16];
  fVar5 = param_2[0x14] - param_2[0x17];
  fVar2 = param_2[0xc] - param_2[0x15];
  fVar4 = param_2[0xd] - param_2[0x16];
  fVar6 = param_2[0xe] - param_2[0x17];
  local_18 = fVar4 * fVar5 - fVar6 * fVar3;
  local_14 = -(fVar2 * fVar5 - fVar6 * fVar1);
  local_10 = fVar2 * fVar3 - fVar4 * fVar1;
  FUN_80247794(&local_18,&local_18);
  param_3[0x14] = -local_18;
  param_3[0x15] = -local_14;
  param_3[0x16] = -local_10;
  param_3[0x17] =
       -(param_3[0x16] * param_2[0x17] +
        param_3[0x14] * param_2[0x15] + param_3[0x15] * param_2[0x16]);
  fVar1 = param_2[3] - *param_2;
  fVar3 = param_2[4] - param_2[1];
  fVar5 = param_2[5] - param_2[2];
  fVar2 = param_2[9] - *param_2;
  fVar4 = param_2[10] - param_2[1];
  fVar6 = param_2[0xb] - param_2[2];
  local_18 = fVar4 * fVar5 - fVar6 * fVar3;
  local_14 = -(fVar2 * fVar5 - fVar6 * fVar1);
  local_10 = fVar2 * fVar3 - fVar4 * fVar1;
  FUN_80247794(&local_18,&local_18);
  param_3[0x19] = -local_18;
  param_3[0x1a] = -local_14;
  param_3[0x1b] = -local_10;
  param_3[0x1c] =
       -(param_3[0x1b] * param_2[2] + param_3[0x19] * *param_2 + param_3[0x1a] * param_2[1]);
  return;
}

