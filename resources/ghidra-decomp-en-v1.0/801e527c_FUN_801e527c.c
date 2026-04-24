// Function: FUN_801e527c
// Entry: 801e527c
// Size: 560 bytes

void FUN_801e527c(short *param_1)

{
  int iVar1;
  undefined2 local_38;
  undefined2 local_36;
  undefined2 local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  undefined4 local_20;
  uint uStack28;
  undefined4 local_18;
  uint uStack20;
  longlong local_10;
  
  *(float *)(param_1 + 6) = *(float *)(param_1 + 0x12) * FLOAT_803db414 + *(float *)(param_1 + 6);
  *(float *)(param_1 + 8) = *(float *)(param_1 + 0x14) * FLOAT_803db414 + *(float *)(param_1 + 8);
  *(float *)(param_1 + 10) = *(float *)(param_1 + 0x16) * FLOAT_803db414 + *(float *)(param_1 + 10);
  local_2c = FLOAT_803e592c;
  local_28 = FLOAT_803e592c;
  local_24 = FLOAT_803e592c;
  local_30 = FLOAT_803e5928;
  if ((int)*(uint *)(param_1 + 0x7a) < 0x3d) {
    uStack28 = *(uint *)(param_1 + 0x7a) ^ 0x80000000;
    local_20 = 0x43300000;
    local_30 = (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e5940) / FLOAT_803e5930;
    local_18 = 0x43300000;
    iVar1 = (int)(FLOAT_803e5934 *
                 ((float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e5940) / FLOAT_803e5930)
                 );
    local_10 = (longlong)iVar1;
    *(char *)(param_1 + 0x1b) = (char)iVar1;
    uStack20 = uStack28;
  }
  local_34 = 0;
  local_36 = 0;
  local_38 = 0;
  (**(code **)(*DAT_803dca88 + 8))(param_1,0xa0,&local_38,1,0xffffffff,0);
  local_2c = (*(float *)(param_1 + 6) - *(float *)(param_1 + 0x40)) / FLOAT_803e5938;
  local_28 = (*(float *)(param_1 + 8) - *(float *)(param_1 + 0x42)) / FLOAT_803e5938;
  local_24 = (*(float *)(param_1 + 10) - *(float *)(param_1 + 0x44)) / FLOAT_803e5938;
  (**(code **)(*DAT_803dca88 + 8))(param_1,0xa0,&local_38,1,0xffffffff,0);
  local_2c = local_2c * FLOAT_803e593c;
  local_28 = local_28 * FLOAT_803e593c;
  local_24 = local_24 * FLOAT_803e593c;
  (**(code **)(*DAT_803dca88 + 8))(param_1,0xa0,&local_38,1,0xffffffff,0);
  *param_1 = *param_1 + (ushort)DAT_803db410 * 0x374;
  param_1[1] = param_1[1] + (ushort)DAT_803db410 * 300;
  *(uint *)(param_1 + 0x7a) = *(int *)(param_1 + 0x7a) - (uint)DAT_803db410;
  if (*(int *)(param_1 + 0x7a) < 0) {
    FUN_8002cbc4(param_1);
  }
  return;
}

