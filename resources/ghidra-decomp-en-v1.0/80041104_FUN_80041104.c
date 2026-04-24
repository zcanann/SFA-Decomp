// Function: FUN_80041104
// Entry: 80041104
// Size: 436 bytes

void FUN_80041104(int param_1,float *param_2,short *param_3,int param_4,undefined2 *param_5,
                 int param_6)

{
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  undefined2 local_80;
  undefined2 local_7e;
  undefined2 local_7c;
  float local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined4 local_6c;
  undefined auStack104 [64];
  undefined4 local_28;
  uint uStack36;
  undefined4 local_20;
  uint uStack28;
  undefined4 local_18;
  uint uStack20;
  
  uStack36 = (int)*param_3 ^ 0x80000000;
  local_28 = 0x43300000;
  local_8c = (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dea40);
  uStack28 = (int)param_3[1] ^ 0x80000000;
  local_20 = 0x43300000;
  local_88 = (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dea40);
  uStack20 = (int)param_3[2] ^ 0x80000000;
  local_18 = 0x43300000;
  local_84 = (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803dea40);
  if (param_6 != 0) {
    local_8c = local_8c * FLOAT_803dea58;
    local_88 = local_88 * FLOAT_803dea58;
    local_84 = local_84 * FLOAT_803dea58;
  }
  if (param_1 == 0) {
    local_74 = *(undefined4 *)(param_5 + 0xc);
    local_70 = *(undefined4 *)(param_5 + 0xe);
    local_6c = *(undefined4 *)(param_5 + 0x10);
    if (param_4 == 0) {
      local_80 = *param_5;
      local_7e = param_5[1];
      local_7c = param_5[2];
    }
    else {
      local_80 = 0;
      local_7e = 0;
      local_7c = 0;
    }
    local_78 = FLOAT_803dea1c;
    FUN_80021ee8(auStack104,&local_80);
    FUN_800226cc((double)local_8c,(double)local_88,(double)local_84,auStack104,param_2,param_2 + 1,
                 param_2 + 2);
  }
  else {
    if (param_4 == 0) {
      FUN_80247494(param_1,&local_8c,&local_98);
      *param_2 = local_98;
      param_2[1] = local_94;
      param_2[2] = local_90;
    }
    else {
      *param_2 = *(float *)(param_1 + 0xc) + local_8c;
      param_2[1] = *(float *)(param_1 + 0x1c) + local_88;
      param_2[2] = *(float *)(param_1 + 0x2c) + local_84;
    }
    *param_2 = *param_2 + FLOAT_803dcdd8;
    param_2[2] = param_2[2] + FLOAT_803dcddc;
  }
  return;
}

