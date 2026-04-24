// Function: FUN_800411fc
// Entry: 800411fc
// Size: 436 bytes

void FUN_800411fc(float *param_1,float *param_2,short *param_3,int param_4,ushort *param_5,
                 int param_6)

{
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  ushort local_80;
  ushort local_7e;
  ushort local_7c;
  float local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined4 local_6c;
  float afStack_68 [16];
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  
  uStack_24 = (int)*param_3 ^ 0x80000000;
  local_28 = 0x43300000;
  local_8c = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803df6c0);
  uStack_1c = (int)param_3[1] ^ 0x80000000;
  local_20 = 0x43300000;
  local_88 = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803df6c0);
  uStack_14 = (int)param_3[2] ^ 0x80000000;
  local_18 = 0x43300000;
  local_84 = (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803df6c0);
  if (param_6 != 0) {
    local_8c = local_8c * FLOAT_803df6d8;
    local_88 = local_88 * FLOAT_803df6d8;
    local_84 = local_84 * FLOAT_803df6d8;
  }
  if (param_1 == (float *)0x0) {
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
    local_78 = FLOAT_803df69c;
    FUN_80021fac(afStack_68,&local_80);
    FUN_80022790((double)local_8c,(double)local_88,(double)local_84,afStack_68,param_2,param_2 + 1,
                 param_2 + 2);
  }
  else {
    if (param_4 == 0) {
      FUN_80247bf8(param_1,&local_8c,&local_98);
      *param_2 = local_98;
      param_2[1] = local_94;
      param_2[2] = local_90;
    }
    else {
      *param_2 = param_1[3] + local_8c;
      param_2[1] = param_1[7] + local_88;
      param_2[2] = param_1[0xb] + local_84;
    }
    *param_2 = *param_2 + FLOAT_803dda58;
    param_2[2] = param_2[2] + FLOAT_803dda5c;
  }
  return;
}

