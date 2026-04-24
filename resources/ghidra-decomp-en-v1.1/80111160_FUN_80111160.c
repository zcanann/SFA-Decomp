// Function: FUN_80111160
// Entry: 80111160
// Size: 1532 bytes

void FUN_80111160(ushort *param_1)

{
  int iVar1;
  int iVar2;
  float fVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  undefined local_88 [4];
  undefined local_84 [4];
  undefined local_80 [4];
  undefined local_7c [4];
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined4 local_50;
  uint uStack_4c;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined4 local_30;
  uint uStack_2c;
  undefined8 local_28;
  undefined8 local_20;
  
  iVar6 = *(int *)(param_1 + 0x52);
  *(float *)(param_1 + 0xc) = DAT_803a5020 * DAT_803a5044;
  *(float *)(param_1 + 0xc) = *(float *)(param_1 + 0xc) + DAT_803a502c;
  *(float *)(param_1 + 0xe) = DAT_803a5024 * DAT_803a5048;
  *(float *)(param_1 + 0xe) = *(float *)(param_1 + 0xe) + DAT_803a5030;
  *(float *)(param_1 + 0x10) = *(float *)(iVar6 + 0x20) + DAT_803a5058;
  if (*(char *)(iVar6 + 0xac) != '&') {
    fVar3 = DAT_803a5060 / DAT_803a505c - FLOAT_803e2820;
    if (FLOAT_803e2824 <= fVar3) {
      local_78 = (double)CONCAT44(0x43300000,-(uint)DAT_803a507b ^ 0x80000000);
      *(float *)(param_1 + 0x10) =
           (float)(local_78 - DOUBLE_803e2838) * fVar3 + *(float *)(param_1 + 0x10);
    }
    else {
      local_78 = (double)CONCAT44(0x43300000,-(uint)DAT_803a507a ^ 0x80000000);
      *(float *)(param_1 + 0x10) =
           (float)(local_78 - DOUBLE_803e2838) * fVar3 + *(float *)(param_1 + 0x10);
    }
  }
  local_78 = (double)CONCAT44(0x43300000,(int)DAT_803a5074 ^ 0x80000000);
  iVar1 = (int)((float)(local_78 - DOUBLE_803e2838) * DAT_803a5064);
  local_70 = (double)(longlong)iVar1;
  local_68 = (double)CONCAT44(0x43300000,(int)DAT_803a5076 ^ 0x80000000);
  iVar2 = (int)((float)(local_68 - DOUBLE_803e2838) * DAT_803a5068);
  local_60 = (double)(longlong)iVar2;
  uVar4 = FUN_8022de14(iVar6);
  if (uVar4 == 0) {
    iVar6 = FUN_8022ddd4(iVar6);
    if (iVar6 == 0) {
      local_20 = (double)CONCAT44(0x43300000,(int)DAT_803a5078 ^ 0x80000000);
      iVar6 = (int)((float)(local_20 - DOUBLE_803e2838) * DAT_803a506c);
      local_28 = (double)(longlong)iVar6;
      uStack_2c = iVar6 - (uint)param_1[2];
      if (0x8000 < (int)uStack_2c) {
        uStack_2c = uStack_2c - 0xffff;
      }
      if ((int)uStack_2c < -0x8000) {
        uStack_2c = uStack_2c + 0xffff;
      }
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_38 = (double)CONCAT44(0x43300000,(int)(short)param_1[2] ^ 0x80000000);
      iVar6 = (int)((float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e2838) *
                    FLOAT_803dc074 * FLOAT_803e282c + (float)(local_38 - DOUBLE_803e2838));
      local_40 = (double)(longlong)iVar6;
      param_1[2] = (ushort)iVar6;
      uVar4 = iVar1 - (uint)*param_1;
      if (0x8000 < (int)uVar4) {
        uVar4 = uVar4 - 0xffff;
      }
      if ((int)uVar4 < -0x8000) {
        uVar4 = uVar4 + 0xffff;
      }
      local_48 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      uStack_4c = (int)(short)*param_1 ^ 0x80000000;
      local_50 = 0x43300000;
      iVar6 = (int)((float)(local_48 - DOUBLE_803e2838) * FLOAT_803dc074 * FLOAT_803e282c +
                   (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e2838));
      local_58 = (double)(longlong)iVar6;
      *param_1 = (ushort)iVar6;
      uVar4 = iVar2 - (uint)param_1[1];
      if (0x8000 < (int)uVar4) {
        uVar4 = uVar4 - 0xffff;
      }
      if ((int)uVar4 < -0x8000) {
        uVar4 = uVar4 + 0xffff;
      }
      local_60 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_68 = (double)CONCAT44(0x43300000,(int)(short)param_1[1] ^ 0x80000000);
      iVar6 = (int)((float)(local_60 - DOUBLE_803e2838) * FLOAT_803dc074 * FLOAT_803e282c +
                   (float)(local_68 - DOUBLE_803e2838));
      local_70 = (double)(longlong)iVar6;
      param_1[1] = (ushort)iVar6;
    }
    else {
      DAT_803a5070 = DAT_803a5070 * FLOAT_803e2830;
      local_20 = (double)CONCAT44(0x43300000,(int)(short)param_1[2] ^ 0x80000000);
      iVar6 = (int)(DAT_803a5070 * FLOAT_803dc074 + (float)(local_20 - DOUBLE_803e2838));
      local_28 = (double)(longlong)iVar6;
      param_1[2] = (ushort)iVar6;
    }
  }
  else {
    DAT_803a5070 = FLOAT_803e2828;
    (**(code **)(*DAT_803dd6d0 + 0x38))
              ((double)FLOAT_803e2824,param_1,local_7c,local_80,local_84,local_88,0);
    local_60 = (double)CONCAT44(0x43300000,(int)(short)param_1[2] ^ 0x80000000);
    iVar6 = (int)(DAT_803a5070 * FLOAT_803dc074 + (float)(local_60 - DOUBLE_803e2838));
    local_68 = (double)(longlong)iVar6;
    param_1[2] = (ushort)iVar6;
    uVar4 = FUN_80021884();
    uVar5 = FUN_80021884();
    uVar4 = (0x8000 - (uVar4 & 0xffff)) - (uint)*param_1;
    if (0x8000 < (int)uVar4) {
      uVar4 = uVar4 - 0xffff;
    }
    if ((int)uVar4 < -0x8000) {
      uVar4 = uVar4 + 0xffff;
    }
    local_70 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    uVar4 = (uint)((float)(local_70 - DOUBLE_803e2838) * FLOAT_803dc074);
    local_78 = (double)(longlong)(int)uVar4;
    local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    uStack_4c = (int)(short)*param_1 ^ 0x80000000;
    local_50 = 0x43300000;
    iVar6 = (int)((float)(local_58 - DOUBLE_803e2838) * FLOAT_803e282c +
                 (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e2838));
    local_48 = (double)(longlong)iVar6;
    *param_1 = (ushort)iVar6;
    uVar4 = (uVar5 & 0xffff) - (uint)param_1[1];
    if (0x8000 < (int)uVar4) {
      uVar4 = uVar4 - 0xffff;
    }
    if ((int)uVar4 < -0x8000) {
      uVar4 = uVar4 + 0xffff;
    }
    local_40 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    uStack_2c = (uint)((float)(local_40 - DOUBLE_803e2838) * FLOAT_803dc074);
    local_38 = (double)(longlong)(int)uStack_2c;
    uStack_2c = uStack_2c ^ 0x80000000;
    local_30 = 0x43300000;
    local_28 = (double)CONCAT44(0x43300000,(int)(short)param_1[1] ^ 0x80000000);
    iVar6 = (int)((float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e2838) * FLOAT_803e282c
                 + (float)(local_28 - DOUBLE_803e2838));
    local_20 = (double)(longlong)iVar6;
    param_1[1] = (ushort)iVar6;
  }
  FUN_8000e054((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
               (double)*(float *)(param_1 + 0x10),(float *)(param_1 + 6),(float *)(param_1 + 8),
               (float *)(param_1 + 10),*(int *)(param_1 + 0x18));
  return;
}

