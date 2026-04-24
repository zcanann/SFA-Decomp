// Function: FUN_801845fc
// Entry: 801845fc
// Size: 492 bytes

void FUN_801845fc(undefined2 *param_1,int param_2,char param_3,float *param_4)

{
  undefined2 uVar1;
  undefined2 uVar2;
  undefined4 *puVar3;
  double dVar4;
  double dVar5;
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
  
  puVar3 = *(undefined4 **)(param_1 + 0x5c);
  if (param_3 == '\x01') {
    local_38 = *(float *)(param_2 + 4);
    local_34 = *(float *)(param_2 + 8);
    local_30 = *(float *)(param_2 + 0xc);
  }
  else if (param_3 == '\0') {
    local_38 = *param_4;
    local_34 = param_4[1];
    local_30 = param_4[2];
  }
  else if (param_3 == '\x02') {
    *(float *)(param_1 + 0x12) = *param_4;
    *(float *)(param_1 + 0x16) = param_4[2];
    dVar5 = (double)(*(float *)(param_1 + 0x12) * *(float *)(param_1 + 0x12) +
                    *(float *)(param_1 + 0x16) * *(float *)(param_1 + 0x16));
    if (dVar5 != (double)FLOAT_803e39f8) {
      dVar5 = (double)FUN_802931a0();
    }
    dVar4 = (double)FLOAT_803e39fc;
    *(float *)(param_1 + 0x12) = *(float *)(param_1 + 0x12) / (float)(dVar4 * dVar5);
    *(float *)(param_1 + 0x16) = *(float *)(param_1 + 0x16) / (float)(dVar4 * dVar5);
    *puVar3 = *(undefined4 *)(param_1 + 0x12);
    puVar3[1] = *(undefined4 *)(param_1 + 0x16);
    uVar1 = FUN_800217c0(-(double)*param_4,-(double)param_4[2]);
    *param_1 = uVar1;
    return;
  }
  local_20 = FLOAT_803e39f8;
  local_1c = FLOAT_803e39f8;
  local_18 = FLOAT_803e39f8;
  local_24 = FLOAT_803e3a00;
  local_28 = 0;
  local_2a = 0;
  local_2c = *param_1;
  FUN_80021ac8(&local_2c,&local_38);
  if (param_2 == 0) {
    param_1[2] = 0;
    uVar1 = FUN_800217c0((double)(*param_4 + param_4[2]),(double)param_4[1]);
    param_1[1] = uVar1;
    if ((short)param_1[1] < 0) {
      param_1[1] = -param_1[1];
    }
    uVar1 = FUN_800217c0((double)*param_4,(double)param_4[2]);
    *param_1 = uVar1;
  }
  else {
    uVar1 = FUN_800217c0((double)local_38,(double)local_34);
    uVar2 = FUN_800217c0((double)local_30,(double)local_34);
    param_1[1] = uVar2;
    param_1[2] = uVar1;
  }
  return;
}

