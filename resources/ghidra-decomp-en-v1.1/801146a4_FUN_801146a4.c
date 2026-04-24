// Function: FUN_801146a4
// Entry: 801146a4
// Size: 436 bytes

void FUN_801146a4(undefined4 param_1,undefined4 param_2,float *param_3,float *param_4)

{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  double extraout_f1;
  double dVar5;
  undefined8 uVar6;
  short local_38;
  short local_36;
  undefined2 local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  undefined4 local_20;
  uint uStack_1c;
  
  uVar6 = FUN_80286840();
  fVar2 = FLOAT_803e2920;
  iVar3 = (int)((ulonglong)uVar6 >> 0x20);
  iVar4 = (int)uVar6;
  if (iVar4 == 0) {
    uStack_1c = (uint)DAT_803dc070;
    local_20 = 0x43300000;
    *param_4 = *param_4 +
               (float)(extraout_f1 *
                      (double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e2928)) /
               param_3[0xd];
    if (FLOAT_803e2924 <= *param_4) {
      *param_4 = FLOAT_803e2924;
    }
  }
  else {
    param_3[6] = FLOAT_803e2920;
    fVar1 = FLOAT_803e2910;
    param_3[7] = FLOAT_803e2910;
    param_3[8] = fVar1;
    param_3[9] = fVar2;
    param_3[10] = fVar1;
    param_3[0xb] = fVar1;
    FUN_80021970(iVar3,param_3 + 6);
    local_34 = 0;
    local_36 = (short)*(char *)(iVar4 + 0x2d);
    local_38 = (short)*(char *)(iVar4 + 0x2c);
    FUN_80021970(&local_38,param_3 + 9);
    *param_4 = FLOAT_803e2910;
    dVar5 = (double)FUN_801144c0(param_3,param_3 + 6,param_3 + 3,param_3 + 9,10);
    param_3[0xd] = (float)dVar5;
  }
  local_30 = *param_3;
  local_2c = param_3[3];
  local_28 = param_3[6];
  local_24 = param_3[9];
  dVar5 = FUN_80010de0((double)*param_4,&local_30,(float *)0x0);
  *(float *)(iVar3 + 0xc) = (float)dVar5;
  local_30 = param_3[1];
  local_2c = param_3[4];
  local_28 = param_3[7];
  local_24 = param_3[10];
  dVar5 = FUN_80010de0((double)*param_4,&local_30,(float *)0x0);
  *(float *)(iVar3 + 0x10) = (float)dVar5;
  local_30 = param_3[2];
  local_2c = param_3[5];
  local_28 = param_3[8];
  local_24 = param_3[0xb];
  dVar5 = FUN_80010de0((double)*param_4,&local_30,(float *)0x0);
  *(float *)(iVar3 + 0x14) = (float)dVar5;
  FUN_8028688c();
  return;
}

