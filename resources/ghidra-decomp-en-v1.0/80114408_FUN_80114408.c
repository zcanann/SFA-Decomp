// Function: FUN_80114408
// Entry: 80114408
// Size: 436 bytes

void FUN_80114408(undefined4 param_1,undefined4 param_2,undefined4 *param_3,float *param_4)

{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  double extraout_f1;
  double dVar6;
  undefined8 uVar7;
  short local_38;
  short local_36;
  undefined2 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  uint uStack28;
  
  uVar7 = FUN_802860dc();
  fVar2 = FLOAT_803e1ca0;
  iVar3 = (int)((ulonglong)uVar7 >> 0x20);
  iVar4 = (int)uVar7;
  uVar5 = 0;
  if (iVar4 == 0) {
    uStack28 = (uint)DAT_803db410;
    local_20 = 0x43300000;
    *param_4 = *param_4 +
               (float)(extraout_f1 *
                      (double)(float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e1ca8)) /
               (float)param_3[0xd];
    if (FLOAT_803e1ca4 <= *param_4) {
      uVar5 = 1;
      *param_4 = FLOAT_803e1ca4;
    }
  }
  else {
    param_3[6] = FLOAT_803e1ca0;
    fVar1 = FLOAT_803e1c90;
    param_3[7] = FLOAT_803e1c90;
    param_3[8] = fVar1;
    param_3[9] = fVar2;
    param_3[10] = fVar1;
    param_3[0xb] = fVar1;
    FUN_800218ac(iVar3,param_3 + 6);
    local_34 = 0;
    local_36 = (short)*(char *)(iVar4 + 0x2d);
    local_38 = (short)*(char *)(iVar4 + 0x2c);
    FUN_800218ac(&local_38,param_3 + 9);
    *param_4 = FLOAT_803e1c90;
    dVar6 = (double)FUN_80114224(param_3,param_3 + 6,param_3 + 3,param_3 + 9,10);
    param_3[0xd] = (float)dVar6;
  }
  local_30 = *param_3;
  local_2c = param_3[3];
  local_28 = param_3[6];
  local_24 = param_3[9];
  dVar6 = (double)FUN_80010dc0((double)*param_4,&local_30,0);
  *(float *)(iVar3 + 0xc) = (float)dVar6;
  local_30 = param_3[1];
  local_2c = param_3[4];
  local_28 = param_3[7];
  local_24 = param_3[10];
  dVar6 = (double)FUN_80010dc0((double)*param_4,&local_30,0);
  *(float *)(iVar3 + 0x10) = (float)dVar6;
  local_30 = param_3[2];
  local_2c = param_3[5];
  local_28 = param_3[8];
  local_24 = param_3[0xb];
  dVar6 = (double)FUN_80010dc0((double)*param_4,&local_30,0);
  *(float *)(iVar3 + 0x14) = (float)dVar6;
  FUN_80286128(uVar5);
  return;
}

