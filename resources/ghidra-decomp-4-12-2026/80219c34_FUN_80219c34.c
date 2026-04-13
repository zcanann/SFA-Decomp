// Function: FUN_80219c34
// Entry: 80219c34
// Size: 772 bytes

void FUN_80219c34(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  short sVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  double dVar7;
  float local_28 [2];
  undefined4 local_20;
  uint uStack_1c;
  
  iVar6 = *(int *)(param_9 + 0x5c);
  iVar5 = *(int *)(param_9 + 0x26);
  local_28[0] = FLOAT_803e7630;
  if ((*(char *)(iVar6 + 0x6e6) == '\0') && (iVar3 = (**(code **)(iVar6 + 0x6d4))(), iVar3 != 0)) {
    FUN_800201ac((int)*(short *)(iVar5 + 0x1e),1);
    *(undefined *)(iVar6 + 0x6e6) = 1;
  }
  sVar2 = (short)((int)*(char *)(iVar5 + 0x18) << 8) - *param_9;
  if (0x8000 < sVar2) {
    sVar2 = sVar2 + 1;
  }
  if (sVar2 < -0x8000) {
    sVar2 = sVar2 + -1;
  }
  if (sVar2 != 0) {
    FUN_80137cd0();
    iVar3 = (int)*(short *)(*(int *)(iVar6 + 0x6dc) + 4);
    if (param_9[0x50] != iVar3) {
      FUN_8003042c((double)FLOAT_803e7624,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,iVar3,0,param_12,param_13,param_14,param_15,param_16);
    }
    uVar4 = (uint)sVar2;
    *param_9 = *param_9 + (short)((int)(uVar4 + 1) >> 4);
    dVar7 = (double)FLOAT_803e7634;
    uStack_1c = ((int)uVar4 >> 10) + (uint)((int)uVar4 < 0 && (uVar4 & 0x3ff) != 0) ^ 0x80000000;
    local_20 = 0x43300000;
    *(float *)(iVar6 + 0x6e0) =
         (float)(dVar7 * (double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e7618));
    if ((int)uVar4 < 0) {
      uVar4 = -uVar4;
    }
    if ((int)uVar4 < 0x400) {
      *param_9 = (short)((int)*(char *)(iVar5 + 0x18) << 8);
      uVar4 = FUN_80022264(0,1);
      FUN_8003042c((double)FLOAT_803e7624,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,(int)*(short *)(*(int *)(iVar6 + 0x6dc) + uVar4 * 2),0,param_12,param_13,
                   param_14,param_15,param_16);
      *(float *)(iVar6 + 0x6e0) = FLOAT_803e7634;
    }
  }
  sVar2 = *(short *)(iVar6 + 0x6e4) - (ushort)DAT_803dc070;
  *(short *)(iVar6 + 0x6e4) = sVar2;
  if (sVar2 < 0) {
    uVar4 = FUN_80022264(0x32,500);
    *(short *)(iVar6 + 0x6e4) = (short)uVar4;
    uVar4 = FUN_80022264(0,3);
    param_12 = 0;
    FUN_800393e8(param_9,iVar6 + 0x684,(ushort *)(*(int *)(iVar6 + 0x6d0) + uVar4 * 6),0);
  }
  dVar7 = (double)FLOAT_803dc074;
  iVar5 = FUN_8002fb40((double)*(float *)(iVar6 + 0x6e0),dVar7);
  if (iVar5 != 0) {
    uVar4 = FUN_80022264(0,7);
    if (uVar4 == 0) {
      uVar4 = FUN_80022264(0,1);
      if (uVar4 == 0) {
        sVar2 = 4;
      }
      else {
        sVar2 = 1;
      }
    }
    else {
      sVar2 = 0;
    }
    FUN_8003042c((double)FLOAT_803e7624,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,(int)*(short *)(*(int *)(iVar6 + 0x6dc) + sVar2 * 2),0,param_12,param_13,
                 param_14,param_15,param_16);
    fVar1 = FLOAT_803e7638;
    if (sVar2 == 0) {
      fVar1 = FLOAT_803e7634;
    }
    *(float *)(iVar6 + 0x6e0) = fVar1;
  }
  FUN_80219790(param_9,iVar6 + 0x6b4,*(ushort **)(iVar6 + 0x6d8));
  FUN_8003b408((int)param_9,iVar6 + 0x654);
  FUN_80039030((int)param_9,(char *)(iVar6 + 0x684));
  iVar5 = FUN_80036f50(1,param_9,local_28);
  if (iVar5 != 0) {
    (**(code **)(**(int **)(iVar5 + 0x68) + 0x28))(iVar5,param_9,1,2);
  }
  return;
}

