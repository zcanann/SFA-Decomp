// Function: FUN_802195bc
// Entry: 802195bc
// Size: 772 bytes

void FUN_802195bc(short *param_1)

{
  float fVar1;
  short sVar2;
  int iVar3;
  undefined2 uVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  float local_28 [2];
  undefined4 local_20;
  uint uStack28;
  
  iVar7 = *(int *)(param_1 + 0x5c);
  iVar6 = *(int *)(param_1 + 0x26);
  local_28[0] = FLOAT_803e6998;
  if ((*(char *)(iVar7 + 0x6e6) == '\0') && (iVar3 = (**(code **)(iVar7 + 0x6d4))(), iVar3 != 0)) {
    FUN_800200e8((int)*(short *)(iVar6 + 0x1e),1);
    *(undefined *)(iVar7 + 0x6e6) = 1;
  }
  sVar2 = (short)((int)*(char *)(iVar6 + 0x18) << 8) - *param_1;
  if (0x8000 < sVar2) {
    sVar2 = sVar2 + 1;
  }
  if (sVar2 < -0x8000) {
    sVar2 = sVar2 + -1;
  }
  if (sVar2 != 0) {
    FUN_80137948(s__YAW_DIFF_8032a86c);
    iVar3 = (int)*(short *)(*(int *)(iVar7 + 0x6dc) + 4);
    if (param_1[0x50] != iVar3) {
      FUN_80030334((double)FLOAT_803e698c,param_1,iVar3,0);
    }
    uVar5 = (uint)sVar2;
    *param_1 = *param_1 + (short)((int)(uVar5 + 1) >> 4);
    uStack28 = ((int)uVar5 >> 10) + (uint)((int)uVar5 < 0 && (uVar5 & 0x3ff) != 0) ^ 0x80000000;
    local_20 = 0x43300000;
    *(float *)(iVar7 + 0x6e0) =
         FLOAT_803e699c * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e6980);
    if ((int)uVar5 < 0) {
      uVar5 = -uVar5;
    }
    if ((int)uVar5 < 0x400) {
      *param_1 = (short)((int)*(char *)(iVar6 + 0x18) << 8);
      iVar6 = FUN_800221a0(0,1);
      FUN_80030334((double)FLOAT_803e698c,param_1,
                   (int)*(short *)(*(int *)(iVar7 + 0x6dc) + iVar6 * 2),0);
      *(float *)(iVar7 + 0x6e0) = FLOAT_803e699c;
    }
  }
  sVar2 = *(short *)(iVar7 + 0x6e4) - (ushort)DAT_803db410;
  *(short *)(iVar7 + 0x6e4) = sVar2;
  if (sVar2 < 0) {
    uVar4 = FUN_800221a0(0x32,500);
    *(undefined2 *)(iVar7 + 0x6e4) = uVar4;
    iVar6 = FUN_800221a0(0,3);
    FUN_800392f0(param_1,iVar7 + 0x684,*(int *)(iVar7 + 0x6d0) + iVar6 * 6,0);
  }
  iVar6 = FUN_8002fa48((double)*(float *)(iVar7 + 0x6e0),(double)FLOAT_803db414,param_1,
                       iVar7 + 0x6b4);
  if (iVar6 != 0) {
    iVar6 = FUN_800221a0(0,7);
    if (iVar6 == 0) {
      iVar6 = FUN_800221a0(0,1);
      if (iVar6 == 0) {
        sVar2 = 4;
      }
      else {
        sVar2 = 1;
      }
    }
    else {
      sVar2 = 0;
    }
    FUN_80030334((double)FLOAT_803e698c,param_1,(int)*(short *)(*(int *)(iVar7 + 0x6dc) + sVar2 * 2)
                 ,0);
    fVar1 = FLOAT_803e69a0;
    if (sVar2 == 0) {
      fVar1 = FLOAT_803e699c;
    }
    *(float *)(iVar7 + 0x6e0) = fVar1;
  }
  FUN_80219118(param_1,iVar7 + 0x6b4,*(undefined4 *)(iVar7 + 0x6d8));
  FUN_8003b310(param_1,iVar7 + 0x654);
  FUN_80038f38(param_1,iVar7 + 0x684);
  iVar6 = FUN_80036e58(1,param_1,local_28);
  if (iVar6 != 0) {
    (**(code **)(**(int **)(iVar6 + 0x68) + 0x28))(iVar6,param_1,1,2);
  }
  return;
}

