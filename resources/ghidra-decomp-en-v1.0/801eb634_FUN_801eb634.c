// Function: FUN_801eb634
// Entry: 801eb634
// Size: 780 bytes

void FUN_801eb634(int param_1,int param_2)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  double dVar5;
  int local_38;
  undefined auStack52 [4];
  undefined auStack48 [4];
  undefined auStack44 [12];
  undefined4 local_20;
  uint uStack28;
  undefined4 local_18;
  uint uStack20;
  
  iVar3 = *(int *)(param_1 + 0x54);
  iVar2 = FUN_80035f7c();
  if (iVar2 != 0) {
    if ((*(byte *)(param_2 + 0x428) >> 1 & 1) == 0) {
      FUN_80035df4(param_1,0x15,1,0);
    }
    else {
      FUN_80035dac(param_1);
      FUN_80035ea4(param_1);
    }
    iVar2 = FUN_8003687c(param_1,&local_38,auStack48,auStack52);
    if (iVar2 == 0x15) {
      if (*(float *)(param_2 + 0x3e4) == FLOAT_803e5ae8) {
        FUN_80247794(param_1 + 0x24,auStack44);
        dVar5 = (double)FUN_8024782c(auStack44,local_38 + 0x24);
        FUN_80247778((double)(float)(dVar5 * (double)*(float *)(param_2 + 0x4ac) +
                                    (double)FLOAT_803e5aec),param_2 + 0x494,param_2 + 0x494);
        *(float *)(param_2 + 0x498) = *(float *)(param_2 + 0x498) * FLOAT_803e5ba8;
        *(float *)(param_2 + 0x3e4) = FLOAT_803e5af4;
        *(float *)(param_2 + 0x3e0) = FLOAT_803e5aec;
      }
    }
    else if (iVar2 < 0x15) {
      if ((iVar2 == 0xd) && ((*(byte *)(param_2 + 0x428) >> 1 & 1) == 0)) {
        *(int *)(param_2 + 0x42c) = local_38;
        *(float *)(param_2 + 0x3e0) = FLOAT_803e5aec;
      }
    }
    else if ((iVar2 == 0x1d) && ((*(byte *)(param_2 + 0x428) >> 1 & 1) == 0)) {
      FUN_800550c4((double)FLOAT_803e5bac,1);
      dVar5 = DOUBLE_803e5b00;
      uStack28 = DAT_803dc0d0 ^ 0x80000000;
      local_20 = 0x43300000;
      *(float *)(param_2 + 0x3e4) = (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e5b00)
      ;
      *(float *)(param_2 + 0x3e0) = FLOAT_803dc0c8;
      uStack20 = DAT_803dc0cc ^ 0x80000000;
      local_18 = 0x43300000;
      *(float *)(param_2 + 0x4c4) = (float)((double)CONCAT44(0x43300000,uStack20) - dVar5);
    }
    local_38 = *(int *)(iVar3 + 0x50);
    if (((local_38 != 0) &&
        (*(int *)(param_2 + 0x42c) = local_38, *(float *)(param_2 + 0x3e4) == FLOAT_803e5ae8)) &&
       (iVar2 = FUN_8007fe74(&DAT_8032852c,0xc,(int)*(short *)(local_38 + 0x46)), iVar2 != -1)) {
      FUN_8009a8c8((double)FLOAT_803e5bb0,param_1);
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x551,0,4,0xffffffff,0);
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x552,0,4,0xffffffff,0);
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x554,0,4,0xffffffff,0);
      uVar4 = 0x32 / DAT_803db410;
      while (bVar1 = uVar4 != 0, uVar4 = uVar4 - 1, bVar1) {
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x553,0,2,0xffffffff,0);
      }
      *(float *)(param_2 + 0x3e4) = FLOAT_803e5af4;
      *(float *)(param_2 + 0x3e0) = FLOAT_803e5aec;
      if ((*(byte *)(param_2 + 0x428) >> 1 & 1) == 0) {
        *(float *)(param_2 + 0x3e4) =
             (float)((double)CONCAT44(0x43300000,DAT_803dc0d4 ^ 0x80000000) - DOUBLE_803e5b00);
      }
    }
  }
  return;
}

