// Function: FUN_8021989c
// Entry: 8021989c
// Size: 440 bytes

undefined4
FUN_8021989c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,undefined4 param_11,int param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  uint uVar5;
  int iVar6;
  double dVar7;
  
  iVar1 = FUN_8002bac4();
  iVar2 = FUN_8002ba84();
  iVar6 = *(int *)(param_9 + 0xb8);
  iVar3 = FUN_80297300(iVar1);
  if (iVar3 == 0x40) {
    uVar4 = 1;
  }
  else {
    if (((*(byte *)(param_9 + 0xaf) & 1) != 0) &&
       (iVar3 = (**(code **)(*DAT_803dd6e8 + 0x1c))(), iVar3 == 0)) {
      FUN_80014b68(0,0x100);
      *(undefined *)(*(int *)(param_9 + 0x54) + 0x6e) = 0xb;
      *(undefined *)(*(int *)(param_9 + 0x54) + 0x6f) = 4;
      uVar5 = FUN_80022264(0,1);
      param_12 = *DAT_803dd6d4;
      (**(code **)(param_12 + 0x48))(uVar5,param_9,0xffffffff);
    }
    if ((((iVar2 != 0) &&
         (dVar7 = (double)FUN_80021754((float *)(param_9 + 0x18),(float *)(iVar2 + 0x18)),
         dVar7 < (double)FLOAT_803e7620)) ||
        ((iVar1 != 0 &&
         (dVar7 = (double)FUN_80021754((float *)(param_9 + 0x18),(float *)(iVar1 + 0x18)),
         dVar7 < (double)FLOAT_803e7620)))) && (*(short *)(param_9 + 0xa0) != 9)) {
      FUN_8003042c((double)FLOAT_803e7624,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,9,0,param_12,param_13,param_14,param_15,param_16);
      *(float *)(iVar6 + 0x6e0) = FLOAT_803e7628;
      if (iVar2 != 0) {
        (**(code **)(**(int **)(iVar2 + 0x68) + 0x34))(iVar2,0,0);
      }
    }
    if (*(short *)(param_9 + 0xa0) == 9) {
      *(undefined *)(*(int *)(param_9 + 0x54) + 0x6e) = 0xb;
      *(undefined *)(*(int *)(param_9 + 0x54) + 0x6f) = 4;
      FUN_80035eec(param_9,0xb,4,7);
      FUN_80033a34(param_9);
    }
    uVar4 = 0;
  }
  return uVar4;
}

