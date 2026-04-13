// Function: FUN_8015ea88
// Entry: 8015ea88
// Size: 444 bytes

undefined4
FUN_8015ea88(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int local_28;
  int local_24 [5];
  
  iVar5 = *(int *)(param_9 + 0xb8);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_80036018(param_9);
  }
  iVar4 = -1;
  FUN_80035eec(param_9,10,1,-1);
  *(undefined *)(*(int *)(param_9 + 0x54) + 0x6c) = 10;
  *(undefined *)(*(int *)(param_9 + 0x54) + 0x6d) = 1;
  FUN_80033a34(param_9);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    iVar1 = FUN_8002e1f4(&local_28,local_24);
    for (; local_28 < local_24[0]; local_28 = local_28 + 1) {
      iVar2 = *(int *)(iVar1 + local_28 * 4);
      if ((iVar2 != param_9) && (*(short *)(iVar2 + 0x46) == 0x306)) {
        iVar4 = **(int **)(iVar2 + 0x68);
        (**(code **)(iVar4 + 0x24))(iVar2,0x81,0);
      }
    }
    uVar3 = FUN_80022264(0,1);
    if (uVar3 == 0) {
      if (*(char *)(param_10 + 0x27a) != '\0') {
        FUN_8003042c((double)FLOAT_803e3a60,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,7,0,iVar4,param_13,param_14,param_15,param_16);
        *(undefined *)(param_10 + 0x346) = 0;
      }
    }
    else if (*(char *)(param_10 + 0x27a) != '\0') {
      FUN_8003042c((double)FLOAT_803e3a60,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,6,0,iVar4,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
    *(undefined *)(param_10 + 0x34d) = 1;
    *(float *)(param_10 + 0x2a0) =
         FLOAT_803e3a74 +
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar5 + 0x406)) - DOUBLE_803e3a58) /
         FLOAT_803e3a78;
  }
  *(float *)(param_10 + 0x280) = FLOAT_803e3a60;
  return 0;
}

