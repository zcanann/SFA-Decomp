// Function: FUN_8015e6bc
// Entry: 8015e6bc
// Size: 400 bytes

undefined4
FUN_8015e6bc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int local_18;
  int local_14;
  
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e3a60,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  if (*(char *)(param_10 + 0x27a) != '\0') {
    iVar1 = FUN_8002e1f4(&local_18,&local_14);
    for (; local_18 < local_14; local_18 = local_18 + 1) {
      uVar2 = *(uint *)(iVar1 + local_18 * 4);
      if ((uVar2 != param_9) && (*(short *)(uVar2 + 0x46) == 0x306)) {
        (**(code **)(**(int **)(uVar2 + 0x68) + 0x24))(uVar2,0x81,0);
      }
    }
    iVar1 = FUN_8002bac4();
    iVar3 = *(int *)(iVar1 + 200);
    iVar1 = FUN_8002bac4();
    iVar3 = (**(code **)(**(int **)(iVar3 + 0x68) + 0x44))(iVar3);
    if (iVar3 == 0) {
      if (*(short *)(iVar1 + 0x46) == 0) {
        FUN_8000bb38(param_9,0x239);
      }
      else {
        FUN_8000bb38(param_9,0x1f2);
      }
    }
    else if (*(short *)(iVar1 + 0x46) == 0) {
      FUN_8000bb38(param_9,0x95);
    }
    else {
      FUN_8000bb38(param_9,0x1f2);
    }
    FUN_8000bb38(param_9,0x267);
  }
  *(undefined *)(param_10 + 0x34d) = 3;
  *(float *)(param_10 + 0x2a0) = FLOAT_803e3a6c;
  *(float *)(param_10 + 0x280) = FLOAT_803e3a60;
  return 0;
}

