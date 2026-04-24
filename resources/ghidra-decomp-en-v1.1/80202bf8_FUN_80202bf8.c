// Function: FUN_80202bf8
// Entry: 80202bf8
// Size: 352 bytes

undefined4
FUN_80202bf8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  
  iVar3 = *(int *)(param_9 + 0xb8);
  iVar4 = *(int *)(iVar3 + 0x40c);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_80036018(param_9);
  }
  uVar2 = 0xffffffff;
  FUN_80035eec(param_9,10,1,-1);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    uVar1 = FUN_80022264(0,1);
    if (uVar1 == 0) {
      if (*(char *)(param_10 + 0x27a) != '\0') {
        FUN_8003042c((double)FLOAT_803e6f40,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,7,0,uVar2,param_13,param_14,param_15,param_16);
        *(undefined *)(param_10 + 0x346) = 0;
      }
    }
    else if (*(char *)(param_10 + 0x27a) != '\0') {
      FUN_8003042c((double)FLOAT_803e6f40,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,6,0,uVar2,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
    *(undefined *)(param_10 + 0x34d) = 1;
    *(float *)(param_10 + 0x2a0) =
         FLOAT_803e6fdc +
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar3 + 0x406)) - DOUBLE_803e6f78) /
         FLOAT_803e6fe0;
  }
  *(float *)(param_10 + 0x280) = FLOAT_803e6f40;
  if (*(char *)(param_10 + 0x346) != '\0') {
    *(undefined *)(iVar4 + 0x34) = 1;
  }
  *(byte *)(iVar4 + 0x14) = *(byte *)(iVar4 + 0x14) | 2;
  return 0;
}

