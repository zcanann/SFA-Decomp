// Function: FUN_8029be1c
// Entry: 8029be1c
// Size: 244 bytes

int FUN_8029be1c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                short *param_9,int param_10,undefined4 param_11,float *param_12,undefined4 *param_13
                ,undefined4 param_14,undefined4 param_15,int param_16)

{
  char cVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_9 + 0x5c);
  iVar2 = FUN_802acf3c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                       param_10,iVar3,param_12,param_13,param_14,param_15,param_16);
  if (iVar2 == 0) {
    if (param_9[0x50] != 0x449) {
      FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0x449,0,param_12,param_13,param_14,param_15,param_16);
      *(float *)(param_10 + 0x2a0) = FLOAT_803e8be4;
      FUN_8000bb38((uint)param_9,0x40b);
      cVar1 = *(char *)(iVar3 + 0x8c8);
      if ((cVar1 != 'B') && (cVar1 != 'L')) {
        (**(code **)(*DAT_803dd6d0 + 0x1c))(0x42,0,1,0,0,0x3c,0xfe);
      }
    }
    if (*(char *)(param_10 + 0x346) == '\0') {
      iVar2 = 0;
    }
    else {
      *(code **)(param_10 + 0x308) = FUN_802a58ac;
      iVar2 = -1;
    }
  }
  return iVar2;
}

