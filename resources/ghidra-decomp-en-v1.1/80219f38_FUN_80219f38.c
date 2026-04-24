// Function: FUN_80219f38
// Entry: 80219f38
// Size: 448 bytes

void FUN_80219f38(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  char cVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_9 + 0x5c);
  *param_9 = (short)((int)*(char *)(param_10 + 0x18) << 8);
  uVar2 = FUN_80020078((int)*(short *)(param_10 + 0x1e));
  if (uVar2 != 0) {
    *(undefined *)(iVar3 + 0x6e6) = 1;
  }
  cVar1 = *(char *)(param_10 + 0x19);
  if (cVar1 == '\x02') {
    *(undefined **)(iVar3 + 0x6dc) = &DAT_8032b424;
    *(code **)(iVar3 + 0x6d4) = FUN_8021989c;
    *(undefined **)(iVar3 + 0x6d8) = &DAT_803dcf30;
    FUN_800372f8((int)param_9,3);
    if (*(char *)(iVar3 + 0x6e6) != '\0') {
      FUN_8002cf80((int)param_9);
      param_9[3] = param_9[3] | 0x4000;
    }
    FUN_80033a34(param_9);
    *(code **)(param_9 + 0x5e) = FUN_80219ae4;
  }
  else {
    if (cVar1 < '\x02') {
      if (cVar1 != '\0') {
        if (-1 < cVar1) {
          *(undefined **)(iVar3 + 0x6dc) = &DAT_8032b418;
          *(code **)(iVar3 + 0x6d4) = FUN_80219a54;
          *(undefined4 *)(iVar3 + 0x6d8) = 0;
          *(code **)(param_9 + 0x5e) = FUN_80219ae4;
        }
        goto LAB_8021a090;
      }
    }
    else if ('\x03' < cVar1) goto LAB_8021a090;
    FUN_800201ac(0x934,0);
    FUN_800201ac(0x933,0);
    *(undefined **)(iVar3 + 0x6dc) = &DAT_8032b430;
    *(code **)(iVar3 + 0x6d4) = FUN_80219638;
    *(undefined **)(iVar3 + 0x6d8) = &DAT_803dcf38;
    *(code **)(param_9 + 0x5e) = FUN_80219560;
  }
LAB_8021a090:
  *(undefined **)(iVar3 + 0x6d0) = &DAT_8032b43c;
  *(float *)(iVar3 + 0x6e0) = FLOAT_803e7634;
  uVar2 = FUN_80022264(0,1);
  FUN_8003042c((double)FLOAT_803e7624,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
               param_9,(int)*(short *)(*(int *)(iVar3 + 0x6dc) + uVar2 * 2),0,param_12,param_13,
               param_14,param_15,param_16);
  param_9[0x58] = param_9[0x58] | 0x2000;
  return;
}

