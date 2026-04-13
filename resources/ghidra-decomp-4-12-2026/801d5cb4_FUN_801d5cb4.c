// Function: FUN_801d5cb4
// Entry: 801d5cb4
// Size: 540 bytes

void FUN_801d5cb4(double param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10,undefined4 param_11,int param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  int iVar2;
  double extraout_f1;
  
  *(undefined **)(param_10 + 0x62c) = &DAT_80328014;
  switch(*(undefined *)(param_10 + 0x626)) {
  case 1:
    *(undefined **)(param_10 + 0x62c) = &DAT_803dcc68;
    break;
  case 2:
    *(undefined **)(param_10 + 0x62c) = &DAT_803dcc68;
    break;
  case 3:
    *(undefined **)(param_10 + 0x62c) = &DAT_803dcc68;
    break;
  case 4:
    *(undefined **)(param_10 + 0x62c) = &DAT_803dcc68;
    break;
  case 5:
    *(undefined **)(param_10 + 0x62c) = &DAT_803dcc68;
    break;
  case 6:
    iVar2 = FUN_801d52c0();
    if (iVar2 != 0) {
      *(undefined *)(param_10 + 0x624) = 0xe;
      return;
    }
    param_1 = extraout_f1;
    if (*(char *)(param_10 + 0x624) == '\x0e') {
      FUN_8000bb38(0,0x409);
      *(undefined *)(param_10 + 0x624) = 0;
      uVar1 = FUN_80022264(1000,2000);
      param_1 = DOUBLE_803e60c0;
      *(float *)(param_10 + 0x630) =
           (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e60c0);
    }
    *(undefined **)(param_10 + 0x62c) = &DAT_803dcc68;
    break;
  case 7:
    if (*(char *)(param_10 + 0x624) == '\x0f') {
      uVar1 = FUN_80020078(0x1a0);
      uVar1 = FUN_80020078(uVar1);
      if (uVar1 == 0) {
        return;
      }
      param_11 = 0;
      param_12 = *DAT_803dd72c;
      (**(code **)(param_12 + 0x50))((int)*(char *)(param_9 + 0x56),3);
      *(undefined *)(param_10 + 0x624) = 0;
      uVar1 = FUN_80022264(1000,2000);
      param_1 = DOUBLE_803e60c0;
      *(float *)(param_10 + 0x630) =
           (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e60c0);
    }
    else {
      uVar1 = FUN_80020078(0x1a0);
      if ((uVar1 == 0) && (iVar2 = FUN_8003811c((int)param_9), iVar2 != 0)) {
        *(byte *)(param_10 + 0x625) = *(byte *)(param_10 + 0x625) | 4;
        *(undefined *)(param_10 + 0x624) = 0xf;
        (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0x56),3,1);
        FUN_800201ac(0x199,1);
        return;
      }
    }
    break;
  case 8:
    *(undefined **)(param_10 + 0x62c) = &DAT_80328072;
  }
  FUN_801d5764(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10,
               param_11,param_12,param_13,param_14,param_15,param_16);
  return;
}

