// Function: FUN_801d6158
// Entry: 801d6158
// Size: 480 bytes

void FUN_801d6158(double param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10,int param_11,undefined4 param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  uint uVar2;
  double extraout_f1;
  
  *(undefined **)(param_10 + 0x62c) = &DAT_80328014;
  iVar1 = param_11;
  switch(*(undefined *)(param_10 + 0x626)) {
  case 1:
    *(uint *)(param_10 + 0x62c) = (uint)*(byte *)(param_11 + 0x1a) * 2 + -0x7fcd7fdc;
    break;
  case 2:
    uVar2 = FUN_80020078(0x9e);
    if (uVar2 == 0) {
      *(uint *)(param_10 + 0x62c) = (uint)*(byte *)(param_11 + 0x1a) * 2 + -0x7fcd7fd0;
    }
    else {
      *(uint *)(param_10 + 0x62c) = (uint)*(byte *)(param_11 + 0x1a) * 2 + -0x7fcd7fc4;
    }
    break;
  case 3:
    uVar2 = FUN_80020078(0x193);
    if (uVar2 == 0) {
      *(uint *)(param_10 + 0x62c) = (uint)*(byte *)(param_11 + 0x1a) * 2 + -0x7fcd7fb8;
    }
    else {
      *(uint *)(param_10 + 0x62c) = (uint)*(byte *)(param_11 + 0x1a) * 2 + -0x7fcd7fac;
    }
    break;
  case 5:
    uVar2 = FUN_80020078(0x23d);
    if (uVar2 == 0) {
      *(uint *)(param_10 + 0x62c) = (uint)*(byte *)(param_11 + 0x1a) * 2 + -0x7fcd7fa0;
    }
    break;
  case 6:
    iVar1 = FUN_801d52c0();
    if (iVar1 != 0) {
      *(undefined *)(param_10 + 0x624) = 0xe;
      return;
    }
    param_1 = extraout_f1;
    if (*(char *)(param_10 + 0x624) == '\x0e') {
      FUN_8000bb38(0,0x409);
      *(undefined *)(param_10 + 0x624) = 0;
      uVar2 = FUN_80022264(1000,2000);
      param_1 = DOUBLE_803e60c0;
      *(float *)(param_10 + 0x630) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e60c0);
    }
    uVar2 = FUN_80020078(0x13f);
    iVar1 = param_11;
    if (uVar2 == 0) {
      *(undefined **)(param_10 + 0x62c) = &DAT_803dcc6c;
    }
    break;
  case 8:
    *(uint *)(param_10 + 0x62c) = (uint)*(byte *)(param_11 + 0x1a) * 2 + -0x7fcd7f94;
  }
  FUN_801d5764(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10,
               iVar1,param_12,param_13,param_14,param_15,param_16);
  return;
}

