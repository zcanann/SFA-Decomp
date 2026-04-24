// Function: FUN_801d5afc
// Entry: 801d5afc
// Size: 440 bytes

void FUN_801d5afc(double param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10,int param_11,undefined4 param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  
  *(undefined **)(param_10 + 0x62c) = &DAT_803dcc70;
  switch(*(undefined *)(param_10 + 0x626)) {
  case 1:
    *(undefined **)(param_10 + 0x62c) = &DAT_803dcc78;
    break;
  case 2:
    uVar1 = FUN_80020078(0xc2);
    if (uVar1 != 6) {
      *(undefined **)(param_10 + 0x62c) = &DAT_803dcc7c;
    }
    break;
  case 3:
    uVar1 = FUN_80020078(0x193);
    if (uVar1 == 0) {
      *(undefined **)(param_10 + 0x62c) = &DAT_803dcc80;
    }
    break;
  case 4:
    *(undefined **)(param_10 + 0x62c) = &DAT_803dcc84;
    break;
  case 5:
    uVar1 = FUN_80020078(0x23c);
    if (uVar1 == 0) {
      uVar1 = FUN_80020078(0x5bd);
      if (uVar1 == 0) {
        uVar1 = FUN_80020078(0x23d);
        if (uVar1 == 0) {
          *(undefined **)(param_10 + 0x62c) = &DAT_803dcc88;
          *(undefined *)(param_10 + 0x624) = 0x10;
          return;
        }
        if (*(char *)(param_10 + 0x624) == '\x10') {
          *(undefined *)(param_10 + 0x624) = 0;
          uVar1 = FUN_80022264(1000,2000);
          param_1 = DOUBLE_803e60c0;
          *(float *)(param_10 + 0x630) =
               (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e60c0);
        }
        *(undefined **)(param_10 + 0x62c) = &DAT_803dcc8c;
      }
      else {
        param_11 = *DAT_803dd72c;
        param_1 = (double)(**(code **)(param_11 + 0x44))(0x1d,3);
        *(undefined **)(param_10 + 0x62c) = &DAT_803dcc90;
      }
    }
    break;
  case 6:
    uVar1 = FUN_80020078(0x13f);
    if (uVar1 == 0) {
      *(undefined **)(param_10 + 0x62c) = &DAT_803dcc94;
    }
    break;
  case 7:
    uVar1 = FUN_80020078(0x199);
    if (uVar1 == 0) {
      *(undefined **)(param_10 + 0x62c) = &DAT_803dcc98;
    }
    break;
  case 8:
    *(undefined **)(param_10 + 0x62c) = &DAT_803dcc9c;
  }
  FUN_801d5764(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10,
               param_11,param_12,param_13,param_14,param_15,param_16);
  return;
}

