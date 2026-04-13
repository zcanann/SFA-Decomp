// Function: FUN_80010924
// Entry: 80010924
// Size: 360 bytes

void FUN_80010924(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  code *pcVar1;
  
  if (*(int *)(param_9 + 0x90) < 4) {
    param_1 = FUN_80137c30(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           s_curvesSetupMoveNetworkCurve__The_802c6790,param_10,param_11,param_12,
                           param_13,param_14,param_15,param_16);
  }
  pcVar1 = *(code **)(param_9 + 0x94);
  if (((pcVar1 == (code *)0x80010d04) || (pcVar1 == FUN_80010de0)) &&
     ((*(uint *)(param_9 + 0x90) & 3) != 0)) {
    FUN_80137c30(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 s_curvesSetupMoveNetworkCurve__The_802c67dc,pcVar1,param_11,param_12,param_13,
                 param_14,param_15,param_16);
  }
  *(float *)(param_9 + 0xc) = FLOAT_803df2d8;
  *(undefined4 *)(param_9 + 0x10) = 0;
  while (*(int *)(param_9 + 0x10) < *(int *)(param_9 + 0x90) + -3) {
    FUN_8000feac();
    *(float *)(param_9 + 0xc) = *(float *)(param_9 + 0xc) + *(float *)(param_9 + 0x14);
    if ((*(code **)(param_9 + 0x94) == (code *)0x80010d04) ||
       (*(code **)(param_9 + 0x94) == FUN_80010de0)) {
      *(int *)(param_9 + 0x10) = *(int *)(param_9 + 0x10) + 4;
    }
    else {
      *(int *)(param_9 + 0x10) = *(int *)(param_9 + 0x10) + 1;
    }
  }
  if (*(int *)(param_9 + 0x80) == 0) {
    *(undefined4 *)(param_9 + 0x10) = 0;
  }
  else {
    *(int *)(param_9 + 0x10) = *(int *)(param_9 + 0x90) + -4;
  }
  FUN_8000feac();
  if (*(int *)(param_9 + 0x80) == 0) {
    *(undefined4 *)(param_9 + 8) = *(undefined4 *)(param_9 + 4);
  }
  else {
    *(float *)(param_9 + 8) = *(float *)(param_9 + 0xc) - *(float *)(param_9 + 4);
  }
  return;
}

