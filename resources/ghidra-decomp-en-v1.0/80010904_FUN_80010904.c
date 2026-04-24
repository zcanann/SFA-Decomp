// Function: FUN_80010904
// Entry: 80010904
// Size: 360 bytes

void FUN_80010904(int param_1)

{
  if (*(int *)(param_1 + 0x90) < 4) {
    FUN_801378a8(s_curvesSetupMoveNetworkCurve__The_802c6010);
  }
  if (((*(code **)(param_1 + 0x94) == (code *)0x80010ce4) ||
      (*(code **)(param_1 + 0x94) == FUN_80010dc0)) && ((*(uint *)(param_1 + 0x90) & 3) != 0)) {
    FUN_801378a8(s_curvesSetupMoveNetworkCurve__The_802c605c);
  }
  *(float *)(param_1 + 0xc) = FLOAT_803de658;
  *(undefined4 *)(param_1 + 0x10) = 0;
  while (*(int *)(param_1 + 0x10) < *(int *)(param_1 + 0x90) + -3) {
    FUN_8000fe8c(param_1,5);
    *(float *)(param_1 + 0xc) = *(float *)(param_1 + 0xc) + *(float *)(param_1 + 0x14);
    if ((*(code **)(param_1 + 0x94) == (code *)0x80010ce4) ||
       (*(code **)(param_1 + 0x94) == FUN_80010dc0)) {
      *(int *)(param_1 + 0x10) = *(int *)(param_1 + 0x10) + 4;
    }
    else {
      *(int *)(param_1 + 0x10) = *(int *)(param_1 + 0x10) + 1;
    }
  }
  if (*(int *)(param_1 + 0x80) == 0) {
    *(undefined4 *)(param_1 + 0x10) = 0;
  }
  else {
    *(int *)(param_1 + 0x10) = *(int *)(param_1 + 0x90) + -4;
  }
  FUN_8000fe8c(param_1,0x14);
  if (*(int *)(param_1 + 0x80) == 0) {
    *(undefined4 *)(param_1 + 8) = *(undefined4 *)(param_1 + 4);
  }
  else {
    *(float *)(param_1 + 8) = *(float *)(param_1 + 0xc) - *(float *)(param_1 + 4);
  }
  return;
}

