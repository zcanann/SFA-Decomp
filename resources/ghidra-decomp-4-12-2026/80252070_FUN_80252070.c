// Function: FUN_80252070
// Entry: 80252070
// Size: 148 bytes

void FUN_80252070(undefined4 *param_1)

{
  param_1[2] = 0;
  *param_1 = 3;
  if (DAT_803decf8 != param_1) {
    if (DAT_803decf4 == param_1) {
      DAT_803decf4 = (undefined4 *)param_1[0xf];
      *(undefined4 *)(param_1[0xf] + 0x38) = 0;
      DAT_803decfc = DAT_803decf8;
      return;
    }
    DAT_803decfc = (undefined4 *)param_1[0xe];
    *(undefined4 *)(param_1[0xf] + 0x38) = param_1[0xe];
    *(undefined4 *)(param_1[0xe] + 0x3c) = param_1[0xf];
    return;
  }
  DAT_803decf8 = (undefined4 *)param_1[0xe];
  if (DAT_803decf8 != (undefined4 *)0x0) {
    *(undefined4 *)(param_1[0xe] + 0x3c) = 0;
    return;
  }
  DAT_803decfc = (undefined4 *)0x0;
  DAT_803decf4 = (undefined4 *)0x0;
  DAT_803decf8 = (undefined4 *)0x0;
  return;
}

