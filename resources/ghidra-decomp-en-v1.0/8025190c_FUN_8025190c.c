// Function: FUN_8025190c
// Entry: 8025190c
// Size: 148 bytes

void FUN_8025190c(undefined4 *param_1)

{
  param_1[2] = 0;
  *param_1 = 3;
  if (DAT_803de078 != param_1) {
    if (DAT_803de074 == param_1) {
      DAT_803de074 = (undefined4 *)param_1[0xf];
      *(undefined4 *)(param_1[0xf] + 0x38) = 0;
      DAT_803de07c = DAT_803de078;
      return;
    }
    DAT_803de07c = (undefined4 *)param_1[0xe];
    *(undefined4 *)(param_1[0xf] + 0x38) = param_1[0xe];
    *(undefined4 *)(param_1[0xe] + 0x3c) = param_1[0xf];
    return;
  }
  DAT_803de078 = (undefined4 *)param_1[0xe];
  if (DAT_803de078 != (undefined4 *)0x0) {
    *(undefined4 *)(param_1[0xe] + 0x3c) = 0;
    return;
  }
  DAT_803de074 = (undefined4 *)0x0;
  DAT_803de078 = (undefined4 *)0x0;
  DAT_803de07c = (undefined4 *)0x0;
  return;
}

