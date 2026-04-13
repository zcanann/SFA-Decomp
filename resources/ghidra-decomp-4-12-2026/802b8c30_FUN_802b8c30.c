// Function: FUN_802b8c30
// Entry: 802b8c30
// Size: 276 bytes

void FUN_802b8c30(undefined2 *param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(*(int *)(param_1 + 0x26) + 0x14);
  if (iVar1 == 0x34316) {
    *(float *)(param_1 + 0xc) = FLOAT_803e8e74;
    *(float *)(param_1 + 0xe) = FLOAT_803e8e78;
    *(float *)(param_1 + 0x10) = FLOAT_803e8e7c;
    *param_1 = 0x2565;
    return;
  }
  if (0x34315 < iVar1) {
    if (iVar1 == 0x460b6) {
      *(float *)(param_1 + 0xc) = FLOAT_803e8e9c;
      *(float *)(param_1 + 0xe) = FLOAT_803e8e78;
      *(float *)(param_1 + 0x10) = FLOAT_803e8ea0;
      *param_1 = 0x119f;
      return;
    }
    if (0x460b5 < iVar1) {
      return;
    }
    if (iVar1 != 0x45c47) {
      return;
    }
    *(float *)(param_1 + 0xc) = FLOAT_803e8e94;
    *(float *)(param_1 + 0xe) = FLOAT_803e8e78;
    *(float *)(param_1 + 0x10) = FLOAT_803e8e98;
    *param_1 = 0x32c1;
    return;
  }
  if (iVar1 == 0x33e3c) {
    *(float *)(param_1 + 0xc) = FLOAT_803e8e80;
    *(float *)(param_1 + 0xe) = FLOAT_803e8e84;
    *(float *)(param_1 + 0x10) = FLOAT_803e8e88;
    *param_1 = 0x1c42;
    return;
  }
  if (0x33e3b < iVar1) {
    return;
  }
  if (iVar1 != 0x33e34) {
    return;
  }
  *(float *)(param_1 + 0xc) = FLOAT_803e8e8c;
  *(float *)(param_1 + 0xe) = FLOAT_803e8e84;
  *(float *)(param_1 + 0x10) = FLOAT_803e8e90;
  *param_1 = 0x1d00;
  return;
}

