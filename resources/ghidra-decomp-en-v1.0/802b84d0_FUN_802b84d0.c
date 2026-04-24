// Function: FUN_802b84d0
// Entry: 802b84d0
// Size: 276 bytes

void FUN_802b84d0(undefined2 *param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(*(int *)(param_1 + 0x26) + 0x14);
  if (iVar1 == 0x34316) {
    *(float *)(param_1 + 0xc) = FLOAT_803e81dc;
    *(float *)(param_1 + 0xe) = FLOAT_803e81e0;
    *(float *)(param_1 + 0x10) = FLOAT_803e81e4;
    *param_1 = 0x2565;
    return;
  }
  if (0x34315 < iVar1) {
    if (iVar1 == 0x460b6) {
      *(float *)(param_1 + 0xc) = FLOAT_803e8204;
      *(float *)(param_1 + 0xe) = FLOAT_803e81e0;
      *(float *)(param_1 + 0x10) = FLOAT_803e8208;
      *param_1 = 0x119f;
      return;
    }
    if (0x460b5 < iVar1) {
      return;
    }
    if (iVar1 != 0x45c47) {
      return;
    }
    *(float *)(param_1 + 0xc) = FLOAT_803e81fc;
    *(float *)(param_1 + 0xe) = FLOAT_803e81e0;
    *(float *)(param_1 + 0x10) = FLOAT_803e8200;
    *param_1 = 0x32c1;
    return;
  }
  if (iVar1 == 0x33e3c) {
    *(float *)(param_1 + 0xc) = FLOAT_803e81e8;
    *(float *)(param_1 + 0xe) = FLOAT_803e81ec;
    *(float *)(param_1 + 0x10) = FLOAT_803e81f0;
    *param_1 = 0x1c42;
    return;
  }
  if (0x33e3b < iVar1) {
    return;
  }
  if (iVar1 != 0x33e34) {
    return;
  }
  *(float *)(param_1 + 0xc) = FLOAT_803e81f4;
  *(float *)(param_1 + 0xe) = FLOAT_803e81ec;
  *(float *)(param_1 + 0x10) = FLOAT_803e81f8;
  *param_1 = 0x1d00;
  return;
}

