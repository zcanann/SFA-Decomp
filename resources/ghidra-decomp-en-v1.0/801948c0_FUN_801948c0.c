// Function: FUN_801948c0
// Entry: 801948c0
// Size: 164 bytes

double FUN_801948c0(int param_1,byte param_2)

{
  int iVar1;
  
  if ((param_1 == 0) || (iVar1 = *(int *)(param_1 + 0xb8), iVar1 == 0)) {
    return (double)FLOAT_803e4000;
  }
  if (param_2 == 4) {
    return (double)*(float *)(iVar1 + 0x44);
  }
  if (param_2 < 4) {
    if (param_2 == 2) {
      return (double)*(float *)(iVar1 + 0x40);
    }
    if (1 < param_2) {
      return (double)(*(float *)(param_1 + 0x10) + *(float *)(iVar1 + 0x44));
    }
    if (param_2 != 0) {
      return (double)(*(float *)(param_1 + 0xc) + *(float *)(iVar1 + 0x40));
    }
  }
  else {
    if (param_2 == 6) {
      return (double)*(float *)(iVar1 + 0x48);
    }
    if (param_2 < 6) {
      return (double)(*(float *)(param_1 + 0x14) + *(float *)(iVar1 + 0x48));
    }
  }
  return (double)FLOAT_803e4000;
}

