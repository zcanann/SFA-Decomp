// Function: FUN_80032508
// Entry: 80032508
// Size: 432 bytes

void FUN_80032508(ushort *param_1,int param_2)

{
  int iVar1;
  ushort local_28;
  ushort local_26;
  ushort local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  iVar1 = *(int *)(param_1 + 0x2c);
  if (iVar1 != 0) {
    if (param_2 != 0) {
      *(byte *)(iVar1 + 0x10c) = *(char *)(iVar1 + 0x10c) + 1U & 1;
    }
    local_28 = -*param_1;
    if ((*(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) & 0x800) == 0) {
      local_26 = -param_1[1];
    }
    else {
      local_26 = 0;
    }
    if ((*(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) & 0x1000) == 0) {
      local_24 = -param_1[2];
    }
    else {
      local_24 = 0;
    }
    local_20 = FLOAT_803df598;
    local_1c = -*(float *)(param_1 + 0xc);
    local_18 = -*(float *)(param_1 + 0xe);
    local_14 = -*(float *)(param_1 + 0x10);
    FUN_80021c64((float *)(iVar1 + (uint)*(byte *)(iVar1 + 0x10c) * 0x40),(int)&local_28);
    local_28 = *param_1;
    if ((*(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) & 0x800) == 0) {
      local_26 = param_1[1];
    }
    else {
      local_26 = 0;
    }
    if ((*(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) & 0x1000) == 0) {
      local_24 = param_1[2];
    }
    else {
      local_24 = 0;
    }
    local_20 = FLOAT_803df598;
    local_1c = *(float *)(param_1 + 0xc);
    local_18 = *(float *)(param_1 + 0xe);
    local_14 = *(float *)(param_1 + 0x10);
    FUN_80021fac((float *)(iVar1 + (*(byte *)(iVar1 + 0x10c) + 2) * 0x40),&local_28);
    if (*(char *)(iVar1 + 0x10d) != '\0') {
      *(char *)(iVar1 + 0x10d) = *(char *)(iVar1 + 0x10d) + -1;
    }
  }
  return;
}

