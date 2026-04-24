// Function: FUN_80025880
// Entry: 80025880
// Size: 612 bytes

void FUN_80025880(int param_1,uint param_2,int *param_3,int param_4)

{
  int iVar1;
  
  if (*(short *)(param_1 + 0xec) == 0) {
    param_3[6] = 0x80;
  }
  else {
    param_3[6] = ((uint)*(byte *)(param_1 + 0xf3) + (uint)*(byte *)(param_1 + 0xf4)) * 0x80;
  }
  if (((*(char *)(param_1 + 0xf9) == '\0') && (*(int *)(param_1 + 0xa4) == 0)) &&
     ((*(ushort *)(param_1 + 2) & 0x10) == 0)) {
    *param_3 = 0;
  }
  else {
    *param_3 = (uint)*(ushort *)(param_1 + 0xe4) * 0xc + 0x60;
  }
  if (*(int *)(param_1 + 200) != 0) {
    if ((*(byte *)(param_1 + 0x24) & 8) == 0) {
      iVar1 = 3;
    }
    else {
      iVar1 = 9;
    }
    *param_3 = (uint)*(ushort *)(param_1 + 0xe6) * iVar1 + *param_3 + 0x40;
  }
  param_3[1] = (uint)*(byte *)(param_1 + 0xf7) << 5;
  param_3[3] = 0;
  if ((*(ushort *)(param_1 + 2) & 0x40) != 0) {
    param_3[5] = (int)*(short *)(param_1 + 0x84);
    while ((param_3[5] & 7U) != 0) {
      param_3[5] = param_3[5] + 1;
    }
    param_3[3] = param_3[5] << 2;
  }
  param_3[4] = 0x68;
  if ((param_2 & 0x80) != 0) {
    param_3[4] = param_3[4] << 1;
    param_3[3] = param_3[3] << 1;
  }
  if ((*(char *)(param_1 + 0xf9) == '\0') && (param_4 == 0)) {
    iVar1 = param_3[3] + param_3[6] + param_3[1] + param_3[4] + 0x6c;
  }
  else {
    param_3[4] = param_3[4] + 0x30;
    iVar1 = param_3[6] + param_3[1] + param_3[3] + param_3[4] + 0x6c;
  }
  iVar1 = iVar1 + *param_3;
  if (((*(int *)(param_1 + 0x3c) != 0) && (*(byte *)(param_1 + 0xf3) != 0)) &&
     (*(int *)(param_1 + 0x18) != 0)) {
    iVar1 = (uint)*(byte *)(param_1 + 0xf3) * 0x1e + 0x1c + iVar1;
  }
  if (*(int *)(param_1 + 0xa4) != 0) {
    iVar1 = (uint)*(ushort *)(param_1 + 0x8a) * 4 + iVar1 + 4;
  }
  if (*(int *)(param_1 + 200) != 0) {
    iVar1 = (uint)*(ushort *)(param_1 + 0xae) * 4 + iVar1 + 4;
  }
  iVar1 = iVar1 + (uint)*(byte *)(param_1 + 0xf8) * 0xc;
  if ((param_2 & 0x8000) != 0) {
    iVar1 = iVar1 + 0x1a;
  }
  FUN_80022e6c((iVar1 + 0x2fU & 0xfffffff0) + 0x10);
  return;
}

