// Function: FUN_8002d30c
// Entry: 8002d30c
// Size: 592 bytes

void FUN_8002d30c(int param_1,uint param_2)

{
  int iVar1;
  int iVar2;
  
  if (*(int *)(param_1 + 0x30) == 0) {
    *(undefined4 *)(param_1 + 0x18) = *(undefined4 *)(param_1 + 0xc);
    *(undefined4 *)(param_1 + 0x1c) = *(undefined4 *)(param_1 + 0x10);
    *(undefined4 *)(param_1 + 0x20) = *(undefined4 *)(param_1 + 0x14);
  }
  else {
    FUN_8000e0a0((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                 (double)*(float *)(param_1 + 0x14),param_1 + 0x18,param_1 + 0x1c,param_1 + 0x20);
  }
  *(undefined4 *)(param_1 + 0x8c) = *(undefined4 *)(param_1 + 0x18);
  *(undefined4 *)(param_1 + 0x90) = *(undefined4 *)(param_1 + 0x1c);
  *(undefined4 *)(param_1 + 0x94) = *(undefined4 *)(param_1 + 0x20);
  *(undefined4 *)(param_1 + 0x80) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(param_1 + 0x84) = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(param_1 + 0x88) = *(undefined4 *)(param_1 + 0x14);
  FUN_8002caec(param_1,*(undefined4 *)(param_1 + 0x4c),0);
  if (*(int *)(param_1 + 0x54) != 0) {
    *(undefined4 *)(*(int *)(param_1 + 0x54) + 0x10) = *(undefined4 *)(param_1 + 0xc);
    *(undefined4 *)(*(int *)(param_1 + 0x54) + 0x14) = *(undefined4 *)(param_1 + 0x10);
    *(undefined4 *)(*(int *)(param_1 + 0x54) + 0x18) = *(undefined4 *)(param_1 + 0x14);
    *(undefined4 *)(*(int *)(param_1 + 0x54) + 0x1c) = *(undefined4 *)(param_1 + 0xc);
    *(undefined4 *)(*(int *)(param_1 + 0x54) + 0x20) = *(undefined4 *)(param_1 + 0x10);
    *(undefined4 *)(*(int *)(param_1 + 0x54) + 0x24) = *(undefined4 *)(param_1 + 0x14);
  }
  iVar1 = (int)*(short *)(*(int *)(param_1 + 0x50) + 0x78);
  if (-1 < iVar1) {
    FUN_80059644(iVar1,param_1);
  }
  if ((*(uint *)(*(int *)(param_1 + 0x50) + 0x44) & 0x40) == 0) {
    if (*(char *)(param_1 + 0xae) == '\0') {
      *(undefined *)(param_1 + 0xae) = 0x50;
    }
  }
  else {
    FUN_80037200(param_1,6);
    if ((*(char *)(param_1 + 0xae) != 'Z') &&
       ((*(uint *)(*(int *)(param_1 + 0x50) + 0x44) & 0x40) != 0)) {
      *(undefined *)(param_1 + 0xae) = 0x5a;
    }
  }
  if ((param_2 & 1) != 0) {
    *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x10;
    iVar1 = DAT_803dcb84 * 4;
    DAT_803dcb84 = DAT_803dcb84 + 1;
    *(int *)(DAT_803dcb88 + iVar1) = param_1;
    if ((*(ushort *)(param_1 + 0xb0) & 0x10) != 0) {
      iVar1 = 0;
      for (iVar2 = iRam803dcb80;
          (iVar2 != 0 && (*(char *)(param_1 + 0xae) < *(char *)(iVar2 + 0xae)));
          iVar2 = *(int *)(iVar2 + sRam803dcb7e)) {
        iVar1 = iVar2;
      }
      FUN_80013b20(&DAT_803dcb7c,iVar1,param_1);
    }
  }
  if ('\0' < *(char *)(*(int *)(param_1 + 0x50) + 0x56)) {
    FUN_80037200(param_1,8);
  }
  if ((*(uint *)(*(int *)(param_1 + 0x50) + 0x44) & 1) != 0) {
    DAT_803dcbc4 = 0;
  }
  return;
}

