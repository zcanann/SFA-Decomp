// Function: FUN_8002d404
// Entry: 8002d404
// Size: 592 bytes

void FUN_8002d404(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,uint param_10)

{
  int iVar1;
  int iVar2;
  undefined8 uVar3;
  
  if (*(int *)(param_9 + 0x30) == 0) {
    *(undefined4 *)(param_9 + 0x18) = *(undefined4 *)(param_9 + 0xc);
    *(undefined4 *)(param_9 + 0x1c) = *(undefined4 *)(param_9 + 0x10);
    *(undefined4 *)(param_9 + 0x20) = *(undefined4 *)(param_9 + 0x14);
  }
  else {
    param_2 = (double)*(float *)(param_9 + 0x10);
    param_3 = (double)*(float *)(param_9 + 0x14);
    param_1 = FUN_8000e0c0((double)*(float *)(param_9 + 0xc),param_2,param_3,
                           (float *)(param_9 + 0x18),(float *)(param_9 + 0x1c),
                           (float *)(param_9 + 0x20),*(int *)(param_9 + 0x30));
  }
  *(undefined4 *)(param_9 + 0x8c) = *(undefined4 *)(param_9 + 0x18);
  *(undefined4 *)(param_9 + 0x90) = *(undefined4 *)(param_9 + 0x1c);
  *(undefined4 *)(param_9 + 0x94) = *(undefined4 *)(param_9 + 0x20);
  *(undefined4 *)(param_9 + 0x80) = *(undefined4 *)(param_9 + 0xc);
  *(undefined4 *)(param_9 + 0x84) = *(undefined4 *)(param_9 + 0x10);
  *(undefined4 *)(param_9 + 0x88) = *(undefined4 *)(param_9 + 0x14);
  uVar3 = FUN_8002cbc4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  if (*(int *)(param_9 + 0x54) != 0) {
    *(undefined4 *)(*(int *)(param_9 + 0x54) + 0x10) = *(undefined4 *)(param_9 + 0xc);
    *(undefined4 *)(*(int *)(param_9 + 0x54) + 0x14) = *(undefined4 *)(param_9 + 0x10);
    *(undefined4 *)(*(int *)(param_9 + 0x54) + 0x18) = *(undefined4 *)(param_9 + 0x14);
    *(undefined4 *)(*(int *)(param_9 + 0x54) + 0x1c) = *(undefined4 *)(param_9 + 0xc);
    *(undefined4 *)(*(int *)(param_9 + 0x54) + 0x20) = *(undefined4 *)(param_9 + 0x10);
    *(undefined4 *)(*(int *)(param_9 + 0x54) + 0x24) = *(undefined4 *)(param_9 + 0x14);
  }
  if (-1 < *(short *)(*(int *)(param_9 + 0x50) + 0x78)) {
    FUN_800597c0(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  if ((*(uint *)(*(int *)(param_9 + 0x50) + 0x44) & 0x40) == 0) {
    if (*(char *)(param_9 + 0xae) == '\0') {
      *(undefined *)(param_9 + 0xae) = 0x50;
    }
  }
  else {
    FUN_800372f8(param_9,6);
    if ((*(char *)(param_9 + 0xae) != 'Z') &&
       ((*(uint *)(*(int *)(param_9 + 0x50) + 0x44) & 0x40) != 0)) {
      *(undefined *)(param_9 + 0xae) = 0x5a;
    }
  }
  if ((param_10 & 1) != 0) {
    *(ushort *)(param_9 + 0xb0) = *(ushort *)(param_9 + 0xb0) | 0x10;
    iVar1 = DAT_803dd804 * 4;
    DAT_803dd804 = DAT_803dd804 + 1;
    *(int *)(DAT_803dd808 + iVar1) = param_9;
    if ((*(ushort *)(param_9 + 0xb0) & 0x10) != 0) {
      iVar1 = 0;
      for (iVar2 = iRam803dd800;
          (iVar2 != 0 && (*(char *)(param_9 + 0xae) < *(char *)(iVar2 + 0xae)));
          iVar2 = *(int *)(iVar2 + sRam803dd7fe)) {
        iVar1 = iVar2;
      }
      FUN_80013b40((short *)&DAT_803dd7fc,iVar1,param_9);
    }
  }
  if ('\0' < *(char *)(*(int *)(param_9 + 0x50) + 0x56)) {
    FUN_800372f8(param_9,8);
  }
  if ((*(uint *)(*(int *)(param_9 + 0x50) + 0x44) & 1) != 0) {
    DAT_803dd844 = 0;
  }
  return;
}

