// Function: FUN_801d286c
// Entry: 801d286c
// Size: 376 bytes

undefined4 FUN_801d286c(int param_1)

{
  int iVar1;
  int iVar2;
  float *pfVar3;
  
  pfVar3 = *(float **)(param_1 + 0xb8);
  if (*(char *)(pfVar3 + 5) == '\0') {
    FUN_8000da58(param_1,0x3fd);
    iVar2 = *(int *)(param_1 + 0x4c);
    if ((*(byte *)((int)pfVar3 + 0x15) & 2) != 0) {
      *(byte *)((int)pfVar3 + 0x15) = *(byte *)((int)pfVar3 + 0x15) & 0xfd;
      iVar1 = FUN_800221a0(0xffffffce,0x32);
      *pfVar3 = (float)((double)CONCAT44(0x43300000,*(short *)(iVar2 + 0x1a) + iVar1 ^ 0x80000000) -
                       DOUBLE_803e5360);
    }
    if ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0) {
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x7f1,0,2,0xffffffff,0);
    }
  }
  else {
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) & 0xbfff;
    iVar2 = *(int *)(param_1 + 0x4c);
    *(undefined *)(param_1 + 0x36) = 0xff;
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) & 0xbfff;
    *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(iVar2 + 8);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar2 + 0xc);
    *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(iVar2 + 0x10);
    *(float *)(param_1 + 8) = FLOAT_803e5358;
    pfVar3[2] = FLOAT_803e535c;
    pfVar3[1] = pfVar3[3];
    pfVar3[4] = pfVar3[1] / pfVar3[2];
    *pfVar3 = pfVar3[2];
    FUN_80036044();
    *(undefined *)(pfVar3 + 5) = 0;
    *(byte *)((int)pfVar3 + 0x15) = *(byte *)((int)pfVar3 + 0x15) | 2;
  }
  return 0;
}

