// Function: FUN_801030c0
// Entry: 801030c0
// Size: 748 bytes

void FUN_801030c0(void)

{
  int iVar1;
  undefined4 uVar2;
  short *psVar3;
  
  iVar1 = FUN_80134be8();
  psVar3 = *(short **)(DAT_803dd524 + 0xa4);
  if (psVar3 == (short *)0x0) {
    *(undefined4 *)(DAT_803dd524 + 0x124) = 0;
    *(undefined4 *)(DAT_803dd524 + 0x11c) = 0;
  }
  else {
    FLOAT_803dd4e8 = *(float *)(psVar3 + 6);
    FLOAT_803dd4e4 = *(float *)(psVar3 + 8);
    FLOAT_803dd4e0 = *(float *)(psVar3 + 10);
    FLOAT_803dd4dc = *(float *)(psVar3 + 0xc);
    FLOAT_803dd4d8 = *(float *)(psVar3 + 0xe);
    FLOAT_803dd4d4 = *(float *)(psVar3 + 0x10);
    FUN_801015a8(DAT_803dd524,psVar3);
    if (*(char *)(DAT_803dd524 + 0x13d) != '\0') {
      *(undefined4 *)(psVar3 + 0xc) = *(undefined4 *)(DAT_803dd524 + 0xdc);
      *(undefined4 *)(psVar3 + 0xe) = *(undefined4 *)(DAT_803dd524 + 0xe0);
      *(undefined4 *)(psVar3 + 0x10) = *(undefined4 *)(DAT_803dd524 + 0xe4);
      FUN_8000e034((double)*(float *)(psVar3 + 0xc),(double)*(float *)(psVar3 + 0xe),
                   (double)*(float *)(psVar3 + 0x10),psVar3 + 6,psVar3 + 8,psVar3 + 10,
                   *(undefined4 *)(psVar3 + 0x18));
      *(undefined *)(DAT_803dd524 + 0x13d) = 0;
    }
    if (*(int *)(DAT_803dd524 + 0x30) != *(int *)(psVar3 + 0x18)) {
      FUN_8000e0a0((double)*(float *)(DAT_803dd524 + 0xc),(double)*(float *)(DAT_803dd524 + 0x10),
                   (double)*(float *)(DAT_803dd524 + 0x14),DAT_803dd524 + 0x18,DAT_803dd524 + 0x1c,
                   DAT_803dd524 + 0x20);
      FUN_8000e0a0((double)*(float *)(DAT_803dd524 + 0xa8),(double)*(float *)(DAT_803dd524 + 0xac),
                   (double)*(float *)(DAT_803dd524 + 0xb0),DAT_803dd524 + 0xb8,DAT_803dd524 + 0xbc,
                   DAT_803dd524 + 0xc0,*(undefined4 *)(DAT_803dd524 + 0x30));
      FUN_8000e034((double)*(float *)(DAT_803dd524 + 0x18),(double)*(float *)(DAT_803dd524 + 0x1c),
                   (double)*(float *)(DAT_803dd524 + 0x20),DAT_803dd524 + 0xc,DAT_803dd524 + 0x10,
                   DAT_803dd524 + 0x14,*(undefined4 *)(psVar3 + 0x18));
      FUN_8000e034((double)*(float *)(DAT_803dd524 + 0xb8),(double)*(float *)(DAT_803dd524 + 0xbc),
                   (double)*(float *)(DAT_803dd524 + 0xc0),DAT_803dd524 + 0xa8,DAT_803dd524 + 0xac,
                   DAT_803dd524 + 0xb0,*(undefined4 *)(psVar3 + 0x18));
      *(undefined4 *)(DAT_803dd524 + 0x30) = *(undefined4 *)(psVar3 + 0x18);
    }
    if (*(short **)(psVar3 + 0x18) != (short *)0x0) {
      *psVar3 = *psVar3 + **(short **)(psVar3 + 0x18);
    }
    FUN_80101ebc();
    if (DAT_803dd51c != 0) {
      (**(code **)(**(int **)(DAT_803dd51c + 4) + 8))(DAT_803dd524);
      FUN_8000e0a0((double)*(float *)(DAT_803dd524 + 0xc),(double)*(float *)(DAT_803dd524 + 0x10),
                   (double)*(float *)(DAT_803dd524 + 0x14),DAT_803dd524 + 0x18,DAT_803dd524 + 0x1c,
                   DAT_803dd524 + 0x20,*(undefined4 *)(DAT_803dd524 + 0x30));
      FUN_80101980(DAT_803dd524);
    }
    FUN_80101ebc();
    if (iVar1 == 0) {
      if (*(int *)(DAT_803dd524 + 0x11c) == 0) {
        uVar2 = FUN_801010b4(DAT_803dd524,psVar3);
        *(undefined4 *)(DAT_803dd524 + 0x124) = uVar2;
      }
      else {
        *(int *)(DAT_803dd524 + 0x124) = *(int *)(DAT_803dd524 + 0x11c);
      }
    }
    *(undefined4 *)(DAT_803dd524 + 0xa8) = *(undefined4 *)(DAT_803dd524 + 0xc);
    *(undefined4 *)(DAT_803dd524 + 0xac) = *(undefined4 *)(DAT_803dd524 + 0x10);
    *(undefined4 *)(DAT_803dd524 + 0xb0) = *(undefined4 *)(DAT_803dd524 + 0x14);
    *(undefined4 *)(DAT_803dd524 + 0xb8) = *(undefined4 *)(DAT_803dd524 + 0x18);
    *(undefined4 *)(DAT_803dd524 + 0xbc) = *(undefined4 *)(DAT_803dd524 + 0x1c);
    *(undefined4 *)(DAT_803dd524 + 0xc0) = *(undefined4 *)(DAT_803dd524 + 0x20);
    *(undefined *)(DAT_803dd524 + 0x140) = 0;
    *(float *)(psVar3 + 6) = FLOAT_803dd4e8;
    *(float *)(psVar3 + 8) = FLOAT_803dd4e4;
    *(float *)(psVar3 + 10) = FLOAT_803dd4e0;
    *(float *)(psVar3 + 0xc) = FLOAT_803dd4dc;
    *(float *)(psVar3 + 0xe) = FLOAT_803dd4d8;
    *(float *)(psVar3 + 0x10) = FLOAT_803dd4d4;
    if (*(short **)(psVar3 + 0x18) != (short *)0x0) {
      *psVar3 = *psVar3 - **(short **)(psVar3 + 0x18);
    }
  }
  return;
}

