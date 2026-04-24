// Function: FUN_8009adec
// Entry: 8009adec
// Size: 756 bytes

int FUN_8009adec(int param_1)

{
  int *piVar1;
  undefined4 uVar2;
  char cVar4;
  int iVar3;
  int iVar5;
  int *piVar6;
  int iVar7;
  int iVar8;
  
  iVar5 = 0;
  piVar6 = &DAT_8039ab58;
  iVar7 = 0x20;
  piVar1 = piVar6;
  do {
    if ((*piVar1 != 0) && (param_1 == piVar1[2])) {
      if (((&DAT_8039ab58)[iVar5 * 4] != 0) &&
         (0x3fff < *(ushort *)((&DAT_8039ab58)[iVar5 * 4] + 0xe))) {
        return -1;
      }
      (&DAT_8039ab5c)[iVar5 * 4] = 1000;
      return (int)(short)iVar5;
    }
    piVar1 = piVar1 + 4;
    iVar5 = iVar5 + 1;
    iVar7 = iVar7 + -1;
  } while (iVar7 != 0);
  iVar5 = 0;
  iVar7 = 0x20;
  piVar1 = piVar6;
  while (*piVar1 != 0) {
    piVar1 = piVar1 + 4;
    iVar5 = iVar5 + 1;
    iVar7 = iVar7 + -1;
    if (iVar7 == 0) {
      cVar4 = FUN_8002e04c();
      if (cVar4 == '\0') {
        iVar5 = -4;
      }
      else {
        iVar5 = 64000;
        iVar7 = 0;
        iVar3 = 0;
        iVar8 = 4;
        do {
          if (piVar6[1] < iVar5) {
            iVar5 = piVar6[1];
            iVar7 = iVar3;
          }
          if (piVar6[5] < iVar5) {
            iVar5 = piVar6[5];
            iVar7 = iVar3 + 1;
          }
          if (piVar6[9] < iVar5) {
            iVar5 = piVar6[9];
            iVar7 = iVar3 + 2;
          }
          if (piVar6[0xd] < iVar5) {
            iVar5 = piVar6[0xd];
            iVar7 = iVar3 + 3;
          }
          if (piVar6[0x11] < iVar5) {
            iVar5 = piVar6[0x11];
            iVar7 = iVar3 + 4;
          }
          if (piVar6[0x15] < iVar5) {
            iVar5 = piVar6[0x15];
            iVar7 = iVar3 + 5;
          }
          if (piVar6[0x19] < iVar5) {
            iVar5 = piVar6[0x19];
            iVar7 = iVar3 + 6;
          }
          if (piVar6[0x1d] < iVar5) {
            iVar5 = piVar6[0x1d];
            iVar7 = iVar3 + 7;
          }
          piVar6 = piVar6 + 0x20;
          iVar3 = iVar3 + 8;
          iVar8 = iVar8 + -1;
        } while (iVar8 != 0);
        DAT_803dd258 = 1;
        if ((&DAT_8039ab58)[iVar7 * 4] != 0) {
          FUN_80054308();
        }
        DAT_803dd258 = 0;
        (&DAT_8039ab58)[iVar7 * 4] = 0;
        uVar2 = FUN_80054d54(param_1);
        (&DAT_8039ab58)[iVar7 * 4] = uVar2;
        if ((&DAT_8039ab58)[iVar7 * 4] == 0) {
          iVar5 = -3;
        }
        else {
          (&DAT_8039ab5c)[iVar7 * 4] = 1000;
          (&DAT_8039ab60)[iVar7 * 4] = param_1;
          iVar5 = (int)(short)iVar7;
        }
      }
      return iVar5;
    }
  }
  uVar2 = FUN_80054d54(param_1);
  (&DAT_8039ab58)[iVar5 * 4] = uVar2;
  iVar7 = (&DAT_8039ab58)[iVar5 * 4];
  if ((iVar7 != 0) && (0x3fff < *(ushort *)(iVar7 + 0xe))) {
    DAT_803dd258 = 1;
    if (iVar7 != 0) {
      FUN_80054308();
    }
    DAT_803dd258 = 0;
    (&DAT_8039ab58)[iVar5 * 4] = 0;
    return -1;
  }
  if (iVar7 != 0) {
    (&DAT_8039ab5c)[iVar5 * 4] = 1000;
    (&DAT_8039ab60)[iVar5 * 4] = param_1;
    return (int)(short)iVar5;
  }
  return -2;
}

