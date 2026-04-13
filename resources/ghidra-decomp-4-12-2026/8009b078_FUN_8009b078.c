// Function: FUN_8009b078
// Entry: 8009b078
// Size: 756 bytes

int FUN_8009b078(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  int *piVar1;
  undefined4 uVar2;
  uint uVar3;
  int iVar4;
  int extraout_r4;
  int iVar5;
  int *piVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  
  iVar5 = 0;
  piVar6 = &DAT_8039b7b8;
  iVar7 = 0x20;
  piVar1 = piVar6;
  do {
    if ((*piVar1 != 0) && (param_9 == piVar1[2])) {
      if (((&DAT_8039b7b8)[iVar5 * 4] != 0) &&
         (0x3fff < *(ushort *)((&DAT_8039b7b8)[iVar5 * 4] + 0xe))) {
        return -1;
      }
      (&DAT_8039b7bc)[iVar5 * 4] = 1000;
      return (int)(short)iVar5;
    }
    piVar1 = piVar1 + 4;
    iVar5 = iVar5 + 1;
    iVar7 = iVar7 + -1;
  } while (iVar7 != 0);
  iVar7 = 0;
  iVar8 = 0x20;
  piVar1 = piVar6;
  while (*piVar1 != 0) {
    piVar1 = piVar1 + 4;
    iVar7 = iVar7 + 1;
    iVar8 = iVar8 + -1;
    if (iVar8 == 0) {
      uVar3 = FUN_8002e144();
      if ((uVar3 & 0xff) == 0) {
        iVar5 = -4;
      }
      else {
        iVar7 = 64000;
        iVar8 = 0;
        iVar4 = 0;
        iVar9 = 4;
        do {
          if (piVar6[1] < iVar7) {
            iVar7 = piVar6[1];
            iVar8 = iVar4;
          }
          if (piVar6[5] < iVar7) {
            iVar7 = piVar6[5];
            iVar8 = iVar4 + 1;
          }
          if (piVar6[9] < iVar7) {
            iVar7 = piVar6[9];
            iVar8 = iVar4 + 2;
          }
          if (piVar6[0xd] < iVar7) {
            iVar7 = piVar6[0xd];
            iVar8 = iVar4 + 3;
          }
          if (piVar6[0x11] < iVar7) {
            iVar7 = piVar6[0x11];
            iVar8 = iVar4 + 4;
          }
          if (piVar6[0x15] < iVar7) {
            iVar7 = piVar6[0x15];
            iVar8 = iVar4 + 5;
          }
          if (piVar6[0x19] < iVar7) {
            iVar7 = piVar6[0x19];
            iVar8 = iVar4 + 6;
          }
          if (piVar6[0x1d] < iVar7) {
            iVar7 = piVar6[0x1d];
            iVar8 = iVar4 + 7;
          }
          piVar6 = piVar6 + 0x20;
          iVar4 = iVar4 + 8;
          iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        DAT_803dded8 = 1;
        if ((&DAT_8039b7b8)[iVar8 * 4] != 0) {
          param_1 = FUN_80054484();
          iVar7 = extraout_r4;
        }
        DAT_803dded8 = 0;
        (&DAT_8039b7b8)[iVar8 * 4] = 0;
        uVar2 = FUN_80054ed0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9
                             ,iVar7,param_11,iVar5,param_13,param_14,param_15,param_16);
        (&DAT_8039b7b8)[iVar8 * 4] = uVar2;
        if ((&DAT_8039b7b8)[iVar8 * 4] == 0) {
          iVar5 = -3;
        }
        else {
          (&DAT_8039b7bc)[iVar8 * 4] = 1000;
          (&DAT_8039b7c0)[iVar8 * 4] = param_9;
          iVar5 = (int)(short)iVar8;
        }
      }
      return iVar5;
    }
  }
  uVar2 = FUN_80054ed0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                       param_10,param_11,iVar5,param_13,param_14,param_15,param_16);
  (&DAT_8039b7b8)[iVar7 * 4] = uVar2;
  iVar5 = (&DAT_8039b7b8)[iVar7 * 4];
  if ((iVar5 != 0) && (0x3fff < *(ushort *)(iVar5 + 0xe))) {
    DAT_803dded8 = 1;
    if (iVar5 != 0) {
      FUN_80054484();
    }
    DAT_803dded8 = 0;
    (&DAT_8039b7b8)[iVar7 * 4] = 0;
    return -1;
  }
  if (iVar5 != 0) {
    (&DAT_8039b7bc)[iVar7 * 4] = 1000;
    (&DAT_8039b7c0)[iVar7 * 4] = param_9;
    return (int)(short)iVar7;
  }
  return -2;
}

